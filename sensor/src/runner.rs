//! Running one question: `beat-probe run -` in a transient systemd unit:
//! read-only file system, no network, no devices, memory/task/time limits, secret files covered by placeholders and
//! their real metadata passed in a file (BEAT_SECRETS_FILE). One child process per question (docs/probes.md §8).
//!
//! The placeholders need concrete paths before the unit starts. Fixed paths and single-level globs are checked for
//! each question (`beat-probe secrets --live`, milliseconds). The recursive patterns are walked in the background, in a
//! limited low-priority unit of their own (`--walk`, `walk_forever`), and questions use the latest result: a walk is far
//! too costly per question (a host with containers and media data spent 25-33 s of every question on it). So a file
//! that matches a recursive pattern and appeared since the last walk has no placeholder until the next one; beat-probe's
//! own check of the patterns does not depend on any of this. A question never runs without the check: until the first
//! walk ends, or when the latest is too old or the live check fails, it is refused (kind `secrets`).
//!
//! The question reaches the unit, and its result comes back, through files in RUN_DIR that systemd opens for the unit
//! (StandardInput=file:...), not through `systemd-run --pipe`: that hands the caller's pipes to PID 1 over D-Bus, and
//! on RHEL-family hosts SELinux forbids dbus-broker to pass them (fifo_file write, a dontaudit rule: no AVC logged).

use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde_json::{json, Value};
use tokio::io::AsyncWriteExt;
use tokio::process::Command;
use tokio::sync::watch;

pub struct Runner {
    pub probe: PathBuf,
    pub tools: PathBuf,
    pub cache: PathBuf,
    pub osqueryi: Option<PathBuf>,
    pub journalctl: Option<PathBuf>,
    /// The eBPF catalog behind trace() (libbpf-tools): a question that names an entry gets that entry's capabilities.
    pub bpf_tools: Option<PathBuf>,
    /// The capture broker (capture.rs): a question that calls capture() gets a socket to it. None: no tcpdump.
    pub capture: Option<Arc<crate::capture::Broker>>,
    /// Placeholders bound over secret files: `<dir>/file` and `<dir>/dir`. None: no sandbox (development only).
    pub sandbox: Option<PathBuf>,
    /// Set once systemd could not mount the placeholders over secret files (226/NAMESPACE; e.g. SELinux forbids PID 1
    /// to mount over shadow_t). Questions then run without them: beat-probe still refuses to read secret files, but a
    /// child it starts (osqueryi) can read them. Reported in the heartbeat (`sandbox`).
    pub secret_mounts_denied: AtomicBool,
    /// Files no question may see in any form (the sensor's signing key): InaccessiblePaths in every unit, also when
    /// the secret placeholders cannot be mounted, so a host that refuses it refuses questions instead.
    pub hide: Vec<PathBuf>,
    /// More properties for every question's unit (`--unit-property`): MountImages= when installed from an image.
    pub unit_props: Vec<String>,
    /// Where the host's systemd-run and systemctl are (`--systemd`): /usr/bin, or the systemd package's bin on NixOS.
    pub systemd: PathBuf,
    /// The latest background walk of the recursive secret patterns.
    pub walk: watch::Sender<Option<Arc<Walked>>>,
    /// Why the last walk failed, when it did.
    pub walk_error: Mutex<Option<String>>,
    /// Paths found since the last heartbeat that no placeholder could cover (`bind_word`).
    pub uncovered: Mutex<Vec<String>>,
    /// The user questions and the walk run as (`--question-user`): name and uid. None: root, as before 0.2.3. A unix
    /// socket owned by root admits root by uid whatever its capabilities: systemd's private socket and the system bus
    /// took a question's commands (docs/security.md). As this user, with its two capabilities ambient, it reads as
    /// before and D-Bus answers it as an unprivileged caller.
    pub question_user: Option<(String, u32)>,
}

/// The question user, looked up (getent: every NSS source; /etc/passwd when getent is not on PATH, NixOS). The sensor's
/// unit makes it (ExecStartPre=+systemd-sysusers; the NixOS module declares it): the sensor's own /etc is read-only.
/// Err: questions run as root, and the heartbeat says so.
pub fn question_user(name: &str) -> Result<(String, u32), String> {
    let uid_in = |line: &str| -> Option<u32> {
        let f: Vec<&str> = line.trim().split(':').collect();
        (f.len() > 2 && f[0] == name).then(|| f[2].parse().ok()).flatten()
    };
    let getent = std::process::Command::new("getent").args(["passwd", name]).output().ok()
        .and_then(|o| uid_in(&String::from_utf8_lossy(&o.stdout)));
    getent.or_else(|| std::fs::read_to_string("/etc/passwd").ok()?.lines().find_map(uid_in))
        .map(|uid| (name.to_string(), uid))
        .ok_or_else(|| format!("no user {name} (the sensor's unit makes it: ExecStartPre=+systemd-sysusers)"))
}

/// A secret file: its path, whether it is a directory, and its metadata line for the question.
#[derive(Clone, Debug, PartialEq)]
pub struct SecretFile {
    pub path: String,
    pub dir: bool,
    pub line: String,
}

/// What a walk found and what it left out (`beat-probe secrets --walk`).
pub struct Walked {
    pub when: Instant,
    pub at: String,
    pub secrets: Vec<SecretFile>,
    pub scan: Value,
}

/// Where a question's time went, for the answer's Beat-Phases header and the log (docs/protocol.md): the sensor's own
/// steps in ms, then beat-probe's `timings` (inside `unit`), flattened. Keys ending in `_calls` are counts, in
/// `_bytes` bytes; every other value is milliseconds.
#[derive(Default)]
pub struct Phases {
    pub queue_ms: AtomicU64,
    pub secrets_ms: AtomicU64,
    pub run_ms: AtomicU64,
    /// `beat-probe needs`: the trace capabilities the probe asks for, a process of its own
    pub needs_ms: AtomicU64,
    /// the secrets map file and the placeholders' bind list
    pub prepare_ms: AtomicU64,
    /// systemd-run, from its start to its end: the sandbox's set-up and beat-probe's whole run
    pub unit_ms: AtomicU64,
    /// the unit run again without placeholders (226/NAMESPACE: mounts refused)
    pub retried: AtomicU64,
    pub seal_ms: AtomicU64,
    /// beat-probe's run result `timings`
    pub probe: std::sync::Mutex<Option<Value>>,
}

impl Phases {
    pub fn text(&self) -> String {
        let l = |a: &AtomicU64| a.load(Ordering::Relaxed);
        let mut out = format!("queue={},secrets={},run={},needs={},prepare={},unit={},seal={}", l(&self.queue_ms),
                              l(&self.secrets_ms), l(&self.run_ms), l(&self.needs_ms), l(&self.prepare_ms),
                              l(&self.unit_ms), l(&self.seal_ms));
        if l(&self.retried) > 0 {
            out.push_str(",retry=1");
        }
        if let Some(Value::Object(t)) = self.probe.lock().unwrap().as_ref() {
            for (k, v) in t {
                match (k.as_str(), v) {
                    ("builtins", Value::Object(b)) => {
                        for (name, x) in b {
                            out.push_str(&format!(",{name}={},{name}_calls={}", x["ms"].as_u64().unwrap_or(0),
                                                  x["calls"].as_u64().unwrap_or(0)));
                        }
                    }
                    (k, Value::Number(n)) if k.chars().all(|c| c.is_ascii_lowercase() || c == '_') => {
                        out.push_str(&format!(",{k}={n}"));
                    }
                    _ => {}
                }
            }
        }
        out
    }
}

/// A question's memory limit (the unit's MemoryMax): past it the kernel kills beat-probe, not the sensor.
const MEMORY_MAX: &str = "1G";
/// Every question's capabilities: reading files whatever their mode, and other processes' /proc entries.
const BASE_CAPS: &str = "CAP_DAC_READ_SEARCH CAP_SYS_PTRACE";
/// What a question's trace() entries may add (`beat-probe needs`), and nothing else whatever it says.
const TRACE_CAPS: [&str; 2] = ["CAP_BPF", "CAP_PERFMON"];
/// The sensor unit's RuntimeDirectory (beat-sensor.service): one question's input, output and error files at a time.
pub const RUN_DIR: &str = "/run/beat-sensor";
/// Between the end of one walk and the start of the next: how long a new file under a recursive pattern can go without
/// a placeholder, plus the walk's own time. A judgement, to review with the cost measured on real hosts.
const WALK_EVERY: Duration = Duration::from_secs(300);
/// After a walk that failed.
const WALK_RETRY: Duration = Duration::from_secs(60);
/// A walk older than this is not used: the questions are refused and say why. A judgement: several failed refreshes.
const WALK_MAX_AGE: Duration = Duration::from_secs(3600);
/// The walk's budget (`beat-probe secrets --budget-s`), and how much longer the unit may run to report it.
const WALK_BUDGET_S: u64 = 300;
/// What the live check may take. Fixed paths on local disks take milliseconds; past this something is stalled.
const LIVE_TIMEOUT: Duration = Duration::from_secs(10);
/// One program's arguments together: the kernel's limit depends on the stack limit (2 MiB by default, 128 KiB at
/// least); a list longer than this is refused rather than left to fail at exec.
const ARGV_MAX: usize = 1 << 20;
static SEQ: AtomicU64 = AtomicU64::new(0);

/// A task stopped when this goes out of scope.
struct Aborted(tokio::task::JoinHandle<()>);

impl Drop for Aborted {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// Files that are removed when this goes out of scope.
struct TempFiles(Vec<PathBuf>);

impl Drop for TempFiles {
    fn drop(&mut self) {
        for f in &self.0 {
            let _ = std::fs::remove_file(f);
        }
    }
}

/// Why a question has no result: the answer's error kind and message. `memory` and `timeout`: the question's unit
/// was stopped at its limit (systemd's Result: oom-kill, timeout); `sensor`: anything else that kept it from running.
pub struct Failed {
    pub kind: &'static str,
    pub message: String,
}

impl From<String> for Failed {
    fn from(message: String) -> Self {
        Failed { kind: "sensor", message }
    }
}

/// What a probe run left: its output, and how its unit ended (systemd's Result and MemoryPeak; empty unsandboxed).
struct Exit {
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    status: String,
    result: String,
    memory_peak: Option<u64>,
}

impl Runner {
    /// Runs the question; Ok is beat-probe's run result (docs/probes.md §9), Err why there is none.
    /// `profile`: the person asked for each host call's time (Beat-Profile): beat-probe --profile.
    pub async fn run(&self, name: &str, source: &str, timeout_s: u64, phases: &Phases, profile: bool) -> Result<Value, Failed> {
        let mut probe = vec![self.probe.display().to_string(), "run".into(), "-".into(), "--name".into(), name.into(),
                             "--map".into(), "/".into(), "--tools".into(), self.tools.display().to_string(),
                             "--cache".into(), self.cache.display().to_string()];
        if profile {
            probe.push("--profile".into());
        }
        for (flag, path) in [("--osqueryi", &self.osqueryi), ("--journalctl", &self.journalctl), ("--bpf-tools", &self.bpf_tools)] {
            if let Some(p) = path {
                probe.extend([flag.to_string(), p.display().to_string()]);
            }
        }
        let x = match &self.sandbox {
            Some(placeholders) => {
                let begun = Instant::now();
                let found = self.secret_files(timeout_s).await;
                phases.secrets_ms.store(begun.elapsed().as_millis() as u64, Ordering::Relaxed);
                let (secrets, report) = found?;
                let left = timeout_s.saturating_sub(begun.elapsed().as_secs()).max(1);
                let ran = Instant::now();
                let x = self.run_sandboxed(probe, source, left, placeholders, name, &secrets, &report, phases).await;
                phases.run_ms.store(ran.elapsed().as_millis() as u64, Ordering::Relaxed);
                x?
            }
            None => run_piped(probe, source, timeout_s).await?,
        };
        if let Ok(v) = serde_json::from_slice::<Value>(&x.stdout) {
            *phases.probe.lock().unwrap() = v.get("timings").cloned();
            return Ok(v);
        }
        Err(match x.result.as_str() {
            "oom-kill" => Failed { kind: "memory", message: format!(
                "out of memory: the question reached its {MEMORY_MAX} limit and was stopped{}. A probe keeps the values \
                 it makes until it ends: aggregate as it goes, emit less, or ask fewer files per question",
                x.memory_peak.map_or(String::new(), |b| format!(" (memory peak {} MiB)", b >> 20))) },
            "timeout" => Failed { kind: "timeout", message: format!(
                "time limit ({timeout_s} s) reached: the question was stopped") },
            _ => {
                let err = String::from_utf8_lossy(&x.stderr);
                let tail: String = err.trim().chars().rev().take(2000).collect::<Vec<_>>().into_iter().rev().collect();
                Failed::from(format!("beat-probe exited {} without a result: {}", x.status,
                                     if tail.is_empty() { "(no output)" } else { &tail }))
            }
        })
    }

    /// What this question needs beyond what every question gets, from its text (`beat-probe needs`): the
    /// capabilities its trace() entries need (only those in TRACE_CAPS, none on a host without the catalog), and
    /// whether it calls capture() (never on a host without the broker).
    async fn needs(&self, source: &str) -> Result<(Vec<String>, bool), String> {
        if self.bpf_tools.is_none() && self.capture.is_none() {
            return Ok((Vec::new(), false));
        }
        let mut child = Command::new(&self.probe).args(["needs", "-"]).stdin(Stdio::piped()).stdout(Stdio::piped())
            .stderr(Stdio::null()).kill_on_drop(true).spawn().map_err(|e| format!("beat-probe needs: {e}"))?;
        let mut stdin = child.stdin.take().expect("piped");
        stdin.write_all(source.as_bytes()).await.map_err(|e| format!("beat-probe needs: {e}"))?;
        drop(stdin);
        let out = tokio::time::timeout(Duration::from_secs(10), child.wait_with_output()).await
            .map_err(|_| "beat-probe needs: timed out".to_string())?.map_err(|e| format!("beat-probe needs: {e}"))?;
        let v: Value = serde_json::from_slice(&out.stdout).map_err(|e| format!("beat-probe needs: {e}"))?;
        let caps = match &self.bpf_tools {
            Some(_) => v["capabilities"].as_array().into_iter().flatten().filter_map(Value::as_str)
                .filter(|c| TRACE_CAPS.contains(c)).map(String::from).collect(),
            None => Vec::new(),
        };
        Ok((caps, self.capture.is_some() && v["capture"] == true))
    }

    /// The probe in a transient unit, with the secret placeholders mounted unless the host refused them before.
    #[allow(clippy::too_many_arguments)]
    async fn run_sandboxed(&self, probe: Vec<String>, source: &str, timeout_s: u64, placeholders: &PathBuf, name: &str,
                           secrets: &[SecretFile], report: &Scan, phases: &Phases) -> Result<Exit, Failed> {
        let mounts = !self.secret_mounts_denied.load(Ordering::Relaxed);
        let t = Instant::now();
        let (caps, capture) = self.needs(source).await?;
        phases.needs_ms.store(t.elapsed().as_millis() as u64, Ordering::Relaxed);
        let q = Question { source, timeout_s, placeholders, name, caps: &caps, capture, secrets, report };
        let (x, code) = self.unit(probe.clone(), &q, mounts, phases).await?;
        if mounts && code == Some(226) {
            eprintln!("secret placeholders cannot be mounted on this host (226/NAMESPACE, e.g. SELinux): questions run \
                       without them from now on; secret files stay unreadable to beat-probe, not to osqueryi");
            self.secret_mounts_denied.store(true, Ordering::Relaxed);
            phases.retried.store(1, Ordering::Relaxed);
            return Ok(self.unit(probe, &q, false, phases).await?.0);
        }
        Ok(x)
    }

    /// One transient unit; its stdin, stdout and stderr are files in RUN_DIR. The exit code is the unit's, and so is
    /// how it ended (Result: oom-kill when MemoryMax was reached, timeout at RuntimeMaxSec).
    async fn unit(&self, probe: Vec<String>, q: &Question<'_>, mounts: bool, phases: &Phases)
                  -> Result<(Exit, Option<i32>), Failed> {
        let Question { source, timeout_s, name, .. } = *q;
        let preparing = Instant::now();
        let id = format!("{}-{}", std::process::id(), SEQ.fetch_add(1, Ordering::Relaxed));
        let file = |ext: &str| Path::new(RUN_DIR).join(format!("{id}.{ext}"));
        let (input, output, error, meta, socket) = (file("star"), file("out"), file("err"), file("secrets"), file("capture"));
        let _cleanup = TempFiles(vec![input.clone(), output.clone(), error.clone(), meta.clone(), socket.clone()]);
        tokio::fs::write(&input, source).await.map_err(|e| format!("cannot write {}: {e}", input.display()))?;
        let unit = format!("beat-question-{id}");
        let (binds, uncovered) = bind_props(q.secrets, q.placeholders);
        if !uncovered.is_empty() {
            let mut held = self.uncovered.lock().unwrap();
            for p in &uncovered {
                if !held.contains(p) {
                    eprintln!("secret file not covered by a placeholder: systemd cannot express {p:?}");
                    held.push(p.clone());
                }
            }
        }
        write_private(&meta, &secrets_text(q.secrets, q.report, &uncovered)).await
            .map_err(|e| format!("cannot write {}: {e}", meta.display()))?;
        // The capture broker's socket, for this question alone and while it runs (the task ends with this scope).
        let _broker = match (&self.capture, q.capture) {
            (Some(b), true) => {
                let _ = std::fs::remove_file(&socket);
                let listener = tokio::net::UnixListener::bind(&socket).map_err(|e| format!("{}: {e}", socket.display()))?;
                // Connecting needs write permission on the socket: the question's user owns it, no one else may.
                if let Some((_, uid)) = &self.question_user {
                    std::os::unix::fs::chown(&socket, Some(*uid), None).map_err(|e| format!("{}: {e}", socket.display()))?;
                    std::fs::set_permissions(&socket, std::os::unix::fs::PermissionsExt::from_mode(0o600))
                        .map_err(|e| format!("{}: {e}", socket.display()))?;
                }
                let (b, deadline) = (b.clone(), Instant::now() + Duration::from_secs(timeout_s));
                Some(Aborted(tokio::spawn(async move { b.serve(listener, deadline).await })))
            }
            _ => None,
        };
        let argv = self.sandboxed(probe, timeout_s, name, [&input, &output, &error, &meta], if mounts { binds } else { Vec::new() },
                                  &unit, q.caps, _broker.as_ref().map(|_| socket.as_path()));
        let size: usize = argv.iter().map(|a| a.len() + 1).sum();
        if size > ARGV_MAX {
            return Err(Failed { kind: "secrets", message: format!(
                "too many secret files to cover: {} placeholders make {size} bytes of arguments to systemd-run, over \
                 {ARGV_MAX}: the question was not run", q.secrets.len()) });
        }
        phases.prepare_ms.store(preparing.elapsed().as_millis() as u64, Ordering::Relaxed);
        let unit_started = Instant::now();
        let child = Command::new(&argv[0])
            .args(&argv[1..]).stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped()).kill_on_drop(true)
            .spawn().map_err(|e| format!("cannot start {}: {e}", argv[0]))?;
        // The unit's RuntimeMaxSec stops the probe itself; this bounds the wait for systemd-run.
        let run = tokio::time::timeout(Duration::from_secs(timeout_s + 15), child.wait_with_output())
            .await
            .map_err(|_| format!("time limit ({timeout_s}s) reached"))?
            .map_err(|e| format!("waiting for beat-probe: {e}"))?;
        phases.unit_ms.store(unit_started.elapsed().as_millis() as u64, Ordering::Relaxed);
        let stdout = tokio::fs::read(&output).await.unwrap_or_default();
        let mut stderr = tokio::fs::read(&error).await.unwrap_or_default();
        stderr.extend_from_slice(&run.stderr); // systemd-run's own complaints, e.g. a unit that could not start
        if run.status.success() {
            return Ok((Exit { stdout, stderr, status: status_text(Some(0)), result: "success".into(), memory_peak: None },
                       Some(0)));
        }
        // systemd-run exits 1 whenever the unit failed, even when it never started (namespace set-up: 226): the
        // unit's own status is systemd's. A failed unit stays loaded until reset (no --collect, so it can be read).
        let show = Command::new(self.systemd.join("systemctl")).args(["show", "-p", "ExecMainStatus,Result,MemoryPeak", &unit]).output()
            .await.map(|o| String::from_utf8_lossy(&o.stdout).to_string()).unwrap_or_default();
        let prop = |k: &str| show.lines().find_map(|l| l.strip_prefix(k)?.strip_prefix('=')).unwrap_or("").to_string();
        let _ = Command::new(self.systemd.join("systemctl")).args(["reset-failed", &unit]).output().await;
        let code = prop("ExecMainStatus").parse::<i32>().ok().filter(|c| *c != 0).or(run.status.code());
        Ok((Exit { stdout, stderr, status: status_text(code), result: prop("Result"),
                   memory_peak: prop("MemoryPeak").parse().ok() }, code))
    }

    #[allow(clippy::too_many_arguments)]
    fn sandboxed(&self, probe: Vec<String>, timeout_s: u64, name: &str, [input, output, error, meta]: [&PathBuf; 4],
                 binds: Vec<String>, unit: &str, caps: &[String], capture: Option<&Path>) -> Vec<String> {
        let mut props: Vec<String> = HARDENING.iter().map(|s| s.to_string()).collect();
        props.extend(self.question_user.iter().map(|(u, _)| format!("User={u}")));
        match capture {
            Some(_) => props.push(PRIVATE_NETWORK.into()),
            None => props.extend(HOST_NETWORK.map(String::from)),
        }
        props.extend(["TasksMax=64", "CPUQuota=100%"].map(String::from));
        let all_caps = format!("{BASE_CAPS}{}", caps.iter().map(|c| format!(" {c}")).collect::<String>());
        props.push(format!("CapabilityBoundingSet={all_caps}"));
        props.push(format!("AmbientCapabilities={all_caps}"));
        props.push(format!("MemoryMax={MEMORY_MAX}"));
        props.push(format!("RuntimeMaxSec={timeout_s}"));
        for p in &self.hide {
            props.push(format!("InaccessiblePaths={}", p.display()));
        }
        props.extend(self.unit_props.iter().cloned());
        props.push(format!("StandardInput=file:{}", input.display()));
        props.push(format!("StandardOutput=file:{}", output.display()));
        props.push(format!("StandardError=file:{}", error.display()));
        props.extend(binds);
        let mut argv: Vec<String> = vec![self.systemd.join("systemd-run").display().to_string()];
        argv.extend(["--quiet", "--wait", "--service-type=exec"].iter().map(|s| s.to_string()));
        argv.push(format!("--unit={unit}"));
        argv.push(format!("--description=beat question {name}"));
        for p in props {
            argv.extend(["-p".into(), p]);
        }
        let hidden = self.hide.iter().map(|p| p.display().to_string()).collect::<Vec<_>>().join("\n");
        for (k, v) in [("HOME", "/tmp".to_string()), ("LANG", "C.UTF-8".to_string()), ("BEAT_SECRETS_FILE", meta.display().to_string()),
                       ("BEAT_HIDDEN", hidden)] {
            argv.extend(["-E".into(), format!("{k}={v}")]);
        }
        if let Some(c) = capture {
            argv.extend(["-E".into(), format!("BEAT_CAPTURE={}", c.display())]);
        }
        argv.extend(probe);
        argv
    }

    /// The walk, over and over while the sensor runs: one at a time, in a unit of its own. Questions wait for the first.
    pub async fn walk_forever(&self) {
        loop {
            let every = match self.walk_once().await {
                Ok(w) => {
                    eprintln!("secret walk: {} secret files; {}", w.secrets.len(), w.scan);
                    *self.walk_error.lock().unwrap() = None;
                    self.walk.send_replace(Some(Arc::new(w)));
                    WALK_EVERY
                }
                Err(e) => {
                    eprintln!("secret walk failed: {e}");
                    *self.walk_error.lock().unwrap() = Some(e);
                    WALK_RETRY
                }
            };
            tokio::time::sleep(every).await;
        }
    }

    /// One walk, in its own unit: read-only, no network, a quarter of a CPU at idle I/O priority, stopped by its limits.
    async fn walk_once(&self) -> Result<Walked, String> {
        let id = format!("{}-{}", std::process::id(), SEQ.fetch_add(1, Ordering::Relaxed));
        let unit = format!("beat-secret-walk-{id}");
        let file = |ext: &str| Path::new(RUN_DIR).join(format!("{id}.{ext}"));
        let (output, error) = (file("walk"), file("walk-err"));
        let _cleanup = TempFiles(vec![output.clone(), error.clone()]);
        let mut argv: Vec<String> = ["--quiet", "--wait", "--collect", "--service-type=exec"].iter().map(|s| s.to_string()).collect();
        argv.push(format!("--unit={unit}"));
        argv.push("--description=beat secret walk".into());
        let mut props: Vec<String> = HARDENING.iter().map(|s| s.to_string()).collect();
        props.push(PRIVATE_NETWORK.into());
        props.extend(self.question_user.iter().map(|(u, _)| format!("User={u}")));
        props.extend(WALK_LIMITS.map(String::from));
        props.push(format!("CapabilityBoundingSet={BASE_CAPS}"));
        props.push(format!("AmbientCapabilities={BASE_CAPS}"));
        props.push(format!("RuntimeMaxSec={}", WALK_BUDGET_S + 60));
        props.extend(self.hide.iter().map(|p| format!("InaccessiblePaths={}", p.display())));
        props.extend(self.unit_props.iter().cloned());
        props.push(format!("StandardOutput=file:{}", output.display()));
        props.push(format!("StandardError=file:{}", error.display()));
        for p in props {
            argv.extend(["-p".into(), p]);
        }
        argv.extend([self.probe.display().to_string(), "secrets".into(), "--walk".into(), "--map".into(), "/".into(),
                     "--budget-s".into(), WALK_BUDGET_S.to_string()]);
        let run = Command::new(self.systemd.join("systemd-run")).args(&argv).stdin(Stdio::null()).kill_on_drop(true).output();
        let run = tokio::time::timeout(Duration::from_secs(WALK_BUDGET_S + 90), run).await
            .map_err(|_| "its unit did not end within its limit".to_string())?
            .map_err(|e| format!("systemd-run: {e}"))?;
        let stdout = tokio::fs::read(&output).await.unwrap_or_default();
        if !run.status.success() {
            let err = tokio::fs::read(&error).await.unwrap_or_default();
            return Err(format!("{}: {}{}", run.status, String::from_utf8_lossy(&err).trim(), String::from_utf8_lossy(&run.stderr).trim()));
        }
        let (secrets, scan) = parse_secrets(&stdout);
        if scan.is_null() {
            return Err("no report from beat-probe secrets --walk".into());
        }
        Ok(Walked { when: Instant::now(), at: crate::iso_now(), secrets, scan })
    }

    /// The secret files for a question now: the live check merged with the latest walk, checked against the disk.
    async fn secret_files(&self, timeout_s: u64) -> Result<(Vec<SecretFile>, Scan), Failed> {
        let refuse = |message: String| Failed { kind: "secrets", message };
        // At most half of what the question has left: the other half is its own.
        let wait = Duration::from_secs(timeout_s) / 2;
        let mut rx = self.walk.subscribe();
        let latest = match tokio::time::timeout(wait, rx.wait_for(Option::is_some)).await {
            Ok(Ok(w)) => w.clone().expect("waited for it"),
            _ => {
                let why = self.walk_error.lock().unwrap().clone().map_or(String::new(), |e| format!(" (the last attempt failed: {e})"));
                return Err(refuse(format!(
                    "the sensor's first look for secret files has not finished{why}: waited {} s, and a question does not run \
                     without it. Ask again shortly", wait.as_secs())));
            }
        };
        if latest.when.elapsed() > WALK_MAX_AGE {
            let why = self.walk_error.lock().unwrap().clone().unwrap_or_else(|| "no reason recorded".into());
            return Err(refuse(format!(
                "the sensor's look for secret files is {} s old, over its {} s limit: a question does not run without a \
                 recent one. The last attempt: {why}", latest.when.elapsed().as_secs(), WALK_MAX_AGE.as_secs())));
        }
        let run = Command::new(&self.probe).args(["secrets", "--live", "--map", "/"]).env_remove("BEAT_SECRETS_FILE")
            .stdin(Stdio::null()).kill_on_drop(true).output();
        let out = tokio::time::timeout(LIVE_TIMEOUT, run).await
            .map_err(|_| refuse(format!(
                "the check for secret files did not finish in {} s (a stalled disk?): the question was not run", LIVE_TIMEOUT.as_secs())))?
            .map_err(|e| refuse(format!("beat-probe secrets: {e}")))?;
        if !out.status.success() {
            return Err(refuse(format!("beat-probe secrets failed: {}", String::from_utf8_lossy(&out.stderr).trim())));
        }
        let (live, live_scan) = parse_secrets(&out.stdout);
        // A cached path may be gone or changed: binding over a missing path makes systemd create it on the host, and a
        // directory over a file fails the unit (226, as a refused mount looks). So each is looked at again, cheaply.
        let cached = latest.secrets.clone();
        let still = tokio::task::spawn_blocking(move || still_there(cached));
        let still = tokio::time::timeout(LIVE_TIMEOUT, still).await
            .map_err(|_| refuse(format!(
                "the check for secret files did not finish in {} s (a stalled disk?): the question was not run", LIVE_TIMEOUT.as_secs())))?
            .map_err(|e| refuse(format!("checking the secret files: {e}")))?;
        let mut skipped = pairs(&latest.scan["skipped"]);
        skipped.extend(pairs(&live_scan["skipped"]));
        skipped.sort();
        skipped.dedup();
        let cut_root = latest.scan["cut"]["root"].as_str().map(String::from);
        Ok((merge(live, still), Scan { skipped, cut_root }))
    }

    /// What the heartbeat says about the look for secret files: when, what it left out, and what no placeholder covers.
    pub fn walk_state(&self) -> Value {
        let latest = self.walk.borrow().clone();
        let error = self.walk_error.lock().unwrap().clone();
        let uncovered = self.uncovered.lock().unwrap().clone();
        match latest {
            None => json!({"at": null, "error": error, "uncovered": uncovered}),
            Some(w) => {
                // Whole numbers: the heartbeat is signed over its canonical form, and two languages print floats differently.
                let seconds = w.scan["seconds"].as_f64().unwrap_or(0.0).round() as u64;
                json!({"at": w.at, "secrets": w.secrets.len(), "skipped": w.scan["skipped"], "cut": w.scan["cut"],
                       "entries": w.scan["entries"], "seconds": seconds, "error": error, "uncovered": uncovered})
            }
        }
    }

    /// The sandbox this sensor's questions get: "full", "no-secret-mounts" (see secret_mounts_denied) or "none".
    /// Who questions run as, for the heartbeat.
    pub fn question_user_name(&self) -> &str {
        self.question_user.as_ref().map_or("root", |(u, _)| u)
    }

    pub fn sandbox_mode(&self) -> &'static str {
        match (&self.sandbox, self.secret_mounts_denied.load(Ordering::Relaxed)) {
            (None, _) => "none",
            (Some(_), false) => "full",
            (Some(_), true) => "no-secret-mounts",
        }
    }

    /// The builtins reference for agents (`beat-probe guide`), with this sensor's tool list.
    pub async fn guide(&self) -> Result<String, String> {
        let out = Command::new(&self.probe)
            .args(["guide", "--tools"]).arg(&self.tools).arg("--cache").arg(&self.cache)
            .output()
            .await
            .map_err(|e| format!("beat-probe guide: {e}"))?;
        if !out.status.success() {
            return Err(format!("beat-probe guide failed: {}", String::from_utf8_lossy(&out.stderr).trim()));
        }
        Ok(String::from_utf8_lossy(&out.stdout).into_owned())
    }
}

/// What every question's unit and the walk's have in common. The network is per unit: see HOST_NETWORK.
const HARDENING: [&str; 11] = [
    "ProtectSystem=strict", "ProtectHome=read-only", "PrivateTmp=yes",
    "PrivateDevices=yes", "NoNewPrivileges=yes", "ProtectKernelTunables=yes", "ProtectKernelModules=yes",
    "ProtectControlGroups=yes", "RestrictSUIDSGID=yes", "LockPersonality=yes", "WorkingDirectory=/",
];
/// A question sees the host's network, and cannot use it. It runs in the host's network namespace, so routes,
/// interfaces, MTUs, neighbours, sockets, qdiscs and /proc/sys/net are the host's, through osquery, netlink or /proc
/// alike (in a private namespace each of these answered for an empty sandbox, silently: docs/spikes.md, scenario 3).
/// Its sockets: netlink (dumps need no privilege; every change needs CAP_NET_ADMIN, which the unit has not) and unix
/// (osquery reads systemd over D-Bus, and glibc names interfaces through one); no AF_INET, AF_INET6 or AF_PACKET, and
/// IPAddressDeny on top. Unix sockets in the host's namespace reach abstract ones too: within what path sockets
/// already gave a question running as root (docs/security.md, "questions run as root"). A question that calls
/// capture() keeps a private namespace (PRIVATE_NETWORK): the capture runs in its own unit on the host's
/// (capture.rs), so it loses nothing.
const HOST_NETWORK: [&str; 2] = ["RestrictAddressFamilies=AF_UNIX AF_NETLINK", "IPAddressDeny=any"];
/// The walk's, and a capture question's: a network namespace of its own, with only loopback.
const PRIVATE_NETWORK: &str = "PrivateNetwork=yes";
/// The walk's limits: judgements, chosen to leave a busy host's work alone.
const WALK_LIMITS: [&str; 5] = ["TasksMax=8", "CPUQuota=25%", "MemoryMax=256M", "IOSchedulingClass=idle", "Nice=19"];

/// A question as the unit that runs it needs it.
struct Question<'a> {
    source: &'a str,
    timeout_s: u64,
    placeholders: &'a PathBuf,
    name: &'a str,
    caps: &'a [String],
    /// It calls capture(), and this sensor has the broker.
    capture: bool,
    secrets: &'a [SecretFile],
    report: &'a Scan,
}

/// What the scans left out, as the run's note needs it.
#[derive(Default)]
pub struct Scan {
    skipped: Vec<(String, String)>,
    cut_root: Option<String>,
}

/// The secret files and the `{"scan": ...}` line of `beat-probe secrets`.
fn parse_secrets(stdout: &[u8]) -> (Vec<SecretFile>, Value) {
    let (mut files, mut scan) = (Vec::new(), Value::Null);
    for l in String::from_utf8_lossy(stdout).lines() {
        let Ok(v) = serde_json::from_str::<Value>(l) else { continue };
        if let Some(p) = v["path"].as_str() {
            files.push(SecretFile { path: p.to_string(), dir: v["kind"] == "dir", line: l.to_string() });
        } else if v.get("scan").is_some() {
            scan = v["scan"].clone();
        }
    }
    (files, scan)
}

fn pairs(v: &Value) -> Vec<(String, String)> {
    v.as_array().into_iter().flatten()
        .filter_map(|p| Some((p[0].as_str()?.to_string(), p[1].as_str()?.to_string())))
        .collect()
}

/// Those that still exist and are still what they were.
fn still_there(files: Vec<SecretFile>) -> Vec<SecretFile> {
    files.into_iter()
        .filter(|f| std::fs::symlink_metadata(&f.path).is_ok_and(|m| m.is_dir() == f.dir))
        .collect()
}

/// The live check's files and the walk's, the live line winning; sorted by path.
fn merge(live: Vec<SecretFile>, walked: Vec<SecretFile>) -> Vec<SecretFile> {
    let mut all = live;
    for f in walked {
        if !all.iter().any(|a| a.path == f.path) {
            all.push(f);
        }
    }
    all.sort_by(|a, b| a.path.cmp(&b.path));
    all
}

/// A path as a word of BindReadOnlyPaths=, or None when systemd cannot express it. Measured on systemd 255: a backslash
/// keeps the next character literal for space, colon and backslash; a quote fails the unit whatever is done to it, and
/// `\n` would mean a plain n, so a path with one of those or a control character cannot be covered.
fn bind_word(path: &str) -> Option<String> {
    if path.chars().any(|c| c == '"' || c == '\'' || c.is_control()) {
        return None;
    }
    let mut w = String::with_capacity(path.len());
    for c in path.chars() {
        if matches!(c, ' ' | ':' | '\\') {
            w.push('\\');
        }
        w.push(c);
    }
    Some(w)
}

/// One BindReadOnlyPaths= property per secret file (a list in one argument fails at exec past 128 KiB), and the paths
/// that cannot be covered. `-`: a source that is gone is ignored.
fn bind_props(secrets: &[SecretFile], placeholders: &Path) -> (Vec<String>, Vec<String>) {
    let (mut binds, mut uncovered) = (Vec::new(), Vec::new());
    for s in secrets {
        match bind_word(&s.path) {
            Some(w) => binds.push(format!("BindReadOnlyPaths=-{}:{w}", placeholders.join(if s.dir { "dir" } else { "file" }).display())),
            None => uncovered.push(s.path.clone()),
        }
    }
    (binds, uncovered)
}

/// The file a question reads for `secrets()` and files of known meaning: the metadata lines and a report line. It holds
/// no more than the question would get: root only, and removed when the question ends.
fn secrets_text(secrets: &[SecretFile], report: &Scan, uncovered: &[String]) -> String {
    let mut text: String = secrets.iter().map(|s| format!("{}\n", s.line)).collect();
    text.push_str(&format!("{}\n", json!({"report": {"skipped": report.skipped, "cut_root": report.cut_root, "uncovered": uncovered}})));
    text
}

async fn write_private(path: &Path, text: &str) -> std::io::Result<()> {
    use tokio::fs::OpenOptions;
    let mut f = OpenOptions::new().write(true).create_new(true).mode(0o600).open(path).await?;
    f.write_all(text.as_bytes()).await
}

/// The probe as a direct child, over pipes (--no-sandbox: development).
async fn run_piped(argv: Vec<String>, source: &str, timeout_s: u64) -> Result<Exit, String> {
    let mut child = Command::new(&argv[0])
        .args(&argv[1..]).stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()).kill_on_drop(true)
        .spawn().map_err(|e| format!("cannot start {}: {e}", argv[0]))?;
    let mut stdin = child.stdin.take().expect("piped stdin");
    let src = source.as_bytes().to_vec();
    tokio::spawn(async move {
        let _ = stdin.write_all(&src).await;
    });
    let out = tokio::time::timeout(Duration::from_secs(timeout_s + 15), child.wait_with_output())
        .await
        .map_err(|_| format!("time limit ({timeout_s}s) reached"))?
        .map_err(|e| format!("waiting for beat-probe: {e}"))?;
    Ok(Exit { stdout: out.stdout, stderr: out.stderr, status: out.status.to_string(), result: String::new(),
              memory_peak: None })
}

fn status_text(code: Option<i32>) -> String {
    code.map_or("killed by a signal".into(), |c| format!("exit status: {c}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn file(path: &str) -> SecretFile {
        SecretFile { path: path.into(), dir: false, line: format!("{{\"path\":{path:?}}}") }
    }

    #[test]
    fn words_systemd_can_and_cannot_express() {
        assert_eq!(bind_word("/etc/a.key").as_deref(), Some("/etc/a.key"));
        assert_eq!(bind_word("/etc/sp ace.key").as_deref(), Some("/etc/sp\\ ace.key"));
        assert_eq!(bind_word("/etc/co:lon.key").as_deref(), Some("/etc/co\\:lon.key"));
        assert_eq!(bind_word("/etc/back\\slash.key").as_deref(), Some("/etc/back\\\\slash.key"));
        assert_eq!(bind_word("/etc/com,ma%h.key").as_deref(), Some("/etc/com,ma%h.key"));
        for bad in ["/etc/q\"uote.key", "/etc/s'q.key", "/etc/new\nline.key"] {
            assert_eq!(bind_word(bad), None, "{bad}");
        }
    }

    #[test]
    fn a_long_list_is_one_argument_per_file() {
        let many: Vec<SecretFile> = (0..5000).map(|i| file(&format!("/etc/some/long/enough/path/key-{i:05}.key"))).collect();
        let (binds, uncovered) = bind_props(&many, Path::new("/opt/ph"));
        assert_eq!(binds.len(), 5000);
        assert!(uncovered.is_empty());
        assert!(binds.iter().all(|b| b.len() < 131072));
    }

    #[test]
    fn what_cannot_be_covered_is_returned_and_reported() {
        let (binds, uncovered) = bind_props(&[file("/etc/a.key"), file("/etc/q\"b.key")], Path::new("/opt/ph"));
        assert_eq!(binds, ["BindReadOnlyPaths=-/opt/ph/file:/etc/a.key"]);
        assert_eq!(uncovered, ["/etc/q\"b.key"]);
        let text = secrets_text(&[file("/etc/a.key")], &Scan::default(), &uncovered);
        assert!(text.contains("q\\\"b.key") && text.contains("report"), "{text}");
    }

    #[test]
    fn a_scan_line_is_read_and_is_not_a_secret() {
        let out = b"{\"path\":\"/etc/a.key\",\"kind\":\"file\"}\n{\"path\":\"/etc/d\",\"kind\":\"dir\"}\n{\"scan\":{\"skipped\":[[\"/var/lib/docker\",\"Docker data root\"]]}}\n";
        let (files, scan) = parse_secrets(out);
        assert_eq!(files.len(), 2);
        assert!(files[1].dir);
        assert_eq!(pairs(&scan["skipped"]), [("/var/lib/docker".to_string(), "Docker data root".to_string())]);
    }

    #[test]
    fn the_live_line_wins_and_gone_files_drop_out() {
        let mut older = file("/etc/a.key");
        older.line = "old".into();
        let merged = merge(vec![file("/etc/a.key")], vec![older, file("/etc/b.key")]);
        assert_eq!(merged.iter().map(|f| f.path.as_str()).collect::<Vec<_>>(), ["/etc/a.key", "/etc/b.key"]);
        assert_ne!(merged[0].line, "old");
        let dir = std::env::temp_dir().join(format!("beat-still-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let (here, gone) = (dir.join("here"), dir.join("gone"));
        std::fs::write(&here, "x").unwrap();
        let mut as_dir = file(here.to_str().unwrap());
        as_dir.dir = true;
        let kept = still_there(vec![file(here.to_str().unwrap()), file(gone.to_str().unwrap()), as_dir]);
        assert_eq!(kept.len(), 1, "a gone file, and a file that was a directory, drop out");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// Who the root tests' questions run as: BEAT_TEST_USER (made when missing, as the sensor's unit does), default
    /// beat-question; "root" for the old way.
    fn test_user() -> Option<(String, u32)> {
        let name = std::env::var("BEAT_TEST_USER").unwrap_or_else(|_| "beat-question".into());
        (name != "root").then(|| {
            let line = format!("u {name} - \"beat sensor questions\" / -");
            assert!(std::process::Command::new("/usr/bin/systemd-sysusers").args(["--inline", &line]).status().unwrap().success());
            question_user(&name).unwrap()
        })
    }

    fn runner_with(probe: PathBuf) -> Runner {
        Runner {
            probe, tools: "/nonexistent".into(), cache: "/nonexistent".into(), osqueryi: None, journalctl: None, bpf_tools: None, capture: None,
            sandbox: Some("/nonexistent".into()), secret_mounts_denied: Default::default(), hide: Vec::new(), unit_props: Vec::new(),
            systemd: "/usr/bin".into(), walk: watch::Sender::new(None), walk_error: Default::default(), uncovered: Default::default(), question_user: None,
        }
    }

    fn walked(age: Duration, secrets: Vec<SecretFile>) -> Option<Arc<Walked>> {
        Some(Arc::new(Walked { when: Instant::now().checked_sub(age).unwrap(), at: "then".into(), secrets, scan: json!({"skipped": []}) }))
    }

    /// A script that stands in for beat-probe.
    fn script(body: &str) -> PathBuf {
        static N: AtomicU64 = AtomicU64::new(0);
        let p = std::env::temp_dir().join(format!("beat-fake-probe-{}-{}", std::process::id(), N.fetch_add(1, Ordering::Relaxed)));
        std::fs::write(&p, format!("#!/bin/sh\n{body}\n")).unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
        p
    }

    #[tokio::test]
    async fn no_question_runs_before_the_first_walk() {
        let r = runner_with(script("exit 0"));
        *r.walk_error.lock().unwrap() = Some("the unit failed".into());
        let e = r.secret_files(2).await.err().expect("refused");
        assert_eq!(e.kind, "secrets");
        assert!(e.message.contains("has not finished") && e.message.contains("the unit failed"), "{}", e.message);
    }

    #[tokio::test]
    async fn a_walk_too_old_is_not_used() {
        let r = runner_with(script("exit 0"));
        r.walk.send_replace(walked(WALK_MAX_AGE + Duration::from_secs(1), Vec::new()));
        assert_eq!(r.secret_files(2).await.err().expect("refused").kind, "secrets");
    }

    #[tokio::test]
    async fn a_live_check_that_fails_or_hangs_refuses_the_question() {
        let r = runner_with(script("echo broken >&2; exit 3"));
        r.walk.send_replace(walked(Duration::ZERO, Vec::new()));
        let e = r.secret_files(2).await.err().expect("refused");
        assert!(e.kind == "secrets" && e.message.contains("broken"), "{}", e.message);
        let r = runner_with(script("exec sleep 300"));
        r.walk.send_replace(walked(Duration::ZERO, Vec::new()));
        let begun = Instant::now();
        let e = r.secret_files(60).await.err().expect("refused");
        assert!(e.kind == "secrets" && e.message.contains("did not finish"), "{}", e.message);
        assert!(begun.elapsed() < LIVE_TIMEOUT + Duration::from_secs(5));
    }

    #[tokio::test]
    async fn the_walks_files_are_used_and_what_was_left_out_is_kept() {
        let here = script("printf '%s\\n' '{\"path\":\"/etc/shadow\",\"kind\":\"file\"}' '{\"scan\":{\"skipped\":[[\"/home\",\"network or shared filesystem (nfs4)\"]]}}'");
        let r = runner_with(here.clone());
        let mut w = walked(Duration::ZERO, vec![file(here.to_str().unwrap()), file("/nonexistent/gone.key")]).unwrap();
        Arc::get_mut(&mut w).unwrap().scan = json!({"skipped": [["/var/lib/docker", "Docker data root"]], "cut": {"root": "/var/lib"}});
        r.walk.send_replace(Some(w));
        let (files, scan) = r.secret_files(10).await.map_err(|e| e.message).unwrap();
        let paths: Vec<&str> = files.iter().map(|f| f.path.as_str()).collect();
        assert!(paths.contains(&"/etc/shadow") && paths.contains(&here.to_str().unwrap()), "{paths:?}");
        assert!(!paths.contains(&"/nonexistent/gone.key"), "a file gone since the walk is not bound: systemd would create it");
        assert_eq!(scan.skipped.len(), 2);
        assert_eq!(scan.cut_root.as_deref(), Some("/var/lib"));
    }

    /// A real question in a real unit: needs root and systemd, so not in `cargo test`. BEAT_TEST_PROBE and
    /// BEAT_TEST_TOOLS and BEAT_TEST_CACHE name the built probe, the tools and their cache; BEAT_TEST_N, how many to time.
    #[tokio::test(flavor = "multi_thread")]
    #[ignore]
    async fn real_questions_in_real_units() {
        let var = |k: &str| std::env::var(k).unwrap_or_else(|_| panic!("{k}"));
        std::fs::create_dir_all(RUN_DIR).unwrap();
        let ph = std::env::temp_dir().join("beat-ph");
        std::fs::create_dir_all(ph.join("dir")).unwrap();
        std::fs::write(ph.join("file"), "placeholder\n").unwrap();
        let cache: PathBuf = var("BEAT_TEST_CACHE").into();  // made beforehand, as ExecStartPre does: `beat-probe tools`
        let runner = Arc::new(Runner {
            probe: var("BEAT_TEST_PROBE").into(), tools: var("BEAT_TEST_TOOLS").into(), cache,
            osqueryi: None, journalctl: None, bpf_tools: None, capture: None, sandbox: Some(ph),
            secret_mounts_denied: Default::default(), hide: Vec::new(), unit_props: Vec::new(),
            systemd: "/usr/bin".into(), walk: watch::Sender::new(None), walk_error: Default::default(),
            uncovered: Default::default(), question_user: test_user(),
        });
        let walking = runner.clone();
        tokio::spawn(async move { walking.walk_forever().await });
        let trivial = "def main() -> None:\n    emit(\"a\", \"b\", \"c\", \"test\")\n";
        let n: usize = std::env::var("BEAT_TEST_N").ok().and_then(|n| n.parse().ok()).unwrap_or(3);
        for _ in 0..n {
            let (begun, phases) = (Instant::now(), Phases::default());
            let r = runner.run("trivial.star", trivial, 120, &phases, false).await;
            match r {
                Ok(v) => println!("trivial: {} in {:?}; {}", v["outcome"], begun.elapsed(), phases.text()),
                Err(e) => panic!("{}: {}", e.kind, e.message),
            }
        }
        // A file gone since the walk: a bind over it would make systemd create it on the host.
        if let Ok(gone) = std::env::var("BEAT_TEST_GONE") {
            std::fs::remove_file(&gone).unwrap();
            let v = runner.run("trivial.star", trivial, 120, &Phases::default(), false).await.map_err(|e| e.message).unwrap();
            assert_eq!(v["outcome"], "ok");
            assert!(!Path::new(&gone).exists(), "the question created {gone}");
            println!("{gone} stayed gone");
        }
        let list = "def main() -> None:\n    for s in secrets():\n        emit(\"secret:\" + s.path, \"mode\", s.mode, \"secrets\")\n";
        let v = runner.run("list.star", list, 120, &Phases::default(), false).await.map_err(|e| e.message).unwrap();
        println!("secrets(): {} records; notes {}", v["records"].as_array().map_or(0, Vec::len), v["notes"]);
        for r in v["records"].as_array().into_iter().flatten() {
            println!("  {}", r["subject"]);
        }
        println!("heartbeat: {}", runner.walk_state());
    }

    /// capture() through the broker, in real units: flows on lo while connections are made, a field the broker
    /// refuses, a capture longer than the question allows, and two at once. Needs root, systemd and tcpdump:
    /// sudo env BEAT_TEST_PROBE=... BEAT_TEST_TOOLS=... BEAT_TEST_CACHE=... [BEAT_TEST_TCPDUMP=/usr/bin/tcpdump]
    ///   <the test binary> capture_in_real_units --ignored --nocapture
    /// with the cache filled first, as the sensor's unit does (`beat-probe tools --tools T --cache C`, as root, the
    /// cache outside /tmp): the units see it read-only, and without it each question compiles the tools (~30 s here).
    #[tokio::test(flavor = "multi_thread")]
    #[ignore]
    async fn capture_in_real_units() {
        let var = |k: &str| std::env::var(k).unwrap_or_else(|_| panic!("{k}"));
        std::fs::create_dir_all(RUN_DIR).unwrap();
        let ph = std::env::temp_dir().join("beat-ph");
        std::fs::create_dir_all(ph.join("dir")).unwrap();
        std::fs::write(ph.join("file"), "placeholder\n").unwrap();
        let tcpdump = std::env::var("BEAT_TEST_TCPDUMP").unwrap_or_else(|_| "/usr/bin/tcpdump".into());
        let broker = crate::capture::Broker::new(tcpdump.into(), "/usr/bin".into(), Vec::new(), Vec::new(), RUN_DIR.into());
        let runner = Arc::new(Runner {
            probe: var("BEAT_TEST_PROBE").into(), tools: var("BEAT_TEST_TOOLS").into(), cache: var("BEAT_TEST_CACHE").into(),
            osqueryi: None, journalctl: None, bpf_tools: None, capture: Some(Arc::new(broker)), sandbox: Some(ph),
            secret_mounts_denied: Default::default(), hide: Vec::new(), unit_props: Vec::new(),
            systemd: "/usr/bin".into(), walk: watch::Sender::new(None), walk_error: Default::default(),
            uncovered: Default::default(), question_user: test_user(),
        });
        let walking = runner.clone();
        tokio::spawn(async move { walking.walk_forever().await });

        // A server that answers, and a port nobody listens on (reset); connections start once the capture runs: its
        // pcap file in RUN_DIR has tcpdump's header, written when it has opened lo. Not a fixed delay from here: the
        // question waits for the first secret walk and its unit's start, and connections made before were not seen.
        let srv = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = srv.local_addr().unwrap().port();
        let closed = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
        std::thread::spawn(move || {
            for c in srv.incoming().flatten() {
                let _ = std::io::Write::write_all(&mut &c, b"hello\n");
            }
        });
        std::thread::spawn(move || {
            let capturing = || std::fs::read_dir(RUN_DIR).into_iter().flatten().flatten()
                .any(|e| e.file_name().to_string_lossy().ends_with(".pcap") && e.metadata().is_ok_and(|m| m.len() > 0));
            let waited = Instant::now();
            while !capturing() && waited.elapsed() < Duration::from_secs(60) {
                std::thread::sleep(Duration::from_millis(20));
            }
            for _ in 0..3 {
                let c = std::net::TcpStream::connect(("127.0.0.1", port)).unwrap();
                let _ = std::io::Read::read(&mut &c, &mut [0u8; 16]);
                let _ = std::net::TcpStream::connect(("127.0.0.1", closed));
            }
        });
        let probe = |extra: &str| format!(
            "def main() -> None:\n    c = capture(\"flows\", host=\"127.0.0.1\"{extra}, key=[\"state\"])\n    \
             emit(\"capture\", \"groups\", json.encode(c[\"groups\"]), \"test\")\n    \
             emit(\"capture\", \"capture\", json.encode(c[\"capture\"]), \"test\")\n");
        let field = |v: &Value, k: &str| -> Value {
            v["records"].as_array().into_iter().flatten().find(|r| r["key"] == k)
                .and_then(|r| serde_json::from_str(r["value"].as_str()?).ok()).unwrap_or(Value::Null)
        };
        let v = runner.run("flows.star", &probe(", seconds=8"), 60, &Phases::default(), false).await
            .map_err(|e| e.message).unwrap();
        let (groups, cap) = (field(&v, "groups"), field(&v, "capture"));
        println!("groups {groups}\ncapture {cap}\nnotes {}", v["notes"]);
        assert_eq!(cap["interface"], "lo");
        assert_eq!(cap["tcpdump"]["end"], "time", "{cap}");
        let count = |state: &str| groups.as_array().into_iter().flatten().find(|g| g["key"]["state"] == state)
            .map_or(0, |g| g["count"].as_u64().unwrap_or(0));
        assert_eq!(count("closed"), 3, "{groups}");
        assert_eq!(count("reset"), 3, "{groups}");

        // Refused by the broker: a free-form host, and more seconds than the question has.
        for (extra, why) in [(", host=\"127.0.0.1 or port 22\"", "not an IP address"), (", seconds=55", "left")] {
            let src = probe(extra).replace("host=\"127.0.0.1\", host=", "host=");
            let v = runner.run("refused.star", &src, 30, &Phases::default(), false).await.map_err(|e| e.message).unwrap();
            let text = v.to_string();
            assert!(text.contains(why), "{extra}: {text}");
            println!("refused ({why}): {}", v["error"]);
        }

        // Two at once on one host: the second is refused.
        let (a, b) = (runner.clone(), runner.clone());
        let (src_a, src_b) = (probe(", seconds=6"), probe(", seconds=6"));
        let one = tokio::spawn(async move { a.run("a.star", &src_a, 60, &Phases::default(), false).await.map_err(|e| e.message) });
        tokio::time::sleep(Duration::from_secs(2)).await;
        let two = b.run("b.star", &src_b, 60, &Phases::default(), false).await.map_err(|e| e.message).unwrap();
        let one = one.await.unwrap().unwrap();
        assert!(two.to_string().contains("one at a time"), "{two}");
        assert_eq!(field(&one, "capture")["tcpdump"]["end"], "time");
        let left = std::fs::read_dir(RUN_DIR).unwrap().flatten().filter(|e| {
            let n = e.file_name().to_string_lossy().to_string();
            n.ends_with(".pcap") || n.ends_with(".capture") || n.ends_with(".tcpdump-err")
        }).count();
        assert_eq!(left, 0, "files left in {RUN_DIR}");
    }

    /// A question's unit sees the host's network and cannot use it (no IP, no packets, no changes; unix sockets yes):
    /// its exact properties (sandboxed()) around a python3 script in place of beat-probe, which tries each kind of socket. A capture question's unit is the
    /// private namespace it was. Needs root, systemd and python3:
    /// sudo <the test binary> question_network --ignored --nocapture
    #[tokio::test(flavor = "multi_thread")]
    #[ignore]
    async fn question_network() {
        let me = std::process::id();
        let dir = PathBuf::from(format!("/var/lib/beat-net-{me}"));
        std::fs::create_dir_all(&dir).unwrap();
        let runner = Runner {
            probe: "/nonexistent".into(), tools: "/nonexistent".into(), cache: "/nonexistent".into(), osqueryi: None, journalctl: None,
            bpf_tools: None, capture: None, sandbox: None, secret_mounts_denied: Default::default(), hide: Vec::new(), unit_props: Vec::new(),
            systemd: "/usr/bin".into(), walk: watch::Sender::new(None), walk_error: Default::default(), uncovered: Default::default(), question_user: test_user(),
        };
        // On the host: a TCP listener, an abstract unix socket (what a host-namespace question must not reach) and a
        // path one.
        let tcp = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = tcp.local_addr().unwrap().port();
        let abs = format!("beat-net-test-{me}");
        let abstract_sock = {
            use std::os::linux::net::SocketAddrExt;
            std::os::unix::net::UnixListener::bind_addr(&std::os::unix::net::SocketAddr::from_abstract_name(abs.as_bytes()).unwrap()).unwrap()
        };
        let path_sock = dir.join("sock");
        let _path_listener = std::os::unix::net::UnixListener::bind(&path_sock).unwrap();
        let nic = std::fs::read_to_string("/proc/1/net/route").unwrap().lines().skip(1)
            .find(|l| l.split('\t').nth(1) == Some("00000000")).and_then(|l| l.split('\t').next()).unwrap().to_string();
        // A unit of the host's for the question to try to stop, over the system bus and systemd's private socket.
        let victim = format!("beat-net-victim-{me}");
        assert!(std::process::Command::new("/usr/bin/systemd-run").args(["--quiet", &format!("--unit={victim}"), "/usr/bin/sleep", "300"])
            .status().unwrap().success());
        let script = format!(r#"
import socket, subprocess
def tryit(name, f):
    try:
        f(); print(name, "ok")
    except Exception as e:
        print(name, "refused", type(e).__name__)
def tcp():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM); s.settimeout(3); s.connect(("127.0.0.1", {port}))
def udp():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.sendto(b"x", ("127.0.0.1", 9))
def tcp6():
    socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
def packet():
    socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
def abstract():
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM); s.connect("\0{abs}")
def path():
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM); s.connect("{path}")
def netlink():
    s = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, 0); s.bind((0, 0))
    # RTM_GETLINK dump
    import struct
    s.send(struct.pack("=IHHII", 32, 18, 0x301, 1, 0) + struct.pack("=BxHiII", 0, 0, 0, 0, 0))
    data = s.recv(65536)
    assert len(data) > 16
def link_down():
    # RTM_NEWLINK on lo with an empty change mask: a no-op if allowed, but any message other than a GET needs
    # CAP_NET_ADMIN, checked before the request is looked at
    import struct
    s = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, 0)
    s.send(struct.pack("=IHHII", 32, 16, 0x5, 2, 0) + struct.pack("=BxHiII", 0, 0, 1, 0, 0))
    data = s.recv(65536)
    err = struct.unpack("=i", data[16:20])[0]
    if err != 0: raise PermissionError(err)
def private():
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM); s.connect("/run/systemd/private")
def stop():
    r = subprocess.run(["/usr/bin/busctl", "--system", "call", "org.freedesktop.systemd1", "/org/freedesktop/systemd1",
                        "org.freedesktop.systemd1.Manager", "StopUnit", "ss", "{victim}.service", "replace"],
                       capture_output=True, text=True, timeout=20)
    if r.returncode != 0: raise PermissionError(r.stderr.strip())
def list_units():
    r = subprocess.run(["/usr/bin/busctl", "--system", "call", "org.freedesktop.systemd1", "/org/freedesktop/systemd1",
                        "org.freedesktop.systemd1.Manager", "GetUnit", "s", "init.scope"], capture_output=True, text=True, timeout=20)
    if r.returncode != 0: raise OSError(r.stderr.strip())
for n, f in [("tcp", tcp), ("udp", udp), ("tcp6", tcp6), ("packet", packet), ("abstract", abstract), ("path", path),
             ("netlink", netlink), ("link_down", link_down), ("private", private), ("stop", stop), ("list_units", list_units)]:
    tryit(n, f)
print("nic", "{nic}:" in open("/proc/net/dev").read())
"#, path = path_sock.display());
        let file = |n: &str| dir.join(n);
        std::fs::write(file("in"), "").unwrap();
        let run = |capture: Option<&Path>| {
            let argv = runner.sandboxed(vec!["/usr/bin/python3".into(), "-c".into(), script.clone()], 30, "net",
                [&file("in"), &file("out"), &file("err"), &file("meta")], Vec::new(), &format!("beat-net-test-{me}"), &[], capture);
            let st = std::process::Command::new(&argv[0]).args(&argv[1..]).status().unwrap();
            let _ = std::process::Command::new("/usr/bin/systemctl").args(["reset-failed", &format!("beat-net-test-{me}")]).status();
            let out = std::fs::read_to_string(file("out")).unwrap_or_default();
            println!("{} ({st}):\n{out}{}", if capture.is_some() { "capture question" } else { "question" },
                     std::fs::read_to_string(file("err")).unwrap_or_default());
            out
        };
        let host = run(None);
        let victim_alive = std::process::Command::new("/usr/bin/systemctl").args(["is-active", "--quiet", &victim]).status().unwrap().success();
        let _ = std::process::Command::new("/usr/bin/systemctl").args(["stop", &victim]).status();
        let private = run(Some(&dir.join("capture")));
        drop((tcp, abstract_sock));
        std::fs::remove_dir_all(&dir).unwrap();
        let line = |o: &str, n: &str| o.lines().find(|l| l.starts_with(&format!("{n} "))).unwrap_or("").to_string();
        for n in ["tcp", "udp", "tcp6", "packet", "link_down"] {
            assert!(line(&host, n).contains("refused"), "question: {n}: {}", line(&host, n));
        }
        // Unix sockets: abstract ones are reached (D-Bus, what osquery needs, is one kind of unix socket); a path
        // socket only root may write to is refused to the question user, as systemd's private socket is.
        assert_eq!(line(&host, "abstract"), "abstract ok");
        let want = if runner.question_user.is_some() { "refused" } else { "ok" };
        assert!(line(&host, "path").contains(want), "question: path: {}", line(&host, "path"));
        assert_eq!(line(&host, "netlink"), "netlink ok");
        // systemd: reads over the system bus, no commands. As root (no --question-user) a question could do both.
        assert_eq!(line(&host, "list_units"), "list_units ok");
        if runner.question_user.is_some() {
            assert!(line(&host, "private").contains("refused"), "question: systemd's private socket: {}", line(&host, "private"));
            assert!(line(&host, "stop").contains("refused"), "question: StopUnit: {}", line(&host, "stop"));
            assert!(victim_alive, "the question stopped {victim}");
        }
        assert_eq!(line(&host, "nic"), "nic True", "the question sees the host's interfaces");
        assert_eq!(line(&private, "nic"), "nic False", "a capture question keeps its own namespace");
        for n in ["tcp", "abstract", "link_down"] {
            assert!(line(&private, n).contains("refused"), "capture question: {n}: {}", line(&private, n));
        }
    }

    /// What a question must keep being able to do to debug a host, and what it must not: security work must not take the
    /// first away unnoticed. Real units, real tools, real osquery, the default pack. Needs root and systemd:
    /// sudo env BEAT_TEST_PROBE=... BEAT_TEST_TOOLS=... BEAT_TEST_CACHE=... BEAT_TEST_OSQUERYI=... BEAT_TEST_PACK=src/beat/pack
    ///   <the test binary> debugging_regression --ignored --nocapture
    #[tokio::test(flavor = "multi_thread")]
    #[ignore]
    async fn debugging_regression() {
        use std::os::fd::AsRawFd;
        let var = |k: &str| std::env::var(k).unwrap_or_else(|_| panic!("{k}"));
        let me = std::process::id();
        let dir = PathBuf::from(format!("/var/lib/beat-debug-{me}")); // not /var/tmp: units have their own
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::create_dir_all(RUN_DIR).unwrap();
        let ph = dir.join("ph");
        std::fs::create_dir_all(ph.join("dir")).unwrap();
        std::fs::write(ph.join("file"), "placeholder\n").unwrap();
        let key = dir.join("sensor.key");
        std::fs::write(&key, "SENSORKEY").unwrap();
        // The host's interface on its default route: a question must see it (the host's network namespace).
        let nic = std::fs::read_to_string("/proc/1/net/route").unwrap().lines().skip(1)
            .find(|l| l.split('\t').nth(1) == Some("00000000")).and_then(|l| l.split('\t').next()).unwrap().to_string();
        let runner = Arc::new(Runner {
            probe: var("BEAT_TEST_PROBE").into(), tools: var("BEAT_TEST_TOOLS").into(), cache: var("BEAT_TEST_CACHE").into(),
            osqueryi: Some(var("BEAT_TEST_OSQUERYI").into()), journalctl: Some("/usr/bin/journalctl".into()), bpf_tools: None, capture: None,
            sandbox: Some(ph), secret_mounts_denied: Default::default(), hide: vec![key.clone()], unit_props: Vec::new(),
            systemd: "/usr/bin".into(), walk: watch::Sender::new(None), walk_error: Default::default(), uncovered: Default::default(), question_user: test_user(),
        });
        let walking = runner.clone();
        tokio::spawn(async move { walking.walk_forever().await });

        // The operator's output in the host's /tmp, which a question's private /tmp hides.
        let op = format!("/tmp/beat-debug-{me}.out");
        std::fs::write(&op, "OPERATOR OUTPUT\n").unwrap();
        // A process in its own mount namespace, as a container: a file there, a secret, links out of it.
        let mut other = std::process::Command::new("/usr/bin/unshare")
            .args(["-m", "sh", "-c", "mount -t tmpfs x /mnt && echo INSIDE > /mnt/app.log && ln -s /etc/shadow /mnt/abs \
                                      && ln -s ../etc/shadow /mnt/up && ln -s /mnt/app.log /mnt/fine && exec sleep 300"])
            .spawn().unwrap();
        let oth = other.id();
        let log = format!("/proc/{oth}/root/mnt/app.log");
        for _ in 0..100 {
            if Path::new(&log).exists() {
                break;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        // Open files: a log deleted while open, a deleted secret, a secret, a socket.
        let path = |n: &str| dir.join(n);
        std::fs::write(path("gone.log"), "DELETED LOG\n").unwrap();
        let gone = std::fs::File::open(path("gone.log")).unwrap();
        std::fs::remove_file(path("gone.log")).unwrap();
        let sec = format!("/etc/beat-debug-{me}.key");
        std::fs::write(&sec, "SECRETKEY").unwrap();
        let gone_secret = std::fs::File::open(&sec).unwrap();
        std::fs::remove_file(&sec).unwrap();
        let shadow = std::fs::File::open("/etc/shadow").unwrap();
        let sock = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        std::os::unix::fs::symlink("/etc/shadow", path("link")).unwrap();

        let ok_reads: Vec<(String, &str)> = vec![
            (format!("/proc/1/root{op}"), "OPERATOR OUTPUT"), (log.clone(), "INSIDE"), (format!("/proc/{oth}/root/mnt/fine"), "INSIDE"),
            (format!("/proc/{me}/fd/{}", gone.as_raw_fd()), "DELETED LOG"), ("/proc/1/net/dev".into(), "Inter-"), ("/proc/1/net/tcp".into(), "local_address"),
            ("/proc/1/mounts".into(), " / "), (format!("/proc/{oth}/status"), "Name:"), (format!("/proc/{oth}/stat"), "sleep"), (format!("/proc/{oth}/io"), "rchar"),
            (format!("/proc/{oth}/limits"), "Max"), (format!("/proc/{oth}/cgroup"), "::"), (format!("/proc/{oth}/maps"), "sleep"), ("/proc/meminfo".into(), "MemTotal"),
        ];
        let refused_reads = ["/etc/shadow".to_string(), "/proc/1/root/etc/shadow".into(), "/proc/self/root/etc/shadow".into(), "/proc/./1/root/etc/shadow".into(),
            "//etc/shadow".into(), "/proc/1/cwd/etc/shadow".into(), "/proc/1/task/1/root/etc/shadow".into(), "/proc/1/root/proc/1/root/etc/shadow".into(),
            format!("/proc/{oth}/root/etc/shadow"), format!("/proc/{oth}/root/mnt/abs"), format!("/proc/{oth}/root/mnt/up"), format!("/proc/{oth}/root/etc/ssh/ssh_host_ed25519_key"),
            path("link").display().to_string(), format!("/proc/1/root{}", path("link").display()), format!("/proc/{me}/fd/{}", shadow.as_raw_fd()),
            format!("/proc/{me}/fd/{}", gone_secret.as_raw_fd()), format!("/proc/{me}/fd/{}", sock.as_raw_fd()), format!("/proc/{oth}/environ"), format!("/proc/{oth}/task/{oth}/environ"),
            format!("/proc/{oth}/mem"), format!("/proc/1/root{}", key.display()), key.display().to_string()];
        let all: Vec<String> = ok_reads.iter().map(|(p, _)| p.clone()).chain(refused_reads.iter().cloned()).collect();
        let q = format!(r#"def main() -> None:
    def one(x):
        emit("read:" + x, "v", read(x)[:400], "read")
    each({all:?}, one)
    me = "{me}"
    emit("list", "fd", str(len(list_dir("/proc/" + me + "/fd"))), "list_dir")
    emit("readlink", "sock", str(readlink("/proc/" + me + "/fd/{sock_fd}")), "readlink")
    emit("journal", "n", str(len(journal(limit = 3))), "journal")
    emit("osq", "processes", str(len(osq("select pid, name, path from processes"))), "osq")
    emit("osq", "listening_ports", str(len(osq("select pid, port from listening_ports where pid > 0"))), "osq")
    emit("osq", "sockets", str(len(osq("select pid, fd from process_open_sockets where pid > 0"))), "osq")
    r = pipe(["cat", "/proc/meminfo"])
    emit("tool", "meminfo", r.stdout[:8], "pipe")
    r = pipe(["cat", "/proc/stat"])
    emit("tool", "stat", r.stdout[:3], "pipe")
    r = pipe(["cat", "/proc/sys/kernel/ostype"])
    emit("tool", "sys", r.stdout[:5], "pipe")
    r = pipe(["cat", "/proc/{oth}/environ"])
    emit("tool", "environ", str(r.ok) + r.stdout[:20], "pipe")
    emit("tool", "hint", r.stderr, "pipe")
    emit("checklist", "keys", str(len(checklist())), "checklist")
    emit("net", "routes", str(len(osq("select destination from routes where interface = '{nic}'"))), "osq")
    emit("net", "interfaces", str(len(osq("select interface from interface_details where interface = '{nic}'"))), "osq")
    emit("net", "dev", str("{nic}:" in read("/proc/net/dev")), "read")
    emit("net", "sysctl", read("/proc/sys/net/ipv4/conf/{nic}/forwarding").strip(), "read")
"#, sock_fd = sock.as_raw_fd());
        let v = runner.run("debugging.star", &q, 120, &Phases::default(), false).await.map_err(|e| e.message).unwrap();
        let rec = |s: &str, k: &str| v["records"].as_array().unwrap().iter().find(|r| r["subject"] == s && r["key"] == k).map(|r| r["value"].as_str().unwrap().to_string());
        let mut bad = Vec::new();
        for (p, want) in &ok_reads {
            match rec(&format!("read:{p}"), "v") {
                Some(got) if got.contains(want) => {}
                got => bad.push(format!("debugging lost: read({p}) gave {got:?}, want {want:?}")),
            }
        }
        for p in &refused_reads {
            if let Some(got) = rec(&format!("read:{p}"), "v") {
                bad.push(format!("not refused: read({p}) gave {got:?}"));
            }
        }
        let positive = |s: &str, k: &str| rec(s, k).and_then(|v| v.parse::<i64>().ok()).is_some_and(|n| n > 0);
        for (s, k) in [("list", "fd"), ("journal", "n"), ("osq", "processes"), ("osq", "listening_ports"), ("osq", "sockets"), ("checklist", "keys")] {
            if !positive(s, k) {
                bad.push(format!("debugging lost: {s} {k}: {:?}", rec(s, k)));
            }
        }
        if !rec("readlink", "sock").is_some_and(|l| l.contains("socket:")) { bad.push(format!("debugging lost: readlink of an fd: {:?}", rec("readlink", "sock"))); }
        for k in ["routes", "interfaces"] {
            if !positive("net", k) { bad.push(format!("the host's network lost: osquery {k} on {nic}: {:?}", rec("net", k))); }
        }
        if rec("net", "dev").as_deref() != Some("True") { bad.push(format!("the host's network lost: {nic} not in /proc/net/dev")); }
        let host_fwd = std::fs::read_to_string(format!("/proc/sys/net/ipv4/conf/{nic}/forwarding")).unwrap().trim().to_string();
        if rec("net", "sysctl") != Some(host_fwd.clone()) { bad.push(format!("the host's sysctls lost: {nic} forwarding {:?}, host {host_fwd}", rec("net", "sysctl"))); }
        if rec("tool", "meminfo").as_deref() != Some("MemTotal") { bad.push(format!("tools lost /proc/meminfo: {:?}", rec("tool", "meminfo"))); }
        if !rec("tool", "stat").is_some_and(|l| l.starts_with("cpu")) { bad.push(format!("tools lost /proc/stat: {:?}", rec("tool", "stat"))); }
        if rec("tool", "sys").as_deref() != Some("Linux") { bad.push(format!("tools lost /proc/sys: {:?}", rec("tool", "sys"))); }
        if !rec("tool", "environ").is_some_and(|l| l.starts_with("False")) { bad.push(format!("a tool read environ: {:?}", rec("tool", "environ"))); }
        if !rec("tool", "hint").is_some_and(|l| l.contains("stdin = read")) { bad.push(format!("no hint for tools: {:?}", rec("tool", "hint"))); }
        if !v["failures"].as_array().unwrap().iter().any(|f| f["message"].as_str().is_some_and(|m| m.contains("secret file"))) { bad.push("no refusal seen".into()); }
        let text = v.to_string();
        for leak in ["SENSORKEY", "SECRETKEY"] {
            if text.contains(leak) { bad.push(format!("leaked {leak}")); }
        }

        // The default pack: every probe runs and answers, and the listeners map sockets to processes.
        let pack = PathBuf::from(var("BEAT_TEST_PACK"));
        let mut names = 0;
        for f in std::fs::read_dir(&pack).unwrap().flatten() {
            let (p, name) = (f.path(), f.file_name().to_string_lossy().into_owned());
            if !name.ends_with(".star") { continue; }
            names += 1;
            let src = std::fs::read_to_string(&p).unwrap();
            match runner.run(&name, &src, 120, &Phases::default(), false).await {
                Ok(a) => {
                    let n = a["records"].as_array().map_or(0, Vec::len);
                    println!("pack {name}: {} {n} records, {} failures", a["outcome"], a["failures"].as_array().map_or(0, Vec::len));
                    // Its own unit is what beat-sensor.star looks at: a test host may not have it installed.
                    let no_unit = name == "beat-sensor.star" && a["failures"].to_string().contains("expected one beat-sensor.service, got 0")
                        && !Path::new("/etc/systemd/system/beat-sensor.service").exists();
                    if no_unit {
                        println!("pack {name}: no beat-sensor.service on this host, as the probe says");
                    } else if a["outcome"] != "ok" || n == 0 { bad.push(format!("pack {name}: {} {n} records: {}", a["outcome"], a["failures"])); }
                    if name == "listeners.star" && !a["records"].as_array().unwrap().iter().any(|r| r["key"].as_str().is_some_and(|k| k.contains("process") || k.contains("pid"))) {
                        bad.push("listeners does not map sockets to processes".into());
                    }
                }
                Err(e) => bad.push(format!("pack {name}: {}: {}", e.kind, e.message)),
            }
        }
        if names != 7 { bad.push(format!("the default pack has {names} probes, this test expected 7")); }

        let _ = other.kill();
        let _ = other.wait();
        let _ = std::fs::remove_file(&op);
        std::fs::remove_dir_all(&dir).unwrap();
        assert!(bad.is_empty(), "{}", bad.join("\n"));
    }
}
