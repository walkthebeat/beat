//! Running one question: `beat-probe run -` in a transient systemd unit:
//! read-only file system, no network, no devices, memory/task/time limits, secret files covered by placeholders and
//! their real metadata passed in as BEAT_SECRETS. One child process per question (docs/probes.md §8).
//!
//! The question reaches the unit, and its result comes back, through files in RUN_DIR that systemd opens for the unit
//! (StandardInput=file:...), not through `systemd-run --pipe`: that hands the caller's pipes to PID 1 over D-Bus, and
//! on RHEL-family hosts SELinux forbids dbus-broker to pass them (fifo_file write, a dontaudit rule: no AVC logged).

use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;

use serde_json::Value;
use tokio::io::AsyncWriteExt;
use tokio::process::Command;

pub struct Runner {
    pub probe: PathBuf,
    pub tools: PathBuf,
    pub cache: PathBuf,
    pub osqueryi: Option<PathBuf>,
    pub journalctl: Option<PathBuf>,
    /// The eBPF catalog behind trace() (libbpf-tools): a question that names an entry gets that entry's capabilities.
    pub bpf_tools: Option<PathBuf>,
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
}

/// A question's memory limit (the unit's MemoryMax): past it the kernel kills beat-probe, not the sensor.
const MEMORY_MAX: &str = "1G";
const SYSTEMD_RUN: &str = "/usr/bin/systemd-run";
const SYSTEMCTL: &str = "/usr/bin/systemctl";
/// Every question's capabilities: reading files whatever their mode, and other processes' /proc entries.
const BASE_CAPS: &str = "CAP_DAC_READ_SEARCH CAP_SYS_PTRACE";
/// What a question's trace() entries may add (`beat-probe needs`), and nothing else whatever it says.
const TRACE_CAPS: [&str; 2] = ["CAP_BPF", "CAP_PERFMON"];
/// The sensor unit's RuntimeDirectory (beat-sensor.service): one question's input, output and error files at a time.
const RUN_DIR: &str = "/run/beat-sensor";
static SEQ: AtomicU64 = AtomicU64::new(0);

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
    pub async fn run(&self, name: &str, source: &str, timeout_s: u64) -> Result<Value, Failed> {
        let mut probe = vec![self.probe.display().to_string(), "run".into(), "-".into(), "--name".into(), name.into(),
                             "--map".into(), "/".into(), "--tools".into(), self.tools.display().to_string(),
                             "--cache".into(), self.cache.display().to_string()];
        for (flag, path) in [("--osqueryi", &self.osqueryi), ("--journalctl", &self.journalctl), ("--bpf-tools", &self.bpf_tools)] {
            if let Some(p) = path {
                probe.extend([flag.to_string(), p.display().to_string()]);
            }
        }
        let x = match &self.sandbox {
            Some(placeholders) => self.run_sandboxed(probe, source, timeout_s, placeholders, name).await?,
            None => run_piped(probe, source, timeout_s).await?,
        };
        if let Ok(v) = serde_json::from_slice(&x.stdout) {
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

    /// The capabilities beyond the base two that this question's trace() entries need, from its text
    /// (`beat-probe needs`); only those in TRACE_CAPS, and none on a host without the catalog.
    async fn trace_caps(&self, source: &str) -> Result<Vec<String>, String> {
        if self.bpf_tools.is_none() {
            return Ok(Vec::new());
        }
        let mut child = Command::new(&self.probe).args(["needs", "-"]).stdin(Stdio::piped()).stdout(Stdio::piped())
            .stderr(Stdio::null()).kill_on_drop(true).spawn().map_err(|e| format!("beat-probe needs: {e}"))?;
        let mut stdin = child.stdin.take().expect("piped");
        stdin.write_all(source.as_bytes()).await.map_err(|e| format!("beat-probe needs: {e}"))?;
        drop(stdin);
        let out = tokio::time::timeout(Duration::from_secs(10), child.wait_with_output()).await
            .map_err(|_| "beat-probe needs: timed out".to_string())?.map_err(|e| format!("beat-probe needs: {e}"))?;
        let v: Value = serde_json::from_slice(&out.stdout).map_err(|e| format!("beat-probe needs: {e}"))?;
        Ok(v["capabilities"].as_array().into_iter().flatten().filter_map(Value::as_str)
            .filter(|c| TRACE_CAPS.contains(c)).map(String::from).collect())
    }

    /// The probe in a transient unit, with the secret placeholders mounted unless the host refused them before.
    async fn run_sandboxed(&self, probe: Vec<String>, source: &str, timeout_s: u64, placeholders: &PathBuf, name: &str)
                           -> Result<Exit, String> {
        let mounts = !self.secret_mounts_denied.load(Ordering::Relaxed);
        let caps = self.trace_caps(source).await?;
        let (x, code) = self.unit(probe.clone(), source, timeout_s, placeholders, name, mounts, &caps).await?;
        if mounts && code == Some(226) {
            eprintln!("secret placeholders cannot be mounted on this host (226/NAMESPACE, e.g. SELinux): questions run \
                       without them from now on; secret files stay unreadable to beat-probe, not to osqueryi");
            self.secret_mounts_denied.store(true, Ordering::Relaxed);
            return Ok(self.unit(probe, source, timeout_s, placeholders, name, false, &caps).await?.0);
        }
        Ok(x)
    }

    /// One transient unit; its stdin, stdout and stderr are files in RUN_DIR. The exit code is the unit's, and so is
    /// how it ended (Result: oom-kill when MemoryMax was reached, timeout at RuntimeMaxSec).
    async fn unit(&self, probe: Vec<String>, source: &str, timeout_s: u64, placeholders: &PathBuf, name: &str,
                  mounts: bool, caps: &[String]) -> Result<(Exit, Option<i32>), String> {
        let id = format!("{}-{}", std::process::id(), SEQ.fetch_add(1, Ordering::Relaxed));
        let file = |ext: &str| Path::new(RUN_DIR).join(format!("{id}.{ext}"));
        let (input, output, error) = (file("star"), file("out"), file("err"));
        let _cleanup = TempFiles(vec![input.clone(), output.clone(), error.clone()]);
        tokio::fs::write(&input, source).await.map_err(|e| format!("cannot write {}: {e}", input.display()))?;
        let unit = format!("beat-question-{id}");
        let argv = self.sandboxed(probe, timeout_s, placeholders, name, [&input, &output, &error], mounts, &unit, caps).await?;
        let child = Command::new(&argv[0])
            .args(&argv[1..]).stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped()).kill_on_drop(true)
            .spawn().map_err(|e| format!("cannot start {}: {e}", argv[0]))?;
        // The unit's RuntimeMaxSec stops the probe itself; this bounds the wait for systemd-run.
        let run = tokio::time::timeout(Duration::from_secs(timeout_s + 15), child.wait_with_output())
            .await
            .map_err(|_| format!("time limit ({timeout_s}s) reached"))?
            .map_err(|e| format!("waiting for beat-probe: {e}"))?;
        let stdout = tokio::fs::read(&output).await.unwrap_or_default();
        let mut stderr = tokio::fs::read(&error).await.unwrap_or_default();
        stderr.extend_from_slice(&run.stderr); // systemd-run's own complaints, e.g. a unit that could not start
        if run.status.success() {
            return Ok((Exit { stdout, stderr, status: status_text(Some(0)), result: "success".into(), memory_peak: None },
                       Some(0)));
        }
        // systemd-run exits 1 whenever the unit failed, even when it never started (namespace set-up: 226): the
        // unit's own status is systemd's. A failed unit stays loaded until reset (no --collect, so it can be read).
        let show = Command::new(SYSTEMCTL).args(["show", "-p", "ExecMainStatus,Result,MemoryPeak", &unit]).output()
            .await.map(|o| String::from_utf8_lossy(&o.stdout).to_string()).unwrap_or_default();
        let prop = |k: &str| show.lines().find_map(|l| l.strip_prefix(k)?.strip_prefix('=')).unwrap_or("").to_string();
        let _ = Command::new(SYSTEMCTL).args(["reset-failed", &unit]).output().await;
        let code = prop("ExecMainStatus").parse::<i32>().ok().filter(|c| *c != 0).or(run.status.code());
        Ok((Exit { stdout, stderr, status: status_text(code), result: prop("Result"),
                   memory_peak: prop("MemoryPeak").parse().ok() }, code))
    }

    async fn sandboxed(&self, probe: Vec<String>, timeout_s: u64, placeholders: &PathBuf, name: &str,
                       [input, output, error]: [&PathBuf; 3], mounts: bool, unit: &str, caps: &[String])
                       -> Result<Vec<String>, String> {
        let secrets = self.secrets().await?;
        let mut props: Vec<String> = [
            "ProtectSystem=strict", "ProtectHome=read-only", "PrivateTmp=yes", "PrivateNetwork=yes",
            "PrivateDevices=yes", "NoNewPrivileges=yes", "ProtectKernelTunables=yes", "ProtectKernelModules=yes",
            "ProtectControlGroups=yes", "RestrictSUIDSGID=yes", "LockPersonality=yes",
            "TasksMax=64",
            "CPUQuota=100%", "WorkingDirectory=/",
        ].iter().map(|s| s.to_string()).collect();
        props.push(format!("CapabilityBoundingSet={BASE_CAPS}{}", caps.iter().map(|c| format!(" {c}")).collect::<String>()));
        props.push(format!("MemoryMax={MEMORY_MAX}"));
        props.push(format!("RuntimeMaxSec={timeout_s}"));
        for p in &self.hide {
            props.push(format!("InaccessiblePaths={}", p.display()));
        }
        props.extend(self.unit_props.iter().cloned());
        props.push(format!("StandardInput=file:{}", input.display()));
        props.push(format!("StandardOutput=file:{}", output.display()));
        props.push(format!("StandardError=file:{}", error.display()));
        // Unit-file list syntax: paths with separators in them cannot be bound. Nothing is bound under
        // /proc: those entries (environ) belong to processes that may be gone by the time the unit starts, which
        // fails the whole unit; beat-probe denies reading them itself.
        let binds: Vec<String> = secrets
            .iter()
            .filter(|s| !s.0.contains([',', ' ', ':']) && !s.0.starts_with("/proc/"))
            .map(|(path, dir, _)| format!("-{}:{path}", placeholders.join(if *dir { "dir" } else { "file" }).display()))
            .collect();
        if mounts && !binds.is_empty() {
            props.push(format!("BindReadOnlyPaths={}", binds.join(" ")));
        }
        let meta: String = secrets.iter().map(|s| format!("{}\n", s.2)).collect();
        let meta = { use base64::Engine; base64::engine::general_purpose::STANDARD.encode(meta) };
        let mut argv: Vec<String> = [SYSTEMD_RUN, "--quiet", "--wait", "--service-type=exec"]
            .iter().map(|s| s.to_string()).collect();
        argv.push(format!("--unit={unit}"));
        argv.push(format!("--description=beat question {name}"));
        for p in props {
            argv.extend(["-p".into(), p]);
        }
        for (k, v) in [("HOME", "/tmp"), ("LANG", "C.UTF-8"), ("BEAT_SECRETS", meta.as_str())] {
            argv.extend(["-E".into(), format!("{k}={v}")]);
        }
        argv.extend(probe);
        Ok(argv)
    }

    /// The sandbox this sensor's questions get: "full", "no-secret-mounts" (see secret_mounts_denied) or "none".
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

    /// (path, is_dir, metadata line) of each secret file, from `beat-probe secrets`, run here outside the sandbox.
    async fn secrets(&self) -> Result<Vec<(String, bool, String)>, String> {
        let out = Command::new(&self.probe)
            .args(["secrets", "--map", "/"])
            .env_remove("BEAT_SECRETS")
            .output()
            .await
            .map_err(|e| format!("beat-probe secrets: {e}"))?;
        if !out.status.success() {
            return Err(format!("beat-probe secrets failed: {}", String::from_utf8_lossy(&out.stderr).trim()));
        }
        Ok(String::from_utf8_lossy(&out.stdout)
            .lines()
            .filter_map(|l| {
                let v: Value = serde_json::from_str(l).ok()?;
                Some((v["path"].as_str()?.to_string(), v["kind"] == "dir", l.to_string()))
            })
            .collect())
    }
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
