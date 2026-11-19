//! Questions sandboxed without systemd (`--bwrap`): for a sensor in a Kubernetes pod (packaging/kubernetes),
//! where the host's PID 1 is not the sensor's to command. The pod is privileged, in the host's PID and network
//! namespaces, with the host's / read-only at `host` (`--host-root`). Each question gets what its systemd unit gets
//! on a host, made by bubblewrap, setpriv, a seccomp filter and a cgroup of its own under the pod's:
//!
//!   systemd unit (runner.rs)                      here
//!   ProtectSystem=strict, ProtectHome=read-only   HOST's top-level entries --ro-bind into a tmpfs root (ro)
//!   PrivateTmp, PrivateDevices                    --tmpfs /tmp (1777), --dev /dev
//!   ProtectKernelTunables                         /proc/sys bound over itself, ro
//!   MountImages=IMAGE:/nix/store                  --ro-bind /nix             (the pod's: the sensor's closure)
//!   InaccessiblePaths= (the sensor's key)         --tmpfs (a directory) or /dev/null (a file) over it
//!   BindReadOnlyPaths= (placeholders)             --ro-bind-try placeholder over each secret file
//!   RestrictAddressFamilies=AF_UNIX AF_NETLINK    --seccomp (packaging/kubernetes/seccomp.c)
//!   PrivateNetwork= (the walk)                    --unshare-net
//!   User=, Capability*, NoNewPrivileges           setpriv: uid, ambient = inheritable = bounding = the question's
//!   MemoryMax, TasksMax, CPUQuota                 memory.max (swap 0), pids.max, cpu.max of the question's cgroup
//!   RuntimeMaxSec                                 cgroup.kill at the deadline
//!
//! capture()'s tcpdump runs in one too (capture.rs): the host's network (the pod's), CAP_NET_RAW only, its own filter.
//! Not here yet: the walk's idle I/O class and nice. A sandbox starts in about the time a unit does (54 ms on one
//! host, 2026-11-18); the debugging regression runs under both (runner.rs, debugging_regression_bwrap).

use std::ffi::CString;
use std::os::fd::AsRawFd;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use tokio::process::Command;

/// The programs and places a sandbox is made from.
pub struct Bwrap {
    pub bwrap: PathBuf,
    pub setpriv: PathBuf,
    /// The compiled filters (BPF), passed to bwrap on fd 9: a question's (AF_UNIX and AF_NETLINK sockets only), and
    /// capture()'s tcpdump's (AF_PACKET and AF_UNIX, no sendto/sendmsg/sendmmsg): `seccomp.c`.
    pub seccomp: PathBuf,
    pub seccomp_capture: PathBuf,
    /// The host's / inside the pod (a hostPath, read-only).
    pub host: PathBuf,
    /// The pod's own cgroup (its namespace's root): questions get children of it, the sensor a leaf `sensor`.
    pub cgroup: PathBuf,
}

/// A sandbox's resource limits.
pub struct Limits {
    pub memory: &'static str,
    pub tasks: u32,
    /// Percent of one CPU.
    pub cpu: u32,
}

/// One sandboxed program.
pub struct Spec<'a> {
    pub argv: &'a [String],
    /// tcpdump for capture(): its filter instead of a question's.
    pub capture: bool,
    /// The user it runs as; None: root (no setpriv).
    pub uid: Option<u32>,
    /// Its capabilities, `CAP_*` names: ambient, inheritable and the bounding set; nothing else.
    pub caps: Vec<String>,
    pub private_net: bool,
    /// Placeholder (the sensor's path) over a secret file (the host's path).
    pub binds: Vec<(PathBuf, String)>,
    pub hide: &'a [PathBuf],
    pub env: Vec<(String, String)>,
    pub limits: Limits,
    pub timeout: Duration,
    pub stdin: Option<&'a Path>,
    pub stdout: &'a Path,
    pub stderr: &'a Path,
}

/// How it ended, in systemd's words (runner.rs reads `result` as it reads a unit's Result=).
pub struct Ended {
    pub code: Option<i32>,
    pub result: &'static str,
    pub memory_peak: Option<u64>,
}

static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

impl Bwrap {
    /// Once, before any sandbox: the pod's processes into a leaf (a cgroup with processes cannot delegate controllers
    /// to children), then memory, pids and cpu delegated. Also checks the programs are there.
    pub fn init(&self) -> Result<(), String> {
        for p in [&self.bwrap, &self.setpriv, &self.seccomp, &self.seccomp_capture] {
            if !p.exists() {
                return Err(format!("{} not found", p.display()));
            }
        }
        if !self.host.join("proc").is_dir() {
            return Err(format!("{}: not the host's / (mount it read-only there)", self.host.display()));
        }
        let leaf = self.cgroup.join("sensor");
        std::fs::create_dir_all(&leaf).map_err(|e| format!("{}: {e} (a privileged pod's cgroup is writable)", leaf.display()))?;
        for _ in 0..5 {
            let procs = std::fs::read_to_string(self.cgroup.join("cgroup.procs")).map_err(|e| e.to_string())?;
            if procs.trim().is_empty() {
                break;
            }
            for p in procs.lines() {
                let _ = std::fs::write(leaf.join("cgroup.procs"), p);
            }
        }
        std::fs::write(self.cgroup.join("cgroup.subtree_control"), "+memory +pids +cpu")
            .map_err(|e| format!("{}: delegating memory, pids, cpu: {e}", self.cgroup.display()))
    }

    /// bwrap's arguments, then setpriv's, then the program's.
    pub fn argv(&self, s: &Spec) -> Vec<String> {
        let d = |p: &Path| p.display().to_string();
        let mut a: Vec<String> = vec![d(&self.bwrap)];
        a.extend(self.host_entries());
        // The pod's /nix, not just its store: with /nix made by bwrap as the mount point, a user without
        // CAP_DAC_READ_SEARCH could not open the store's libraries (tcpdump's libpcap: EACCES; k3s, Debian 12,
        // 2026-11-18). Questions had the capability and never showed it.
        a.extend(["--ro-bind", "/nix", "/nix", "--proc", "/proc", "--ro-bind", "/proc/sys", "/proc/sys",
                  "--dev", "/dev", "--perms", "1777", "--tmpfs", "/tmp"].map(String::from));
        for (src, dst) in &s.binds {
            // Not under another bind: that one's placeholder directory has emptied it, so there is no file left to
            // mount over (the live check gives /etc/ssl/private, the walk the key in it; Ubuntu 24.04, 2026-11-19).
            if s.binds.iter().any(|(_, outer)| outer != dst && Path::new(dst).starts_with(outer)) {
                continue;
            }
            // Not over a link: bwrap cannot mount there; the file it leads to is covered on its own when it is secret,
            // and beat-probe refuses a link by where it leads either way.
            let on_host = self.host.join(dst.trim_start_matches('/'));
            if std::fs::symlink_metadata(&on_host).is_ok_and(|m| m.file_type().is_symlink()) {
                continue;
            }
            a.extend(["--ro-bind-try".into(), d(src), dst.clone()]);
        }
        for h in s.hide {
            let on_host = self.host.join(h.strip_prefix("/").unwrap_or(h));
            if on_host.is_dir() {
                a.extend(["--tmpfs".into(), d(h), "--remount-ro".into(), d(h)]);
            } else if on_host.exists() {
                a.extend(["--ro-bind".into(), "/dev/null".into(), d(h)]);
            }
        }
        if s.private_net {
            a.push("--unshare-net".into());
        }
        a.extend(["--new-session", "--die-with-parent", "--cap-drop", "ALL"].map(String::from));
        let setpriv_caps: &[&str] = if s.uid.is_some() { &["CAP_SETUID", "CAP_SETGID", "CAP_SETPCAP"] } else { &[] };
        for c in setpriv_caps.iter().map(|c| c.to_string()).chain(s.caps.iter().cloned()) {
            a.extend(["--cap-add".into(), c]);
        }
        a.extend(["--chdir", "/", "--clearenv"].map(String::from));
        for (k, v) in &s.env {
            a.extend(["--setenv".into(), k.clone(), v.clone()]);
        }
        a.extend(["--remount-ro", "/", "--seccomp", "9", "--"].map(String::from));
        if let Some(uid) = s.uid {
            let list = s.caps.iter().map(|c| format!(",+{}", c.trim_start_matches("CAP_").to_lowercase())).collect::<String>();
            a.push(d(&self.setpriv));
            a.extend([format!("--reuid={uid}"), format!("--regid={uid}"), "--clear-groups".into(), "--no-new-privs".into(),
                      format!("--inh-caps=-all{list}"), format!("--ambient-caps=-all{list}"),
                      format!("--bounding-set=-all{list}"), "--".into()]);
        }
        a.extend(s.argv.iter().cloned());
        a
    }

    /// The host's / in the question's: each top-level entry bound read-only into bwrap's new root (a tmpfs, made
    /// read-only last), so /nix/store can be added on a host without /nix, where the host's own / (read-only) has no
    /// mount point for it. Links stay links (/bin -> usr/bin); /proc, /dev and /tmp are the sandbox's own.
    fn host_entries(&self) -> Vec<String> {
        let mut entries: Vec<_> = std::fs::read_dir(&self.host).into_iter().flatten().flatten().collect();
        entries.sort_by_key(|e| e.file_name());
        let mut a = Vec::new();
        for e in entries {
            let name = e.file_name().to_string_lossy().to_string();
            if matches!(name.as_str(), "proc" | "dev" | "tmp" | "nix") {
                continue;
            }
            let (src, dst) = (e.path().display().to_string(), format!("/{name}"));
            match std::fs::read_link(e.path()) {
                Ok(target) => a.extend(["--symlink".into(), target.display().to_string(), dst]),
                Err(_) => a.extend(["--ro-bind".into(), src, dst]),
            }
        }
        a
    }

    /// Runs it to its end or its deadline; Err when it could not be started at all.
    pub async fn run(&self, s: &Spec<'_>) -> Result<Ended, String> {
        let Running { mut child, sandbox } = self.spawn(s)?;
        let status = match tokio::time::timeout(s.timeout, child.wait()).await {
            Ok(st) => Some(st.map_err(|e| e.to_string())?),
            Err(_) => {
                sandbox.kill();
                let _ = tokio::time::timeout(Duration::from_secs(10), child.wait()).await;
                None
            }
        };
        let field = |file: &str, key: &str| std::fs::read_to_string(sandbox.cgroup.join(file)).ok()
            .and_then(|t| t.lines().find_map(|l| l.strip_prefix(key)?.trim().parse::<u64>().ok()));
        let oom = field("memory.events", "oom_kill ").unwrap_or(0) > 0;
        let memory_peak = std::fs::read_to_string(sandbox.cgroup.join("memory.peak")).ok().and_then(|t| t.trim().parse().ok());
        let result = match &status {
            None => "timeout",
            Some(_) if oom => "oom-kill",
            Some(st) if st.success() => "success",
            Some(st) if st.code().is_some() => "exit-code",
            Some(_) => "signal",
        };
        Ok(Ended { code: status.and_then(|st| st.code()), result, memory_peak })
    }

    /// Starts it in a cgroup of its own and returns at once; dropping the result kills whatever is left in it. Its
    /// deadline is the caller's (`timeout` is not used here).
    pub fn spawn(&self, s: &Spec<'_>) -> Result<Running, String> {
        let cgroup = self.cgroup.join(format!("q-{}-{}", std::process::id(), SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed)));
        std::fs::create_dir(&cgroup).map_err(|e| format!("{}: {e}", cgroup.display()))?;
        let cg = Cgroup(cgroup.clone());
        let set = |f: &str, v: &str| std::fs::write(cgroup.join(f), v).map_err(|e| format!("{}/{f}: {e}", cgroup.display()));
        set("memory.max", s.limits.memory)?;
        let _ = set("memory.swap.max", "0"); // absent where swap accounting is off
        set("pids.max", &s.limits.tasks.to_string())?;
        set("cpu.max", &format!("{} 100000", s.limits.cpu * 1000))?;
        let argv = self.argv(s);
        let procs = CString::new(cgroup.join("cgroup.procs").as_os_str().as_bytes()).map_err(|e| e.to_string())?;
        let filter_path = if s.capture { &self.seccomp_capture } else { &self.seccomp };
        let filter = std::fs::File::open(filter_path).map_err(|e| format!("{}: {e}", filter_path.display()))?;
        let fd = filter.as_raw_fd();
        let out = |p: &Path| std::fs::OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(p)
            .map_err(|e| format!("{}: {e}", p.display()));
        let stdin = match s.stdin {
            Some(p) => Stdio::from(std::fs::File::open(p).map_err(|e| format!("{}: {e}", p.display()))?),
            None => Stdio::null(),
        };
        let mut cmd = Command::new(&argv[0]);
        cmd.args(&argv[1..]).stdin(stdin).stdout(out(s.stdout)?).stderr(out(s.stderr)?).kill_on_drop(true);
        // In the child, before exec: into its cgroup (so everything it starts is counted and killed with it), and the
        // filter on fd 9 for bwrap. Only system calls here: no allocation after fork.
        unsafe {
            cmd.pre_exec(move || {
                let f = libc::open(procs.as_ptr(), libc::O_WRONLY | libc::O_CLOEXEC);
                if f < 0 || libc::write(f, b"0".as_ptr().cast(), 1) != 1 {
                    return Err(std::io::Error::last_os_error());
                }
                libc::close(f);
                // dup2 onto itself keeps FD_CLOEXEC (the file may already be fd 9): clear it then
                let ok = if fd == 9 { libc::fcntl(9, libc::F_SETFD, 0) >= 0 } else { libc::dup2(fd, 9) >= 0 };
                if !ok {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let child = cmd.spawn().map_err(|e| format!("cannot start {}: {e}", argv[0]))?;
        Ok(Running { child, sandbox: Sandbox { cgroup, _cg: cg } })
    }
}

/// A sandbox started by `spawn`: its bwrap process, and its cgroup.
pub struct Running {
    pub child: tokio::process::Child,
    pub sandbox: Sandbox,
}

/// A started sandbox's cgroup: killed and removed when this is dropped.
pub struct Sandbox {
    pub cgroup: PathBuf,
    _cg: Cgroup,
}

impl Sandbox {
    /// Everything in its cgroup, at once.
    pub fn kill(&self) {
        let _ = std::fs::write(self.cgroup.join("cgroup.kill"), "1");
    }

    /// A signal to the processes in it named `comm` (not to bwrap, which would end them all without a word).
    pub fn signal(&self, comm: &str, sig: i32) {
        let procs = std::fs::read_to_string(self.cgroup.join("cgroup.procs")).unwrap_or_default();
        for pid in procs.lines().filter_map(|p| p.trim().parse::<i32>().ok()) {
            if std::fs::read_to_string(format!("/proc/{pid}/comm")).is_ok_and(|c| c.trim() == comm) {
                // SAFETY: kill(2) on a pid in a cgroup this sensor made.
                unsafe { libc::kill(pid, sig) };
            }
        }
    }
}

/// A cgroup this sensor made: what is left in it is killed, and it is removed (in the background: rmdir succeeds only
/// once the kernel has reaped what was killed).
struct Cgroup(PathBuf);

impl Drop for Cgroup {
    fn drop(&mut self) {
        let _ = std::fs::write(self.0.join("cgroup.kill"), "1");
        if std::fs::remove_dir(&self.0).is_err() {
            let p = self.0.clone();
            std::thread::spawn(move || {
                for _ in 0..100 {
                    std::thread::sleep(Duration::from_millis(50));
                    if std::fs::remove_dir(&p).is_ok() {
                        break;
                    }
                }
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bw() -> Bwrap {
        Bwrap { bwrap: "/b/bwrap".into(), setpriv: "/b/setpriv".into(), seccomp: "/b/filter".into(), seccomp_capture: "/b/cf".into(),
                host: "/host".into(), cgroup: "/sys/fs/cgroup".into() }
    }

    #[test]
    fn a_question_drops_to_its_user_with_its_caps_only() {
        let argv = vec!["/p/beat-probe".to_string(), "run".into(), "-".into()];
        let s = Spec { argv: &argv, capture: false, uid: Some(64321), caps: vec!["CAP_DAC_READ_SEARCH".into(), "CAP_BPF".into()],
                       private_net: false, binds: vec![("/ph/file".into(), "/etc/shadow".into())], hide: &[],
                       env: vec![("HOME".into(), "/tmp".into())], limits: Limits { memory: "1G", tasks: 64, cpu: 100 },
                       timeout: Duration::from_secs(1), stdin: None, stdout: Path::new("/o"), stderr: Path::new("/e") };
        let a = bw().argv(&s).join(" ");
        assert!(a.starts_with("/b/bwrap --ro-bind /nix /nix"), "no /host here: {a}");
        assert!(a.contains("--remount-ro / --seccomp 9"), "{a}");
        assert!(a.contains("--ro-bind-try /ph/file /etc/shadow"), "{a}");
        assert!(a.contains("--cap-drop ALL --cap-add CAP_SETUID --cap-add CAP_SETGID --cap-add CAP_SETPCAP \
                            --cap-add CAP_DAC_READ_SEARCH --cap-add CAP_BPF"), "{a}");
        assert!(a.contains("--seccomp 9 -- /b/setpriv --reuid=64321 --regid=64321 --clear-groups --no-new-privs \
                            --inh-caps=-all,+dac_read_search,+bpf --ambient-caps=-all,+dac_read_search,+bpf \
                            --bounding-set=-all,+dac_read_search,+bpf -- /p/beat-probe run -"), "{a}");
        assert!(!a.contains("--unshare-net"), "{a}");
    }

    #[test]
    fn a_secret_under_a_secret_directory_is_left_to_the_directory() {
        let argv = vec!["/p/beat-probe".to_string()];
        let binds = vec![("/ph/dir".into(), "/etc/ssl/private".into()), ("/ph/file".into(), "/etc/ssl/private/k.key".into()),
                         ("/ph/file".into(), "/etc/ssl/private2".into())];
        let s = Spec { argv: &argv, capture: false, uid: None, caps: vec![], private_net: false, binds, hide: &[], env: vec![],
                       limits: Limits { memory: "1G", tasks: 64, cpu: 100 }, timeout: Duration::from_secs(1),
                       stdin: None, stdout: Path::new("/o"), stderr: Path::new("/e") };
        let a = bw().argv(&s).join(" ");
        assert!(a.contains("--ro-bind-try /ph/dir /etc/ssl/private "), "{a}");
        assert!(a.contains("--ro-bind-try /ph/file /etc/ssl/private2 "), "{a}");
        assert!(!a.contains("k.key"), "{a}");
    }
}
