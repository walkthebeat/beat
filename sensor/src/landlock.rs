//! --landlock: questions sandboxed with no privilege at all, for a sensor in a pod that is not privileged (the
//! cluster sensor: no host to read, packaging/kubernetes/beat-cluster.yaml). bwrap there needs the pod's seccomp and AppArmor
//! profiles turned off and still has no cgroup (tested 2026-11-20); this needs neither. Before beat-probe starts:
//! - no_new_privs;
//! - Landlock: the files the question may read (its programs under /nix, the compiled tools, the paths given), nothing
//!   else; no write anywhere. The sensor's key and the pod's service-account token are outside, so unreadable. On
//!   ABI 6 and later also signals and abstract unix sockets scoped to the question (Debian 12's 6.1 has ABI 2: there
//!   a question could signal the sensor, which runs as the same uid; a DoS by a question the org signed);
//! - the seccomp filter (packaging/kubernetes/seccomp.c `cluster`): no socket of any family, so no network;
//! - RLIMIT_CORE 0, RLIMIT_FSIZE 0.
//! Memory has no cgroup here: the container's limit is the backstop, beat-probe's own limits the first line. The
//! deadline is the sensor's (run_piped kills at the timeout).
//! A kernel without Landlock refuses to start the sensor: it never runs a question unsandboxed.

use std::ffi::CString;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::path::{Path, PathBuf};

const CREATE_RULESET_VERSION: u32 = 1;
const RULE_PATH_BENEATH: u32 = 1;
const EXECUTE: u64 = 1 << 0;
const READ_FILE: u64 = 1 << 2;
const READ_DIR: u64 = 1 << 3;
const SCOPE_ABSTRACT_UNIX_SOCKET: u64 = 1 << 0;
const SCOPE_SIGNAL: u64 = 1 << 1;

#[repr(C)]
struct RulesetAttr {
    handled_access_fs: u64,
    handled_access_net: u64,
    scoped: u64,
}

#[repr(C, packed)]
struct PathBeneath {
    allowed_access: u64,
    parent_fd: i32,
}

/// Every filesystem right the kernel's ABI knows: what is handled and not granted is refused.
fn handled_fs(abi: i64) -> u64 {
    match abi {
        1 => (1 << 13) - 1,      // up to MAKE_SYM
        2 => (1 << 14) - 1,      // REFER
        3 | 4 => (1 << 15) - 1,  // TRUNCATE
        _ => (1 << 16) - 1,      // IOCTL_DEV (5)
    }
}

pub struct Landlock {
    ruleset: OwnedFd,
    filter: Vec<libc::sock_filter>,
    pub abi: i64,
}

impl Landlock {
    /// The ruleset (read and execute beneath each of `read`) and the seccomp filter, made once at start.
    pub fn new(read: &[PathBuf], seccomp: &Path) -> Result<Landlock, String> {
        let abi = unsafe { libc::syscall(libc::SYS_landlock_create_ruleset, std::ptr::null::<u8>(), 0, CREATE_RULESET_VERSION) };
        if abi < 1 {
            return Err(format!("this kernel has no Landlock ({}): questions cannot be sandboxed without privileges",
                               std::io::Error::last_os_error()));
        }
        let attr = RulesetAttr { handled_access_fs: handled_fs(abi), handled_access_net: 0,
                                 scoped: if abi >= 6 { SCOPE_ABSTRACT_UNIX_SOCKET | SCOPE_SIGNAL } else { 0 } };
        let size = if abi >= 6 { std::mem::size_of::<RulesetAttr>() } else { 8 };  // older ABIs know only the fs field
        let fd = unsafe { libc::syscall(libc::SYS_landlock_create_ruleset, &attr as *const RulesetAttr, size, 0u32) };
        if fd < 0 {
            return Err(format!("landlock_create_ruleset: {}", std::io::Error::last_os_error()));
        }
        let ruleset = unsafe { OwnedFd::from_raw_fd(fd as i32) };
        for p in read {
            let c = CString::new(p.as_os_str().as_encoded_bytes()).map_err(|e| e.to_string())?;
            let dir = unsafe { libc::open(c.as_ptr(), libc::O_PATH | libc::O_CLOEXEC) };
            if dir < 0 {
                return Err(format!("{}: {}", p.display(), std::io::Error::last_os_error()));
            }
            let dir = unsafe { OwnedFd::from_raw_fd(dir) };
            let is_dir = p.is_dir();
            let rule = PathBeneath { allowed_access: READ_FILE | EXECUTE | if is_dir { READ_DIR } else { 0 },
                                     parent_fd: dir.as_raw_fd() };
            if unsafe { libc::syscall(libc::SYS_landlock_add_rule, ruleset.as_raw_fd(), RULE_PATH_BENEATH,
                                      &rule as *const PathBeneath, 0u32) } != 0 {
                return Err(format!("landlock_add_rule {}: {}", p.display(), std::io::Error::last_os_error()));
            }
        }
        let bpf = std::fs::read(seccomp).map_err(|e| format!("{}: {e}", seccomp.display()))?;
        if bpf.is_empty() || bpf.len() % 8 != 0 {
            return Err(format!("{}: not a BPF program", seccomp.display()));
        }
        let filter = bpf.chunks(8).map(|c| libc::sock_filter {
            code: u16::from_ne_bytes([c[0], c[1]]), jt: c[2], jf: c[3], k: u32::from_ne_bytes([c[4], c[5], c[6], c[7]]),
        }).collect();
        Ok(Landlock { ruleset, filter, abi })
    }

    /// For Command::pre_exec, in the child after fork: only system calls on what `new` prepared.
    pub fn apply(&self) -> std::io::Result<()> {
        let err = std::io::Error::last_os_error;
        let zero = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
        unsafe {
            if libc::setrlimit(libc::RLIMIT_CORE, &zero) != 0 || libc::setrlimit(libc::RLIMIT_FSIZE, &zero) != 0 {
                return Err(err());
            }
            if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
                return Err(err());
            }
            if libc::syscall(libc::SYS_landlock_restrict_self, self.ruleset.as_raw_fd(), 0u32) != 0 {
                return Err(err());
            }
            let prog = libc::sock_fprog { len: self.filter.len() as u16, filter: self.filter.as_ptr() as *mut _ };
            if libc::prctl(libc::PR_SET_SECCOMP, libc::SECCOMP_MODE_FILTER, &prog as *const libc::sock_fprog) != 0 {
                return Err(err());
            }
        }
        Ok(())
    }
}
