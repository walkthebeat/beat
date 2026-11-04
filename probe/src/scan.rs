//! Finding secret files for the sensor's placeholders (docs/security.md): what the recursive secret patterns must not
//! walk, and the walk itself.
//!
//! The walk runs in the background (sensor/src/runner.rs), not per question, and is bounded three ways. Container
//! storage is not entered: it holds image layers by the million, which is where a walk over /var/lib spends its time on
//! a host with containers. Network and similar mounts are not entered: a walk over NFS would load the server and hang
//! with it. And a budget stops whatever else turns out to be large. What it left out is reported, never silent: those
//! files have no placeholder, so a tool or osquery in a question could read them. beat-probe's own check of the
//! patterns (`LocalHost::is_secret`) does not depend on the walk and still denies them to `read()`.

use std::collections::HashMap;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use glob::{MatchOptions, Pattern};
use serde::Serialize;

/// Where a walk stops. The defaults are a judgement, not a measurement of real hosts: a walk is low priority and in
/// the background, so it may take a while, but a tree too large for this is reported rather than walked for ever.
#[derive(Clone, Debug)]
pub struct Budget {
    pub seconds: u64,
    pub entries: u64,
}

impl Default for Budget {
    fn default() -> Self {
        Budget { seconds: 300, entries: 5_000_000 }
    }
}

/// How often the walk looks at the clock, in directory entries.
const CLOCK_EVERY: u64 = 4096;

/// Why a walk stopped early, and where.
#[derive(Clone, Debug, Serialize, PartialEq)]
pub struct Cut {
    /// The tree it was in (a pattern's root): the trees after it were not walked.
    pub root: String,
    pub at: String,
    pub why: String,
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct WalkReport {
    pub entries: u64,
    pub seconds: f64,
    /// (path, why): directories not entered.
    pub skipped: Vec<(String, String)>,
    pub cut: Option<Cut>,
}

/// (mount point, filesystem type) of each line of /proc/self/mountinfo. Mount points are octal-escaped there.
pub fn parse_mountinfo(text: &str) -> Vec<(String, String)> {
    let unescape = |s: &str| {
        let b = s.as_bytes();
        let (mut out, mut i) = (Vec::with_capacity(b.len()), 0);
        while i < b.len() {
            if b[i] == b'\\' && i + 3 < b.len() {
                if let Ok(c) = u8::from_str_radix(&s[i + 1..i + 4], 8) {
                    out.push(c);
                    i += 4;
                    continue;
                }
            }
            out.push(b[i]);
            i += 1;
        }
        String::from_utf8_lossy(&out).into_owned()
    };
    text.lines()
        .filter_map(|l| {
            let (left, right) = l.split_once(" - ")?;
            Some((unescape(left.split(' ').nth(4)?), right.split(' ').next()?.to_string()))
        })
        .collect()
}

/// Why a mount of this type is not entered, if it is not. fuse.* covers sshfs, s3fs, rclone and the like; fuseblk is a
/// local disk and is walked. autofs: entering it would mount what it manages.
pub fn skipped_fstype(fs: &str) -> Option<String> {
    let kind = match fs {
        "nfs" | "nfs4" | "cifs" | "smb3" | "smbfs" | "ceph" | "glusterfs" | "lustre" | "gpfs" | "beegfs" | "pvfs2"
        | "orangefs" | "afs" | "9p" | "davfs" | "ocfs2" | "gfs2" | "autofs" => "network or shared",
        "overlay" | "aufs" | "squashfs" => "layered image",
        f if f.starts_with("fuse.") => "FUSE",
        _ => return None,
    };
    Some(format!("{kind} filesystem ({fs})"))
}

fn toml_string(text: &str, key: &str) -> Option<String> {
    text.lines().find_map(|l| {
        let (k, v) = l.split_once('=')?;
        (k.trim() == key).then(|| v.trim().trim_matches('"').to_string()).filter(|v| v.starts_with('/'))
    })
}

fn flag_value(argv: &[String], names: &[&str]) -> Option<String> {
    let mut it = argv.iter();
    while let Some(a) = it.next() {
        for n in names {
            if a == n {
                return it.next().cloned();
            }
            if let Some(v) = a.strip_prefix(n).and_then(|r| r.strip_prefix('=')) {
                return Some(v.to_string());
            }
        }
    }
    None
}

/// Container storage on this host, where it is configured to be and where it is by default: path -> why not entered.
/// `read` reads a host file, `commands` are the running processes' command lines.
pub fn container_roots(read: &dyn Fn(&str) -> Option<String>, commands: &[Vec<String>]) -> HashMap<String, String> {
    let mut out: HashMap<String, String> = HashMap::new();
    let mut add = |p: String, why: &str| {
        let p = p.trim_end_matches('/');
        if p.starts_with('/') && p.len() > 1 {
            out.insert(p.to_string(), why.to_string());
        }
    };
    add("/var/lib/docker".into(), "Docker data root");
    if let Some(v) = read("/etc/docker/daemon.json").and_then(|t| serde_json::from_str::<serde_json::Value>(&t).ok()) {
        if let Some(p) = v["data-root"].as_str().or(v["graph"].as_str()) {
            add(p.into(), "Docker data root");
        }
    }
    add("/var/lib/containerd".into(), "containerd root");
    if let Some(p) = read("/etc/containerd/config.toml").and_then(|t| toml_string(&t, "root")) {
        add(p, "containerd root");
    }
    add("/var/lib/containers".into(), "Podman storage");
    if let Some(p) = read("/etc/containers/storage.conf").and_then(|t| toml_string(&t, "graphroot")) {
        add(p, "Podman storage");
    }
    add("/var/lib/kubelet/pods".into(), "kubelet pods");
    add("/var/lib/rancher/k3s/agent/containerd".into(), "containerd root");
    for argv in commands {
        match argv.first().and_then(|a| a.rsplit('/').next()) {
            Some("dockerd") => {
                if let Some(p) = flag_value(argv, &["--data-root", "--graph", "-g"]) {
                    add(p, "Docker data root");
                }
            }
            Some("containerd") => {
                if let Some(p) = flag_value(argv, &["--root"]) {
                    add(p, "containerd root");
                }
            }
            Some("kubelet") => {
                if let Some(p) = flag_value(argv, &["--root-dir"]) {
                    add(format!("{}/pods", p.trim_end_matches('/')), "kubelet pods");
                }
            }
            _ => {}
        }
    }
    out
}

/// Walks each root for entries whose name matches one of its patterns, without following symlinks, reading each
/// directory once and each entry's type from the directory itself (no stat per file: most of what a walk costs).
/// A matching directory is listed and not entered, as everything under it is secret. Returns guest paths.
pub fn walk(roots: &[(String, Vec<Pattern>)], skip: &HashMap<String, String>, budget: &Budget,
            host_of: &dyn Fn(&str) -> Option<PathBuf>, options: MatchOptions) -> (Vec<String>, WalkReport) {
    let start = Instant::now();
    let limit = Duration::from_secs(budget.seconds);
    let mut found = Vec::new();
    let mut r = WalkReport::default();
    'roots: for (root, patterns) in roots {
        if let Some(why) = skip.get(root) {
            r.skipped.push((root.clone(), why.clone()));
            continue;
        }
        let mut stack = vec![root.clone()];
        while let Some(dir) = stack.pop() {
            let Some(host) = host_of(&dir) else { continue };
            let Ok(entries) = std::fs::read_dir(&host) else { continue };
            for e in entries.flatten() {
                r.entries += 1;
                let why = if r.entries >= budget.entries {
                    Some(format!("{} entries", budget.entries))
                } else if r.entries % CLOCK_EVERY == 0 && start.elapsed() >= limit {
                    Some(format!("{} s", budget.seconds))
                } else {
                    None
                };
                if let Some(why) = why {
                    r.cut = Some(Cut { root: root.clone(), at: dir.clone(), why });
                    break 'roots;
                }
                let name = e.file_name();
                let name = name.to_string_lossy();
                let path = format!("{dir}/{name}");
                let is_dir = e.file_type().is_ok_and(|t| t.is_dir());
                if patterns.iter().any(|p| p.matches_with(&name, options)) {
                    found.push(path);
                } else if is_dir {
                    match skip.get(&path) {
                        Some(why) => r.skipped.push((path, why.clone())),
                        None => stack.push(path),
                    }
                }
            }
        }
    }
    r.skipped.sort();
    r.skipped.dedup();
    r.seconds = start.elapsed().as_secs_f64();
    (found, r)
}

/// The run note on what the scan left out, for a probe that asked for `secrets()`. It goes in the answer, and equal
/// answers must stay equal: paths and reasons only, no counts, times or where a budget happened to stop.
pub fn report_note(skipped: &[(String, String)], cut_root: Option<&str>, uncovered: &[String]) -> Option<String> {
    let mut parts = Vec::new();
    if !skipped.is_empty() {
        let list: Vec<String> = skipped.iter().map(|(p, why)| format!("{p} ({why})")).collect();
        parts.push(format!("not checked: {}", list.join(", ")));
    }
    if let Some(root) = cut_root {
        parts.push(format!("the walk reached its budget in {root}, so that tree and the ones after it are only partly checked"));
    }
    if !uncovered.is_empty() {
        parts.push(format!("found but not covered by a placeholder (systemd cannot express these paths): {}", uncovered.join(", ")));
    }
    if parts.is_empty() {
        return None;
    }
    Some(format!("secret files: {}. Files there have no placeholder: read() still refuses what the patterns name, but a \
                  tool or osquery in a question could read them", parts.join("; ")))
}

#[cfg(test)]
mod tests {
    use super::*;

    const MATCH: MatchOptions = MatchOptions { case_sensitive: true, require_literal_separator: true, require_literal_leading_dot: true };

    #[test]
    fn mountinfo_gives_mount_point_and_type() {
        let t = "36 35 98:0 / / rw,noatime master:1 - ext4 /dev/root rw\n\
                 37 36 0:50 / /srv/my\\040share rw shared:2 - nfs4 server:/x rw\n\
                 38 36 0:51 / /opt/x rw - fuse.sshfs a:/ rw\n";
        assert_eq!(parse_mountinfo(t), vec![("/".to_string(), "ext4".to_string()), ("/srv/my share".to_string(), "nfs4".to_string()),
                                            ("/opt/x".to_string(), "fuse.sshfs".to_string())]);
    }

    #[test]
    fn which_filesystems_are_not_entered() {
        for fs in ["nfs", "nfs4", "cifs", "lustre", "autofs", "overlay", "squashfs", "fuse.sshfs"] {
            assert!(skipped_fstype(fs).is_some(), "{fs}");
        }
        for fs in ["ext4", "xfs", "btrfs", "zfs", "fuseblk", "tmpfs"] {
            assert!(skipped_fstype(fs).is_none(), "{fs}");
        }
    }

    #[test]
    fn container_storage_is_found_where_it_is_configured() {
        let read = |p: &str| match p {
            "/etc/docker/daemon.json" => Some(r#"{"data-root": "/opt/dock/"}"#.to_string()),
            "/etc/containerd/config.toml" => Some("version = 2\nroot = \"/srv/ctr\"\n[plugins]\n".to_string()),
            "/etc/containers/storage.conf" => Some("[storage]\ndriver = \"overlay\"\ngraphroot = \"/srv/pod\"\n".to_string()),
            _ => None,
        };
        let cmd = vec![vec!["/usr/bin/dockerd".to_string(), "--data-root=/data/d".to_string()],
                       vec!["kubelet".to_string(), "--root-dir".to_string(), "/data/k/".to_string()]];
        let r = container_roots(&read, &cmd);
        for p in ["/var/lib/docker", "/opt/dock", "/srv/ctr", "/srv/pod", "/data/d", "/data/k/pods", "/var/lib/containerd",
                  "/var/lib/containers", "/var/lib/kubelet/pods"] {
            assert!(r.contains_key(p), "{p} in {r:?}");
        }
    }

    #[test]
    fn broken_settings_leave_the_defaults() {
        let read = |p: &str| (p == "/etc/docker/daemon.json").then(|| "{not json".to_string());
        assert!(container_roots(&read, &[]).contains_key("/var/lib/docker"));
    }

    fn tree() -> (tempdir::Dir, Vec<(String, Vec<Pattern>)>) {
        let d = tempdir::Dir::new();
        for f in ["etc/a.key", "etc/sub/b.key", "etc/.hidden/c.key", "etc/.dot.key", "etc/other.txt", "etc/dir.key/inner",
                  "var/x.keytab", "var/docker/layer/d.keytab", "var/nfs/e.keytab", "var/f.key"] {
            d.write(f);
        }
        let root = |r: &str, ps: &[&str]| (format!("/{r}"), ps.iter().map(|p| Pattern::new(p).unwrap()).collect());
        (d, vec![root("etc", &["*.key"]), root("var", &["*.keytab"])])
    }

    #[test]
    fn walk_finds_by_name_and_leaves_out_what_it_is_told_to() {
        let (d, roots) = tree();
        let skip: HashMap<String, String> = [("/var/docker".to_string(), "Docker data root".to_string()),
                                             ("/var/nfs".to_string(), "network".to_string())].into();
        let host = |g: &str| Some(d.path(g));
        let (mut found, r) = walk(&roots, &skip, &Budget::default(), &host, MATCH);
        found.sort();
        assert_eq!(found, ["/etc/.hidden/c.key", "/etc/a.key", "/etc/dir.key", "/etc/sub/b.key", "/var/x.keytab"]);
        assert_eq!(r.skipped, [("/var/docker".to_string(), "Docker data root".to_string()),
                               ("/var/nfs".to_string(), "network".to_string())]);
        assert_eq!(r.cut, None);
    }

    #[test]
    fn a_skipped_root_is_reported() {
        let (d, roots) = tree();
        let skip: HashMap<String, String> = [("/var".to_string(), "nfs".to_string())].into();
        let host = |g: &str| Some(d.path(g));
        let (found, r) = walk(&roots, &skip, &Budget::default(), &host, MATCH);
        assert!(found.iter().all(|f| f.starts_with("/etc/")));
        assert_eq!(r.skipped, [("/var".to_string(), "nfs".to_string())]);
    }

    #[test]
    fn the_budget_stops_the_walk_and_says_where() {
        let (d, roots) = tree();
        let host = |g: &str| Some(d.path(g));
        let (_, r) = walk(&roots, &HashMap::new(), &Budget { seconds: 300, entries: 2 }, &host, MATCH);
        let cut = r.cut.expect("cut");
        assert_eq!(cut.root, "/etc");
        assert_eq!(cut.why, "2 entries");
    }

    #[test]
    fn a_symlink_is_not_followed() {
        let (d, roots) = tree();
        std::os::unix::fs::symlink(d.path("/var"), d.path("/etc/link")).unwrap();
        let host = |g: &str| Some(d.path(g));
        let (found, _) = walk(&roots[..1], &HashMap::new(), &Budget::default(), &host, MATCH);
        assert!(!found.iter().any(|f| f.contains("/link/")), "{found:?}");
    }

    #[test]
    fn the_note_is_stable_and_says_nothing_when_nothing_was_left_out() {
        assert_eq!(report_note(&[], None, &[]), None);
        let n = report_note(&[("/var/lib/docker".into(), "Docker data root".into())], Some("/var/lib"), &["/etc/a\"b.key".into()]).unwrap();
        assert!(n.contains("/var/lib/docker (Docker data root)") && n.contains("budget in /var/lib") && n.contains("a\"b.key"), "{n}");
        assert!(!n.chars().any(|c| c.is_ascii_digit()), "no counts or times: {n}");
    }

    mod tempdir {
        use std::path::PathBuf;
        pub struct Dir(PathBuf);
        impl Dir {
            pub fn new() -> Dir {
                use std::sync::atomic::{AtomicU32, Ordering};
                static N: AtomicU32 = AtomicU32::new(0);
                let p = std::env::temp_dir().join(format!("beat-scan-{}-{}", std::process::id(), N.fetch_add(1, Ordering::Relaxed)));
                std::fs::create_dir_all(&p).unwrap();
                Dir(p)
            }
            pub fn path(&self, guest: &str) -> PathBuf {
                self.0.join(guest.trim_start_matches('/'))
            }
            pub fn write(&self, rel: &str) {
                let p = self.path(rel);
                std::fs::create_dir_all(p.parent().unwrap()).unwrap();
                std::fs::write(p, "x").unwrap();
            }
        }
        impl Drop for Dir {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }
    }
}
