//! `LocalHost`: the host-side builtins on the machine the evaluator runs on (docs/probes.md §4).
//!
//! Files are read through cap-std, opened at each mapped directory, so a path or a symlink cannot lead outside the
//! mapping: the same rule the WASM tools get from their read-only preopens. `root` lets tests map a
//! fixture tree instead of `/`. The one exception: the host's whole `/` mapped as `/` has no outside, so plain file
//! access is used there, which also follows absolute symlinks (`/etc/localtime`), which cap-std always refuses.
//!
//! Gap in version 0: tools see secret files under a mapped directory ([B9] wants EACCES). The per-run process
//! sandbox closes it (placeholders bound over them: sensor/src/runner.rs); `read()` and `stat()` here already enforce it.

use std::cell::{OnceCell, RefCell};
use std::collections::HashMap;
use std::io::ErrorKind;
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;

use cap_std::ambient_authority;
use cap_std::fs::Dir;
use glob::{MatchOptions, Pattern};

use crate::scan::{self, Budget, WalkReport};
use crate::host::{Host, HostError, HostResult, JournalOptions, Sample, Secret, Stat, ToolResult};
use crate::sources::{Journal, Osquery};
use crate::tools::{ToolLimits, Tools};
use crate::transform;

/// Bounds on what `beat-probe secrets` prepares for the sandbox (BEAT_SECRETS_FILE): files looked at under one secret
/// directory, and the size of one prepared answer.
const PREPARE_FILES: usize = 50;
/// The longest interval `sample()` waits: a question's whole run is limited (120 s by default).
const SAMPLE_MAX_S: f64 = 60.0;
const PREPARE_BYTES: usize = 8 << 10;

/// Secret paths: metadata only, never content ([B9]). Shadow files, SSH and TLS keys, keytabs, plus process
/// environments. A directory in this list makes everything under it secret. `is_secret` checks these live on every
/// read. `beat-probe secrets` enumerates them for the sensor's placeholders (scan.rs): the fixed ones and single-level
/// globs on every question (`--live`), the recursive ones in a background walk (`--walk`), `/proc` never.
pub const SECRET_GLOBS: &[&str] = &[
    "/etc/shadow", "/etc/shadow-", "/etc/gshadow", "/etc/gshadow-", "/etc/ssh/ssh_host_*_key", "/etc/ssl/private",
    "/root/.ssh", "/home/*/.ssh", "/etc/**/*.key", "/etc/**/*.keytab", "/opt/**/*.key", "/opt/**/*.keytab",
    "/srv/**/*.key", "/var/lib/**/*.keytab", "/proc/*/environ", "/proc/*/task/*/environ",
    // A process's memory, whatever it holds. Its root, cwd and fds are doors, checked by where they lead (`through`).
    "/proc/*/mem", "/proc/*/task/*/mem",
    // The sensor's own keys: hidden from questions' mounts, and reachable through /proc/<pid>/root but for this.
    SENSOR_KEYS,
];
const SENSOR_KEYS: &str = "/var/lib/beat-sensor/keys";
/// How many /proc doors one path may go through, each inside the last: /proc/1/root/proc/1/root/... Past this: refused.
const DOORS_MAX: usize = 8;
/// How many symlinks one path may follow, as the kernel's own limit.
const LINKS_MAX: usize = 40;
/// /proc's own files a tool can read, copied for each pipe that names /proc (`ProcFiles`): a tool's files must be in a
/// directory, and /proc/<pid> must not be. Small files that do not block; not kcore, kmsg, kallsyms or pagemap.
const PROC_FILES: &[&str] = &["buddyinfo", "cgroups", "cmdline", "consoles", "cpuinfo", "crypto", "devices", "diskstats",
                              "execdomains", "filesystems", "interrupts", "iomem", "ioports", "loadavg", "locks", "meminfo",
                              "misc", "modules", "mounts", "pagetypeinfo", "partitions", "schedstat", "slabinfo", "softirqs", "stat",
                              "swaps", "uptime", "version", "vmallocinfo", "vmstat", "zoneinfo"];
const ROOT_HINT: &str = "a tool does not see / itself, only what is in it: use list_dir(\"/\") to list it";
const PROC_HINT: &str = "a tool sees /proc's own files and directories such as /proc/sys, not /proc/<pid>: read the file and pass it in, as pipe([tool, ...], stdin = read(path))";


const MATCH: MatchOptions = MatchOptions { case_sensitive: true, require_literal_separator: true, require_literal_leading_dot: true };

struct Mapping {
    guest: String, // "/etc"
    host: PathBuf, // <root>/etc
    dir: Dir,
}

/// File metadata, whichever way it was read.
struct Meta {
    file: bool,
    dir: bool,
    link: bool,
    len: u64,
    mode: u32,
    uid: u32,
    gid: u32,
    mtime: i64,
}

impl From<cap_std::fs::Metadata> for Meta {
    fn from(m: cap_std::fs::Metadata) -> Meta {
        use cap_std::fs::MetadataExt;
        Meta { file: m.is_file(), dir: m.is_dir(), link: m.is_symlink(), len: m.len(), mode: m.mode(), uid: m.uid(),
               gid: m.gid(), mtime: m.mtime() }
    }
}

impl From<std::fs::Metadata> for Meta {
    fn from(m: std::fs::Metadata) -> Meta {
        use std::os::unix::fs::MetadataExt;
        Meta { file: m.is_file(), dir: m.is_dir(), link: m.is_symlink(), len: m.len(), mode: m.mode(), uid: m.uid(),
               gid: m.gid(), mtime: m.mtime() }
    }
}

/// File access within one mapping: cap-std, except for the host's own `/` (see the module comment).
impl Mapping {
    fn whole_host(&self) -> bool {
        self.guest == "/" && self.host == Path::new("/")
    }
    fn metadata(&self, rel: &Path) -> std::io::Result<Meta> {
        if self.whole_host() { std::fs::metadata(self.host.join(rel)).map(Meta::from) } else { self.dir.metadata(rel).map(Meta::from) }
    }
    fn symlink_metadata(&self, rel: &Path) -> std::io::Result<Meta> {
        if self.whole_host() {
            std::fs::symlink_metadata(self.host.join(rel)).map(Meta::from)
        } else {
            self.dir.symlink_metadata(rel).map(Meta::from)
        }
    }
    fn read(&self, rel: &Path) -> std::io::Result<Vec<u8>> {
        if self.whole_host() { std::fs::read(self.host.join(rel)) } else { self.dir.read(rel) }
    }
    fn names(&self, rel: &Path) -> std::io::Result<Vec<String>> {
        let mut v: Vec<String> = if self.whole_host() {
            std::fs::read_dir(self.host.join(rel))?.filter_map(|e| e.ok().map(|e| e.file_name().to_string_lossy().into_owned())).collect()
        } else {
            self.dir.read_dir(rel)?.filter_map(|e| e.ok().map(|e| e.file_name().to_string_lossy().into_owned())).collect()
        };
        v.sort();
        Ok(v)
    }
    fn read_link(&self, rel: &Path) -> std::io::Result<PathBuf> {
        if self.whole_host() { std::fs::read_link(self.host.join(rel)) } else { self.dir.read_link_contents(rel) }
    }
}

/// What a `LocalHost` reads and with what.
pub struct LocalConfig {
    /// Files are read under this directory (`/` on a real host, a fixture tree in tests).
    pub root: PathBuf,
    /// Absolute paths ("/etc", "/var/log") mapped read-only from `root`.
    pub maps: Vec<String>,
    pub tools: Option<Arc<Tools>>,
    pub limits: ToolLimits,
    /// osqueryi for `osq()`; it reads the live host, not `root`.
    pub osqueryi: Option<PathBuf>,
    /// journalctl for `journal()`; it reads the live host's journal.
    pub journalctl: Option<PathBuf>,
    /// The catalog's programs for `trace()` (libbpf-tools and `timeout`); they read the live kernel.
    pub bpf_tools: Option<PathBuf>,
}

pub struct LocalHost {
    maps: Vec<Mapping>, // longest guest path first
    tools: Option<Arc<Tools>>,
    limits: ToolLimits,
    osquery: Option<Osquery>,
    journal: Option<Journal>,
    bpf_tools: Option<PathBuf>,
    secrets: Vec<Pattern>,
    users: HashMap<u32, String>,
    groups: HashMap<u32, String>,
    notes: RefCell<Vec<String>>,
    /// Transformer answers the sensor prepared outside the sandbox (BEAT_SECRETS_FILE): path -> (kind, value).
    prepared: OnceCell<HashMap<String, (String, serde_json::Value)>>,
    /// While enumerating (`secrets_live`): mount points not to touch, so a stalled network mount cannot hold a question.
    pruned: RefCell<HashMap<String, String>>,
    /// The mount points `pruned` actually stopped at.
    pruned_hit: RefCell<Vec<(String, String)>>,
}

impl LocalHost {
    pub fn new(c: LocalConfig) -> anyhow::Result<LocalHost> {
        let LocalConfig { root, maps: guest_dirs, tools, limits, osqueryi, journalctl, bpf_tools } = c;
        let mut maps = Vec::new();
        for g in &guest_dirs {
            let guest = normalize(g).ok_or_else(|| anyhow::anyhow!("mapped directory must be absolute: {g}"))?;
            let host = root.join(guest.trim_start_matches('/'));
            let dir = Dir::open_ambient_dir(&host, ambient_authority())
                .map_err(|e| anyhow::anyhow!("cannot map {}: {e}", host.display()))?;
            maps.push(Mapping { guest, host, dir });
        }
        maps.sort_by_key(|m| std::cmp::Reverse(m.guest.len()));
        let mut secrets: Vec<Pattern> = SECRET_GLOBS.iter().map(|g| Pattern::new(g).expect("valid secret glob")).collect();
        // What else the sensor hides from questions (its key, wherever it was told it is).
        let hidden = std::env::var("BEAT_HIDDEN").unwrap_or_default();
        secrets.extend(hidden.lines().filter_map(|p| Pattern::new(&Pattern::escape(p)).ok()));
        let mut h = LocalHost {
            maps, tools, limits, secrets,
            osquery: osqueryi.map(Osquery::new),
            journal: journalctl.map(|journalctl| Journal { journalctl }),
            bpf_tools,
            users: HashMap::new(), groups: HashMap::new(), notes: RefCell::new(Vec::new()), prepared: OnceCell::new(),
            pruned: RefCell::new(HashMap::new()), pruned_hit: RefCell::new(Vec::new()),
        };
        h.users = h.id_names("/etc/passwd");
        h.groups = h.id_names("/etc/group");
        Ok(h)
    }

    /// The file's bytes for a transformer: secret files included, within the value size limit.
    fn read_bytes(&self, path: &str) -> HostResult<Vec<u8>> {
        let (m, rel) = self.resolve_noted(path).ok_or_else(|| HostError::Missing(path.to_string()))?;
        let md = m.metadata(&rel).map_err(|_| HostError::Missing(path.to_string()))?;
        if md.len as usize > self.limits.value_bytes {
            return Err(HostError::Limit(format!("{path}: {} bytes, over {}", md.len, self.limits.value_bytes)));
        }
        m.read(&rel).map_err(|e| HostError::Io(format!("{path}: {e}")))
    }

    /// What `beat-probe secrets` adds to a secret's metadata line: the transformer answer for a file of a known kind,
    /// and for a directory, those of the files under it. The sandbox covers them; probes get these instead.
    pub fn prepare(&self, s: &Secret) -> serde_json::Value {
        let one = |path: &str| -> Option<serde_json::Value> {
            let bytes = self.read_bytes(path).ok()?;
            let kind = transform::detect(&bytes)?;
            let value = transform::transform(kind, &bytes).ok()?;
            (value.to_string().len() <= PREPARE_BYTES).then(|| serde_json::json!({"kind": kind, "value": value}))
        };
        if s.kind != "dir" {
            return one(&s.path).map(|t| serde_json::json!({"transformed": t})).unwrap_or_default();
        }
        let mut files: Vec<String> = Vec::new();
        for pat in [format!("{}/**/*", s.path), format!("{}/**/.*", s.path)] {
            files.extend(self.glob(&pat).unwrap_or_default());
        }
        files.sort();
        files.dedup();
        let contents: Vec<serde_json::Value> = files
            .iter()
            .take(PREPARE_FILES)
            .filter_map(|f| one(f).map(|t| serde_json::json!({"path": f, "transformed": t})))
            .collect();
        if contents.is_empty() { serde_json::Value::Null } else { serde_json::json!({"contents": contents}) }
    }

    fn prepared(&self) -> &HashMap<String, (String, serde_json::Value)> {
        self.prepared.get_or_init(|| {
            let Some(text) = secrets_file() else { return HashMap::new() };
            prepared_from_text(&text)
        })
    }

    fn note(&self, n: String) {
        let mut notes = self.notes.borrow_mut();
        if !notes.contains(&n) {
            notes.push(n);
        }
    }

    /// The mapping a guest path falls in, and the path relative to it. `None`: not absolute, `..`, or unmapped.
    fn resolve(&self, path: &str) -> Option<(&Mapping, PathBuf)> {
        let p = normalize(path)?;
        for m in &self.maps {
            let rest = if m.guest == "/" {
                Some(p.trim_start_matches('/'))
            } else if p == m.guest {
                Some("")
            } else {
                p.strip_prefix(&m.guest).and_then(|r| r.strip_prefix('/'))
            };
            if let Some(r) = rest {
                return Some((m, PathBuf::from(if r.is_empty() { "." } else { r })));
            }
        }
        None
    }

    fn resolve_noted(&self, path: &str) -> Option<(&Mapping, PathBuf)> {
        let r = self.resolve(path);
        if r.is_none() {
            self.note(format!("{path}: outside the mapped directories, treated as missing"));
        }
        r
    }

    /// Whether the path itself is one the patterns name. See `open_as` for what it leads to.
    pub fn is_secret(&self, path: &str) -> bool {
        // As read() will resolve it: /proc/./1/root and //etc/shadow are the same files.
        let normal = normalize(path).unwrap_or_else(|| path.to_string());
        let mut p = Path::new(&normal);
        loop {
            let s = p.to_string_lossy();
            if self.secrets.iter().any(|g| g.matches_with(&s, MATCH)) {
                return true;
            }
            match p.parent() {
                Some(q) => p = q,
                None => return false,
            }
        }
    }

    /// The path to open for this one, or why not. The check is on the target, not the door: reaching a secret is what is
    /// refused, not using /proc, as reading a process's files is how a question debugs it (the operator's output in the
    /// sensor's private /tmp through /proc/1/root/tmp; a file in a container). So /proc/<pid>/root/<rest> and cwd are
    /// resolved inside that root and the patterns applied to what they name, relative to it. In a container that is
    /// right too: its /etc/shadow is refused, its other files are as readable as the host's. An fd or map_files link is
    /// judged by the file it names; a socket or a pipe names none, and a read could hang on it.
    fn open_as(&self, path: &str, doors: usize) -> Result<String, String> {
        let refused = |target: &str| format!("{path} is {target}, a secret file: metadata only (stat, secrets)");
        let Some(normal) = normalize(path) else { return Ok(path.to_string()) };
        if self.is_secret(&normal) {
            return Err(format!("{path} is a secret file: metadata only (stat, secrets)"));
        }
        if doors > DOORS_MAX {
            return Err(format!("{path}: too many /proc doors in one path"));
        }
        if !normal.starts_with("/proc/") {
            // A symlink on this host: where it leads.
            let Some((m, rel)) = self.resolve(&normal) else { return Ok(normal) };
            let Ok(real) = std::fs::canonicalize(m.host.join(rel)) else { return Ok(normal) };
            let Ok(rel) = real.strip_prefix(&m.host) else { return Ok(normal) };
            let target = format!("{}/{}", m.guest.trim_end_matches('/'), rel.display());
            return if target == normal { Ok(normal) } else { self.open_as(&target, doors + 1).map(|_| normal) };
        }
        let comps: Vec<&str> = normal.split('/').filter(|c| !c.is_empty()).collect();
        let at = if comps.get(2) == Some(&"task") { 4 } else { 2 };
        let (Some(door), Some(base)) = (comps.get(at), comps.get(..at).map(|c| format!("/{}", c.join("/")))) else { return Ok(normal) };
        let rest = &comps[at + 1..];
        match *door {
            "root" | "cwd" if !(rest.is_empty() && *door == "root") => {
                let mut start = Vec::new();
                if *door == "cwd" {
                    let link = self.link(&format!("{base}/cwd")).ok_or_else(|| format!("{path}: cannot tell where this process's cwd is"))?;
                    if !link.starts_with('/') || link.ends_with(" (deleted)") {
                        return Err(format!("{path}: this process's cwd is {link}"));
                    }
                    start = link.split('/').filter(|c| !c.is_empty()).map(String::from).collect();
                }
                let inside = self.inside_root(&base, start, rest).ok_or_else(|| format!("{path}: too many symlinks"))?;
                let target = format!("/{}", inside.join("/"));
                self.open_as(&target, doors + 1).map_err(|_| refused(&target))?;
                Ok(format!("{base}/root{}", if inside.is_empty() { String::new() } else { target }))
            }
            "fd" | "map_files" if rest.len() == 1 => {
                let Some(link) = self.link(&normal) else { return Ok(normal) };
                if !link.starts_with('/') || link.starts_with("/memfd:") {
                    return Err(format!("{path} is {link}, not a file: only its name is known (readlink, list_dir)"));
                }
                let target = link.strip_suffix(" (deleted)").unwrap_or(&link);
                self.open_as(target, doors + 1).map_err(|_| refused(target))?;
                Ok(normal)
            }
            _ => Ok(normal),
        }
    }

    fn link(&self, path: &str) -> Option<String> {
        let (m, rel) = self.resolve(path)?;
        m.read_link(&rel).ok().map(|t| t.to_string_lossy().into_owned())
    }

    /// `rest` from `start`, inside the root of the process at `base`: its symlinks followed here, as the kernel would
    /// take an absolute one from the root of whoever reads, and `..` stopping at that root. Components that do not exist
    /// are kept, for the read to find missing. None past LINKS_MAX.
    fn inside_root(&self, base: &str, start: Vec<String>, rest: &[&str]) -> Option<Vec<String>> {
        let mut at = start;
        let mut todo: Vec<String> = rest.iter().rev().map(|c| c.to_string()).collect();
        let mut links = 0;
        while let Some(c) = todo.pop() {
            match c.as_str() {
                "" | "." => continue,
                ".." => {
                    at.pop();
                    continue;
                }
                _ => {}
            }
            let here = format!("{base}/root/{}", at.iter().chain([&c]).cloned().collect::<Vec<_>>().join("/"));
            let is_link = self.resolve(&here).is_some_and(|(m, rel)| m.symlink_metadata(&rel).is_ok_and(|md| md.link));
            if !is_link {
                at.push(c);
                continue;
            }
            links += 1;
            if links > LINKS_MAX {
                return None;
            }
            let target = self.link(&here)?;
            if target.starts_with('/') {
                at.clear();
            }
            todo.extend(target.split('/').rev().map(String::from));
        }
        Some(at)
    }

    /// Whether a read of this path would be refused.
    fn denied(&self, path: &str) -> bool {
        self.open_as(path, 0).is_err()
    }

    /// What tools get mapped: the whole host is mapped entry by entry, without /proc's processes. A preopen cannot
    /// leave one file out and a tool can name any path (awk builds them), so a tool cannot reach /proc/<pid>/environ
    /// only because nothing under /proc/<pid> is mapped. /proc's own files are not directories and cannot be preopened
    /// either, so a pipe that names /proc gets a copy of them (`ProcFiles`). /proc's directories stay (sys, pressure, ...).
    fn tool_maps(&self, proc_files: Option<&ProcFiles>) -> Vec<(PathBuf, String)> {
        let mut out: Vec<(PathBuf, String)> = proc_files.map(|p| (p.0.clone(), "/proc".to_string())).into_iter().collect();
        for m in &self.maps {
            if m.guest != "/" {
                if m.guest != "/proc" && !m.guest.starts_with("/proc/") {
                    out.push((m.host.clone(), m.guest.clone()));
                }
                continue;
            }
            let dirs = |dir: &Path| -> Vec<String> {
                std::fs::read_dir(dir).map(|d| d.flatten().filter(|e| e.path().is_dir())
                    .map(|e| e.file_name().to_string_lossy().into_owned()).collect()).unwrap_or_default()
            };
            for name in dirs(&m.host).into_iter().filter(|n| n != "proc") {
                out.push((m.host.join(&name), format!("/{name}")));
            }
            for name in dirs(&m.host.join("proc")).into_iter()
                .filter(|n| !n.bytes().all(|b| b.is_ascii_digit()) && n != "self" && n != "thread-self" && n != "net") {
                out.push((m.host.join("proc").join(&name), format!("/proc/{name}")));
            }
        }
        out
    }

    /// A tool's argument, if it names a path through a symlink out of its top-level directory (/etc/os-release ->
    /// ../usr/lib/os-release, /etc/resolv.conf, /var/run): the path it leads to. The host is mapped to tools one top-level
    /// directory at a time (`tool_maps`), and a preopen refuses a link out of itself. The result is a path a tool could
    /// name anyway, so this opens nothing new; a target in /proc/<pid> stays out, as /proc/self/mounts becomes the copy
    /// of /proc's own file. Only whole arguments: a path a tool builds, or `--file=/etc/x`, still fails.
    fn tool_arg(&self, arg: &str) -> String {
        let unchanged = || arg.to_string();
        let Some(normal) = arg.starts_with('/').then(|| normalize(arg)).flatten() else { return unchanged() };
        if normal.starts_with("/proc/") {
            return unchanged(); // /proc/<pid>/root resolves to "/" in any mount namespace: the wrong file, not a path
        }
        let Some(m) = self.maps.iter().find(|m| m.guest == "/") else { return unchanged() };
        let Ok(root) = m.host.canonicalize() else { return unchanged() };
        let Ok(real) = m.host.join(normal.trim_start_matches('/')).canonicalize() else { return unchanged() };
        let Ok(rel) = real.strip_prefix(&root) else { return unchanged() };
        let target = format!("/{}", rel.display());
        let top = |p: &str| p.split('/').nth(1).unwrap_or("").to_string();
        if top(&target) == top(&normal) {
            return unchanged();
        }
        if top(&target) == "proc" {
            let file = target.rsplit('/').next().unwrap_or("");
            return if PROC_FILES.contains(&file) { format!("/proc/{file}") } else { unchanged() };
        }
        target
    }

    fn id_names(&self, path: &str) -> HashMap<u32, String> {
        let Some((m, rel)) = self.resolve(path) else { return HashMap::new() };
        let Ok(bytes) = m.read(&rel) else { return HashMap::new() };
        let text = String::from_utf8_lossy(&bytes);
        text.lines()
            .filter_map(|l| {
                let f: Vec<&str> = l.split(':').collect();
                Some((f.get(2)?.parse().ok()?, f[0].to_string()))
            })
            .collect()
    }

    fn stat_from(&self, path: &str, md: &Meta, kind: &'static str) -> Stat {
        let secret = self.denied(path);
        Stat {
            kind,
            size: md.len,
            mode: format!("{:o}", md.mode & 0o7777),
            uid: md.uid,
            gid: md.gid,
            user: self.users.get(&md.uid).cloned().unwrap_or_else(|| md.uid.to_string()),
            group: self.groups.get(&md.gid).cloned().unwrap_or_else(|| md.gid.to_string()),
            mtime: md.mtime,
            readable: !secret && (kind == "file" || kind == "dir"),
            secret,
        }
    }

    /// Pathname expansion over the mapping, without notes for the directories it passes through.
    fn expand(&self, prefix: &str, comps: &[&str], out: &mut Vec<String>) {
        if let Some(why) = self.pruned.borrow().get(prefix) {
            self.pruned_hit.borrow_mut().push((prefix.to_string(), why.clone()));
            return;
        }
        let Some((first, rest)) = comps.split_first() else {
            if self.resolve(prefix).is_some_and(|(m, rel)| m.symlink_metadata(&rel).is_ok()) {
                out.push(prefix.to_string());
            }
            return;
        };
        let join = |name: &str| if prefix == "/" { format!("/{name}") } else { format!("{prefix}/{name}") };
        if *first == "**" {
            self.expand(prefix, rest, out);
            for name in self.names(prefix) {
                let p = join(&name);
                if self.resolve(&p).is_some_and(|(m, rel)| m.symlink_metadata(&rel).is_ok_and(|md| md.dir)) {
                    self.expand(&p, comps, out);
                }
            }
        } else if first.contains(['*', '?', '[']) {
            let Ok(pat) = Pattern::new(first) else { return };
            for name in self.names(prefix) {
                if pat.matches_with(&name, MATCH) {
                    self.expand(&join(&name), rest, out);
                }
            }
        } else {
            self.expand(&join(first), rest, out);
        }
    }

    fn names(&self, path: &str) -> Vec<String> {
        let Some((m, rel)) = self.resolve(path) else { return Vec::new() };
        m.names(&rel).unwrap_or_default()
    }

    /// A small file's text, for the scan's configuration lookups (the mount table, the container runtimes' settings).
    fn text(&self, path: &str) -> Option<String> {
        let (m, rel) = self.resolve(path)?;
        m.read(&rel).ok().map(|b| String::from_utf8_lossy(&b).into_owned())
    }

    /// A copy of /proc's own files for this pipe, when the whole host is mapped.
    fn proc_files(&self) -> Option<ProcFiles> {
        let (m, rel) = self.resolve("/proc").filter(|(m, _)| m.guest == "/")?;
        use std::sync::atomic::{AtomicU32, Ordering};
        static N: AtomicU32 = AtomicU32::new(0);
        let dir = std::env::temp_dir().join(format!("beat-proc-{}-{}", std::process::id(), N.fetch_add(1, Ordering::Relaxed)));
        std::fs::create_dir(&dir).ok()?;
        let copies = ProcFiles(dir);
        for f in PROC_FILES {
            if let Ok(bytes) = m.read(&rel.join(f)) {
                std::fs::write(copies.0.join(f), bytes).ok()?;
            }
        }
        Some(copies)
    }

    fn mount_table(&self) -> Vec<(String, String)> {
        self.text("/proc/self/mountinfo").map(|t| scan::parse_mountinfo(&t)).unwrap_or_default()
    }

    fn secret_of(&self, p: String) -> Option<Secret> {
        let (m, rel) = self.resolve(&p)?;
        let md = m.symlink_metadata(&rel).ok()?;
        Some(Secret {
            kind: if md.dir { "dir" } else { "file" }.into(),
            mode: format!("{:04o}", md.mode & 0o7777),
            uid: md.uid,
            gid: md.gid,
            size: md.len,
            mtime: md.mtime,
            path: p,
        })
    }

    /// The fixed secret paths and single-level globs, now: no recursion, and nothing under a network or similar mount,
    /// so this stays cheap and a stalled mount cannot hold a question. What it would not touch is returned.
    pub fn secrets_live(&self) -> HostResult<(Vec<Secret>, Vec<(String, String)>)> {
        *self.pruned.borrow_mut() = self.mount_table().iter()
            .filter_map(|(mount, fs)| Some((mount.clone(), scan::skipped_fstype(fs)?)))
            .collect();
        let mut paths = Vec::new();
        for g in SECRET_GLOBS.iter().filter(|g| !g.contains("**") && !g.starts_with("/proc/") && **g != SENSOR_KEYS) {
            paths.extend(self.glob(g)?);
        }
        self.pruned.borrow_mut().clear();
        paths.sort();
        paths.dedup();
        let mut hit = std::mem::take(&mut *self.pruned_hit.borrow_mut());
        hit.sort();
        hit.dedup();
        Ok((paths.into_iter().filter_map(|p| self.secret_of(p)).collect(), hit))
    }

    /// The recursive secret patterns, one pass over their trees within the budget (scan.rs): container storage and
    /// network mounts are not entered, and the report says what was left out.
    pub fn secrets_walk(&self, budget: &Budget) -> HostResult<(Vec<Secret>, WalkReport)> {
        let mut roots: Vec<(String, Vec<Pattern>)> = Vec::new();
        for g in SECRET_GLOBS.iter().filter(|g| g.contains("**")) {
            let (root, name) = g.split_once("/**/").expect("a recursive secret glob is ROOT/**/NAME");
            let pat = Pattern::new(name).expect("valid secret glob");
            match roots.iter_mut().find(|(r, _)| r == root) {
                Some((_, pats)) => pats.push(pat),
                None => roots.push((root.to_string(), vec![pat])),
            }
        }
        let mut skip = scan::container_roots(&|p| self.text(p), &self.command_lines());
        for (mount, fs) in self.mount_table() {
            if let Some(why) = scan::skipped_fstype(&fs) {
                skip.entry(mount).or_insert(why);
            }
        }
        let host_of = |guest: &str| self.resolve(guest).map(|(m, rel)| m.host.join(rel));
        let (mut paths, report) = scan::walk(&roots, &skip, budget, &host_of, MATCH);
        paths.sort();
        paths.dedup();
        Ok((paths.into_iter().filter_map(|p| self.secret_of(p)).collect(), report))
    }

    /// The running processes' command lines, for a data root given only as a flag (dockerd --data-root).
    fn command_lines(&self) -> Vec<Vec<String>> {
        self.names("/proc").iter().filter(|n| n.bytes().all(|b| b.is_ascii_digit()))
            .filter_map(|pid| self.text(&format!("/proc/{pid}/cmdline")))
            .map(|c| c.split('\0').filter(|a| !a.is_empty()).map(String::from).collect())
            .collect()
    }
}

impl Host for LocalHost {
    fn pipe(&self, stages: &[Vec<String>], stdin: &[u8]) -> HostResult<ToolResult> {
        let tools = self.tools.as_ref().ok_or_else(|| HostError::Tool("this host has no WASM tools".into()))?;
        let stages: Vec<Vec<String>> = stages.iter()
            .map(|st| st.iter().enumerate().map(|(i, a)| if i == 0 { a.clone() } else { self.tool_arg(a) }).collect())
            .collect();
        let names_proc = stages.iter().flatten().any(|a| a.contains("/proc"));
        let names_root = stages.iter().flatten().any(|a| a == "/");
        let copies = if names_proc { self.proc_files() } else { None };
        let maps = self.tool_maps(copies.as_ref());
        let mut r = tools.pipe(&stages, stdin, &maps, &self.limits)?;
        if r.status.iter().any(|s| *s != 0) {
            for hint in [(names_proc, PROC_HINT), (names_root, ROOT_HINT)].iter().filter(|h| h.0).map(|h| h.1) {
                r.stderr.push_str(hint);
                r.stderr.push('\n');
            }
        }
        Ok(r)
    }

    fn stat(&self, path: &str) -> HostResult<Option<Stat>> {
        let Some((m, rel)) = self.resolve_noted(path) else { return Ok(None) };
        match m.metadata(&rel) {
            Ok(md) => {
                let kind = if md.file { "file" } else if md.dir { "dir" } else { "other" };
                Ok(Some(self.stat_from(path, &md, kind)))
            }
            Err(e) if e.kind() == ErrorKind::NotFound => {
                // A dangling symlink is still something: report the link itself.
                Ok(m.symlink_metadata(&rel).ok().map(|md| self.stat_from(path, &md, "link")))
            }
            Err(_) => match m.symlink_metadata(&rel) {
                Ok(md) if md.link => {
                    self.note(format!("{path}: symlink leads outside the mapped directories"));
                    Ok(Some(self.stat_from(path, &md, "link")))
                }
                Ok(_) | Err(_) => Ok(None),
            },
        }
    }

    fn read(&self, path: &str) -> HostResult<String> {
        let real = self.open_as(path, 0).map_err(HostError::Denied)?;
        let (m, rel) = self.resolve_noted(&real).ok_or_else(|| HostError::Missing(path.to_string()))?;
        let md = m.metadata(&rel).map_err(|_| HostError::Missing(path.to_string()))?;
        if md.len as usize > self.limits.value_bytes {
            return Err(HostError::Limit(format!("read({path}): {} bytes, over {}", md.len, self.limits.value_bytes)));
        }
        let bytes = m.read(&rel).map_err(|e| HostError::Io(format!("{path}: {e}")))?;
        Ok(String::from_utf8_lossy(&bytes).into_owned())
    }

    fn glob(&self, pattern: &str) -> HostResult<Vec<String>> {
        let p = normalize(pattern).ok_or_else(|| HostError::Io(format!("glob({pattern}): pattern must be absolute")))?;
        let comps: Vec<&str> = p.split('/').filter(|c| !c.is_empty()).collect();
        let mut out = Vec::new();
        self.expand("/", &comps, &mut out);
        out.sort();
        out.dedup();
        Ok(out)
    }

    fn list_dir(&self, path: &str) -> HostResult<Vec<String>> {
        let (m, rel) = self.resolve_noted(path).ok_or_else(|| HostError::Missing(path.to_string()))?;
        m.names(&rel).map_err(|_| HostError::Missing(path.to_string()))
    }

    fn readlink(&self, path: &str) -> HostResult<Option<String>> {
        let Some((m, rel)) = self.resolve_noted(path) else { return Ok(None) };
        Ok(m.read_link(&rel).ok().map(|t| t.to_string_lossy().into_owned()))
    }

    fn osq(&self, query: &str, params: &[serde_json::Value]) -> HostResult<Vec<serde_json::Value>> {
        let o = self.osquery.as_ref().ok_or_else(|| HostError::Source("osq(): no osquery on this host".into()))?;
        o.osq(query, params)
    }

    fn journal(&self, opts: &JournalOptions) -> HostResult<Vec<serde_json::Value>> {
        let j = self.journal.as_ref().ok_or_else(|| HostError::Source("journal(): no journal on this host".into()))?;
        j.entries(opts)
    }

    fn sample(&self, patterns: &[String], seconds: f64) -> HostResult<Sample> {
        if !(0.0..=SAMPLE_MAX_S).contains(&seconds) {
            return Err(HostError::Limit(format!("sample(): seconds must be 0 to {SAMPLE_MAX_S}, got {seconds}")));
        }
        let mut paths = Vec::new();
        for p in patterns {
            paths.extend(self.glob(p)?);
        }
        paths.sort();
        paths.dedup();
        let mut opened = Vec::with_capacity(paths.len());
        for p in &paths {
            opened.push((p.clone(), self.open_as(p, 0).map_err(HostError::Denied)?));
        }
        // Read as close together as possible: no metadata calls between the files, errors (a process gone) skipped.
        let read_all = |budget: &mut usize| -> HostResult<std::collections::BTreeMap<String, String>> {
            let mut out = std::collections::BTreeMap::new();
            for (p, real) in &opened {
                let Some((m, rel)) = self.resolve(real) else { continue };
                let Ok(bytes) = m.read(&rel) else { continue };
                *budget = budget.checked_sub(bytes.len()).ok_or_else(|| {
                    HostError::Limit(format!("sample(): {} files, over {} bytes in all", paths.len(), self.limits.value_bytes))
                })?;
                out.insert(p.clone(), String::from_utf8_lossy(&bytes).into_owned());
            }
            Ok(out)
        };
        let mut budget = self.limits.value_bytes;
        let t0 = std::time::Instant::now();
        let before = read_all(&mut budget)?;
        std::thread::sleep(std::time::Duration::from_secs_f64(seconds));
        let t1 = std::time::Instant::now();
        let after = read_all(&mut budget)?;
        Ok(Sample { seconds: (t1 - t0).as_secs_f64(), before, after })
    }

    fn trace(&self, entry: &str, o: &crate::catalog::TraceOptions) -> HostResult<serde_json::Value> {
        let e = crate::catalog::entry(entry).ok_or_else(|| HostError::Source(format!("trace(): no catalog entry {entry:?}")))?;
        let dir = self.bpf_tools.as_ref().ok_or_else(|| HostError::Source("trace(): this host has no catalog (eBPF tools)".into()))?;
        let own = [u64::from(std::process::id())].into_iter().collect();
        crate::catalog::run(dir, e, o, &own)
    }

    fn capture(&self, request: &serde_json::Value, o: &crate::catalog::TraceOptions) -> HostResult<serde_json::Value> {
        let view = crate::capture::View::parse(request["view"].as_str().unwrap_or_default())?;
        // The question's unit has a network namespace of its own: the sensor captures for it (BEAT_CAPTURE: the
        // socket of its broker, given to questions that call capture()).
        let socket = std::env::var_os("BEAT_CAPTURE").ok_or_else(|| HostError::Source(
            "capture(): this host's sensor does not capture (no tcpdump, or not sandboxed)".into()))?;
        crate::capture::remote(std::path::Path::new(&socket), request, view, o)
    }

    fn tools(&self) -> Vec<String> {
        self.tools.as_ref().map(|t| t.manifest().into_keys().collect()).unwrap_or_default()
    }

    fn environ(&self, pid: u32) -> HostResult<Vec<(String, String)>> {
        let path = format!("/proc/{pid}/environ");
        let (m, rel) = self.resolve_noted(&path).ok_or_else(|| HostError::Missing(path.clone()))?;
        let bytes = m.read(&rel).map_err(|e| match e.kind() {
            ErrorKind::NotFound => HostError::Missing(path.clone()),
            _ => HostError::Io(format!("{path}: {e}")),
        })?;
        Ok(crate::environ::parse(&bytes))
    }

    fn secrets(&self) -> HostResult<Vec<Secret>> {
        // Under the sensor's sandbox, secret files are covered by placeholders; their real metadata is read outside
        // it and passed in a file (BEAT_SECRETS_FILE: JSON lines), with what could not be checked or covered.
        if let Some(text) = secrets_file() {
            let (list, report) = secrets_from_text(&text);
            if let Some(n) = report {
                self.note(n);
            }
            return Ok(list);
        }
        let (mut list, _) = self.secrets_live()?;
        let (walked, report) = self.secrets_walk(&Budget::default())?;
        list.extend(walked);
        list.sort_by(|a, b| a.path.cmp(&b.path));
        list.dedup_by(|a, b| a.path == b.path);
        if let Some(n) = scan::report_note(&report.skipped, report.cut.as_ref().map(|c| c.root.as_str()), &[]) {
            self.note(n);
        }
        Ok(list)
    }

    fn transformed(&self, kind: &str, path: &str) -> HostResult<serde_json::Value> {
        if let Some((k, v)) = self.prepared().get(path) {
            return if k == kind { Ok(v.clone()) } else { Err(HostError::Format(format!("{path} is a {k}, not a {kind}"))) };
        }
        if std::env::var_os(SECRETS_FILE).is_some() && self.is_secret(path) {
            return Err(HostError::Format(format!(
                "{path}: covered by the sandbox, and the sensor did not recognize it as a {kind}")));
        }
        let bytes = self.read_bytes(path)?;
        transform::transform(kind, &bytes).map_err(|e| HostError::Format(format!("{path}: {e}")))
    }

    fn notes(&self) -> Vec<String> {
        self.notes.borrow().clone()
    }
}

/// A temporary directory with copies of /proc's own files, removed with this.
struct ProcFiles(PathBuf);

impl Drop for ProcFiles {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Names the file with the secret files' metadata under the sensor's sandbox (the sensor writes it, runner.rs). A file,
/// since a list in an environment variable fails the whole question past the kernel's 128 KiB per argument.
pub const SECRETS_FILE: &str = "BEAT_SECRETS_FILE";

fn secrets_file() -> Option<String> {
    std::fs::read_to_string(std::env::var_os(SECRETS_FILE)?).ok()
}

/// The transformer answers in the file (`LocalHost::prepare`), by path.
fn prepared_from_text(text: &str) -> HashMap<String, (String, serde_json::Value)> {
    let mut out = HashMap::new();
    for l in text.lines() {
        let Ok(v) = serde_json::from_str::<serde_json::Value>(l) else { continue };
        let mut add = |path: &serde_json::Value, t: &serde_json::Value| {
            if let (Some(p), Some(k)) = (path.as_str(), t["kind"].as_str()) {
                out.insert(p.to_string(), (k.to_string(), t["value"].clone()));
            }
        };
        if v["transformed"].is_object() {
            add(&v["path"], &v["transformed"]);
        }
        for c in v["contents"].as_array().into_iter().flatten() {
            add(&c["path"], &c["transformed"]);
        }
    }
    out
}

/// The secret files in the file, and the note on what was not checked or covered, from its `report` line.
fn secrets_from_text(text: &str) -> (Vec<Secret>, Option<String>) {
    let mut list = Vec::new();
    let mut note = None;
    for l in text.lines() {
        let Ok(v) = serde_json::from_str::<serde_json::Value>(l) else { continue };
        if v["report"].is_object() {
            let r = &v["report"];
            let skipped: Vec<(String, String)> = r["skipped"].as_array().into_iter().flatten()
                .filter_map(|p| Some((p[0].as_str()?.to_string(), p[1].as_str()?.to_string()))).collect();
            let uncovered: Vec<String> = r["uncovered"].as_array().into_iter().flatten()
                .filter_map(|p| p.as_str().map(String::from)).collect();
            note = scan::report_note(&skipped, r["cut_root"].as_str(), &uncovered);
        }
        let Some(path) = v["path"].as_str() else { continue };
        list.push(Secret {
            path: path.into(),
            kind: v["kind"].as_str().unwrap_or("file").into(),
            mode: v["mode"].as_str().unwrap_or("").into(),
            uid: v["uid"].as_u64().unwrap_or(0) as u32,
            gid: v["gid"].as_u64().unwrap_or(0) as u32,
            size: v["size"].as_u64().unwrap_or(0),
            mtime: v["mtime"].as_i64().unwrap_or(0),
        });
    }
    (list, note)
}

/// An absolute path without `.`, `..` or repeated slashes; `None` if it is relative or uses `..`.
fn normalize(path: &str) -> Option<String> {
    let p = Path::new(path);
    if !p.is_absolute() {
        return None;
    }
    let mut parts = Vec::new();
    for c in p.components() {
        match c {
            Component::RootDir | Component::CurDir => {}
            Component::Normal(s) => parts.push(s.to_string_lossy().into_owned()),
            Component::ParentDir | Component::Prefix(_) => return None,
        }
    }
    Some(format!("/{}", parts.join("/")))
}

#[cfg(test)]
mod scan_tests {
    use super::*;

    fn host(files: &[&str]) -> (PathBuf, LocalHost) {
        use std::sync::atomic::{AtomicU32, Ordering};
        static N: AtomicU32 = AtomicU32::new(0);
        let root = std::env::temp_dir().join(format!("beat-local-{}-{}", std::process::id(), N.fetch_add(1, Ordering::Relaxed)));
        for f in files {
            let (rel, text) = f.split_once('=').unwrap_or((f, "x"));
            let p = root.join(rel);
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(p, text).unwrap();
        }
        std::fs::create_dir_all(&root).unwrap();
        let h = LocalHost::new(LocalConfig { root: root.clone(), maps: vec!["/".into()], tools: None, limits: ToolLimits::default(),
                                             osqueryi: None, journalctl: None, bpf_tools: None }).unwrap();
        (root, h)
    }

    #[test]
    fn the_live_check_takes_fixed_paths_only_and_keeps_off_network_mounts() {
        let (root, h) = host(&["etc/shadow", "etc/deep/a.key", "root/.ssh/id", "home/a/.ssh/id",
                               "proc/self/mountinfo=1 2 0:1 / /home rw - nfs4 s:/h rw\n"]);
        let (list, skipped) = h.secrets_live().unwrap();
        let paths: Vec<&str> = list.iter().map(|s| s.path.as_str()).collect();
        assert_eq!(paths, ["/etc/shadow", "/root/.ssh"]);
        assert_eq!(skipped, [("/home".to_string(), "network or shared filesystem (nfs4)".to_string())]);
        // The pruning is for the enumeration: what the patterns name is still denied.
        assert!(h.is_secret("/home/a/.ssh/id"));
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn the_walk_takes_recursive_patterns_and_leaves_out_a_configured_data_root() {
        let (root, h) = host(&["etc/deep/a.key", "etc/shadow", "opt/app/b.key", "opt/dock/layer/c.key", "var/lib/x.keytab",
                               "var/lib/docker/overlay2/d.keytab", "var/lib/y.key",
                               r#"etc/docker/daemon.json={"data-root": "/opt/dock"}"#]);
        let (list, r) = h.secrets_walk(&Budget::default()).unwrap();
        let paths: Vec<&str> = list.iter().map(|s| s.path.as_str()).collect();
        assert_eq!(paths, ["/etc/deep/a.key", "/opt/app/b.key", "/var/lib/x.keytab"]);
        assert_eq!(r.skipped, [("/opt/dock".to_string(), "Docker data root".to_string()),
                               ("/var/lib/docker".to_string(), "Docker data root".to_string())]);
        assert!(h.is_secret("/opt/dock/layer/c.key"), "not walked, but read() still refuses it");
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn process_environments_are_denied_and_not_enumerated() {
        let (root, h) = host(&["proc/1/environ"]);
        let (live, _) = h.secrets_live().unwrap();
        let (walked, _) = h.secrets_walk(&Budget::default()).unwrap();
        assert!(live.iter().chain(&walked).all(|s| !s.path.starts_with("/proc/")));
        assert!(h.is_secret("/proc/1/environ"));
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn the_file_gives_the_list_the_answers_and_the_note() {
        let text = r#"{"path":"/etc/a.key","kind":"file","mode":"0600","uid":0,"gid":0,"size":3,"mtime":9,"transformed":{"kind":"key","value":{"t":1}}}
{"report":{"skipped":[["/var/lib/docker","Docker data root"]],"cut_root":null,"uncovered":[]}}
"#;
        let (list, note) = secrets_from_text(text);
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].mode, "0600");
        assert!(note.unwrap().contains("/var/lib/docker (Docker data root)"));
        assert_eq!(prepared_from_text(text)["/etc/a.key"].0, "key");
        let (_, none) = secrets_from_text("{\"report\":{\"skipped\":[],\"cut_root\":null,\"uncovered\":[]}}\n");
        assert_eq!(none, None, "nothing left out: no note");
    }
}

#[cfg(test)]
mod tool_arg_tests {
    use super::*;

    #[test]
    fn a_link_out_of_its_top_level_directory_is_followed_for_the_tool() {
        use std::os::unix::fs::symlink;
        let root = std::env::temp_dir().join(format!("beat-toolarg-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        for d in ["etc", "usr/lib", "run/x", "var", "proc/self", "proc/7/root/etc"] {
            std::fs::create_dir_all(root.join(d)).unwrap();
        }
        std::fs::write(root.join("usr/lib/os-release"), "NAME=x\n").unwrap();
        std::fs::write(root.join("run/x/f"), "f").unwrap();
        std::fs::write(root.join("etc/plain"), "p").unwrap();
        std::fs::write(root.join("proc/self/mounts"), "m").unwrap();
        std::fs::write(root.join("proc/self/environ"), "e").unwrap();
        symlink("../usr/lib/os-release", root.join("etc/os-release")).unwrap();
        symlink("plain", root.join("etc/inside")).unwrap();
        symlink("../run", root.join("var/run")).unwrap();
        symlink("../proc/self/mounts", root.join("etc/mtab")).unwrap();
        symlink("../proc/self/environ", root.join("etc/env")).unwrap();
        let h = LocalHost::new(LocalConfig { root: root.clone(), maps: vec!["/".into()], tools: None,
                                             limits: ToolLimits::default(), osqueryi: None, journalctl: None,
                                             bpf_tools: None }).unwrap();
        assert_eq!(h.tool_arg("/etc/os-release"), "/usr/lib/os-release");
        assert_eq!(h.tool_arg("/var/run/x/f"), "/run/x/f");
        assert_eq!(h.tool_arg("/etc/mtab"), "/proc/mounts");
        // Not a way into /proc/<pid>, not rewritten when a tool can follow it itself, not for what is no path.
        assert_eq!(h.tool_arg("/etc/env"), "/etc/env");
        assert_eq!(h.tool_arg("/etc/inside"), "/etc/inside");
        assert_eq!(h.tool_arg("/proc/7/root/etc"), "/proc/7/root/etc");
        assert_eq!(h.tool_arg("-n"), "-n");
        assert_eq!(h.tool_arg("/nope"), "/nope");
        std::fs::remove_dir_all(&root).unwrap();
    }
}

#[cfg(test)]
mod door_tests {
    use super::*;

    /// A fixture host with /proc/7 as a container: root/etc/shadow, a link out, a link up, its cwd, its fds.
    fn host() -> (PathBuf, LocalHost) {
        use std::os::unix::fs::symlink;
        use std::sync::atomic::{AtomicU32, Ordering};
        static N: AtomicU32 = AtomicU32::new(0);
        let root = std::env::temp_dir().join(format!("beat-door-{}-{}", std::process::id(), N.fetch_add(1, Ordering::Relaxed)));
        let w = |rel: &str| {
            let p = root.join(rel);
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(p, "content").unwrap();
        };
        for f in ["etc/hostname", "tmp/op.out", "proc/7/root/etc/shadow", "proc/7/root/etc/hostname", "proc/7/root/app/log", "proc/7/root/etc/ssh/ssh_host_rsa_key"] {
            w(f);
        }
        std::fs::create_dir_all(root.join("proc/7/fd")).unwrap();
        std::fs::create_dir_all(root.join("proc/7/task/7")).unwrap();
        let c = root.join("proc/7/root");
        symlink("/etc/shadow", c.join("app/abs")).unwrap();
        symlink("../../../../../../etc/shadow", c.join("app/up")).unwrap();
        symlink("/app/log", c.join("app/fine")).unwrap();
        symlink("loop", c.join("app/loop")).unwrap();
        symlink("/app", root.join("proc/7/cwd")).unwrap();
        symlink("/var/log/app.log (deleted)", root.join("proc/7/fd/1")).unwrap();
        symlink("/etc/secret.key (deleted)", root.join("proc/7/fd/2")).unwrap();
        symlink("socket:[123]", root.join("proc/7/fd/3")).unwrap();
        symlink("/etc/shadow", root.join("proc/7/fd/4")).unwrap();
        let h = LocalHost::new(LocalConfig { root: root.clone(), maps: vec!["/".into()], tools: None, limits: ToolLimits::default(),
                                             osqueryi: None, journalctl: None, bpf_tools: None }).unwrap();
        (root, h)
    }

    #[test]
    fn the_target_is_checked_not_the_door() {
        let (root, h) = host();
        for ok in ["/proc/7/root/app/log", "/proc/7/root/etc/hostname", "/proc/7/root/app/fine", "/proc/7/cwd/log", "/proc/7/stat", "/proc/7/fd/1"] {
            assert!(h.open_as(ok, 0).is_ok(), "{ok}: {:?}", h.open_as(ok, 0));
        }
        assert_eq!(h.open_as("/proc/7/root/app/fine", 0).unwrap(), "/proc/7/root/app/log", "a link is followed inside the root");
        for no in ["/proc/7/root/etc/shadow", "/proc/./7/root/etc/shadow", "/proc/7/root/app/abs", "/proc/7/root/app/up", "/proc/7/cwd/abs",
                   "/proc/7/root/etc/ssh/ssh_host_rsa_key", "/proc/7/task/7/root/etc/shadow", "/proc/7/root/proc/7/root/etc/shadow",
                   "/proc/7/fd/2", "/proc/7/fd/3", "/proc/7/fd/4", "/proc/7/environ", "/proc/7/task/7/environ", "/proc/7/mem", "/etc/shadow",
                   "/proc/7/root/app/loop", "/var/lib/beat-sensor/keys/sensor.key", "/proc/7/root/var/lib/beat-sensor/keys/sensor.key"] {
            assert!(h.open_as(no, 0).is_err(), "{no}: {:?}", h.open_as(no, 0));
        }
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn a_links_listing_and_target_stay_available() {
        let (root, h) = host();
        assert_eq!(h.list_dir("/proc/7/fd").unwrap().len(), 4);
        assert_eq!(h.readlink("/proc/7/fd/3").unwrap().as_deref(), Some("socket:[123]"));
        std::fs::remove_dir_all(root).unwrap();
    }
}
