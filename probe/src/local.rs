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

use crate::host::{Host, HostError, HostResult, JournalOptions, Sample, Secret, Stat, ToolResult};
use crate::sources::{Journal, Osquery};
use crate::tools::{ToolLimits, Tools};
use crate::transform;

/// Bounds on what `beat-probe secrets` prepares for the sandbox (BEAT_SECRETS is one environment variable, and Linux
/// caps one at 128 KiB): files looked at under one secret directory, and the size of one prepared answer.
const PREPARE_FILES: usize = 50;
/// The longest interval `sample()` waits: a question's whole run is limited (120 s by default).
const SAMPLE_MAX_S: f64 = 60.0;
const PREPARE_BYTES: usize = 8 << 10;

/// Secret paths: metadata only, never content ([B9]). Shadow files, SSH and TLS keys, keytabs, plus process
/// environments. A directory in this list makes everything under it secret.
pub const SECRET_GLOBS: &[&str] = &[
    "/etc/shadow", "/etc/shadow-", "/etc/gshadow", "/etc/gshadow-", "/etc/ssh/ssh_host_*_key", "/etc/ssl/private",
    "/root/.ssh", "/home/*/.ssh", "/etc/**/*.key", "/etc/**/*.keytab", "/opt/**/*.key", "/opt/**/*.keytab",
    "/srv/**/*.key", "/var/lib/**/*.keytab", "/proc/*/environ",
];

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
    /// Transformer answers the sensor prepared outside the sandbox (BEAT_SECRETS): path -> (kind, value).
    prepared: OnceCell<HashMap<String, (String, serde_json::Value)>>,
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
        let secrets = SECRET_GLOBS.iter().map(|g| Pattern::new(g).expect("valid secret glob")).collect();
        let mut h = LocalHost {
            maps, tools, limits, secrets,
            osquery: osqueryi.map(|osqueryi| Osquery { osqueryi }),
            journal: journalctl.map(|journalctl| Journal { journalctl }),
            bpf_tools,
            users: HashMap::new(), groups: HashMap::new(), notes: RefCell::new(Vec::new()), prepared: OnceCell::new(),
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
            let Ok(b64) = std::env::var("BEAT_SECRETS") else { return HashMap::new() };
            prepared_from_env(&b64)
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

    pub fn is_secret(&self, path: &str) -> bool {
        let mut p = Path::new(path);
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
        let secret = self.is_secret(path);
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
}

impl Host for LocalHost {
    fn pipe(&self, stages: &[Vec<String>], stdin: &[u8]) -> HostResult<ToolResult> {
        let tools = self.tools.as_ref().ok_or_else(|| HostError::Tool("this host has no WASM tools".into()))?;
        let maps: Vec<(PathBuf, String)> = self.maps.iter().map(|m| (m.host.clone(), m.guest.clone())).collect();
        tools.pipe(stages, stdin, &maps, &self.limits)
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
        if self.is_secret(path) {
            return Err(HostError::Denied(format!("{path} is a secret file: metadata only (stat, secrets)")));
        }
        let (m, rel) = self.resolve_noted(path).ok_or_else(|| HostError::Missing(path.to_string()))?;
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
        if let Some(p) = paths.iter().find(|p| self.is_secret(p)) {
            return Err(HostError::Denied(format!("{p} is a secret file: metadata only (stat, secrets)")));
        }
        // Read as close together as possible: no metadata calls between the files, errors (a process gone) skipped.
        let read_all = |budget: &mut usize| -> HostResult<std::collections::BTreeMap<String, String>> {
            let mut out = std::collections::BTreeMap::new();
            for p in &paths {
                let Some((m, rel)) = self.resolve(p) else { continue };
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

    fn tools(&self) -> Vec<String> {
        self.tools.as_ref().map(|t| t.manifest().into_keys().collect()).unwrap_or_default()
    }

    fn secrets(&self) -> HostResult<Vec<Secret>> {
        // Under the sensor's sandbox, secret files are covered by placeholders; their real metadata is read outside
        // it and passed in BEAT_SECRETS (base64 JSON lines: path kind mode uid gid size mtime).
        if let Ok(b64) = std::env::var("BEAT_SECRETS") {
            return Ok(secrets_from_env(&b64));
        }
        let mut paths = Vec::new();
        for g in SECRET_GLOBS {
            paths.extend(self.glob(g)?);
        }
        paths.sort();
        paths.dedup();
        Ok(paths
            .into_iter()
            .filter_map(|p| {
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
            })
            .collect())
    }

    fn transformed(&self, kind: &str, path: &str) -> HostResult<serde_json::Value> {
        if let Some((k, v)) = self.prepared().get(path) {
            return if k == kind { Ok(v.clone()) } else { Err(HostError::Format(format!("{path} is a {k}, not a {kind}"))) };
        }
        if std::env::var_os("BEAT_SECRETS").is_some() && self.is_secret(path) {
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

/// The transformer answers in BEAT_SECRETS (`LocalHost::prepare`), by path.
fn prepared_from_env(b64: &str) -> HashMap<String, (String, serde_json::Value)> {
    use base64::Engine;
    let mut out = HashMap::new();
    let Ok(bytes) = base64::engine::general_purpose::STANDARD.decode(b64.trim()) else { return out };
    for l in String::from_utf8_lossy(&bytes).lines() {
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

fn secrets_from_env(b64: &str) -> Vec<Secret> {
    use base64::Engine;
    let Ok(bytes) = base64::engine::general_purpose::STANDARD.decode(b64.trim()) else { return Vec::new() };
    String::from_utf8_lossy(&bytes)
        .lines()
        .filter_map(|l| {
            let v: serde_json::Value = serde_json::from_str(l).ok()?;
            Some(Secret {
                path: v["path"].as_str()?.into(),
                kind: v["kind"].as_str().unwrap_or("file").into(),
                mode: v["mode"].as_str().unwrap_or("").into(),
                uid: v["uid"].as_u64().unwrap_or(0) as u32,
                gid: v["gid"].as_u64().unwrap_or(0) as u32,
                size: v["size"].as_u64().unwrap_or(0),
                mtime: v["mtime"].as_i64().unwrap_or(0),
            })
        })
        .collect()
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
