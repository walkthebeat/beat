//! The host-side builtins (docs/probes.md §12): everything a probe can do that touches the host.
//!
//! Arguments and results are plain data, never Starlark values, so the same interface can later be offered to an
//! evaluator running as WASM (as imports). The native sensor implements it directly (`local::LocalHost`); some
//! builtins reach a separate native program (osquery, journalctl), which is an implementation detail behind this trait.

use std::fmt;

/// Result of `pipe()` ([B1]-[B6]).
#[derive(Debug, Clone, Default)]
pub struct ToolResult {
    pub stdout: String,
    pub stderr: String,
    /// One exit status per stage, like bash's PIPESTATUS. Non-zero is a value, not a failure ([B3]).
    pub status: Vec<i32>,
}

/// Result of `stat()` ([B7], [B8]).
#[derive(Debug, Clone)]
pub struct Stat {
    pub kind: &'static str, // "file", "dir", "link", "other"
    pub size: u64,
    pub mode: String, // octal permission bits, "644"
    pub uid: u32,
    pub gid: u32,
    pub user: String, // name from the host's /etc/passwd, or the number
    pub group: String,
    pub mtime: i64, // epoch seconds
    pub readable: bool,
    pub secret: bool,
}

/// Metadata of one secret file ([B9]): never its content.
#[derive(Debug, Clone)]
pub struct Secret {
    pub path: String,
    pub kind: String,
    pub mode: String,
    pub uid: u32,
    pub gid: u32,
    pub size: u64,
    pub mtime: i64,
}

/// Result of `sample()`: the same files read twice, `seconds` apart (counters in /proc and /sys, for rates).
#[derive(Debug, Clone, Default)]
pub struct Sample {
    /// Measured between the two reads, not the requested interval.
    pub seconds: f64,
    pub before: std::collections::BTreeMap<String, String>,
    /// A path missing here (a process that exited) is missing from `after` only.
    pub after: std::collections::BTreeMap<String, String>,
}

/// Options of `journal()` ([B11]), as journalctl's.
#[derive(Debug, Clone, Default)]
pub struct JournalOptions {
    /// The kernel's messages only (`journalctl -k`, what dmesg shows), this boot.
    pub kernel: bool,
    pub unit: Option<String>,
    pub since: Option<String>,
    pub grep: Option<String>,
    pub limit: usize,
}

/// Why a host-side builtin did not return a value. `Denied` and `Missing` are probe failures (§5): the host differs
/// from what the probe assumed. The others are errors.
#[derive(Debug, Clone)]
pub enum HostError {
    /// Content of a secret path was asked for ([B9]).
    Denied(String),
    /// `read` or `list_dir` of a path that does not exist (or is outside the mapping).
    Missing(String),
    /// A limit was hit ([L2]): which one, and where.
    Limit(String),
    /// A WASM tool trapped, or is not in the manifest.
    Tool(String),
    /// osquery or the journal failed, or this host has none.
    Source(String),
    /// Reading the host failed in a way a probe cannot express (I/O error on a mapped path).
    Io(String),
    /// A transformer was asked for a file that is not of its kind (`keytab()` of a text file).
    Format(String),
}

impl fmt::Display for HostError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HostError::Denied(m) => write!(f, "denied: {m}"),
            HostError::Missing(p) => write!(f, "missing: {p}"),
            HostError::Limit(m) => write!(f, "limit: {m}"),
            HostError::Tool(m) => write!(f, "tool: {m}"),
            HostError::Source(m) => write!(f, "source: {m}"),
            HostError::Io(m) => write!(f, "io: {m}"),
            HostError::Format(m) => write!(f, "format: {m}"),
        }
    }
}

impl std::error::Error for HostError {}

pub type HostResult<T> = Result<T, HostError>;

pub trait Host {
    fn pipe(&self, stages: &[Vec<String>], stdin: &[u8]) -> HostResult<ToolResult>;
    /// `None`: missing, or outside the mapping (then `notes()` says so).
    fn stat(&self, path: &str) -> HostResult<Option<Stat>>;
    fn read(&self, path: &str) -> HostResult<String>;
    /// Sorted; no match gives an empty list.
    fn glob(&self, pattern: &str) -> HostResult<Vec<String>>;
    /// Sorted names (not paths).
    fn list_dir(&self, path: &str) -> HostResult<Vec<String>>;
    fn readlink(&self, path: &str) -> HostResult<Option<String>>;
    /// osquery SQL; `?` are bound to `params` on the host side. Rows as JSON objects keyed by column name, typed.
    fn osq(&self, query: &str, params: &[serde_json::Value]) -> HostResult<Vec<serde_json::Value>>;
    /// A process's environment, as (name, value): for `environ()`, which never hands a question the value of a name it
    /// does not know to be safe (environ.rs).
    fn environ(&self, pid: u32) -> HostResult<Vec<(String, String)>>;
    /// Journal entries, oldest first: ts, unit, pid, priority, message.
    fn journal(&self, opts: &JournalOptions) -> HostResult<Vec<serde_json::Value>>;
    /// The files matching `patterns` (globs) read at once, then again after `seconds`: counters in /proc and /sys.
    /// Paths that vanish between the reads (a process exited) are left out of `after`.
    fn sample(&self, patterns: &[String], seconds: f64) -> HostResult<Sample>;
    /// A catalog entry (`catalog::ENTRIES`) run for `o.seconds`, its output reduced: never the events themselves.
    fn trace(&self, entry: &str, o: &crate::catalog::TraceOptions) -> HostResult<serde_json::Value>;
    /// Traffic captured on the host for `o.seconds` and reduced to a view (`capture::View`): never the packets.
    /// `request` is what the sensor's broker takes ({view, interface?, host?, port?, proto?, seconds}).
    fn capture(&self, request: &serde_json::Value, o: &crate::catalog::TraceOptions) -> HostResult<serde_json::Value>;
    fn secrets(&self) -> HostResult<Vec<Secret>>;
    /// A file of known meaning read for what it means (C23, `transform`): kind is one of `transform::KINDS`.
    /// Never its bytes. Secret files are read too: the result is metadata.
    fn transformed(&self, kind: &str, path: &str) -> HostResult<serde_json::Value>;
    /// Names of the WASM tools behind `pipe()`; each also becomes a Starlark function.
    fn tools(&self) -> Vec<String>;
    /// Things the reviewer should know about this run ("unmapped path ... treated as missing").
    fn notes(&self) -> Vec<String>;
}
