//! Where a probe run's time went (docs/probes.md §9, "timings"): every host call timed by builtin, and with
//! `--profile` each call on its own, the slowest kept. A wrapper around the host, so no builtin needs to know.
//!
//! The totals travel in the run result's `timings`, which the sensor puts in the answer's Beat-Phases header, not in
//! the answer: equal answers stay equal. A profiled run's calls are records of the answer (`profile_records`), as the
//! person asked for them: they pass gate 1 like any record, since a call's arguments name paths and queries.

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::rc::Rc;
use std::time::{Duration, Instant};

use serde_json::{json, Value};

use crate::builtins::Record;
use crate::catalog::TraceOptions;
use crate::host::{Host, HostResult, JournalOptions, Sample, Secret, Stat, ToolResult};

/// The slowest calls a profiled run reports; the rest are counted in the totals only.
pub const PROFILE_CALLS: usize = 50;
/// A call's arguments as reported: enough to tell calls apart, not a copy of what was asked.
const WHAT_MAX: usize = 160;

#[derive(Default)]
pub struct Stats {
    /// builtin -> (calls, total time)
    pub totals: BTreeMap<&'static str, (u64, Duration)>,
    /// Each call, with --profile: (builtin, its arguments, time, error)
    pub calls: Option<Vec<(&'static str, String, Duration, bool)>>,
}

impl Stats {
    pub fn busy(&self) -> Duration {
        self.totals.values().map(|(_, d)| *d).sum()
    }
}

pub struct Timed {
    inner: Box<dyn Host>,
    stats: Rc<RefCell<Stats>>,
}

impl Timed {
    /// The host, timed; the stats are read through the returned handle once the run is over.
    pub fn new(inner: Box<dyn Host>, profile: bool) -> (Timed, Rc<RefCell<Stats>>) {
        let stats = Rc::new(RefCell::new(Stats { calls: profile.then(Vec::new), ..Default::default() }));
        (Timed { inner, stats: stats.clone() }, stats)
    }

    fn time<T>(&self, builtin: &'static str, what: impl FnOnce() -> String, f: impl FnOnce() -> HostResult<T>) -> HostResult<T> {
        let t0 = Instant::now();
        let r = f();
        let took = t0.elapsed();
        let mut s = self.stats.borrow_mut();
        let e = s.totals.entry(builtin).or_default();
        e.0 += 1;
        e.1 += took;
        if let Some(calls) = s.calls.as_mut() {
            let mut w = what();
            if w.len() > WHAT_MAX {
                let mut cut = WHAT_MAX;
                while !w.is_char_boundary(cut) {
                    cut -= 1;
                }
                w.truncate(cut);
                w.push('…');
            }
            calls.push((builtin, w, took, r.is_err()));
        }
        r
    }
}

impl Host for Timed {
    fn pipe(&self, stages: &[Vec<String>], stdin: &[u8]) -> HostResult<ToolResult> {
        self.time("pipe", || stages.iter().map(|s| s.join(" ")).collect::<Vec<_>>().join(" | "), || self.inner.pipe(stages, stdin))
    }
    fn stat(&self, path: &str) -> HostResult<Option<Stat>> {
        self.time("stat", || path.to_string(), || self.inner.stat(path))
    }
    fn read(&self, path: &str) -> HostResult<String> {
        self.time("read", || path.to_string(), || self.inner.read(path))
    }
    fn glob(&self, pattern: &str) -> HostResult<Vec<String>> {
        self.time("glob", || pattern.to_string(), || self.inner.glob(pattern))
    }
    fn list_dir(&self, path: &str) -> HostResult<Vec<String>> {
        self.time("list_dir", || path.to_string(), || self.inner.list_dir(path))
    }
    fn readlink(&self, path: &str) -> HostResult<Option<String>> {
        self.time("readlink", || path.to_string(), || self.inner.readlink(path))
    }
    fn osq(&self, query: &str, params: &[Value]) -> HostResult<Vec<Value>> {
        self.time("osq", || query.split_whitespace().collect::<Vec<_>>().join(" "), || self.inner.osq(query, params))
    }
    fn environ(&self, pid: u32) -> HostResult<Vec<(String, String)>> {
        self.time("environ", || pid.to_string(), || self.inner.environ(pid))
    }
    fn journal(&self, opts: &JournalOptions) -> HostResult<Vec<Value>> {
        let what = || {
            let mut w = Vec::new();
            if opts.kernel {
                w.push("kernel".to_string());
            }
            w.extend(opts.unit.as_ref().map(|u| format!("unit={u}")));
            w.extend(opts.since.as_ref().map(|s| format!("since={s}")));
            w.extend(opts.grep.as_ref().map(|g| format!("grep={g}")));
            w.push(format!("limit={}", opts.limit));
            w.join(" ")
        };
        self.time("journal", what, || self.inner.journal(opts))
    }
    fn sample(&self, patterns: &[String], seconds: f64) -> HostResult<Sample> {
        self.time("sample", || format!("{} {seconds}s", patterns.join(" ")), || self.inner.sample(patterns, seconds))
    }
    fn trace(&self, entry: &str, o: &TraceOptions) -> HostResult<Value> {
        self.time("trace", || entry.to_string(), || self.inner.trace(entry, o))
    }
    fn capture(&self, request: &Value, o: &TraceOptions) -> HostResult<Value> {
        self.time("capture", || request.to_string(), || self.inner.capture(request, o))
    }
    fn secrets(&self) -> HostResult<Vec<Secret>> {
        self.time("secrets", String::new, || self.inner.secrets())
    }
    fn transformed(&self, kind: &str, path: &str) -> HostResult<Value> {
        self.time("transformed", || format!("{kind} {path}"), || self.inner.transformed(kind, path))
    }
    fn tools(&self) -> Vec<String> {
        self.inner.tools()
    }
    fn notes(&self) -> Vec<String> {
        self.inner.notes()
    }
}

pub fn ms(d: Duration) -> u64 {
    d.as_millis() as u64
}

/// The totals as the run result's `timings.builtins`: {builtin: {ms, calls}}.
pub fn totals_json(s: &Stats) -> Value {
    let mut m = serde_json::Map::new();
    for (b, (n, d)) in &s.totals {
        m.insert(b.to_string(), json!({"ms": ms(*d), "calls": n}));
    }
    Value::Object(m)
}

/// A profiled run's slowest calls, as records: subject `beat:profile:<builtin>#<rank>`, with keys `ms` (a metric),
/// `call` (its arguments, shortened) and `failed` when it returned an error; then how many calls there were in all.
pub fn profile_records(s: &Stats) -> Vec<Record> {
    let Some(calls) = &s.calls else { return Vec::new() };
    let mut sorted: Vec<_> = calls.iter().collect();
    sorted.sort_by(|a, b| b.2.cmp(&a.2));
    let mut out = Vec::new();
    for (rank, (builtin, what, took, err)) in sorted.iter().take(PROFILE_CALLS).enumerate() {
        let subject = format!("beat:profile:{builtin}#{:02}", rank + 1);
        out.push(record(&subject, "ms", &ms(*took).to_string(), "metric"));
        out.push(record(&subject, "call", what, "semantic"));
        if *err {
            out.push(record(&subject, "failed", "true", "semantic"));
        }
    }
    out.push(record("beat:profile", "calls", &calls.len().to_string(), "metric"));
    out.push(record("beat:profile", "reported", &calls.len().min(PROFILE_CALLS).to_string(), "metric"));
    out
}

fn record(subject: &str, key: &str, value: &str, kind: &str) -> Record {
    Record { subject: subject.into(), key: key.into(), value: value.into(), source: "beat-probe --profile".into(),
             span: String::new(), kind: Some(kind.into()) }
}

/// CPU time (ms) of this process and of the children it waited for (osqueryi, journalctl, the trace tools), and the
/// bytes it read from storage, from /proc/self (no dependency): the ticks are USER_HZ, 100 on Linux.
pub fn usage() -> (Option<u64>, Option<u64>, Option<u64>) {
    let stat = std::fs::read_to_string("/proc/self/stat").ok();
    let ticks = stat.as_deref().and_then(|s| {
        // after the command name, which is in parentheses and may hold spaces
        let f: Vec<&str> = s[s.rfind(')')? + 2..].split(' ').collect();
        // `f` starts at field 3 (state); fields 14-17 of proc_pid_stat(5) are utime, stime, cutime, cstime. By
        // position: a field before them may be -1 (tpgid), so none may be dropped.
        let n = |field: usize| f.get(field - 3)?.parse::<u64>().ok();
        Some((n(14)? + n(15)?, n(16)? + n(17)?))
    });
    let read = std::fs::read_to_string("/proc/self/io").ok().and_then(|s| {
        s.lines().find_map(|l| l.strip_prefix("read_bytes: ")?.trim().parse::<u64>().ok())
    });
    (ticks.map(|t| t.0 * 10), ticks.map(|t| t.1 * 10), read)
}
