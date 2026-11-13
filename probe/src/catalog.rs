//! The catalog behind `trace()` (docs/probes.md [B11c]): B. Gregg's tools (libbpf-tools, CO-RE) run for a few
//! seconds, their output reduced as it streams. An answer is a reduction, never the event stream: histograms with
//! approximate percentiles, or events grouped, counted and bounded (the reduction vocabulary), and it always says what
//! it saw (events seen, matched, unparsed, lost, its own left out).
//!
//! Each entry declares the capabilities it needs; the sensor adds exactly those to the question's unit
//! (`needs`), from the probe's text, before it runs.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::io::{BufRead, BufReader, Read};
use std::path::Path;
use std::process::{Command, Stdio};

use regex::Regex;
use serde_json::{json, Map, Value};

use crate::host::{HostError, HostResult};

/// What an entry's output is.
pub enum Kind {
    /// bcc-style log2 histograms, one per disk or process when asked; the tool stops itself after the interval.
    Histogram,
    /// One line per event; `pattern` names the fields (numbers in `numeric`); stopped by SIGINT after the interval.
    Events { pattern: &'static str, numeric: &'static [&'static str] },
}

/// An option a probe may pass in `options`: its flag, and whether it takes a value.
pub struct Opt {
    pub name: &'static str,
    pub flag: &'static str,
    pub value: bool,
    pub help: &'static str,
}

pub struct Entry {
    pub name: &'static str,
    pub about: &'static str,
    pub capabilities: &'static [&'static str],
    pub kind: Kind,
    pub options: &'static [Opt],
}

const BPF: &[&str] = &["CAP_BPF", "CAP_PERFMON"];

pub const ENTRIES: &[Entry] = &[
    Entry {
        name: "biolatency", about: "block I/O latency, a histogram (per disk with per_disk)",
        capabilities: BPF, kind: Kind::Histogram,
        options: &[
            Opt { name: "per_disk", flag: "-D", value: false, help: "a histogram per disk" },
            Opt { name: "queued", flag: "-Q", value: false, help: "include the time queued in the OS" },
            Opt { name: "disk", flag: "-d", value: true, help: "this disk only" },
            Opt { name: "cgroup", flag: "-c", value: true, help: "this cgroup only (a /sys/fs/cgroup path)" },
        ],
    },
    Entry {
        name: "runqlat", about: "run queue latency: how long runnable threads waited for a CPU, a histogram",
        capabilities: BPF, kind: Kind::Histogram,
        options: &[
            Opt { name: "per_process", flag: "-P", value: false, help: "a histogram per process" },
            Opt { name: "pid", flag: "-p", value: true, help: "this process only" },
            Opt { name: "cgroup", flag: "-c", value: true, help: "this cgroup only (a /sys/fs/cgroup path)" },
        ],
    },
    Entry {
        name: "cpudist", about: "on-CPU time per scheduling (off-CPU with offcpu), a histogram",
        capabilities: BPF, kind: Kind::Histogram,
        options: &[
            Opt { name: "per_process", flag: "-P", value: false, help: "a histogram per process" },
            Opt { name: "offcpu", flag: "-O", value: false, help: "time off the CPU instead" },
            Opt { name: "pid", flag: "-p", value: true, help: "this process only" },
            Opt { name: "cgroup", flag: "-c", value: true, help: "this cgroup only (a /sys/fs/cgroup path)" },
        ],
    },
    Entry {
        name: "execsnoop", about: "new processes (exec): comm, pid, ppid, ret, args",
        capabilities: BPF,
        kind: Kind::Events { pattern: r"^(?P<comm>.{1,16}?)\s+(?P<pid>\d+)\s+(?P<ppid>\d+)\s+(?P<ret>-?\d+)\s(?P<args>.*)$",
                             numeric: &["pid", "ppid", "ret"] },
        options: &[
            Opt { name: "failed", flag: "-x", value: false, help: "include failed exec()s" },
            Opt { name: "uid", flag: "-u", value: true, help: "this user id only" },
        ],
    },
    Entry {
        name: "opensnoop", about: "files opened: pid, comm, fd, err, path",
        capabilities: BPF,
        kind: Kind::Events { pattern: r"^(?P<pid>\d+)\s+(?P<comm>.{1,16}?)\s+(?P<fd>-?\d+)\s+(?P<err>\d+)\s(?P<path>.*)$",
                             numeric: &["pid", "fd", "err"] },
        options: &[
            Opt { name: "failed", flag: "-x", value: false, help: "failed opens only" },
            Opt { name: "pid", flag: "-p", value: true, help: "this process only" },
            Opt { name: "uid", flag: "-u", value: true, help: "this user id only" },
        ],
    },
    Entry {
        name: "tcpconnect", about: "TCP connections made (active opens): pid, comm, ip, saddr, daddr, dport",
        capabilities: BPF,
        kind: Kind::Events { pattern: r"^(?P<pid>\d+)\s+(?P<comm>.{1,16}?)\s+(?P<ip>[46])\s+(?P<saddr>\S+)\s+(?P<daddr>\S+)\s+(?P<dport>\d+)\s*$",
                             numeric: &["pid", "dport"] },
        options: &[
            Opt { name: "pid", flag: "-p", value: true, help: "this process only" },
            Opt { name: "ports", flag: "-P", value: true, help: "these destination ports only (comma-separated)" },
        ],
    },
    Entry {
        name: "tcplife", about: "TCP connections closed, with their life: pid, comm, laddr, lport, raddr, rport, tx_kb, rx_kb, ms",
        capabilities: BPF,
        kind: Kind::Events { pattern: r"^(?P<pid>\d+)\s+(?P<comm>.{1,16}?)\s+(?P<laddr>\S+)\s+(?P<lport>\d+)\s+(?P<raddr>\S+)\s+(?P<rport>\d+)\s+(?P<tx_kb>\d+)\s+(?P<rx_kb>\d+)\s+(?P<ms>[\d.]+)\s*$",
                             numeric: &["pid", "lport", "rport", "tx_kb", "rx_kb", "ms"] },
        options: &[
            Opt { name: "pid", flag: "-p", value: true, help: "this process only" },
            Opt { name: "local_ports", flag: "-L", value: true, help: "these local ports only (comma-separated)" },
            Opt { name: "remote_ports", flag: "-D", value: true, help: "these remote ports only (comma-separated)" },
        ],
    },
];

pub fn entry(name: &str) -> Option<&'static Entry> {
    ENTRIES.iter().find(|e| e.name == name)
}

/// Capabilities the named entries need, sorted: what the sensor adds to the question's unit.
pub fn capabilities<'a>(names: impl IntoIterator<Item = &'a str>) -> Vec<String> {
    let mut caps: Vec<String> = names.into_iter().filter_map(entry).flat_map(|e| e.capabilities.iter().map(|c| c.to_string())).collect();
    caps.sort();
    caps.dedup();
    caps
}

pub const MAX_SECONDS: f64 = 60.0;
/// Distinct keys kept per answer; events of further keys are counted as overflow.
pub const MAX_KEYS: usize = 10_000;
const EXAMPLE_CHARS: usize = 200;

/// What a probe asked of `trace()`.
#[derive(Debug, Clone, Default)]
pub struct TraceOptions {
    pub seconds: f64,
    /// The entry's own options (`per_disk`, `pid`, ...): true for a flag, a string or number for a value.
    pub options: BTreeMap<String, Value>,
    pub filter: BTreeMap<String, Value>,
    pub key: Vec<String>,
    pub sum: Vec<String>,
    pub hist: Option<String>,
    pub top: usize,
    pub examples: usize,
}

/// The command line: the entry's binary in `dir`, its options, the interval; event tools under `timeout -s INT`
/// (they print what they buffered on SIGINT; a kill would lose it).
pub fn argv(dir: &Path, e: &Entry, o: &TraceOptions) -> HostResult<Vec<String>> {
    if !(1.0..=MAX_SECONDS).contains(&o.seconds) {
        return Err(HostError::Limit(format!("trace(): seconds must be 1 to {MAX_SECONDS}, got {}", o.seconds)));
    }
    let mut args = Vec::new();
    for (name, v) in &o.options {
        let opt = e.options.iter().find(|x| x.name == name).ok_or_else(|| {
            let known: Vec<&str> = e.options.iter().map(|x| x.name).collect();
            HostError::Source(format!("trace({}): no option {name:?} (options: {})", e.name, known.join(", ")))
        })?;
        match (opt.value, v) {
            (false, Value::Bool(true)) => args.push(opt.flag.to_string()),
            (false, Value::Bool(false)) => {}
            (true, Value::String(s)) if !s.is_empty() && !s.starts_with('-') => args.extend([opt.flag.to_string(), s.clone()]),
            (true, Value::Number(n)) => args.extend([opt.flag.to_string(), n.to_string()]),
            _ => return Err(HostError::Source(format!("trace({}): option {name}: {}", e.name,
                                                       if opt.value { "a value (string or number)" } else { "True or False" }))),
        }
    }
    let bin = dir.join(e.name).to_string_lossy().into_owned();
    let secs = format!("{}", o.seconds.round() as u64);
    Ok(match e.kind {
        Kind::Histogram => [vec![bin], args, vec![secs, "1".into()]].concat(),
        Kind::Events { .. } => [vec![dir.join("timeout").to_string_lossy().into_owned(), "-s".into(), "INT".into(),
                                     secs, bin], args].concat(),
    })
}

/// Runs the entry and reduces its output as it streams. `own`: process ids to leave out (beat-probe's).
pub fn run(dir: &Path, e: &Entry, o: &TraceOptions, own: &HashSet<u64>) -> HostResult<Value> {
    let argv = argv(dir, e, o)?;
    let mut child = Command::new(&argv[0]).args(&argv[1..]).stdin(Stdio::null()).stdout(Stdio::piped())
        .stderr(Stdio::piped()).spawn().map_err(|err| HostError::Source(format!("trace({}): cannot start {}: {err}", e.name, argv[0])))?;
    let mut own = own.clone();
    own.insert(child.id() as u64);
    let stderr = child.stderr.take().expect("piped");
    let err_reader = std::thread::spawn(move || {
        let mut s = String::new();
        let _ = BufReader::new(stderr).take(64 << 10).read_to_string(&mut s);
        s
    });
    let lines = BufReader::new(child.stdout.take().expect("piped")).lines().map_while(Result::ok);
    let mut out = match &e.kind {
        Kind::Histogram => histograms(lines, o.top),
        Kind::Events { pattern, numeric } => {
            let mut r = Reducer::new(o, numeric)?;
            r.feed(lines, &Regex::new(pattern).expect("catalog patterns are valid"), &own);
            r.finish(o.seconds)
        }
    };
    let status = child.wait().map_err(|err| HostError::Source(format!("trace({}): {err}", e.name)))?;
    let stderr = err_reader.join().unwrap_or_default();
    let lost: u64 = Regex::new(r"lost (\d+) (?:events|samples)").unwrap().captures_iter(&stderr)
        .filter_map(|c| c[1].parse::<u64>().ok()).sum();
    // timeout exits 124 when it had to stop the tool: that is the normal end of an event tool.
    let ok = status.success() || (matches!(e.kind, Kind::Events { .. }) && status.code() == Some(124));
    if !ok {
        let tail: String = stderr.lines().filter(|l| !l.trim().is_empty()).take(5).collect::<Vec<_>>().join("; ");
        return Err(HostError::Source(format!("trace({}): {} ({status})", e.name, if tail.is_empty() { "failed" } else { &tail })));
    }
    let m = out.as_object_mut().expect("an object");
    m.insert("entry".into(), json!(e.name));
    m.insert("seconds".into(), json!(o.seconds));
    if let Some(Value::Object(ev)) = m.get_mut("events") {
        ev.insert("lost".into(), json!(lost));
    } else {
        m.insert("events".into(), json!({"lost": lost}));
    }
    Ok(out)
}

// --- histograms ---------------------------------------------------------------------------------------------------

/// bcc's histogram text: optional label lines ("disk = nvme0n1", "pid = 123 comm"), a unit header ("usecs : count"),
/// then "lo -> hi : count |***|" rows. Labelled histograms are ranked by count and cut to `top`.
pub fn histograms(lines: impl Iterator<Item = String>, top: usize) -> Value {
    let row = Regex::new(r"^\s*(\d+)\s*->\s*(\d+)\s*:\s*(\d+)").unwrap();
    let unit = Regex::new(r"^\s*(\w+)\s*:\s*count\s+distribution").unwrap();
    let label = Regex::new(r"^\s*(disk|pid|tid|flags)\s*=\s*(.*?)\s*$").unwrap();
    let mut hists: Vec<(Map<String, Value>, String, Vec<(u64, u64, u64)>)> = Vec::new();
    let mut pending: Map<String, Value> = Map::new();
    for l in lines {
        if let Some(c) = label.captures(&l) {
            pending = Map::new();
            let v = c[2].trim_matches(|ch| ch == '\'' || ch == '"').to_string();
            match &c[1] {
                "pid" | "tid" => {
                    let (id, comm) = v.split_once(' ').unwrap_or((v.as_str(), ""));
                    pending.insert(c[1].to_string(), json!(id.trim_end_matches(',').parse::<u64>().unwrap_or(0)));
                    pending.insert("comm".into(), json!(comm.trim().trim_start_matches("comm = ")));
                }
                k => { pending.insert(k.to_string(), json!(v)); }
            }
        } else if let Some(c) = unit.captures(&l) {
            hists.push((std::mem::take(&mut pending), c[1].to_string(), Vec::new()));
        } else if let Some(c) = row.captures(&l) {
            if let Some(h) = hists.last_mut() {
                h.2.push((c[1].parse().unwrap_or(0), c[2].parse().unwrap_or(0), c[3].parse().unwrap_or(0)));
            }
        }
    }
    let total = hists.len();
    let mut out: Vec<Value> = hists.into_iter().map(|(lab, unit, rows)| {
        let mut m = lab;
        m.extend(summary(&unit, &rows).as_object().unwrap().clone());
        Value::Object(m)
    }).collect();
    out.sort_by(|a, b| b["count"].as_u64().cmp(&a["count"].as_u64()));
    let labelled = out.first().is_some_and(|h| h.get("disk").or(h.get("pid")).or(h.get("tid")).is_some());
    if labelled {
        out.truncate(top.max(1));
        json!({"histograms": out, "histograms_total": total})
    } else {
        json!({"histogram": out.into_iter().next().unwrap_or_else(|| summary("usecs", &[]))})
    }
}

/// Buckets (non-empty range only), count, and percentiles as the upper bound of the bucket they fall in.
fn summary(unit: &str, rows: &[(u64, u64, u64)]) -> Value {
    let count: u64 = rows.iter().map(|r| r.2).sum();
    let pct = |p: f64| -> Value {
        if count == 0 { return Value::Null }
        let target = (count as f64 * p).ceil() as u64;
        let mut acc = 0;
        for r in rows {
            acc += r.2;
            if acc >= target { return json!(r.1) }
        }
        Value::Null
    };
    let first = rows.iter().position(|r| r.2 > 0).unwrap_or(0);
    let last = rows.iter().rposition(|r| r.2 > 0).map_or(0, |i| i + 1);
    let buckets: Vec<Value> = rows.get(first..last).unwrap_or(&[]).iter().map(|r| json!([r.0, r.1, r.2])).collect();
    json!({"unit": unit, "count": count, "p50": pct(0.5), "p90": pct(0.9), "p99": pct(0.99), "max": pct(1.0),
           "buckets": buckets})
}

// --- events: the reduction vocabulary -----------------------------------------------------------------------------

enum Match {
    Exact(String),
    Prefix(String),
    Not(String),
    Any(Vec<String>),
}

impl Match {
    fn from(v: &Value) -> HostResult<Match> {
        Ok(match v {
            Value::Array(a) => Match::Any(a.iter().map(text).collect()),
            Value::String(s) if s.starts_with('!') => Match::Not(s[1..].to_string()),
            Value::String(s) if s.ends_with('*') => Match::Prefix(s[..s.len() - 1].to_string()),
            Value::String(_) | Value::Number(_) => Match::Exact(text(v)),
            _ => return Err(HostError::Source("trace(): a filter value is a string, a number or a list".into())),
        })
    }
    fn test(&self, s: &str) -> bool {
        match self {
            Match::Exact(x) => s == x,
            Match::Prefix(x) => s.starts_with(x.as_str()),
            Match::Not(x) => s != x,
            Match::Any(xs) => xs.iter().any(|x| x == s),
        }
    }
}

fn text(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        other => other.to_string(),
    }
}

/// A key field and its coarsening: "path:dir2" (the first 2 directories), "daddr:/24" (an IPv4 prefix),
/// "args:template" (numbers and hex masked), "path:basename".
struct KeySpec {
    field: String,
    how: Option<String>,
}

impl KeySpec {
    fn parse(s: &str) -> HostResult<KeySpec> {
        let (field, how) = match s.split_once(':') {
            Some((f, h)) => (f.to_string(), Some(h.to_string())),
            None => (s.to_string(), None),
        };
        if let Some(h) = &how {
            let ok = h == "template" || h == "basename" || h.strip_prefix("dir").is_some_and(|n| n.parse::<usize>().is_ok())
                || h.strip_prefix('/').is_some_and(|n| n.parse::<u8>().is_ok_and(|n| n <= 32));
            if !ok {
                return Err(HostError::Source(format!("trace(): key {s:?}: coarsenings are dirN, /N, template, basename")));
            }
        }
        Ok(KeySpec { field, how })
    }

    fn apply(&self, v: &str, masks: &[(Regex, &str)]) -> String {
        let Some(h) = &self.how else { return v.to_string() };
        if h == "basename" {
            return v.rsplit('/').next().unwrap_or(v).to_string();
        }
        if h == "template" {
            return masks.iter().fold(v.to_string(), |s, (re, with)| re.replace_all(&s, *with).into_owned());
        }
        if let Some(n) = h.strip_prefix("dir").and_then(|n| n.parse::<usize>().ok()) {
            let parts: Vec<&str> = v.split('/').collect();
            let keep = if v.starts_with('/') { n + 1 } else { n };
            return if parts.len() > keep { format!("{}/", parts[..keep].join("/")) } else { v.to_string() };
        }
        if let Some(bits) = h.strip_prefix('/').and_then(|n| n.parse::<u32>().ok()) {
            if let Ok(ip) = v.parse::<std::net::Ipv4Addr>() {
                let mask = if bits == 0 { 0 } else { u32::MAX << (32 - bits) };
                return format!("{}/{bits}", std::net::Ipv4Addr::from(u32::from(ip) & mask));
            }
        }
        v.to_string()
    }
}

#[derive(Default)]
struct Group {
    count: u64,
    sums: Vec<f64>,
    hist: Vec<u64>, // log2 buckets
    examples: Vec<Value>,
}

pub struct Reducer {
    filter: Vec<(String, Match)>,
    key: Vec<KeySpec>,
    sum: Vec<String>,
    hist: Option<String>,
    top: usize,
    examples: usize,
    numeric: HashSet<&'static str>,
    masks: Vec<(Regex, &'static str)>,
    groups: HashMap<Vec<String>, Group>,
    seen: u64,
    matched: u64,
    unparsed: u64,
    own: u64,
    overflow: u64,
}

impl Reducer {
    pub fn new(o: &TraceOptions, numeric: &'static [&'static str]) -> HostResult<Reducer> {
        let numeric: HashSet<&'static str> = numeric.iter().copied().collect();
        for f in o.sum.iter().chain(o.hist.iter()) {
            if !numeric.contains(f.as_str()) {
                return Err(HostError::Source(format!("trace(): {f:?} is not a numeric field (numeric: {})",
                                                     { let mut n: Vec<_> = numeric.iter().copied().collect(); n.sort(); n.join(", ") })));
            }
        }
        Ok(Reducer {
            filter: o.filter.iter().map(|(k, v)| Ok((k.clone(), Match::from(v)?))).collect::<HostResult<_>>()?,
            key: o.key.iter().map(|k| KeySpec::parse(k)).collect::<HostResult<_>>()?,
            sum: o.sum.clone(),
            hist: o.hist.clone(),
            top: o.top.max(1),
            examples: o.examples,
            numeric,
            masks: vec![
                (Regex::new(r"0x[0-9a-fA-F]+|\b[0-9a-f]{12,}\b").unwrap(), "<HEX>"),
                (Regex::new(r"\d+").unwrap(), "<N>"),
            ],
            groups: HashMap::new(),
            seen: 0, matched: 0, unparsed: 0, own: 0, overflow: 0,
        })
    }

    pub fn feed(&mut self, lines: impl Iterator<Item = String>, pattern: &Regex, own: &HashSet<u64>) {
        let names: Vec<&str> = pattern.capture_names().flatten().collect();
        for line in lines {
            let Some(c) = pattern.captures(&line) else {
                // the header and the tools' own messages are not events
                if !line.trim().is_empty() && !line.chars().next().is_some_and(|ch| ch.is_ascii_uppercase()) {
                    self.unparsed += 1;
                }
                continue;
            };
            self.seen += 1;
            let mut ev = Map::new();
            for n in &names {
                let s = c.name(n).map_or("", |m| m.as_str()).trim();
                let v = match (self.numeric.contains(n), s.parse::<i64>(), s.parse::<f64>()) {
                    (true, Ok(i), _) => json!(i),
                    (true, _, Ok(f)) => json!(f),
                    _ => json!(s),
                };
                ev.insert(n.to_string(), v);
            }
            let id = |k: &str| ev.get(k).and_then(Value::as_f64).map(|f| f as u64);
            if id("pid").is_some_and(|p| own.contains(&p)) || id("ppid").is_some_and(|p| own.contains(&p)) {
                self.own += 1;
                continue;
            }
            self.add(ev);
        }
    }

    /// One event from a source that is not a tool's text output (`capture()`'s views).
    pub fn event(&mut self, ev: Map<String, Value>) {
        self.seen += 1;
        self.add(ev);
    }

    fn add(&mut self, ev: Map<String, Value>) {
        let field = |k: &str| ev.get(k).map(text).unwrap_or_default();
        if !self.filter.iter().all(|(k, m)| m.test(&field(k))) {
            return;
        }
        self.matched += 1;
        let key: Vec<String> = self.key.iter().map(|k| k.apply(&field(&k.field), &self.masks)).collect();
        if !self.groups.contains_key(&key) && self.groups.len() >= MAX_KEYS {
            self.overflow += 1;
            return;
        }
        let g = self.groups.entry(key).or_default();
        g.count += 1;
        if g.sums.is_empty() {
            g.sums = vec![0.0; self.sum.len()];
        }
        for (i, f) in self.sum.iter().enumerate() {
            g.sums[i] += ev.get(f).and_then(Value::as_f64).unwrap_or(0.0);
        }
        // an event without the field (a DNS query never answered has no latency) is counted, not put in bucket 0
        if let Some(x) = self.hist.as_ref().and_then(|h| ev.get(h)).and_then(Value::as_f64) {
            let x = x.max(0.0) as u64;
            let b = if x == 0 { 0 } else { 64 - x.leading_zeros() as usize };
            if g.hist.len() <= b {
                g.hist.resize(b + 1, 0);
            }
            g.hist[b] += 1;
        }
        if g.examples.len() < self.examples {
            let short: Map<String, Value> = ev.into_iter().map(|(k, v)| match v {
                Value::String(s) if s.chars().count() > EXAMPLE_CHARS => (k, json!(format!("{}...", s.chars().take(EXAMPLE_CHARS).collect::<String>()))),
                v => (k, v),
            }).collect();
            g.examples.push(Value::Object(short));
        }
    }

    pub fn finish(self, seconds: f64) -> Value {
        let distinct = self.groups.len();
        let mut groups: Vec<(Vec<String>, Group)> = self.groups.into_iter().collect();
        groups.sort_by(|a, b| b.1.count.cmp(&a.1.count).then_with(|| a.0.cmp(&b.0)));
        let shown: Vec<Value> = groups.into_iter().take(self.top).map(|(k, g)| {
            let mut m = Map::new();
            m.insert("key".into(), Value::Object(self.key.iter().zip(k).map(|(s, v)| {
                let name = match &s.how { Some(h) => format!("{}:{h}", s.field), None => s.field.clone() };
                (name, json!(v))
            }).collect()));
            m.insert("count".into(), json!(g.count));
            m.insert("per_s".into(), json!((g.count as f64 / seconds * 10.0).round() / 10.0));
            if !self.sum.is_empty() {
                m.insert("sum".into(), Value::Object(self.sum.iter().cloned().zip(g.sums.iter().map(|x| json!(x))).collect()));
            }
            if let Some(h) = &self.hist {
                let rows: Vec<(u64, u64, u64)> = g.hist.iter().enumerate()
                    .map(|(b, n)| if b == 0 { (0, 0, *n) } else { (1u64 << (b - 1), (1u64 << b) - 1, *n) }).collect();
                let mut s = summary(h, &rows);
                s.as_object_mut().unwrap().insert("field".into(), json!(h));
                m.insert("hist".into(), s);
            }
            if self.examples > 0 {
                m.insert("examples".into(), json!(g.examples));
            }
            Value::Object(m)
        }).collect();
        json!({
            "events": {"seen": self.seen, "matched": self.matched, "unparsed": self.unparsed, "own_left_out": self.own,
                       "per_s": (self.matched as f64 / seconds * 10.0).round() / 10.0},
            "keys": {"distinct": distinct, "shown": shown.len(), "overflow_events": self.overflow},
            "groups": shown,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lines(s: &str) -> impl Iterator<Item = String> + '_ {
        s.lines().map(String::from)
    }

    #[test]
    fn histogram_single() {
        let out = "Tracing block device I/O... Hit Ctrl-C to end.\n\n     usecs               : count    distribution\n\
                   \x20        0 -> 1          : 0        |                                        |\n\
                   \x20      512 -> 1023       : 20       |**********                              |\n\
                   \x20     1024 -> 2047       : 34       |****************************************|\n";
        let h = &histograms(lines(out), 10)["histogram"];
        assert_eq!(h["count"], 54);
        assert_eq!(h["unit"], "usecs");
        assert_eq!(h["p50"], 2047);
        assert_eq!(h["buckets"], json!([[512, 1023, 20], [1024, 2047, 34]]));
    }

    #[test]
    fn histograms_per_process() {
        let out = "pid = 124284 kworker/u8:3\n     usecs               : count    distribution\n\
                   \x20        2 -> 3          : 7        |***|\n\
                   pid = 945 lockstep\n     usecs               : count    distribution\n\
                   \x20        2 -> 3          : 70       |***|\n\
                   \x20     4096 -> 8191       : 30       |***|\n\
                   disk = nvme0n1\t\n     usecs               : count    distribution\n\
                   \x20      512 -> 1023       : 1        |***|\n";
        let v = histograms(lines(out), 2);
        assert_eq!(v["histograms_total"], 3);
        let hs = v["histograms"].as_array().unwrap();
        assert_eq!(hs.len(), 2);
        assert_eq!(hs[0]["pid"], 945);
        assert_eq!(hs[0]["comm"], "lockstep");
        assert_eq!(hs[0]["p99"], 8191);
        assert_eq!(hs[0]["p50"], 3);
    }

    fn opts(key: &[&str]) -> TraceOptions {
        TraceOptions { seconds: 10.0, key: key.iter().map(|s| s.to_string()).collect(), top: 20, examples: 1, ..Default::default() }
    }

    #[test]
    fn execsnoop_grouped_by_template() {
        let e = entry("execsnoop").unwrap();
        let Kind::Events { pattern, numeric } = e.kind else { panic!() };
        let out = "PCOMM            PID    PPID   RET ARGS\n\
                   tmux: server     100    1        0 /usr/bin/true 1\n\
                   sh               101    100      0 /bin/sh -c sleep 5\n\
                   sh               102    100      0 /bin/sh -c sleep 17\n\
                   beat-probe-kid   103    999      0 /x\n\
                   lost 3 events on CPU #1\n";
        let own: HashSet<u64> = [999].into();
        let mut r = Reducer::new(&opts(&["comm", "args:template"]), numeric).unwrap();
        r.feed(lines(out), &Regex::new(pattern).unwrap(), &own);
        let v = r.finish(10.0);
        assert_eq!(v["events"]["seen"], 4);
        assert_eq!(v["events"]["own_left_out"], 1);
        assert_eq!(v["events"]["unparsed"], 1, "the lost line");
        let g = &v["groups"][0];
        assert_eq!(g["key"], json!({"comm": "sh", "args:template": "/bin/sh -c sleep <N>"}));
        assert_eq!(g["count"], 2);
        assert_eq!(g["examples"][0]["pid"], 101, "whole numbers stay integers");
        assert_eq!(v["groups"][1]["key"]["comm"], "tmux: server", "a comm with a space");
    }

    #[test]
    fn filters_coarsening_sums_and_hist() {
        let e = entry("tcplife").unwrap();
        let Kind::Events { pattern, numeric } = e.kind else { panic!() };
        let out = "PID     COMM             LADDR           LPORT RADDR           RPORT TX_KB  RX_KB  MS\n\
                   10      lockstep         10.0.0.1        20007 10.0.0.2        5000  64     64     3.5\n\
                   11      lockstep         10.0.0.1        20008 10.0.1.9        5000  10     0      900.0\n\
                   12      curl             10.0.0.1        40000 10.0.0.3        80    1      2      1.0\n";
        let mut o = opts(&["raddr:/24"]);
        o.filter.insert("comm".into(), json!("lock*"));
        o.sum = vec!["tx_kb".into()];
        o.hist = Some("ms".into());
        let mut r = Reducer::new(&o, numeric).unwrap();
        r.feed(lines(out), &Regex::new(pattern).unwrap(), &HashSet::new());
        let v = r.finish(10.0);
        assert_eq!(v["events"]["matched"], 2);
        assert_eq!(v["keys"]["distinct"], 2);
        let g: Vec<&Value> = v["groups"].as_array().unwrap().iter().collect();
        assert!(g.iter().any(|g| g["key"]["raddr:/24"] == "10.0.1.0/24" && g["sum"]["tx_kb"] == 10.0 && g["hist"]["max"] == 1023));
        assert!(Reducer::new(&TraceOptions { sum: vec!["comm".into()], ..opts(&[]) }, numeric).is_err(), "sum of a text field");
    }

    #[test]
    fn path_coarsening() {
        let k = KeySpec::parse("path:dir2").unwrap();
        assert_eq!(k.apply("/proc/123/stat", &[]), "/proc/123/");
        assert_eq!(k.apply("/etc/hosts", &[]), "/etc/hosts");
        assert!(KeySpec::parse("path:dirs").is_err());
    }

    #[test]
    fn argv_checks_options() {
        let d = Path::new("/c");
        let mut o = TraceOptions { seconds: 5.0, ..Default::default() };
        o.options.insert("per_disk".into(), json!(true));
        assert_eq!(argv(d, entry("biolatency").unwrap(), &o).unwrap(), ["/c/biolatency", "-D", "5", "1"]);
        o.options.insert("nope".into(), json!(true));
        assert!(argv(d, entry("biolatency").unwrap(), &o).is_err());
        let mut o = TraceOptions { seconds: 3.0, ..Default::default() };
        o.options.insert("pid".into(), json!(42));
        assert_eq!(argv(d, entry("opensnoop").unwrap(), &o).unwrap(), ["/c/timeout", "-s", "INT", "3", "/c/opensnoop", "-p", "42"]);
        o.options.insert("pid".into(), json!("-x"));
        assert!(argv(d, entry("opensnoop").unwrap(), &o).is_err(), "no flags smuggled in as values");
        assert!(argv(d, entry("opensnoop").unwrap(), &TraceOptions { seconds: 0.5, ..Default::default() }).is_err());
        assert_eq!(capabilities(["biolatency", "execsnoop", "nope"]), ["CAP_BPF", "CAP_PERFMON"]);
    }
}
