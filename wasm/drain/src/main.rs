//! `drain`: log lines on stdin, a JSON summary of their templates on stdout (docs/security.md C21).
//!
//!   drain [--sim F] [--depth N] [--header N] [--self NAME]... [--mask NAME=REGEX]... [--no-default-masks] [--templates JSON]
//!         [--cap N] [--examples N] [--raw-examples] [--top N] [--max-line BYTES] [--max-tokens N] [--minutes N] [--levels N]
//!   drain --extract [--templates JSON] [--grep REGEX] [--limit N] [--first] [mask options as above]
//!
//! A probe feeds it a file (`pipe(["cat", log], ["drain"])`) or journal messages (`drain(stdin = ...)`). Nothing is
//! kept between runs: the summary is of this window only.
//!
//! 1. Masks: shapes that never carry a message's meaning become named tokens before mining (`<UUID>`, `<TIME>`,
//!    `<IP>`, `<PID>`, `<HEX>`; decisions L3, L13): `from 10.0.0.1 port 22` → `from <IP> port 22`. The host's own
//!    names (--self: hostname, addresses) become `<SELF>`, or a syslog header's hostname would make every host's
//!    templates different. A mask with a group named `v` replaces only that group (`sshd[<PID>]:`). Done here, not
//!    in the crate, because Rust's regex has no lookaround and some masks need checks a regex cannot make.
//! 2. Templates, one of two ways:
//!    - mined (no --templates): Drain over the window (the `drain3` crate, checked against Python Drain3),
//!      then every line matched against the final templates, so its parameters are read against them;
//!    - curated (--templates '["template", ...]'): the given templates only, matched exactly (`<*>` matches one
//!      token), so answers from different hosts name the same templates; lines that match none are mined
//!      separately and reported as `"new": true`.
//! 3. Per template: a stable id (FNV-1a of its text: equal across hosts and runs), its text, the lines it matched,
//!    per parameter (`<*>`) its distinct values with counts (the `cap` most frequent) and min/max when all are
//!    numbers, the first `examples` lines (masked unless --raw-examples), and `minutes`: its lines per minute,
//!    `[[minute, count], ...]`, so a template is a time series and a window is a sum over minutes (decision L17).
//!    A parameter with 2 to --levels (12) distinct values is categorical (a status, a method, a level): all its
//!    values are reported, `"categorical": true`, and `minutes` counts each value per minute,
//!    `[[minute, [[value, count], ...]], ...]` (503s per minute). Wider parameters (ids, pids, sizes) only have their
//!    `cap` most frequent values: counting them per minute would mostly repeat each line.
//!
//! Minutes: a line's minute is its time (the first <TIME> mask match) cut after the minutes, normalized where the
//! line says enough: `2026-10-11T13:49` from ISO times and from `2026/10/11 13:49:04` (nginx error log) or
//! `11/Oct/2026:13:49:04` (nginx access log); `Oct 11 13:49` (syslog: no year) and `13:49` (a clock only) are left
//! for the reader to place, against when the summary was made. Zones are not applied (as written: the hosts' local
//! time). Only the last --minutes (60) distinct minutes of the input are reported, for every template; lines with
//! no time, or in earlier minutes, count only in `count`.
//!
//! --header N: the first N tokens (after masking) are a header that every line has, e.g. syslog's
//! `<TIME> <SELF> sshd[<PID>]:` (3). Drain's prefix tree routes by the first depth-2 tokens, so a header makes
//! unrelated messages share a branch and merge; --header adds N to the depth (21 templates with the header
//! at depth 4, 23 at depth 7, as many as the messages alone at depth 4).
//!
//! --extract: instead of a summary, the lines themselves, as they are (not masked: C22), that match any of the
//! --templates and the --grep regex (either may be left out): `{"matched": N, "lines": [...]}` with the last
//! --limit (20) of them, or the first with --first.
//!
//! Both say what they covered: `"span": {"lines_read", "first_time", "last_time"}` (the times as written in the
//! first and last lines that have one; null when no line has a time).
//!
//! Lines longer than --max-line bytes or --max-tokens tokens are counted, not mined (`skipped`).
use std::collections::{BTreeMap, BTreeSet};
use std::io::{self, Read, Write};

use regex::{Captures, Regex};
use serde_json::{json, Value};

/// The crate's default tokenizer splits on single spaces (`Jul  1` is three tokens); with any extra delimiter it
/// splits on runs of whitespace, as Python Drain3 does. A tab is the delimiter that changes nothing else.
const DELIMITERS: [&str; 1] = ["\t"];

struct Mask {
    name: String,
    re: Regex,
    /// A check on the match and the text around it, for what a regex without lookaround cannot say.
    check: fn(&str, usize, usize) -> bool,
}

fn any(_: &str, _: usize, _: usize) -> bool {
    true
}

/// Not part of a longer dotted or word token: `10.0.0.1`, not `v1.2.3.4` or `1.2.3.4.5`.
fn standalone(s: &str, start: usize, end: usize) -> bool {
    let word = |c: char| c.is_alphanumeric() || c == '_' || c == '.';
    !s[..start].chars().next_back().is_some_and(word) && !s[end..].chars().next().is_some_and(word)
}

/// Hex with both a digit and a letter: `a03f2a2b`, not `deadbeef` or `20261007`.
fn mixed_hex(s: &str, start: usize, end: usize) -> bool {
    let m = &s[start..end];
    m.bytes().any(|b| b.is_ascii_digit()) && m.bytes().any(|b| b.is_ascii_alphabetic())
}

fn default_masks() -> Vec<Mask> {
    let m = |name: &str, re: &str, check: fn(&str, usize, usize) -> bool| Mask {
        name: name.into(),
        re: Regex::new(re).unwrap(),
        check,
    };
    vec![
        m("UUID", r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b", any),
        // 2026-10-07T12:00:01.5Z, 2026-10-07 12:00:01+02:00, 2026-10-07
        m("TIME", r"\b\d{4}-\d{2}-\d{2}(?:[T ]\d{2}:\d{2}(?::\d{2}(?:[.,]\d+)?)?(?:Z|[+-]\d{2}:?\d{2})?)?\b", any),
        // Sun Jul  3 04:27:01 2005, Jul 3 04:27:01, Jul 3
        m("TIME", r"\b(?:(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun)\w*,? +)?(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\w* +\d{1,2}(?: +\d{1,2}:\d{2}(?::\d{2})?)?(?: +\d{4})?\b", any),
        m("IP", r"(?:\d{1,3}\.){3}\d{1,3}(?::\d{1,5})?", standalone),
        m("TIME", r"\b\d{1,2}:\d{2}:\d{2}(?:[.,]\d+)?\b", any),
        // syslog's program[pid]: keeps the program, masks the pid
        m("PID", r"\w\[(?P<v>\d+)\]:", any),
        m("HEX", r"\b0[xX][0-9a-fA-F]+\b", any),
        m("HEX", r"\b[0-9a-fA-F]{8,}\b", mixed_hex),
    ]
}

fn mask(masks: &[Mask], line: &str) -> String {
    let mut out = line.to_string();
    for m in masks {
        let token = format!("<{}>", m.name);
        let src = out.clone();
        out = m
            .re
            .replace_all(&src, |c: &Captures| {
                let all = c.get(0).unwrap();
                // a mask with a group named v replaces only that group: sshd[4711]: -> sshd[<PID>]:
                let g = c.name("v").unwrap_or(all);
                if !(m.check)(&src, g.start(), g.end()) {
                    return all.as_str().to_string();
                }
                format!("{}{}{}", &src[all.start()..g.start()], token, &src[g.end()..all.end()])
            })
            .into_owned();
    }
    out
}

/// FNV-1a, 64 bits: a template's id is a function of its text only.
fn template_id(text: &str) -> String {
    let mut h: u64 = 0xcbf29ce484222325;
    for b in text.bytes() {
        h ^= b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    format!("{h:016x}")
}

fn render(t: &drain3::Template) -> String {
    // tokens() holds only the literal tokens; parameter positions come from is_param
    let mut lit = t.tokens().iter();
    (0..t.token_count())
        .map(|i| if t.is_param(i) { "<*>".to_string() } else { lit.next().unwrap().to_string() })
        .collect::<Vec<_>>()
        .join(" ")
}

struct Settings {
    extract: bool,
    grep: Option<Regex>,
    limit: usize,
    first: bool,
    sim: f64,
    depth: usize,
    masks: Vec<Mask>,
    templates: Option<Vec<String>>,
    cap: usize,
    examples: usize,
    raw_examples: bool,
    top: usize,
    max_line: usize,
    max_tokens: usize,
    minutes: usize,
    levels: usize,
}

fn config(s: &Settings, sim: f64) -> drain3::Config {
    drain3::Config::builder()
        .similarity_threshold(sim)
        .depth(s.depth)
        .max_tokens(s.max_tokens)
        .max_bytes(s.max_line * 2) // masking can lengthen a line a little; the limit is applied before (skipped)
        .extra_delimiters(DELIMITERS.iter().map(|d| d.to_string()).collect())
        .build()
}

/// What one template collected: lines, parameter values by position (in total and per minute), example lines.
#[derive(Default)]
struct Acc {
    count: u64,
    params: Vec<BTreeMap<String, u64>>,
    param_minutes: Vec<BTreeMap<(String, String), u64>>, // (minute, value) -> lines
    examples: Vec<String>,
    new: bool,
    minutes: BTreeMap<String, u64>,
}

impl Acc {
    fn add(&mut self, args: Vec<String>, example: &str, minute: Option<&String>, s: &Settings) {
        self.count += 1;
        if let Some(m) = minute {
            *self.minutes.entry(m.clone()).or_default() += 1;
        }
        if self.params.len() < args.len() {
            self.params.resize_with(args.len(), BTreeMap::new);
            self.param_minutes.resize_with(args.len(), BTreeMap::new);
        }
        for (i, a) in args.into_iter().enumerate() {
            if let Some(m) = minute {
                *self.param_minutes[i].entry((m.clone(), a.clone())).or_default() += 1;
            }
            *self.params[i].entry(a).or_default() += 1;
        }
        if self.examples.len() < s.examples {
            self.examples.push(example.to_string());
        }
    }

    fn json(&self, text: &str, s: &Settings, kept: &BTreeSet<String>) -> Value {
        let params: Vec<Value> = self
            .params
            .iter()
            .zip(&self.param_minutes)
            .map(|(vals, per_minute)| {
                let mut top: Vec<(&String, &u64)> = vals.iter().collect();
                top.sort_by(|a, b| b.1.cmp(a.1).then(a.0.cmp(b.0)));
                let nums: Vec<f64> = vals.keys().filter_map(|v| v.parse::<f64>().ok()).collect();
                let categorical = (2..=s.levels).contains(&vals.len());
                let mut p = json!({
                    "distinct": vals.len(),
                    "values": top.iter().take(if categorical { vals.len() } else { s.cap }).map(|(v, c)| json!([v, c])).collect::<Vec<_>>(),
                });
                if categorical {
                    let mut by: BTreeMap<&String, Vec<Value>> = BTreeMap::new();
                    for ((m, v), c) in per_minute.iter().filter(|((m, _), _)| kept.contains(m)) {
                        by.entry(m).or_default().push(json!([v, c]));
                    }
                    p["categorical"] = json!(true);
                    p["minutes"] = json!(by.into_iter().map(|(m, vs)| json!([m, vs])).collect::<Vec<_>>());
                }
                if !nums.is_empty() && nums.len() == vals.len() {
                    let min = nums.iter().cloned().fold(f64::INFINITY, f64::min);
                    let max = nums.iter().cloned().fold(f64::NEG_INFINITY, f64::max);
                    p["min"] = json!(min);
                    p["max"] = json!(max);
                }
                p
            })
            .collect();
        let mut t = json!({
            "id": template_id(text),
            "template": text,
            "count": self.count,
            "params": params,
            "examples": self.examples,
            "minutes": self.minutes.iter().filter(|(m, _)| kept.contains(*m)).map(|(m, c)| json!([m, c])).collect::<Vec<_>>(),
        });
        if self.new {
            t["new"] = json!(true);
        }
        t
    }
}

/// Mines `lines` (masked, original) and adds each line to its template's accumulator.
type Line = (String, String, Option<String>); // masked, as written, its minute

fn mine(lines: &[Line], s: &Settings, new: bool, acc: &mut BTreeMap<String, Acc>) -> Result<(), String> {
    if lines.is_empty() {
        return Ok(());
    }
    let masked: Vec<String> = lines.iter().map(|(m, _, _)| m.clone()).collect();
    let m = drain3::train(&masked, config(s, s.sim)).map_err(|e| e.to_string())?;
    let text: BTreeMap<usize, String> = m.templates().iter().map(|t| (t.id(), render(t))).collect();
    for (masked, raw, minute) in lines {
        let (id, args, ok) = m.match_line(masked);
        // a mined line always matches its own final template; this is a guard, not a path
        let key = if ok { text[&id].clone() } else { masked.clone() };
        let a = acc.entry(key).or_default();
        a.new |= new;
        a.add(if ok { args } else { vec![] }, if s.raw_examples { raw } else { masked }, minute.as_ref(), s);
    }
    Ok(())
}

/// The curated templates, each parsed as its own (similarity 1.0: no two merge), for exact matching: `<*>` matches
/// one token. Returns the matcher and the templates' text by the crate's ids.
fn curated(seeds: &[String], s: &Settings) -> Result<(drain3::Matcher, BTreeMap<usize, String>), String> {
    let seeds: Vec<String> = seeds.iter().cloned().collect::<BTreeSet<_>>().into_iter().collect();
    let m = drain3::train(&seeds, config(s, 1.0)).map_err(|e| format!("templates: {e}"))?;
    let text: BTreeMap<usize, String> = m.templates().iter().map(|t| (t.id(), render(t))).collect();
    if text.len() != seeds.len() {
        return Err(format!("templates: {} given, {} distinct after parsing", seeds.len(), text.len()));
    }
    Ok((m, text))
}

/// What a summary or extract covered: lines read (all of them, skipped ones too) and the first and last time found
/// in them (the first <TIME> mask match of the first and last lines that have one, as written). Two calls over the
/// same file can cover different stretches of it (a tail and the whole file; a live file that grew in between);
/// the span makes that visible in the answer.
fn span(input: &str, masks: &[Mask]) -> Value {
    let time = |line: &str| time(masks, line);
    let lines: Vec<&str> = input.lines().filter(|l| !l.trim().is_empty()).collect();
    json!({
        "lines_read": lines.len(),
        "first_time": lines.iter().find_map(|l| time(l)),
        "last_time": lines.iter().rev().find_map(|l| time(l)),
    })
}

/// A line's time as written: the first <TIME> mask match.
fn time(masks: &[Mask], line: &str) -> Option<String> {
    masks.iter().filter(|m| m.name == "TIME").find_map(|m| {
        m.re.find_iter(line).find(|g| (m.check)(line, g.start(), g.end())).map(|g| g.as_str().to_string())
    })
}

const MONTHS: [&str; 12] = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];

/// A line's minute (the module docs): `2026-10-11T13:49`, `Oct 11 13:49` or `13:49`; None without a clock time.
fn minute(masks: &[Mask], line: &str) -> Option<String> {
    use std::sync::OnceLock;
    static RE: OnceLock<[Regex; 4]> = OnceLock::new();
    let [clock, iso, ymd, dmy] = RE.get_or_init(|| {
        [
            Regex::new(r"(\d{1,2}):(\d{2})").unwrap(),
            Regex::new(r"^(\d{4}-\d{2}-\d{2})[T ]").unwrap(),
            Regex::new(r"\b(\d{4})/(\d{2})/(\d{2})[ T:]\d{1,2}:\d{2}").unwrap(),
            Regex::new(r"\b(\d{1,2})/([A-Z][a-z]{2})/(\d{4}):\d{1,2}:\d{2}").unwrap(),
        ]
    });
    let t = time(masks, line)?;
    let c = clock.captures(&t)?;
    let hm = format!("{:0>2}:{}", &c[1], &c[2]);
    if let Some(d) = iso.captures(&t) {
        return Some(format!("{}T{hm}", &d[1]));
    }
    if let Some(d) = ymd.captures(line) {
        return Some(format!("{}-{}-{}T{hm}", &d[1], &d[2], &d[3]));
    }
    if let Some(d) = dmy.captures(line) {
        if let Some(i) = MONTHS.iter().position(|m| *m == &d[2]) {
            return Some(format!("{}-{:02}-{:0>2}T{hm}", &d[3], i + 1, &d[1]));
        }
    }
    let before = t[..c.get(0).unwrap().start()].trim();
    if !before.is_empty() && MONTHS.iter().any(|m| before.starts_with(m)) {
        return Some(format!("{before} {hm}").split_whitespace().collect::<Vec<_>>().join(" "));
    }
    Some(hm)
}

fn extract(input: &str, s: &Settings) -> Result<Value, String> {
    let m = match &s.templates {
        Some(seeds) => Some(curated(seeds, s)?.0),
        None => None,
    };
    let mut matched = 0u64;
    let mut kept = std::collections::VecDeque::new();
    for raw in input.lines() {
        let raw = raw.strip_suffix('\r').unwrap_or(raw);
        if raw.trim().is_empty() || raw.len() > s.max_line {
            continue;
        }
        if s.grep.as_ref().is_some_and(|g| !g.is_match(raw)) {
            continue;
        }
        if m.as_ref().is_some_and(|m| !m.match_line(&mask(&s.masks, raw)).2) {
            continue;
        }
        matched += 1;
        if s.first && kept.len() >= s.limit {
            continue;
        }
        kept.push_back(raw.to_string());
        if kept.len() > s.limit {
            kept.pop_front();
        }
    }
    Ok(json!({"matched": matched, "lines": kept, "span": span(input, &s.masks)}))
}

fn summarize(input: &str, s: &Settings) -> Result<Value, String> {
    let mut lines = Vec::new();
    let (mut too_long, mut empty) = (0u64, 0u64);
    for raw in input.lines() {
        let raw = raw.strip_suffix('\r').unwrap_or(raw);
        if raw.trim().is_empty() {
            empty += 1;
        } else if raw.len() > s.max_line || raw.split_whitespace().count() > s.max_tokens {
            too_long += 1;
        } else {
            lines.push((mask(&s.masks, raw), raw.to_string(), minute(&s.masks, raw)));
        }
    }
    // the last `minutes` distinct minutes, in the order the input has them (a log is written in time order)
    let (mut seen, mut known): (Vec<&String>, BTreeSet<&String>) = (Vec::new(), BTreeSet::new());
    for m in lines.iter().filter_map(|(_, _, m)| m.as_ref()) {
        if known.insert(m) {
            seen.push(m);
        }
    }
    let kept: BTreeSet<String> = seen[seen.len().saturating_sub(s.minutes)..].iter().map(|m| m.to_string()).collect();
    let mut acc: BTreeMap<String, Acc> = BTreeMap::new();
    match &s.templates {
        None => mine(&lines, s, false, &mut acc)?,
        Some(seeds) => {
            let (m, text) = curated(seeds, s)?;
            for t in text.values() {
                acc.entry(t.clone()).or_default();
            }
            let mut rest = Vec::new();
            for (masked, raw, minute) in lines {
                let (id, args, ok) = m.match_line(&masked);
                if ok {
                    acc.get_mut(&text[&id]).unwrap().add(args, if s.raw_examples { &raw } else { &masked }, minute.as_ref(), s);
                } else {
                    rest.push((masked, raw, minute));
                }
            }
            mine(&rest, s, true, &mut acc)?;
        }
    }
    let total: u64 = acc.values().map(|a| a.count).sum();
    let mut order: Vec<(&String, &Acc)> = acc.iter().collect();
    // curated templates are all reported, matched or not; mined ones by count, the `top` most frequent
    order.sort_by(|a, b| b.1.count.cmp(&a.1.count).then(a.0.cmp(b.0)));
    let curated = s.templates.is_some();
    let (shown, omitted): (Vec<_>, Vec<_>) = order
        .into_iter()
        .enumerate()
        .partition(|(i, (_, a))| (curated && !a.new) || *i < s.top);
    Ok(json!({
        "span": span(input, &s.masks),
        "lines": total,
        "skipped": {"too_long": too_long, "empty": empty},
        "templates": shown.iter().map(|(_, (t, a))| a.json(t, s, &kept)).collect::<Vec<_>>(),
        "omitted": {
            "templates": omitted.len(),
            "lines": omitted.iter().map(|(_, (_, a))| a.count).sum::<u64>(),
        },
        "settings": {
            "sim": s.sim, "depth": s.depth, "cap": s.cap, "examples": s.examples, "raw_examples": s.raw_examples,
            "masks": s.masks.iter().map(|m| json!([m.name, m.re.as_str()])).collect::<Vec<_>>(),
            "curated": s.templates.as_ref().map(|t| t.len()), "minutes": s.minutes, "levels": s.levels,
        },
    }))
}

fn parse(args: &[String]) -> Result<Settings, String> {
    let mut s = Settings {
        extract: false,
        grep: None,
        limit: 20,
        first: false,
        sim: 0.4,
        depth: 4,
        masks: default_masks(),
        templates: None,
        cap: 8,
        examples: 3,
        raw_examples: false,
        top: 200,
        max_line: 4096,
        max_tokens: 256,
        minutes: 60,
        levels: 12,
    };
    let mut extra = Vec::new();
    let mut selves: Vec<String> = Vec::new();
    let mut header = 0;
    let mut it = args.iter();
    while let Some(a) = it.next() {
        let mut val = || it.next().ok_or(format!("{a} needs a value"));
        let num = |v: &String| v.parse::<usize>().map_err(|_| format!("{a}: not a number: {v}"));
        match a.as_str() {
            "--sim" => s.sim = val()?.parse().map_err(|_| format!("{a}: not a number"))?,
            "--depth" => s.depth = num(val()?)?,
            "--header" => header = num(val()?)?,
            "--cap" => s.cap = num(val()?)?,
            "--examples" => s.examples = num(val()?)?,
            "--top" => s.top = num(val()?)?,
            "--max-line" => s.max_line = num(val()?)?,
            "--max-tokens" => s.max_tokens = num(val()?)?,
            "--minutes" => s.minutes = num(val()?)?,
            "--levels" => s.levels = num(val()?)?,
            "--raw-examples" => s.raw_examples = true,
            "--extract" => s.extract = true,
            "--first" => s.first = true,
            "--limit" => s.limit = num(val()?)?,
            "--grep" => s.grep = Some(Regex::new(val()?).map_err(|e| format!("--grep: {e}"))?),
            "--no-default-masks" => s.masks.clear(),
            "--self" => selves.push(val()?.clone()),
            "--mask" => {
                let v = val()?;
                let (name, re) = v.split_once('=').ok_or(format!("--mask NAME=REGEX, got {v}"))?;
                let re = Regex::new(re).map_err(|e| format!("--mask {name}: {e}"))?;
                extra.push(Mask { name: name.into(), re, check: any });
            }
            "--templates" => {
                let v = val()?;
                let t: Vec<String> = serde_json::from_str(v).map_err(|e| format!("--templates: {e}"))?;
                s.templates = Some(t);
            }
            _ => return Err(format!("unknown argument {a}")),
        }
    }
    // the host's own names first, longest first, as whole words (<self>); then the shapes; then the probe's own
    selves.sort_by_key(|n| std::cmp::Reverse(n.len()));
    let mut masks: Vec<Mask> = selves
        .iter()
        .filter(|n| !n.is_empty())
        .map(|n| Mask { name: "SELF".into(), re: Regex::new(&format!(r"\b{}\b", regex::escape(n))).unwrap(), check: standalone })
        .collect();
    masks.append(&mut s.masks);
    masks.extend(extra);
    s.masks = masks;
    s.depth += header;
    Ok(s)
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let run = || -> Result<Value, String> {
        let s = parse(&args)?;
        let mut buf = Vec::new();
        io::stdin().read_to_end(&mut buf).map_err(|e| e.to_string())?;
        let input = String::from_utf8_lossy(&buf);
        if s.extract { extract(&input, &s) } else { summarize(&input, &s) }
    };
    match run() {
        Ok(v) => {
            let mut out = io::stdout().lock();
            serde_json::to_writer(&mut out, &v).unwrap();
            writeln!(out).unwrap();
        }
        Err(e) => {
            eprintln!("drain: {e}");
            std::process::exit(2);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(input: &str, args: &[&str]) -> Value {
        let s = parse(&args.iter().map(|a| a.to_string()).collect::<Vec<_>>()).unwrap();
        if s.extract { extract(input, &s).unwrap() } else { summarize(input, &s).unwrap() }
    }

    fn templates(v: &Value) -> Vec<String> {
        v["templates"].as_array().unwrap().iter().map(|t| t["template"].as_str().unwrap().to_string()).collect()
    }

    #[test]
    fn minutes_from_each_time_format() {
        let m = default_masks();
        let at = |l: &str| minute(&m, l);
        assert_eq!(at("2026-10-11 13:49:04,064 ERROR x").as_deref(), Some("2026-10-11T13:49"));
        assert_eq!(at("2026/10/11 13:49:04 [error] 625#625: x").as_deref(), Some("2026-10-11T13:49"));
        assert_eq!(at("10.0.0.1 - - [11/Oct/2026:03:49:04 +0000] \"GET / HTTP/1.1\" 200").as_deref(), Some("2026-10-11T03:49"));
        assert_eq!(at("Oct  1 13:49:04 web-1 sshd[1]: x").as_deref(), Some("Oct 1 13:49"));
        assert_eq!(at("[3:49:04] worker up").as_deref(), Some("03:49"));
        assert_eq!(at("no time here"), None);
        assert_eq!(at("on 2026-10-11 only a date"), None);
    }

    #[test]
    fn templates_count_lines_per_minute_for_the_last_minutes() {
        let log = "2026-10-11 13:48:59 ERROR pool exhausted\n2026-10-11 13:49:01 ERROR pool exhausted\n\
                   2026-10-11 13:49:30 ERROR pool exhausted\n2026-10-11 13:50:02 INFO ok\n- ERROR pool exhausted\n";
        let curated = r#"["<*> ERROR pool exhausted", "<*> INFO ok"]"#;
        let v = run(log, &["--templates", curated]);
        let t = |name: &str| v["templates"].as_array().unwrap().iter().find(|t| t["template"].as_str().unwrap().contains(name)).unwrap().clone();
        assert_eq!(t("pool")["count"], 4);  // the line with no time counts, in no minute
        assert_eq!(t("pool")["minutes"], json!([["2026-10-11T13:48", 1], ["2026-10-11T13:49", 2]]));
        assert_eq!(t("ok")["minutes"], json!([["2026-10-11T13:50", 1]]));
        let v = run(log, &["--templates", curated, "--minutes", "2"]);  // the last 2 minutes of the input: 13:49 and 13:50
        let pool = v["templates"].as_array().unwrap().iter().find(|t| t["template"].as_str().unwrap().contains("pool")).unwrap().clone();
        assert_eq!(pool["minutes"], json!([["2026-10-11T13:49", 2]]));
    }

    #[test]
    fn categorical_parameters_are_counted_per_minute() {
        let log = "2026-10-11 15:16:01 GET 200 id=1\n2026-10-11 15:16:02 GET 503 id=2\n2026-10-11 15:16:03 GET 503 id=3\n\
                   2026-10-11 15:17:01 GET 200 id=4\n2026-10-11 15:17:02 GET 200 id=5\n";
        let v = run(log, &["--templates", r#"["<*> GET <*> <*>"]"#, "--levels", "4", "--cap", "2"]);
        let p = &v["templates"][0]["params"];
        assert_eq!(p[1]["categorical"], true);
        assert_eq!(p[1]["minutes"], json!([["2026-10-11T15:16", [["200", 1], ["503", 2]]], ["2026-10-11T15:17", [["200", 2]]]]));
        assert_eq!(p[2]["distinct"], 5);  // ids: wider than --levels, the cap most frequent only, not per minute
        assert_eq!(p[2]["values"].as_array().unwrap().len(), 2);
        assert!(p[2].get("minutes").is_none() && p[2].get("categorical").is_none());
        let v = run("2026-10-11 15:16:01 GET 200 id=1\n", &["--templates", r#"["<*> GET <*> <*>"]"#]);
        assert!(v["templates"][0]["params"][1].get("minutes").is_none());  // one value: the template says it already
    }

    #[test]
    fn masks_name_shapes() {
        let m = default_masks();
        assert_eq!(mask(&m, "from 10.0.0.1:22 at Jul  3 04:27:01 2005"), "from <IP> at <TIME>");
        assert_eq!(mask(&m, "v1.2.3.4 build a03f2a2b deadbeef"), "v1.2.3.4 build <HEX> deadbeef");
        assert_eq!(mask(&m, "unit run-6f1e7c1a-0b2d-4c3e-9f4a-5b6c7d8e9f00.scope"), "unit run-<UUID>.scope");
    }

    #[test]
    fn syslog_headers_compare_across_hosts() {
        let a = run("Dec 10 06:55:46 web-1 sshd[24200]: Invalid user admin from 10.0.0.9\n", &["--self", "web-1"]);
        let b = run("Dec 10 07:01:02 web-2 sshd[911]: Invalid user oracle from 10.0.0.7\n", &["--self", "web-2"]);
        assert_eq!(templates(&a), vec!["<TIME> <SELF> sshd[<PID>]: Invalid user admin from <IP>"]);
        assert_eq!(a["templates"][0]["id"].as_str().unwrap().len(), 16);
        let (ta, tb) = (&templates(&a)[0], &templates(&b)[0]);
        assert_eq!(ta.replace("admin", "x"), tb.replace("oracle", "x"));
    }

    #[test]
    fn double_spaces_do_not_make_tokens() {
        let v = run("Invalid user  0101 from a\nInvalid user webmaster from b\n", &[]);
        assert_eq!(templates(&v), vec!["Invalid user <*> from <*>"]);
    }

    #[test]
    fn mined_parameters_are_summarized() {
        let v = run("batch 1 finished rows=5\nbatch 2 finished rows=7\nbatch 3 finished rows=5\n", &[]);
        let t = &v["templates"][0];
        assert_eq!(t["template"], "batch <*> finished <*>");
        assert_eq!(t["count"], 3);
        assert_eq!(t["params"][0]["min"], 1.0);
        assert_eq!(t["params"][1]["values"][0], json!(["rows=5", 2]));
        assert_eq!(t["id"], template_id("batch <*> finished <*>"));
    }

    #[test]
    fn curated_templates_compare_and_new_lines_are_mined() {
        let seeds = r#"["session opened for user <*>", "session closed for user <*>"]"#;
        let v = run("session opened for user root\nkernel: oops at 1\nkernel: oops at 2\n", &["--templates", seeds]);
        let t: BTreeMap<String, &Value> =
            v["templates"].as_array().unwrap().iter().map(|t| (t["template"].as_str().unwrap().into(), t)).collect();
        assert_eq!(t["session opened for user <*>"]["count"], 1);
        assert_eq!(t["session closed for user <*>"]["count"], 0); // curated: reported even when unmatched
        assert_eq!(t["kernel: oops at <*>"]["new"], true);
    }

    #[test]
    fn extracts_are_raw_lines_of_a_template_and_a_pattern() {
        let log = "Jul  1 10:00:00 h sshd[1]: Invalid user admin from 10.0.0.1\n\
                   Jul  1 10:00:01 h sshd[2]: Accepted password for root from 10.0.0.2\n\
                   Jul  1 10:00:02 h sshd[3]: Invalid user oracle from 10.0.0.3\n";
        let t = r#"["<TIME> <SELF> sshd[<PID>]: Invalid user <*> from <IP>"]"#;
        let v = run(log, &["--extract", "--self", "h", "--templates", t]);
        assert_eq!(v["matched"], 2);
        assert_eq!(v["lines"][1], "Jul  1 10:00:02 h sshd[3]: Invalid user oracle from 10.0.0.3");
        let v = run(log, &["--extract", "--grep", "root|oracle", "--limit", "1", "--first"]);
        assert_eq!(v["matched"], 2);
        assert_eq!(v["lines"], json!(["Jul  1 10:00:01 h sshd[2]: Accepted password for root from 10.0.0.2"]));
    }

    #[test]
    fn answers_say_what_they_covered() {
        let log = "2026-10-01 10:00:00,1 INFO a[1]: x\nno time here\n2026-10-07 15:35:44,4 INFO a[2]: y\n";
        for args in [&[][..], &["--extract"][..]] {
            let v = run(log, args);
            assert_eq!(v["span"]["lines_read"], 3);
            assert_eq!(v["span"]["first_time"], "2026-10-01 10:00:00,1");
            assert_eq!(v["span"]["last_time"], "2026-10-07 15:35:44,4");
        }
        assert_eq!(run("no time\n", &[])["span"]["first_time"], Value::Null);
    }

    #[test]
    fn long_lines_are_skipped_and_counted() {
        let v = run(&format!("{}\nshort line\n", "x".repeat(5000)), &[]);
        assert_eq!(v["skipped"]["too_long"], 1);
        assert_eq!(v["lines"], 1);
    }
}
