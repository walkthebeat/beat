//! Gate 1: what the run returns is scanned for secrets before it leaves the evaluator (docs/security.md).
//!
//! Rules are data: `rules/betterleaks.json` (converted from Betterleaks by `rules/convert.py`) and `rules/beat.json`
//! (host-shaped secrets those miss). A rule is a regex, its keywords, a confidence and reject filters. Keywords are
//! found in one pass; only rules whose keywords occur are compiled and run, so a run pays for the few rules its text
//! can match (16 of 466 on the S1 fixture host), not for all of them.
//!
//! What a match does follows its certainty:
//! - **mask** (confidence high): the secret is replaced by `«secret:<rule>:sha256:<12 hex>»`. Final: equality across
//!   hosts survives (a plain digest is safe for a value that cannot be guessed), the value does not.
//! - **flag** (medium, low): left as is and listed, for gate 2 at the collector to decide.
//! - **hash** (a rule's `action`): a known secret field of low entropy (a password in a DSN); listed for the
//!   collector to replace with a keyed hash (the service's gate 2).
//!
//! Scanned: record values, `print()` output and failure messages. Not scanned: subjects and keys (names the probe
//! chose: paths, field names). Consecutive records with the same subject and key (a file emitted line by line) are
//! scanned as one text, joined by newlines, so a secret over several lines (a PEM key) is still one match. The section is left out of the run result when nothing matched, so clean answers
//! hash as before.

use std::collections::{BTreeSet, HashMap};
use std::sync::OnceLock;

use regex::bytes::{Regex, RegexBuilder};
use serde::Deserialize;
use serde_json::{json, Value as Json};

use crate::builtins::RunState;

const BETTERLEAKS: &str = include_str!("../rules/betterleaks.json");
const BEAT: &str = include_str!("../rules/beat.json");
const SIZE_LIMIT: usize = 50 << 20;

#[derive(Debug, Deserialize)]
struct RuleFile {
    #[serde(default)]
    global: Option<Reject>,
    rules: Vec<Rule>,
}

#[derive(Debug, Default, Deserialize)]
struct Reject {
    max_entropy: Option<f64>,
    #[serde(default)]
    reject_regex: Vec<String>,
    #[serde(default)]
    reject_contains: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct Rule {
    id: String,
    regex: String,
    #[serde(default)]
    keywords: Vec<String>,
    confidence: String,
    #[serde(default)]
    action: Option<String>,
    group: Option<usize>,
    // The reject filters, as in Reject. Not `#[serde(flatten)]`: with serde_json's arbitrary_precision (enabled by a
    // dependency), a flattened f64 arrives as a map and fails to parse.
    max_entropy: Option<f64>,
    #[serde(default)]
    reject_regex: Vec<String>,
    #[serde(default)]
    reject_contains: Vec<String>,
}

struct Compiled {
    re: Regex,
    reject: Vec<Regex>,
}

pub struct Rules {
    rules: Vec<Rule>,
    global: Reject,
    global_re: Vec<Regex>,
    keywords: Option<regex::Regex>,
    by_keyword: HashMap<String, Vec<usize>>,
    always: Vec<usize>,
    compiled: Vec<OnceLock<Option<Compiled>>>,
}

/// One match: where the secret is in the text, and which rule found it.
#[derive(Debug, Clone, PartialEq)]
pub struct Finding {
    pub start: usize,
    pub end: usize,
    pub rule: usize,
}

pub fn rules() -> &'static Rules {
    static RULES: OnceLock<Rules> = OnceLock::new();
    RULES.get_or_init(|| {
        let bl: RuleFile = serde_json::from_str(BETTERLEAKS).expect("rules/betterleaks.json");
        let beat: RuleFile = serde_json::from_str(BEAT).expect("rules/beat.json");
        Rules::new(bl.rules.into_iter().chain(beat.rules).collect(), bl.global.unwrap_or_default())
    })
}

/// Byte regexes without Unicode classes: `\w`, `\s` and `\d` are ASCII, as in Go, whose syntax the Betterleaks rules
/// are written for. Also 28 times cheaper to compile (all 466 rules: 3.4 s with Unicode, 0.12 s without), which
/// matters because every run is a new process.
fn build(re: &str) -> Option<Regex> {
    RegexBuilder::new(re).unicode(false).size_limit(SIZE_LIMIT).build().ok()
}

/// Widens a byte span to the characters it touches: a byte regex may start or end inside a UTF-8 sequence.
fn snap(text: &str, mut start: usize, mut end: usize) -> (usize, usize) {
    while start > 0 && !text.is_char_boundary(start) {
        start -= 1;
    }
    while end < text.len() && !text.is_char_boundary(end) {
        end += 1;
    }
    (start, end)
}

/// Shannon entropy in bits per character, as Betterleaks computes it for its thresholds.
pub fn entropy(s: &str) -> f64 {
    let mut counts: HashMap<char, usize> = HashMap::new();
    let mut n = 0usize;
    for c in s.chars() {
        *counts.entry(c).or_default() += 1;
        n += 1;
    }
    if n == 0 {
        return 0.0;
    }
    counts.values().map(|&k| { let p = k as f64 / n as f64; -p * p.log2() }).sum()
}

impl Rules {
    fn new(rules: Vec<Rule>, global: Reject) -> Rules {
        let mut by_keyword: HashMap<String, Vec<usize>> = HashMap::new();
        let mut always = Vec::new();
        for (i, r) in rules.iter().enumerate() {
            if r.keywords.is_empty() {
                always.push(i);
            }
            for k in &r.keywords {
                by_keyword.entry(k.to_lowercase()).or_default().push(i);
            }
        }
        // Longest first, so that at one position the longer keyword is the one reported (all are checked anyway).
        let mut kws: Vec<&String> = by_keyword.keys().collect();
        kws.sort_by_key(|k| std::cmp::Reverse(k.len()));
        let alternation = kws.iter().map(|k| regex::escape(k)).collect::<Vec<_>>().join("|");
        let keywords = (!kws.is_empty()).then(|| {
            regex::RegexBuilder::new(&format!("(?i){alternation}")).size_limit(SIZE_LIMIT).build().expect("keyword regex")
        });
        let global_re = global.reject_regex.iter().filter_map(|r| build(r)).collect();
        let compiled = rules.iter().map(|_| OnceLock::new()).collect();
        Rules { rules, global, global_re, keywords, by_keyword, always, compiled }
    }

    pub fn len(&self) -> usize {
        self.rules.len()
    }

    pub fn id(&self, rule: usize) -> &str {
        &self.rules[rule].id
    }

    /// mask, flag or hash (module doc).
    pub fn action(&self, rule: usize) -> &str {
        let r = &self.rules[rule];
        match r.action.as_deref() {
            Some(a) => a,
            None if r.confidence == "high" => "mask",
            None => "flag",
        }
    }

    pub fn confidence(&self, rule: usize) -> &str {
        &self.rules[rule].confidence
    }

    /// Rules whose keywords occur in the text, and the rules without keywords.
    fn candidates(&self, text: &str) -> BTreeSet<usize> {
        let mut out: BTreeSet<usize> = self.always.iter().copied().collect();
        let Some(kw) = &self.keywords else { return out };
        let lower = text.to_lowercase(); // positions in it are not used: only which keywords occur
        for m in kw.find_iter(&lower) {
            // Keywords that start inside this match are not reported by find_iter: try each offset of it.
            for s in m.start()..m.end() {
                if !lower.is_char_boundary(s) {
                    continue;
                }
                let rest = &lower[s..];
                for (k, ids) in &self.by_keyword {
                    if rest.starts_with(k.as_str()) {
                        out.extend(ids.iter().copied());
                    }
                }
            }
        }
        out
    }

    fn compiled(&self, i: usize) -> Option<&Compiled> {
        self.compiled[i]
            .get_or_init(|| {
                let r = &self.rules[i];
                let re = build(&r.regex)?;
                let reject = r.reject_regex.iter().filter_map(|x| build(x)).collect();
                Some(Compiled { re, reject })
            })
            .as_ref()
    }

    fn rejected(&self, i: usize, c: &Compiled, secret: &str) -> bool {
        let r = &self.rules[i];
        let g = &self.global;
        let e = entropy(secret);
        r.max_entropy.is_some_and(|m| e <= m)
            || g.max_entropy.is_some_and(|m| e <= m)
            || c.reject.iter().any(|x| x.is_match(secret.as_bytes()))
            || self.global_re.iter().any(|x| x.is_match(secret.as_bytes()))
            || r.reject_contains.iter().chain(&g.reject_contains).any(|x| secret.contains(x.as_str()))
    }

    /// Every match in the text, after the reject filters. The secret is the rule's group, else the first group that
    /// took part in the match, else the whole match.
    pub fn scan(&self, text: &str) -> Vec<Finding> {
        let mut out = Vec::new();
        for i in self.candidates(text) {
            let Some(c) = self.compiled(i) else { continue };
            for caps in c.re.captures_iter(text.as_bytes()) {
                let m = match self.rules[i].group {
                    Some(g) => caps.get(g),
                    None => (1..caps.len()).find_map(|g| caps.get(g)).or_else(|| caps.get(0)),
                };
                let Some(m) = m else { continue };
                let (start, end) = snap(text, m.start(), m.end());
                let secret = &text[start..end];
                if secret.is_empty() || secret.contains("«secret:") || self.rejected(i, c, secret) {
                    continue;
                }
                out.push(Finding { start, end, rule: i });
            }
        }
        out
    }
}

pub fn marker(rule: &str, secret: &str) -> String {
    use sha2::Digest;
    let d = sha2::Sha256::digest(secret.as_bytes());
    let hex: String = d.iter().take(6).map(|b| format!("{b:02x}")).collect();
    format!("«secret:{rule}:sha256:{hex}»")
}

/// The text with every masking finding replaced by its marker. Overlapping masks merge into one (the first rule's).
pub fn mask(rules: &Rules, text: &str, findings: &[Finding]) -> String {
    let mut spans: Vec<&Finding> = findings.iter().filter(|f| rules.action(f.rule) == "mask").collect();
    spans.sort_by_key(|f| (f.start, std::cmp::Reverse(f.end)));
    let mut out = String::with_capacity(text.len());
    let mut at = 0;
    for f in spans {
        if f.start < at {
            continue; // inside a span already masked
        }
        out.push_str(&text[at..f.start]);
        out.push_str(&marker(rules.id(f.rule), &text[f.start..f.end]));
        at = f.end;
    }
    out.push_str(&text[at..]);
    out
}

/// Scans several fields as one text (joined by newlines) and masks each; appends what was found to the lists,
/// deduplicated per (where, rule). A finding over several fields is cut at their edges, each part masked on its own.
/// A flag over a span that is masked is dropped: what it pointed at is gone (`token=ghp_...` is a GitHub token to one
/// rule and a generic key to another).
fn gate_fields(rules: &Rules, fields: Vec<(String, &mut String)>, masked: &mut Vec<Json>, flagged: &mut Vec<Json>) {
    let mut joined = String::new();
    let mut starts = Vec::with_capacity(fields.len());
    for (i, (_, text)) in fields.iter().enumerate() {
        if i > 0 {
            joined.push('\n');
        }
        starts.push(joined.len());
        joined.push_str(text);
    }
    let findings = rules.scan(&joined);
    if findings.is_empty() {
        return;
    }
    let mut seen = BTreeSet::new();
    for (k, (at, text)) in fields.into_iter().enumerate() {
        let (s, e) = (starts[k], starts[k] + text.len());
        let local: Vec<Finding> = findings
            .iter()
            .filter(|f| f.start < e && f.end > s)
            .map(|f| Finding { start: f.start.max(s) - s, end: f.end.min(e) - s, rule: f.rule })
            .filter(|f| f.end > f.start)
            .collect();
        let masks: Vec<(usize, usize)> =
            local.iter().filter(|f| rules.action(f.rule) == "mask").map(|f| (f.start, f.end)).collect();
        for f in &local {
            let (id, action) = (rules.id(f.rule), rules.action(f.rule));
            if action != "mask" && masks.iter().any(|&(ms, me)| f.start < me && f.end > ms) {
                continue;
            }
            if !seen.insert((at.clone(), f.rule)) {
                continue;
            }
            if action == "mask" {
                masked.push(json!({"at": at, "rule": id}));
            } else {
                flagged.push(json!({"at": at, "rule": id, "confidence": rules.confidence(f.rule), "action": action}));
            }
        }
        if !local.is_empty() {
            *text = mask(rules, text, &local);
        }
    }
}

/// Gate 1 over a finished run: masks in place, returns the `secrets` section of the run result (None when clean).
pub fn gate(st: &mut RunState) -> Option<Json> {
    let rules = rules();
    let (mut masked, mut flagged) = (Vec::new(), Vec::new());
    let mut i = 0;
    while i < st.records.len() {
        let mut j = i + 1;
        while j < st.records.len()
            && st.records[j].subject == st.records[i].subject
            && st.records[j].key == st.records[i].key
        {
            j += 1;
        }
        let fields = st.records[i..j]
            .iter_mut()
            .enumerate()
            .map(|(k, r)| (format!("records[{}]", i + k), &mut r.value))
            .collect();
        gate_fields(rules, fields, &mut masked, &mut flagged);
        i = j;
    }
    for (i, f) in st.failures.iter_mut().enumerate() {
        gate_fields(rules, vec![(format!("failures[{i}]"), &mut f.message)], &mut masked, &mut flagged);
    }
    gate_fields(rules, vec![("diag".to_string(), &mut st.diag)], &mut masked, &mut flagged);
    if masked.is_empty() && flagged.is_empty() {
        return None;
    }
    Some(json!({"check": !flagged.is_empty(), "masked": masked, "flagged": flagged}))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_rule_compiles() {
        let r = rules();
        let bad: Vec<&str> = (0..r.len()).filter(|&i| r.compiled(i).is_none()).map(|i| r.id(i)).collect();
        assert!(bad.is_empty(), "rules that do not compile: {bad:?}");
        assert!(r.len() > 400);
    }

    /// A generated canary in a real token's shape, written in two parts so secret scanners (and GitHub's push
    /// protection) do not take this file for a leak.
    const GITHUB_CANARY: &str = concat!("ghp_", "ondpPLS5fGEQWQYcQ4EOJmkcm8Tw7h3hKAcu");

    #[test]
    fn high_confidence_is_masked() {
        let r = rules();
        let token = GITHUB_CANARY;
        let text = format!("GITHUB_TOKEN={token}\nORDERS=1");
        let f = r.scan(&text);
        let out = mask(r, &text, &f);
        assert!(!out.contains(token), "{out}");
        assert!(out.contains("«secret:github-pat:sha256:"), "{out}");
        assert!(out.ends_with("\nORDERS=1"));
        // The same secret masks to the same marker: equality across hosts survives.
        assert_eq!(mask(r, &text, &r.scan(&text)), out);
    }

    #[test]
    fn a_masked_secret_is_not_also_flagged() {
        use crate::builtins::Record;
        let mut st = RunState::default();
        st.records.push(Record { subject: "canary".into(), key: "github".into(),
                                 value: format!("token={GITHUB_CANARY}"), source: "literal".into(),
                                 span: String::new(), kind: None });
        let s = gate(&mut st).unwrap();
        assert_eq!(s["masked"][0]["rule"], "github-pat", "{s}");
        assert!(s["flagged"].as_array().unwrap().is_empty(), "{s}");
        assert_eq!(s["check"], false);
    }

    #[test]
    fn filters_reject_examples_and_low_entropy() {
        let r = rules();
        assert!(r.scan("aws_access_key_id = AKIAIOSFODNN7EXAMPLE").iter().all(|f| r.id(f.rule) != "aws-access-token"));
        assert!(r.scan("token ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa").iter().all(|f| r.id(f.rule) != "github-pat"));
    }

    #[test]
    fn libpq_password_is_flagged_to_hash() {
        let r = rules();
        let line = "primary = host=db-1 dbname=orders user=orders_app password=Summer4081! connect_timeout=3";
        let f = r.scan(line);
        let hit = f.iter().find(|f| r.id(f.rule) == "beat-libpq-password").expect("libpq rule");
        assert_eq!(&line[hit.start..hit.end], "Summer4081!");
        assert_eq!(r.action(hit.rule), "hash");
        assert_eq!(mask(r, line, &f), line, "a hash finding is not masked on the sensor");
    }

    #[test]
    fn look_alikes_are_not_masked() {
        let r = rules();
        let text = "commit = 3f786850e387550fdab836ed7e6dc881de23001b\nimage = sha256:2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae\nrequest_id=0b9e3c7a-6f1e-4b0e-9d1a-2f8c4e5d6a7b";
        let f = r.scan(text);
        assert_eq!(mask(r, text, &f), text, "{:?}", f.iter().map(|f| r.id(f.rule)).collect::<Vec<_>>());
    }

    #[test]
    fn a_key_emitted_line_by_line_is_masked() {
        use crate::builtins::Record;
        let body = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7VJTUt9Us8cKj\nMzEfYyjiWA4R4/M2bS1GB4t7NXp98C3SC6dVMvDuictGeurT8jNbvJZHtCSuYEvu";
        let text = format!("-----BEGIN PRIVATE KEY-----\n{body}\n-----END PRIVATE KEY-----");
        let mut st = RunState::default();
        for line in text.lines() {
            st.records.push(Record { subject: "file:/k.pem".into(), key: "line".into(), value: line.into(),
                                     source: "read".into(), span: String::new(), kind: None });
        }
        let s = gate(&mut st).expect("found");
        assert!(st.records.iter().all(|r| !body.lines().any(|b| r.value.contains(b))), "{:?}", st.records);
        assert_eq!(s["masked"].as_array().unwrap().len(), 4, "{s}");
    }

    #[test]
    fn non_ascii_text_does_not_split_characters() {
        let r = rules();
        let text = "password=Grüße2026€x connect_timeout=3 ünïcödé";
        let f = r.scan(text);
        let _ = mask(r, text, &f); // slicing at a non-boundary would panic
        assert!(f.iter().all(|f| text.is_char_boundary(f.start) && text.is_char_boundary(f.end)));
    }

    #[test]
    fn entropy_matches_shannon() {
        assert_eq!(entropy("aaaa"), 0.0);
        assert!((entropy("abcd") - 2.0).abs() < 1e-9);
    }
}
