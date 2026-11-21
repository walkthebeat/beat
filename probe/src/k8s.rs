//! k8s(): Kubernetes objects from the cluster sensor's snapshot of its API (sensor/src/kube.rs). The sensor hands the
//! question each kind's file already open (BEAT_K8S: `Kind=fd ...`); nothing here opens a path, so the sandbox needs
//! no rule for them. A file is a status line ({kind, synced, error, count}) and then an object per line.
//!
//! Objects are as the API gives them, with one change made in the builtin: a container's env entry's `value` is
//! what environ() would show (only names known to be safe, passwords masked), and the rest a token in `hash`, the
//! same token environ() gives an equal value, so a spec and a process can be compared without the value.

use std::cell::RefCell;
use std::collections::HashMap;
use std::io::Read;
use std::rc::Rc;

use serde_json::Value;

use crate::host::{HostError, HostResult};

pub const ENV: &str = "BEAT_K8S";

#[derive(Debug, Default, Clone)]
pub struct Query {
    pub kind: String,
    pub namespace: Option<String>,
    pub name: Option<String>,
    pub selector: Option<String>,
}

/// One kind as the sensor wrote it.
struct Kind {
    status: Value,
    items: Vec<Value>,
}

/// The kinds this run was given, each read once on first use.
#[derive(Default)]
pub struct Snapshot {
    read: RefCell<HashMap<String, Rc<Kind>>>,
}

fn descriptors() -> Option<Vec<(String, i32)>> {
    let v = std::env::var(ENV).ok()?;
    Some(v.split_whitespace().filter_map(|kv| {
        let (k, fd) = kv.split_once('=')?;
        Some((k.to_string(), fd.parse().ok()?))
    }).collect())
}

fn parse(text: &str) -> Result<Kind, String> {
    let mut lines = text.lines();
    let status: Value = serde_json::from_str(lines.next().ok_or("empty")?).map_err(|e| e.to_string())?;
    let items = lines.map(|l| serde_json::from_str(l).map_err(|e| e.to_string())).collect::<Result<_, _>>()?;
    Ok(Kind { status, items })
}

impl Snapshot {
    /// Matching objects, or why there are none to give; `note` is told when the watch has failed since.
    pub fn query(&self, q: &Query, note: impl Fn(String)) -> HostResult<Vec<Value>> {
        let fds = descriptors().ok_or_else(|| HostError::Source(
            "k8s(): this sensor has no view of a cluster's API (the cluster sensor answers it, as <cluster>_api)".into()))?;
        let (kind, fd) = fds.iter().find(|(k, _)| k.eq_ignore_ascii_case(&q.kind)).ok_or_else(|| HostError::Source(format!(
            "k8s(): no kind {:?} here; the sensor watches {}", q.kind,
            fds.iter().map(|(k, _)| k.as_str()).collect::<Vec<_>>().join(", "))))?;
        let k = self.kind(kind, *fd)?;
        let error = k.status["error"].as_str();
        if k.status["synced"].is_null() {
            return Err(HostError::Source(format!("k8s(): {kind} not read from the API yet{}",
                error.map_or(" (the sensor has just started)".into(), |e| format!(": {e}")))));
        }
        if let Some(e) = error {
            note(format!("k8s(): the sensor's watch of {kind} failed since it last listed them: {e}; they may be stale"));
        }
        let sel = q.selector.as_deref().map(Selector::parse).transpose().map_err(HostError::Format)?;
        Ok(k.items.iter().filter(|o| {
            let m = &o["metadata"];
            q.namespace.as_ref().is_none_or(|ns| m["namespace"].as_str() == Some(ns))
                && q.name.as_ref().is_none_or(|n| m["name"].as_str() == Some(n))
                && sel.as_ref().is_none_or(|s| s.matches(&m["labels"]))
        }).cloned().collect())
    }

    fn kind(&self, kind: &str, fd: i32) -> HostResult<Rc<Kind>> {
        if let Some(k) = self.read.borrow().get(kind) {
            return Ok(k.clone());
        }
        // Safety: the sensor opened this descriptor for this process, and it is taken once (cached by kind).
        let mut f = unsafe { <std::fs::File as std::os::fd::FromRawFd>::from_raw_fd(fd) };
        let mut text = String::new();
        f.read_to_string(&mut text).map_err(|e| HostError::Io(format!("k8s(): {kind}: {e}")))?;
        let k = Rc::new(parse(&text).map_err(|e| HostError::Io(format!("k8s(): {kind}: {e}")))?);
        self.read.borrow_mut().insert(kind.to_string(), k.clone());
        Ok(k)
    }
}

/// A label selector as kubectl takes it: `a=b`, `a==b`, `a!=b`, `a`, `!a`, `a in (x,y)`, `a notin (x,y)`, joined
/// by commas, all of them to hold. As in Kubernetes, `!=` and `notin` hold for an object without the label.
#[derive(Debug, PartialEq)]
pub struct Selector(Vec<Term>);

#[derive(Debug, PartialEq)]
enum Term {
    Eq(String, String),
    Ne(String, String),
    Exists(String),
    Absent(String),
    In(String, Vec<String>),
    NotIn(String, Vec<String>),
}

impl Selector {
    pub fn parse(s: &str) -> Result<Selector, String> {
        let mut terms = Vec::new();
        let (mut depth, mut start) = (0, 0);
        let mut parts = Vec::new();
        for (i, c) in s.char_indices() {
            match c {
                '(' => depth += 1,
                ')' => depth -= 1,
                ',' if depth == 0 => { parts.push(&s[start..i]); start = i + 1; }
                _ => {}
            }
        }
        parts.push(&s[start..]);
        let bad = |t: &str| format!("selector {s:?}: cannot read {t:?}");
        for t in parts.into_iter().map(str::trim).filter(|t| !t.is_empty()) {
            let set = |rest: &str| -> Result<Vec<String>, String> {
                let inner = rest.trim().strip_prefix('(').and_then(|r| r.strip_suffix(')')).ok_or_else(|| bad(t))?;
                Ok(inner.split(',').map(|v| v.trim().to_string()).collect())
            };
            let words: Vec<&str> = t.splitn(2, char::is_whitespace).collect();
            terms.push(if let Some(k) = t.strip_prefix('!') {
                Term::Absent(k.trim().into())
            } else if let Some((k, v)) = t.split_once("!=") {
                Term::Ne(k.trim().into(), v.trim().into())
            } else if let Some((k, v)) = t.split_once("==").or_else(|| t.split_once('=')) {
                Term::Eq(k.trim().into(), v.trim().into())
            } else if words.len() == 2 && words[1].trim_start().starts_with("notin") {
                Term::NotIn(words[0].into(), set(&words[1].trim_start()[5..])?)
            } else if words.len() == 2 && words[1].trim_start().starts_with("in") {
                Term::In(words[0].into(), set(&words[1].trim_start()[2..])?)
            } else if words.len() == 1 {
                Term::Exists(t.into())
            } else {
                return Err(bad(t));
            });
        }
        Ok(Selector(terms))
    }

    pub fn matches(&self, labels: &Value) -> bool {
        let get = |k: &str| labels.get(k).and_then(Value::as_str);
        self.0.iter().all(|t| match t {
            Term::Eq(k, v) => get(k) == Some(v),
            Term::Ne(k, v) => get(k) != Some(v),
            Term::Exists(k) => get(k).is_some(),
            Term::Absent(k) => get(k).is_none(),
            Term::In(k, vs) => get(k).is_some_and(|l| vs.iter().any(|v| v == l)),
            Term::NotIn(k, vs) => get(k).is_none_or(|l| vs.iter().all(|v| v != l)),
        })
    }
}

/// Every container env entry in `v` (any object's `env` list of {name, value}), its value as environ() gives it.
pub fn env_as_environ(v: &mut Value, tokens: &mut Vec<(String, String)>) {
    match v {
        Value::Object(m) => {
            if let Some(Value::Array(env)) = m.get_mut("env") {
                for e in env.iter_mut().filter_map(Value::as_object_mut) {
                    let (Some(name), Some(value)) = (e.get("name").and_then(Value::as_str), e.get("value").and_then(Value::as_str))
                    else { continue };
                    let shown = crate::environ::shown(name, value);
                    let hash = match &shown {
                        Some(_) => Value::Null,
                        None => Value::String(crate::environ::token(tokens, value)),
                    };
                    e.insert("value".into(), shown.map_or(Value::Null, Value::String));
                    e.insert("hash".into(), hash);
                }
            }
            for (k, x) in m.iter_mut() {
                if k != "env" {
                    env_as_environ(x, tokens);
                }
            }
        }
        Value::Array(a) => a.iter_mut().for_each(|x| env_as_environ(x, tokens)),
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn selectors_as_kubectl_reads_them() {
        let l = json!({"app": "web", "tier": "front"});
        let m = |s: &str| Selector::parse(s).unwrap().matches(&l);
        assert!(m("app=web") && m("app==web") && m("app=web,tier=front") && m("app") && m("!canary"));
        assert!(m("tier in (front, back)") && m("tier notin (back)") && m("canary!=yes") && m("canary notin (yes)"));
        assert!(!m("app=db") && !m("app!=web") && !m("canary") && !m("!app") && !m("tier in (back)") && !m("canary in (yes)"));
        assert!(m(""), "an empty selector selects everything");
        assert!(Selector::parse("tier in front").is_err());
    }

    #[test]
    fn env_values_become_what_environ_gives() {
        let mut tokens = Vec::new();
        let mut pod = json!({"spec": {"containers": [{"name": "c", "env": [
            {"name": "DB_PASS", "value": "hunter2"},
            {"name": "TZ", "value": "UTC"},
            {"name": "FROM_SECRET", "valueFrom": {"secretKeyRef": {"name": "db", "key": "pass"}}},
            {"name": "SAME", "value": "hunter2"}]}]}});
        env_as_environ(&mut pod, &mut tokens);
        let env = &pod["spec"]["containers"][0]["env"];
        assert_eq!(env[0], json!({"name": "DB_PASS", "value": null, "hash": "«env:hash:0»"}));
        assert_eq!(env[1], json!({"name": "TZ", "value": "UTC", "hash": null}));
        assert_eq!(env[2], json!({"name": "FROM_SECRET", "valueFrom": {"secretKeyRef": {"name": "db", "key": "pass"}}}));
        assert_eq!(env[3]["hash"], "«env:hash:0»", "equal values, equal tokens");
        assert!(!pod.to_string().contains("hunter2"));
    }

    #[test]
    fn files_are_a_status_line_then_objects() {
        let k = parse("{\"kind\":\"Pod\",\"synced\":7,\"error\":null,\"count\":1}\n{\"metadata\":{\"name\":\"a\"}}\n").unwrap();
        assert_eq!(k.status["synced"], 7);
        assert_eq!(k.items.len(), 1);
    }
}
