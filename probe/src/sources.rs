//! Native programs behind builtins: osquery for `osq()`, journalctl for `journal()` (docs/probes.md §4.3).
//!
//! The sensor starts them; a probe cannot (it has no builtin that starts anything). Arguments are built here from
//! values, never from probe text spliced into a command line ([P4]).

use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use serde_json::{Map, Value};

use crate::builtins::iso_utc;
use crate::host::{HostError, HostResult, JournalOptions};

pub const TIMEOUT: Duration = Duration::from_secs(30);
const OUTPUT_LIMIT: usize = 64 << 20;

/// Runs a program with a timeout; stdout if it exits 0.
fn run(argv: &[String], cwd: &Path, what: &str) -> HostResult<Vec<u8>> {
    let mut child = Command::new(&argv[0])
        .args(&argv[1..])
        .current_dir(cwd)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| HostError::Source(format!("{what}: cannot start {}: {e}", argv[0])))?;
    // Read stdout in a thread so a large output cannot block the child while we wait.
    let mut out = child.stdout.take().unwrap();
    let reader = std::thread::spawn(move || {
        let mut buf = Vec::new();
        let _ = (&mut out).take(OUTPUT_LIMIT as u64 + 1).read_to_end(&mut buf);
        buf
    });
    let deadline = Instant::now() + TIMEOUT;
    let status = loop {
        if let Some(s) = child.try_wait().map_err(|e| HostError::Source(format!("{what}: {e}")))? {
            break s;
        }
        if Instant::now() > deadline {
            let _ = child.kill();
            let _ = child.wait();
            return Err(HostError::Limit(format!("{what}: no answer after {} s", TIMEOUT.as_secs())));
        }
        std::thread::sleep(Duration::from_millis(10));
    };
    let stdout = reader.join().unwrap_or_default();
    if stdout.len() > OUTPUT_LIMIT {
        return Err(HostError::Limit(format!("{what}: output over {OUTPUT_LIMIT} bytes")));
    }
    if !status.success() {
        let mut err = String::new();
        if let Some(mut e) = child.stderr.take() {
            let _ = (&mut e).take(4096).read_to_string(&mut err);
        }
        let msg = if err.trim().is_empty() { String::from_utf8_lossy(&stdout).into_owned() } else { err };
        return Err(HostError::Source(format!("{what} failed: {}", msg.trim())));
    }
    Ok(stdout)
}

/// osquery through `osqueryi --json`, one short-lived process per call.
pub struct Osquery {
    pub osqueryi: PathBuf,
}

impl Osquery {
    fn query(&self, sql: &str) -> HostResult<Vec<Map<String, Value>>> {
        let tmp = tempdir()?;
        let argv = vec![
            self.osqueryi.to_string_lossy().into_owned(),
            "--json".into(),
            format!("--database_path={}/db", tmp.0.display()), // a throwaway state directory per call
            format!("--extensions_socket={}/sock", tmp.0.display()),
            "--disable_extensions".into(),
            "--logger_min_status=3".into(),
            sql.into(),
        ];
        let out = run(&argv, &tmp.0, "osquery")?;
        let rows: Vec<Map<String, Value>> = serde_json::from_slice(if out.is_empty() { b"[]" } else { &out })
            .map_err(|e| HostError::Source(format!("osquery did not return JSON ({e}): {}", String::from_utf8_lossy(&out[..out.len().min(300)]))))?;
        Ok(rows)
    }

    /// `osqueryi --json` gives every value as a string (NULL as ""). Typed values come from SQLite's own
    /// `json_object()`, which needs the column names: the first call gives them, the second the typed rows.
    pub fn osq(&self, query: &str, params: &[Value]) -> HostResult<Vec<Value>> {
        let sql = bind(query, params)?;
        let sql = sql.trim().trim_end_matches(';').trim().to_string();
        let first = self.query(&sql)?;
        let Some(row) = first.first() else { return Ok(Vec::new()) };
        let pairs: Vec<String> = row
            .keys()
            .map(|k| format!("'{}', \"{}\"", k.replace('\'', "''"), k.replace('"', "\"\"")))
            .collect();
        let typed = self.query(&format!("select json_object({}) as j from ({sql})", pairs.join(", ")))?;
        typed
            .into_iter()
            .map(|r| match r.get("j") {
                Some(Value::String(j)) => serde_json::from_str(j).map_err(|e| HostError::Source(format!("osquery json_object: {e}"))),
                _ => Err(HostError::Source("osquery: no json_object column".into())),
            })
            .collect()
    }
}

/// Replaces each `?` outside literals, identifiers and comments with the next parameter as a SQL literal.
pub fn bind(query: &str, params: &[Value]) -> HostResult<String> {
    let mut out = String::with_capacity(query.len());
    let mut it = params.iter();
    let mut chars = query.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '\'' | '"' | '`' | '[' => {
                let close = if c == '[' { ']' } else { c };
                out.push(c);
                for d in chars.by_ref() {
                    out.push(d);
                    if d == close {
                        break; // a doubled quote ('') closes and reopens: same result
                    }
                }
            }
            '-' if chars.peek() == Some(&'-') => {
                out.push(c);
                for d in chars.by_ref() {
                    out.push(d);
                    if d == '\n' {
                        break;
                    }
                }
            }
            '/' if chars.peek() == Some(&'*') => {
                out.push(c);
                let mut prev = ' ';
                for d in chars.by_ref() {
                    out.push(d);
                    if prev == '*' && d == '/' {
                        break;
                    }
                    prev = d;
                }
            }
            '?' => {
                let p = it.next().ok_or_else(|| HostError::Source("osq(): more `?` than parameters".into()))?;
                out.push_str(&literal(p)?);
            }
            _ => out.push(c),
        }
    }
    if it.next().is_some() {
        return Err(HostError::Source("osq(): more parameters than `?`".into()));
    }
    Ok(out)
}

fn literal(v: &Value) -> HostResult<String> {
    Ok(match v {
        Value::Null => "NULL".into(),
        Value::Bool(b) => if *b { "1" } else { "0" }.into(),
        Value::Number(n) => n.to_string(),
        Value::String(s) => format!("'{}'", s.replace('\'', "''")),
        _ => return Err(HostError::Source(format!("osq(): a parameter must be a string, number, bool or None, not {v}"))),
    })
}

/// The journal through `journalctl -o json`.
pub struct Journal {
    pub journalctl: PathBuf,
}

impl Journal {
    pub fn entries(&self, o: &JournalOptions) -> HostResult<Vec<Value>> {
        let mut argv = vec![
            self.journalctl.to_string_lossy().into_owned(),
            "--output=json".into(),
            "--no-pager".into(),
            "--quiet".into(),
            format!("--lines={}", o.limit),
        ];
        if o.kernel {
            argv.push("--dmesg".into());
        }
        if let Some(u) = &o.unit {
            argv.push(format!("--unit={u}"));
        }
        if let Some(s) = &o.since {
            argv.push(format!("--since={s}"));
        }
        if let Some(g) = &o.grep {
            argv.push(format!("--grep={g}"));
        }
        let out = run(&argv, Path::new("/"), "journal")?;
        let mut rows = Vec::new();
        for line in String::from_utf8_lossy(&out).lines().filter(|l| !l.trim().is_empty()) {
            let e: Map<String, Value> = serde_json::from_str(line).map_err(|e| HostError::Source(format!("journal: {e}")))?;
            let field = |k: &str| e.get(k).map(text).unwrap_or_default();
            let us: i64 = field("__REALTIME_TIMESTAMP").parse().unwrap_or(0);
            // systemd's own messages about a unit ("Reloading nginx.service") come from PID 1: the unit is in UNIT,
            // and _SYSTEMD_UNIT is init.scope.
            let unit = if e.contains_key("UNIT") { field("UNIT") } else { field("_SYSTEMD_UNIT") };
            let mut row = Map::new();
            row.insert("ts".into(), Value::String(iso_utc(us / 1_000_000)));
            row.insert("unit".into(), Value::String(unit));
            row.insert("pid".into(), field("_PID").parse::<i64>().map(Value::from).unwrap_or(Value::Null));
            row.insert("priority".into(), field("PRIORITY").parse::<i64>().map(Value::from).unwrap_or(Value::Null));
            row.insert("message".into(), Value::String(field("MESSAGE")));
            rows.push((us, Value::Object(row)));
        }
        // journalctl prints --grep results newest first: order by time here, so "oldest first" holds either way.
        rows.sort_by_key(|(us, _)| *us);
        Ok(rows.into_iter().map(|(_, r)| r).collect())
    }
}

/// journalctl gives a field as a string, or as an array of bytes when it is not valid UTF-8.
fn text(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Array(a) => {
            let bytes: Vec<u8> = a.iter().filter_map(|b| b.as_u64().map(|b| b as u8)).collect();
            String::from_utf8_lossy(&bytes).into_owned()
        }
        other => other.to_string(),
    }
}

/// A temporary directory removed on drop.
struct TempDir(PathBuf);

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn tempdir() -> HostResult<TempDir> {
    use std::sync::atomic::{AtomicU64, Ordering};
    static N: AtomicU64 = AtomicU64::new(0);
    let p = std::env::temp_dir().join(format!("beat-osq-{}-{}", std::process::id(), N.fetch_add(1, Ordering::Relaxed)));
    std::fs::create_dir(&p).map_err(|e| HostError::Source(format!("osquery: temporary directory: {e}")))?;
    Ok(TempDir(p))
}

#[cfg(test)]
mod tests {
    use super::bind;
    use serde_json::json;

    #[test]
    fn binds_outside_literals() {
        let q = bind("select '?' as a, \"x?\" as b, ? as c -- ?\n, ? /* ? */ from t where n = ?",
                     &[json!("it's"), json!(null), json!(3)]).unwrap();
        assert_eq!(q, "select '?' as a, \"x?\" as b, 'it''s' as c -- ?\n, NULL /* ? */ from t where n = 3");
    }

    #[test]
    fn counts_must_match() {
        assert!(bind("select ?", &[]).is_err());
        assert!(bind("select 1", &[json!(1)]).is_err());
        assert!(bind("select ?", &[json!([1])]).is_err());
    }
}
