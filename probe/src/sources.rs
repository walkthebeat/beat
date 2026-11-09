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

/// osquery through one `osqueryi --json` session per probe run, its queries on stdin (docs/hosted.md H25). One
/// process per call cost about 0.36 s before any work, measured 2026-11-08: a RocksDB database made from scratch
/// (`--disable_database` drops it; it was thrown away anyway) and a 200 ms sleep in a thread osqueryi waits for
/// before it answers a one-off query; discovery's 7 osq() calls took 5.5-6 s on the lab's hosts. The session pays
/// its start once, and is killed with the run (Drop), never waited for.
pub struct Osquery {
    pub osqueryi: PathBuf,
    session: std::sync::Mutex<Option<Session>>,
}

impl Osquery {
    pub fn new(osqueryi: PathBuf) -> Osquery {
        Osquery { osqueryi, session: std::sync::Mutex::new(None) }
    }

    /// One statement's rows, in the session (started on first use, started again after one that failed).
    fn query(&self, sql: &str) -> HostResult<Vec<Map<String, Value>>> {
        let mut held = self.session.lock().unwrap_or_else(|e| e.into_inner());
        if held.is_none() {
            *held = Some(Session::start(&self.osqueryi)?);
        }
        let r = held.as_mut().unwrap().query(sql);
        if matches!(r, Err(HostError::Limit(_))) || held.as_ref().is_some_and(|s| s.dead) {
            *held = None; // a query that ran over its limits, or osqueryi gone: the next one starts afresh
        }
        r
    }

    /// `osqueryi --json` gives every value as a string (NULL as ""). Typed values come from SQLite's own
    /// `json_object()`, which needs the column names. The query runs once, into a temporary table: its columns from
    /// `pragma table_info`, its typed rows from that table (one run of an expensive table such as systemd_units,
    /// where two runs of the query used to read it twice).
    pub fn osq(&self, query: &str, params: &[Value]) -> HostResult<Vec<Value>> {
        let sql = bind(query, params)?;
        let sql = sql.trim().trim_end_matches(';').trim().to_string();
        if let Some(why) = refused(&sql) {
            return Err(HostError::Denied(why));
        }
        let t = format!("beat_q{}", NEXT_TABLE.fetch_add(1, std::sync::atomic::Ordering::Relaxed));
        self.query(&format!("create temp table {t} as {sql}"))?;
        let rows = (|| {
            let cols = self.query(&format!("pragma table_info({t})"))?;
            let names: Vec<String> = cols.iter().filter_map(|c| c.get("name")?.as_str().map(String::from)).collect();
            if names.is_empty() {
                return Ok(Vec::new());
            }
            let pairs: Vec<String> =
                names.iter().map(|k| format!("'{}', \"{}\"", k.replace('\'', "''"), k.replace('"', "\"\""))).collect();
            let typed = self.query(&format!("select json_object({}) as j from {t}", pairs.join(", ")))?;
            typed
                .into_iter()
                .map(|r| match r.get("j") {
                    Some(Value::String(j)) => serde_json::from_str(j).map_err(|e| HostError::Source(format!("osquery json_object: {e}"))),
                    _ => Err(HostError::Source("osquery: no json_object column".into())),
                })
                .collect()
        })();
        let _ = self.query(&format!("drop table if exists {t}"));
        rows
    }
}

static NEXT_TABLE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// A running `osqueryi --json`: each statement is followed by a marker query, `select '<nonce>' as beat_end`, so the
/// end of its result is the marker's row. The nonce is random per session, so no value in a table can be taken for
/// it; values are JSON strings, escaped, so neither can a name. Errors are read from osqueryi's stderr, a file.
struct Session {
    child: std::process::Child,
    stdin: std::process::ChildStdin,
    out: std::sync::mpsc::Receiver<Vec<u8>>,
    buf: Vec<u8>,
    err: PathBuf,
    err_seen: usize,
    marker: Vec<u8>,
    nonce: String,
    dead: bool,
    _dir: TempDir,
}

impl Session {
    fn start(osqueryi: &Path) -> HostResult<Session> {
        let dir = tempdir()?;
        let err = dir.0.join("stderr");
        let errf = std::fs::File::create(&err).map_err(|e| HostError::Source(format!("osquery: {e}")))?;
        let mut child = Command::new(osqueryi)
            .args(["--json", &format!("--database_path={}/db", dir.0.display()),
                   &format!("--extensions_socket={}/sock", dir.0.display()), "--disable_extensions", "--disable_database",
                   "--logger_min_status=3"])
            .current_dir(&dir.0)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(errf)
            .spawn()
            .map_err(|e| HostError::Source(format!("osquery: cannot start {}: {e}", osqueryi.display())))?;
        let mut stdout = child.stdout.take().unwrap();
        let stdin = child.stdin.take().unwrap();
        let (tx, out) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let mut chunk = vec![0u8; 64 << 10];
            while let Ok(n) = stdout.read(&mut chunk) {
                if n == 0 || tx.send(chunk[..n].to_vec()).is_err() {
                    break;
                }
            }
        });
        let nonce = nonce()?;
        let marker = format!("\"beat_end\":\"{nonce}\"").into_bytes();
        Ok(Session { child, stdin, out, buf: Vec::new(), err, err_seen: 0, marker, nonce, dead: false, _dir: dir })
    }

    fn query(&mut self, sql: &str) -> HostResult<Vec<Map<String, Value>>> {
        use std::io::Write;
        let request = format!("{sql};\nselect '{}' as beat_end;\n", self.nonce);
        if self.stdin.write_all(request.as_bytes()).and_then(|_| self.stdin.flush()).is_err() {
            self.dead = true;
            return Err(HostError::Source(format!("osquery exited: {}", self.stderr())));
        }
        let deadline = Instant::now() + TIMEOUT;
        let at = loop {
            if let Some(at) = find(&self.buf, &self.marker) {
                break at;
            }
            if self.buf.len() > OUTPUT_LIMIT {
                return Err(HostError::Limit(format!("osquery: output over {OUTPUT_LIMIT} bytes")));
            }
            match self.out.recv_timeout(deadline.saturating_duration_since(Instant::now())) {
                Ok(c) => self.buf.extend_from_slice(&c),
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                    return Err(HostError::Limit(format!("osquery: no answer after {} s", TIMEOUT.as_secs())));
                }
                Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                    self.dead = true;
                    return Err(HostError::Source(format!("osquery exited: {}", self.stderr())));
                }
            }
        };
        // The marker's own array, `[\n  {"beat_end":"<nonce>"}\n]\n`: the statement's output is what comes before it.
        let open = self.buf[..at].iter().rposition(|&b| b == b'[').unwrap_or(0);
        let close = at + self.buf[at..].iter().position(|&b| b == b']').map(|p| p + 1).unwrap_or(self.buf.len() - at);
        let end = (close + self.buf[close..].iter().take_while(|b| b.is_ascii_whitespace()).count()).min(self.buf.len());
        let text = String::from_utf8_lossy(&self.buf[..open]).trim().to_string();
        self.buf.drain(..end);
        // A failed statement still prints an empty result; its error is on stderr, before the marker's row.
        let err = self.stderr();
        if !err.is_empty() {
            return Err(HostError::Source(format!("osquery failed: {}", err.replace("near line 1: ", ""))));
        }
        if text.is_empty() {
            return Ok(Vec::new());
        }
        serde_json::from_str(&text).map_err(|e| {
            HostError::Source(format!("osquery did not return JSON ({e}): {}", &text[..text.len().min(300)]))
        })
    }

    /// What osqueryi wrote to stderr since the last look.
    fn stderr(&mut self) -> String {
        let all = std::fs::read(&self.err).unwrap_or_default();
        let new = String::from_utf8_lossy(&all[self.err_seen.min(all.len())..]).trim().to_string();
        self.err_seen = all.len();
        new.chars().take(4096).collect()
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        let _ = self.child.kill(); // read-only, its state thrown away: no need to wait out its exit
        let _ = self.child.wait();
    }
}

fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}

fn nonce() -> HostResult<String> {
    let mut b = [0u8; 16];
    std::fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut b))
        .map_err(|e| HostError::Source(format!("osquery: /dev/urandom: {e}")))?;
    Ok(b.iter().map(|x| format!("{x:02x}")).collect())
}

/// Tables that hand out processes' and containers' environments, with their values.
const ENV_TABLES: [&str; 3] = ["process_envs", "docker_container_envs", "process_events"];

/// Why a query may not run, if so. The check reads the query as SQLite's tokenizer does, so case, quoting, comments and
/// aliases do not get past it: SQLite finds a table only from a name in the text (osquery has no eval(), and its
/// authorizer refuses ATTACH and load_extension), and a name is an identifier or, in FROM, a string. So a string equal
/// to one of these names is refused too, also where it is only compared. Tables that merely have such a column:
/// docker_containers has env_variables, and `select *` would give it under any alias a CTE's column list chooses, so
/// with that table the columns must be named.
pub fn refused(sql: &str) -> Option<String> {
    let instead = "it returns environment values: use environ(pid), which gives every name, a keyed hash of each value, \
                   and the values of names known to be safe";
    if sql.starts_with('.') {
        return Some("osq() takes SQL, not osqueryi's dot commands".into());
    }
    let (words, star) = tokens(sql);
    // One read per call: the statements share a session (Osquery), so none may change it or follow another.
    if words.iter().any(|w| w == ";") {
        return Some("osq() takes one statement: no `;` inside it".into());
    }
    if !matches!(words.first().map(String::as_str), Some("select" | "with" | "values")) {
        return Some("osq() only reads: a select (or with ... select)".into());
    }
    if let Some(t) = words.iter().find(|w| ENV_TABLES.contains(&w.as_str())) {
        return Some(format!("osq(): {t} is refused: {instead}"));
    }
    if words.iter().any(|w| w == "env_variables") {
        return Some(format!("osq(): docker_containers.env_variables is refused: {instead}"));
    }
    if star && words.iter().any(|w| w == "docker_containers") {
        return Some("osq(): name the columns of docker_containers instead of *: its env_variables is refused".into());
    }
    if words.iter().any(|w| FILE_TABLES.contains(&w.as_str())) {
        if let Some(why) = file_table_refusal(&words) {
            return Some(why);
        }
    }
    None
}

/// Tables that read or describe a path they are given, as root, so /proc/<pid>/root/etc/shadow is the real file.
const FILE_TABLES: [&str; 4] = ["hash", "file", "yara", "augeas"];
/// What builds a string in SQL: with these tables a path could be built past the check on literals.
const STRING_BUILDERS: [&str; 15] = ["char", "printf", "format", "replace", "substr", "substring", "ltrim", "rtrim", "trim", "lower",
                                     "upper", "concat", "concat_ws", "group_concat", "unhex"];

/// A best effort, and it says so in docs/security.md: for these tables, a literal path through a process's root, cwd or
/// fd is refused, spelled with wildcards or not, and so is anything that builds strings. A path taken from another
/// table's column is not seen.
fn file_table_refusal(words: &[String]) -> Option<String> {
    let doors = "a process's root, cwd or fd: read() checks what such a path leads to, and these tables do not";
    if words.iter().any(|w| w == "||") {
        return Some(format!("osq(): {FILE_TABLES:?} take literal paths here, not built with ||: {doors}"));
    }
    if let Some(f) = words.iter().find(|w| STRING_BUILDERS.contains(&w.as_str())) {
        return Some(format!("osq(): {FILE_TABLES:?} take literal paths here, not built with {f}(): {doors}"));
    }
    words.iter().find(|w| names_a_door(w)).map(|w| format!("osq(): {w} goes through {doors}"))
}

/// Whether a string could name a path through /proc/<pid>/{root,cwd,fd}, or /dev/fd, as written or as a pattern.
fn names_a_door(s: &str) -> bool {
    if !s.contains('/') {
        return false;
    }
    if s.split('/').any(|c| c == "..") {
        return true; // what it comes to depends on the disk
    }
    let wild = |c: &str| c.contains(['%', '_', '*', '?', '[']);
    let comps: Vec<&str> = s.split('/').filter(|c| !c.is_empty() && *c != ".").collect();
    let Some(first) = comps.first() else { return false };
    if *first == "dev" {
        return comps.get(1).is_some_and(|c| *c == "fd" || wild(c));
    }
    if !like(first, "proc") {
        return false;
    }
    let Some(pid) = comps.get(1) else { return false };
    let pidlike = pid.bytes().all(|b| b.is_ascii_digit()) || *pid == "self" || *pid == "thread-self" || wild(pid);
    pidlike && (comps.iter().any(|c| wild(c)) || comps.iter().any(|c| matches!(*c, "root" | "cwd" | "fd" | "map_files")))
}

/// Whether a LIKE or GLOB pattern could match this word.
fn like(pattern: &str, word: &str) -> bool {
    if !pattern.contains(['%', '_', '*', '?', '[']) {
        return pattern == word;
    }
    if pattern.contains(['%', '*', '[']) {
        return true;
    }
    pattern.len() == word.len() && pattern.bytes().zip(word.bytes()).all(|(p, w)| p == w || p == b'_' || p == b'?')
}

/// The query's names and strings, in ASCII lower case as SQLite compares them, and whether it has a `*` other than
/// count(*). Comments are skipped; `""` inside a quoted name is one quote.
fn tokens(sql: &str) -> (Vec<String>, bool) {
    let b: Vec<char> = sql.chars().collect();
    let (mut words, mut star, mut i) = (Vec::new(), false, 0);
    let mut last = ' '; // the last character that was not space or a comment
    while i < b.len() {
        let c = b[i];
        match c {
            '-' if b.get(i + 1) == Some(&'-') => {
                while i < b.len() && b[i] != '\n' {
                    i += 1;
                }
                continue;
            }
            '/' if b.get(i + 1) == Some(&'*') => {
                i += 2;
                while i < b.len() && !(b[i] == '*' && b.get(i + 1) == Some(&'/')) {
                    i += 1;
                }
                i += 2;
                continue;
            }
            '\'' | '"' | '`' | '[' => {
                let close = if c == '[' { ']' } else { c };
                let mut w = String::new();
                i += 1;
                while i < b.len() {
                    if b[i] == close {
                        if close != ']' && b.get(i + 1) == Some(&close) {
                            w.push(close);
                            i += 2;
                            continue;
                        }
                        break;
                    }
                    w.push(b[i]);
                    i += 1;
                }
                words.push(w.to_ascii_lowercase());
            }
            '*' => {
                let next = b[i + 1..].iter().find(|c| !c.is_whitespace());
                if !(last == '(' && next == Some(&')')) {
                    star = true;
                }
            }
            c if c.is_alphanumeric() || c == '_' || c == '$' || !c.is_ascii() => {
                let mut w = String::new();
                while i < b.len() && (b[i].is_alphanumeric() || b[i] == '_' || b[i] == '$' || !b[i].is_ascii()) {
                    w.push(b[i]);
                    i += 1;
                }
                words.push(w.to_ascii_lowercase());
                last = 'a';
                continue;
            }
            '|' if b.get(i + 1) == Some(&'|') => words.push("||".to_string()),
            ';' => words.push(";".to_string()),
            _ => {}
        }
        if !c.is_whitespace() {
            last = c;
        }
        i += 1;
    }
    (words, star)
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
    use super::{refused, Osquery};
    use crate::host::HostError;
    use serde_json::Value;
    use super::bind;
    use serde_json::json;

    #[test]
    fn binds_outside_literals() {
        let q = bind("select '?' as a, \"x?\" as b, ? as c -- ?\n, ? /* ? */ from t where n = ?",
                     &[json!("it's"), json!(null), json!(3)]).unwrap();
        assert_eq!(q, "select '?' as a, \"x?\" as b, 'it''s' as c -- ?\n, NULL /* ? */ from t where n = 3");
    }

    #[test]
    fn environment_tables_are_refused_however_they_are_written() {
        for q in ["select * from process_envs", "SELECT * FROM PROCESS_ENVS", "select * from Process_Envs",
                  r#"select * from "process_envs""#, "select * from `process_envs`", "select * from [process_envs]",
                  "select * from 'process_envs'", "select * from main.process_envs", "select * from/**/process_envs",
                  "select * from -- x\nprocess_envs", "select value v from process_envs e where e.key='A'",
                  "with t as (select * from process_envs) select * from t",
                  "select * from (select key, value from process_envs)",
                  "select p.name, e.value from processes p join process_envs e using (pid)",
                  "select 1 union select value from process_envs", "select * from docker_container_envs",
                  "select env from process_events", "select env_variables from docker_containers",
                  "select id, ENV_VARIABLES x from docker_containers", "select * from docker_containers",
                  "with t(a,b,c) as (select * from docker_containers) select * from t",
                  ".all process_envs", ".read /tmp/x"] {
            assert!(refused(q).is_some(), "{q}");
        }
    }

    #[test]
    fn file_tables_are_refused_through_a_process_root() {
        for q in ["select * from hash where path = '/proc/1/root/etc/shadow'",
                  "select * from file where path = '/proc/1/cwd/x'", "select * from FILE where path='/proc/self/fd/3'",
                  "select * from yara where path = '/proc/thread-self/root/etc/shadow' and sigrule='x'",
                  "select * from augeas where path = '/proc/2/root/etc/passwd'",
                  "select * from file where path like '/proc/%/root/etc/%'", "select * from file where path like '/proc/1/r__t/etc/shadow'",
                  "select * from file where path like '/%/1/root/etc/shadow'", "select * from file where path like '/pr__/1/root/x'",
                  "select * from file where path glob '/proc/*/root/etc/shadow'", "select * from file where directory = '/proc/1/root/etc'",
                  "select * from hash where path = '/proc/./1/root/etc/shadow'", "select * from hash where path = '//proc//1/root/x'",
                  "select * from hash where path = '/usr/../proc/1/root/x'", "select * from hash where path = '/dev/fd/3'",
                  "select * from hash where path = '/proc/1/ro' || 'ot/etc/shadow'",
                  "select * from hash where path = printf('/proc/%d/root/etc/shadow', 1)",
                  "select * from hash where path = replace('/x/1/root', 'x', 'proc')",
                  "select h.sha256 from processes p, hash h where h.path = '/proc/' || p.pid || '/root/etc/shadow'"] {
            assert!(refused(q).is_some(), "{q}");
        }
    }

    #[test]
    fn ordinary_file_and_process_queries_are_not_refused() {
        for q in ["select * from file where path = '/etc/hostname'", "select * from hash where path = '/usr/bin/nginx'",
                  "select * from file where directory = '/etc/nginx'", "select * from file where path like '/etc/%%'",
                  "select * from file where path = '/proc/meminfo'", "select * from file where path like '/usr_local/%'",
                  "select * from process_open_sockets", "select pid, path from process_open_files where path like '/proc/%/root/x'",
                  "select * from processes where path like '/proc/%' or cwd = '/proc/1/root'",
                  "select p.name, l.port from listening_ports l join processes p using (pid)"] {
            assert_eq!(refused(q), None, "{q}");
        }
    }

    #[test]
    fn ordinary_queries_are_not_refused() {
        for q in ["select * from processes", "select pid, name from processes where name = 'nginx'",
                  "select id, name, image from docker_containers", "select count(*) as n from docker_containers",
                  "select count( * ) n from docker_containers", "select * from system_info -- process_envs in a comment",
                  "select 2*3 as x from osquery_info /* process_envs */"] {
            assert_eq!(refused(q), None, "{q}");
        }
    }

    /// Against real osquery: what is refused really is a way in, and the tokens are right about what SQLite accepts.
    #[test]
    fn the_dodges_are_real_against_osquery() {
        let Some(o) = std::env::var_os("BEAT_OSQUERYI") else { return };
        let os = Osquery::new(o.into());
        for q in ["select 1 as x from 'process_envs' limit 1", r#"select 1 as x from "PROCESS_ENVS" limit 1"#,
                  "select 1 as x from [Process_Envs] limit 1", "select 1 as x from main.process_envs limit 1",
                  "select 1 as x from/**/process_envs limit 1"] {
            assert!(refused(q).is_some(), "{q}");
            assert!(os.query(q).is_ok(), "SQLite accepts {q}");
            assert!(os.osq(q, &[]).is_err(), "osq refuses {q}");
        }
    }

    #[test]
    fn a_session_answers_like_a_process_per_call() {
        // One osqueryi session for every call of a run (docs/hosted.md H25): typed rows, an empty result, and an
        // error that is an error, after which the session still answers.
        let Some(o) = std::env::var_os("BEAT_OSQUERYI") else { return };
        let os = Osquery::new(o.into());
        let rows = os.osq("select 1 as x, 'a' as y, null as z, 2.5 as w", &[]).unwrap();
        assert_eq!(rows, vec![serde_json::json!({"x": 1, "y": "a", "z": null, "w": 2.5})]);
        assert_eq!(os.osq("select 1 as x where 1 = 0", &[]).unwrap(), Vec::<Value>::new());
        let e = os.osq("select nosuchcol from osquery_info", &[]).unwrap_err().to_string();
        assert!(e.contains("no such column: nosuchcol"), "{e}");
        assert_eq!(os.osq("select ? as v", &[Value::from("o'k")]).unwrap(), vec![serde_json::json!({"v": "o'k"})]);
        for q in ["select 1; select 2", "create temp table t as select 1", "drop table x"] {
            assert!(matches!(os.osq(q, &[]), Err(HostError::Denied(_))), "{q}");
        }
    }

    #[test]
    fn counts_must_match() {
        assert!(bind("select ?", &[]).is_err());
        assert!(bind("select 1", &[json!(1)]).is_err());
        assert!(bind("select ?", &[json!([1])]).is_err());
    }
}
