//! The beat builtins as Starlark globals (docs/probes.md §4, §5).
//!
//! Host-side builtins forward to `Host`; everything else (checks, records, `each`, pure helpers) is computed here,
//! on the evaluator's side of the line drawn in §12.

use std::cell::RefCell;

use starlark::any::ProvidesStaticType;
use starlark::environment::{Globals, GlobalsBuilder, LibraryExtension, Module};
use starlark::eval::Evaluator;
use starlark::starlark_module;
use starlark::values::float::UnpackFloat;
use starlark::values::list::UnpackList;
use starlark::values::none::NoneType;
use starlark::values::structs::AllocStruct;
use starlark::values::tuple::UnpackTuple;
use starlark::values::typing::StarlarkNever;
use starlark::values::{Heap, Value};
use starlark::PrintHandler;

use starlark::syntax::AstModule;

use crate::check::dialect;
use crate::host::{Host, HostError, JournalOptions, Stat};

/// Limits on what a run returns (§8): over them is an error, never a silent cut.
pub const MAX_RECORDS: usize = 100_000;
pub const MAX_DIAG_BYTES: usize = 1 << 20;

#[derive(Debug, Clone, serde::Serialize)]
pub struct Record {
    pub subject: String,
    pub key: String,
    pub value: String,
    pub source: String,
    pub span: String,
    /// Declared by the probe (`emit(..., kind = "metric")`): what the value is, so the control plane need not infer
    /// it (docs/probes.md §4.4.1). Left out of the record when not declared, so answers without it hash as before.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
}

/// The kinds a probe may declare (§4.4.1).
pub const KINDS: [&str; 4] = ["semantic", "metric", "time", "identity"];

#[derive(Debug, Clone, serde::Serialize)]
pub struct Failure {
    pub kind: String, // assertion, denied, missing
    pub message: String,
    pub span: String,
    pub stack: String,
}

#[derive(Debug, Default)]
pub struct RunState {
    pub records: Vec<Record>,
    pub failures: Vec<Failure>,
    pub diag: String,
    /// A failure was raised and has not been caught by `each` yet ([F2]). Starlark has no exceptions of its own, so
    /// the error that carries a failure up the stack is told apart from real errors by this flag.
    pub unwinding: bool,
    /// Kind of the last host error raised (limit, tool, endpoint, io), to classify the run's error (§5).
    pub error_kind: Option<String>,
    /// environ(): what stands for a value in the question, and the digest gate 1 puts there (environ.rs).
    pub env_tokens: Vec<(String, String)>,
}

/// What the builtins reach through `Evaluator::extra`.
#[derive(ProvidesStaticType)]
pub struct Ctx {
    pub host: Box<dyn Host>,
    pub state: RefCell<RunState>,
}

/// `print()` goes to the run's diagnostic text, not to the records.
pub struct DiagPrint<'a>(pub &'a RefCell<RunState>);

impl PrintHandler for DiagPrint<'_> {
    fn println(&self, text: &str) -> starlark::Result<()> {
        let mut st = self.0.borrow_mut();
        if st.diag.len() + text.len() + 1 > MAX_DIAG_BYTES {
            st.error_kind = Some("limit".into());
            return Err(starlark::Error::new_other(anyhow::anyhow!("limit: print output over {MAX_DIAG_BYTES} bytes")));
        }
        st.diag.push_str(text);
        st.diag.push('\n');
        Ok(())
    }
}

fn base() -> GlobalsBuilder {
    GlobalsBuilder::extended_by(&[
        LibraryExtension::Print,
        LibraryExtension::Json,
        LibraryExtension::Typing,
        LibraryExtension::StructType,
    ])
    .with(beat_builtins)
}

/// The log built-ins (`log_summary`, `log_extract`, `emit_log_summary`): Starlark over the `drain` tool, defined
/// only where the sensor has it (§4.3).
const LOGS: &str = include_str!("logs.star");
const LOG_BUILTINS: [&str; 3] = ["log_summary", "log_extract", "emit_log_summary"];

/// Gregg's 60-second checklist (`checklist`, `emit_checklist`): Starlark over `sample()`, defined everywhere (§4.3).
const CHECKLIST: &str = include_str!("checklist.star");
const CHECKLIST_BUILTINS: [&str; 2] = ["checklist", "emit_checklist"];

/// The globals a probe sees: Starlark's, the beat builtins, the checklist, and one function per WASM tool, so that
/// `sort("-u", stdin = text)` is `pipe(["sort", "-u"], stdin = text)`. A tool missing on the target is then simply
/// an unknown name to the checks. Tools whose name is already taken (`readlink`, `dir`) stay reachable via `pipe()`.
/// With the `drain` tool, also the log built-ins (logs.star).
pub fn globals(tools: &[String]) -> Globals {
    let plain = base().build();
    let taken: std::collections::HashSet<String> = plain.names().map(|n| n.as_str().to_string()).collect();
    let mut names: Vec<String> = tools
        .iter()
        .filter(|t| t.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') && !t.starts_with(|c: char| c.is_ascii_digit()))
        .filter(|t| !taken.contains(*t))
        .cloned()
        .collect();
    let mut src: String = names
        .iter()
        // `*args` is left unannotated: starlark-rust 0.14.2 checks `*args: str` per element statically but against the
        // whole tuple at run time, so no annotation passes both. A wrong argument fails in pipe() at run time.
        .map(|t| format!("def {t}(*args, stdin: str = \"\"):\n    return pipe([\"{t}\"] + list(args), stdin = stdin)\n"))
        .collect();
    if tools.iter().any(|t| t == "drain") {
        src.push_str(LOGS);
        names.extend(LOG_BUILTINS.iter().map(|n| n.to_string()));
    }
    src.push_str(CHECKLIST);
    names.extend(CHECKLIST_BUILTINS.iter().map(|n| n.to_string()));
    let frozen = Module::with_temp_heap(|m| -> anyhow::Result<_> {
        {
            let mut eval = Evaluator::new(&m);
            let ast = AstModule::parse("tools.star", src, &dialect()).map_err(|e| anyhow::anyhow!("{e}"))?;
            eval.eval_module(ast, &plain).map_err(|e| anyhow::anyhow!("{e}"))?;
        }
        m.freeze().map_err(|e| anyhow::anyhow!("{e:?}"))
    })
    .expect("tool functions are generated from valid names; logs.star and checklist.star are tested");
    let mut b = base();
    for t in &names {
        let v = frozen.get(t).expect("defined above");
        b.frozen_heap().add_reference(v.owner());
        // SAFETY: the heap that owns `v` is referenced by the globals' heap just above, so it lives as long.
        b.set(t, unsafe { v.unchecked_frozen_value() });
    }
    b.build()
}

fn ctx<'a>(eval: &Evaluator<'_, 'a, '_>) -> &'a Ctx {
    eval.extra.expect("beat context").downcast_ref::<Ctx>().expect("beat context type")
}

fn location(eval: &Evaluator) -> String {
    eval.call_stack_top_location().map(|s| s.to_string()).unwrap_or_default()
}

/// Records a failure and returns the error that carries it up to `each` or to the top ([F1], [F2]).
fn failure(eval: &Evaluator, kind: &str, message: String) -> starlark::Error {
    let c = ctx(eval);
    let mut st = c.state.borrow_mut();
    st.failures.push(Failure {
        kind: kind.into(),
        message: message.clone(),
        span: location(eval),
        stack: eval.call_stack().to_string(),
    });
    st.unwinding = true;
    starlark::Error::new_other(anyhow::anyhow!("{kind}: {message}"))
}

fn host_error(eval: &Evaluator, e: HostError) -> starlark::Error {
    match e {
        HostError::Denied(m) => failure(eval, "denied", m),
        HostError::Missing(p) => failure(eval, "missing", format!("{p} does not exist")),
        HostError::Format(m) => failure(eval, "format", m),
        other => {
            let kind = match &other {
                HostError::Limit(_) => "limit",
                HostError::Tool(_) => "tool",
                HostError::Source(_) => "source",
                _ => "io",
            };
            ctx(eval).state.borrow_mut().error_kind = Some(kind.into());
            starlark::Error::new_other(anyhow::anyhow!("{other}"))
        }
    }
}

fn transformed<'v>(eval: &mut Evaluator<'v, '_, '_>, kind: &str, path: &str) -> starlark::Result<Value<'v>> {
    let v = ctx(eval).host.transformed(kind, path).map_err(|e| host_error(eval, e))?;
    Ok(eval.heap().alloc(v))
}

fn stat_value<'v>(heap: Heap<'v>, s: Stat) -> Value<'v> {
    heap.alloc(AllocStruct([
        ("kind", heap.alloc(s.kind)),
        ("size", heap.alloc(s.size)),
        ("mode", heap.alloc(s.mode)),
        ("uid", heap.alloc(s.uid)),
        ("gid", heap.alloc(s.gid)),
        ("user", heap.alloc(s.user)),
        ("group", heap.alloc(s.group)),
        ("mtime", heap.alloc(s.mtime)),
        ("readable", heap.alloc(s.readable)),
        ("secret", heap.alloc(s.secret)),
    ]))
}

#[starlark_module]
fn beat_builtins(builder: &mut GlobalsBuilder) {
    // --- records and checks (§4.4) -----------------------------------------------------------------------------

    /// One observation: subject, key, value, source. All strings. `kind`, if given, declares what the value is:
    /// semantic, metric, time or identity (§4.4.1).
    fn emit<'v>(
        subject: &str,
        key: &str,
        value: &str,
        source: &str,
        #[starlark(require = named, default = "")] kind: &str,
        eval: &mut Evaluator<'v, '_, '_>,
    ) -> starlark::Result<NoneType> {
        if !kind.is_empty() && !KINDS.contains(&kind) {
            return Err(starlark::Error::new_other(anyhow::anyhow!(
                "emit: kind must be one of {}, got {kind:?}", KINDS.join(", "))));
        }
        let span = location(eval);
        let mut st = ctx(eval).state.borrow_mut();
        if st.records.len() >= MAX_RECORDS {
            st.error_kind = Some("limit".into());
            return Err(starlark::Error::new_other(anyhow::anyhow!("limit: more than {MAX_RECORDS} records")));
        }
        let kind = (!kind.is_empty()).then(|| kind.to_string());
        st.records.push(Record { subject: subject.into(), key: key.into(), value: value.into(), source: source.into(), span, kind });
        Ok(NoneType)
    }

    /// The only element of `items`; a failure if there are 0 or more than 1.
    fn one<'v>(items: UnpackList<Value<'v>>, message: &str, eval: &mut Evaluator<'v, '_, '_>) -> starlark::Result<Value<'v>> {
        match items.items.as_slice() {
            [x] => Ok(*x),
            v => Err(failure(eval, "assertion", format!("{message}, got {}", v.len()))),
        }
    }

    /// A failure if `condition` is False.
    fn expect<'v>(condition: bool, message: &str, eval: &mut Evaluator<'v, '_, '_>) -> starlark::Result<NoneType> {
        if condition { Ok(NoneType) } else { Err(failure(eval, "assertion", message.into())) }
    }

    /// Always a failure: an assumption of the probe does not hold here.
    fn fail<'v>(message: &str, eval: &mut Evaluator<'v, '_, '_>) -> starlark::Result<StarlarkNever> {
        Err(failure(eval, "assertion", message.into()))
    }

    /// Calls `fn(item)` for each item; a failure ends that call only, and `each` goes on with the next item ([F2]).
    fn each<'v>(items: UnpackList<Value<'v>>, r#fn: Value<'v>, eval: &mut Evaluator<'v, '_, '_>) -> starlark::Result<NoneType> {
        for item in items.items {
            if let Err(e) = eval.eval_function(r#fn, &[item], &[]) {
                let mut st = ctx(eval).state.borrow_mut();
                if st.unwinding {
                    st.unwinding = false;
                } else {
                    return Err(e);
                }
            }
        }
        Ok(NoneType)
    }

    // --- tools (§4.1) ------------------------------------------------------------------------------------------

    /// Runs WASM tools connected stdout -> stdin: `pipe(["grep", "-E", re, path], ["sort", "-u"])`.
    /// Returns a struct: stdout, stderr, status (one exit code per stage), ok (all zero).
    fn pipe<'v>(
        #[starlark(args)] stages: UnpackTuple<UnpackList<String>>,
        #[starlark(require = named, default = "")] stdin: &str,
        eval: &mut Evaluator<'v, '_, '_>,
    ) -> starlark::Result<Value<'v>> {
        let stages: Vec<Vec<String>> = stages.items.into_iter().map(|s| s.items).collect();
        let r = ctx(eval).host.pipe(&stages, stdin.as_bytes()).map_err(|e| host_error(eval, e))?;
        let heap = eval.heap();
        let ok = r.status.iter().all(|s| *s == 0);
        Ok(heap.alloc(AllocStruct([
            ("stdout", heap.alloc(r.stdout)),
            ("stderr", heap.alloc(r.stderr)),
            ("status", heap.alloc(r.status)),
            ("ok", heap.alloc(ok)),
        ])))
    }

    // --- file system (§4.2) ------------------------------------------------------------------------------------

    /// Metadata of a path, or None if it is missing: kind, size, mode, uid, gid, user, group, mtime, readable, secret.
    fn stat<'v>(path: &str, eval: &mut Evaluator<'v, '_, '_>) -> starlark::Result<Value<'v>> {
        let r = ctx(eval).host.stat(path).map_err(|e| host_error(eval, e))?;
        Ok(match r {
            Some(s) => stat_value(eval.heap(), s),
            None => Value::new_none(),
        })
    }

    /// Content of a file as text. A secret path is a failure ("denied"), a missing one too ("missing").
    fn read<'v>(path: &str, eval: &mut Evaluator<'v, '_, '_>) -> starlark::Result<String> {
        ctx(eval).host.read(path).map_err(|e| host_error(eval, e))
    }

    /// Paths matching a pattern (`*`, `?`, `[...]`, `**`), sorted; no match gives [].
    fn glob<'v>(pattern: &str, eval: &mut Evaluator<'v, '_, '_>) -> starlark::Result<Vec<String>> {
        ctx(eval).host.glob(pattern).map_err(|e| host_error(eval, e))
    }

    /// Names in a directory, sorted.
    fn list_dir<'v>(path: &str, eval: &mut Evaluator<'v, '_, '_>) -> starlark::Result<Vec<String>> {
        ctx(eval).host.list_dir(path).map_err(|e| host_error(eval, e))
    }

    /// Target of a symlink, or None if the path is not one.
    fn readlink<'v>(path: &str, eval: &mut Evaluator<'v, '_, '_>) -> starlark::Result<Value<'v>> {
        let r = ctx(eval).host.readlink(path).map_err(|e| host_error(eval, e))?;
        Ok(r.map_or(Value::new_none(), |t| eval.heap().alloc(t)))
    }

    // --- live state (§4.3) -------------------------------------------------------------------------------------

    /// osquery SQL (its SQLite dialect, joins included); `?` take the extra arguments. Rows are dicts by column name,
    /// with typed values (int, float, str, None).
    fn osq<'v>(
        #[starlark(require = pos)] query: &str,
        #[starlark(args)] params: UnpackTuple<Value<'v>>,
        eval: &mut Evaluator<'v, '_, '_>,
    ) -> starlark::Result<Value<'v>> {
        let params = params.items.iter().map(|v| v.to_json_value()).collect::<anyhow::Result<Vec<_>>>()?;
        let rows = ctx(eval).host.osq(query, &params).map_err(|e| host_error(eval, e))?;
        Ok(eval.heap().alloc(rows))
    }

    /// A process's environment: a struct per variable with .name, .value and .hash. .value is the value of a name known
    /// to be safe, with passwords in it masked, else None. .hash stands for any other value: put it in a record, and the
    /// answer says a keyed hash there, equal on two hosts when the values are equal. The value itself is not in the
    /// question's reach.
    fn environ<'v>(pid: u32, eval: &mut Evaluator<'v, '_, '_>) -> starlark::Result<Value<'v>> {
        let vars = ctx(eval).host.environ(pid).map_err(|e| host_error(eval, e))?;
        let heap = eval.heap();
        let mut items: Vec<Value<'v>> = Vec::with_capacity(vars.len());
        for (name, value) in vars {
            let shown = crate::environ::shown(&name, &value);
            let hash = match &shown {
                Some(_) => None,
                None => Some(crate::environ::token(&mut ctx(eval).state.borrow_mut().env_tokens, &value)),
            };
            items.push(heap.alloc(AllocStruct([
                ("name", heap.alloc(name)),
                ("value", shown.map_or(Value::new_none(), |v| heap.alloc(v))),
                ("hash", hash.map_or(Value::new_none(), |v| heap.alloc(v))),
            ])));
        }
        Ok(heap.alloc(items))
    }

    /// Journal entries, oldest first, as dicts: ts, unit, pid, priority, message. `since` as journalctl takes it
    /// ("-30d", "2026-10-01"), `grep` a regex on the message, `limit` the newest N entries. `kernel`: the kernel's
    /// messages only, this boot (what dmesg shows).
    fn journal<'v>(
        #[starlark(require = named, default = false)] kernel: bool,
        #[starlark(require = named)] unit: Option<&str>,
        #[starlark(require = named)] since: Option<&str>,
        #[starlark(require = named)] grep: Option<&str>,
        #[starlark(require = named, default = 1000)] limit: i32,
        eval: &mut Evaluator<'v, '_, '_>,
    ) -> starlark::Result<Value<'v>> {
        let opts = JournalOptions {
            kernel,
            unit: unit.map(Into::into),
            since: since.map(Into::into),
            grep: grep.map(Into::into),
            limit: limit.clamp(1, 100_000) as usize,
        };
        let rows = ctx(eval).host.journal(&opts).map_err(|e| host_error(eval, e))?;
        Ok(eval.heap().alloc(rows))
    }

    /// The files matching `patterns` (globs) read, then read again `seconds` later: counters in /proc and /sys, for
    /// rates. A struct: seconds (measured), before and after ({path: content}; a path gone by then, such as a process
    /// that exited, is missing from after). At most 60 s; a secret path is a failure "denied".
    fn sample<'v>(
        patterns: UnpackList<String>,
        #[starlark(require = named, default = UnpackFloat(1.0))] seconds: UnpackFloat,
        eval: &mut Evaluator<'v, '_, '_>,
    ) -> starlark::Result<Value<'v>> {
        let r = ctx(eval).host.sample(&patterns.items, seconds.0).map_err(|e| host_error(eval, e))?;
        let heap = eval.heap();
        Ok(heap.alloc(AllocStruct([
            ("seconds", heap.alloc(r.seconds)),
            ("before", heap.alloc(serde_json::json!(r.before))),
            ("after", heap.alloc(serde_json::json!(r.after))),
        ])))
    }

    /// A catalog entry (B. Gregg's tools) run for `seconds`, its output reduced on the host: histograms, or events
    /// filtered, grouped by `key`, counted, summed and bounded, with what it saw. The entry is a
    /// literal (a check): it decides the question's capabilities.
    fn trace<'v>(
        #[starlark(require = pos)] entry: &str,
        #[starlark(require = named, default = UnpackFloat(5.0))] seconds: UnpackFloat,
        #[starlark(require = named)] options: Option<Value<'v>>,
        #[starlark(require = named)] filter: Option<Value<'v>>,
        #[starlark(require = named)] key: Option<UnpackList<String>>,
        #[starlark(require = named)] sum: Option<UnpackList<String>>,
        #[starlark(require = named)] hist: Option<&str>,
        #[starlark(require = named, default = 20)] top: i32,
        #[starlark(require = named, default = 3)] examples: i32,
        eval: &mut Evaluator<'v, '_, '_>,
    ) -> starlark::Result<Value<'v>> {
        let dict = |v: Option<Value<'v>>, what: &str| -> anyhow::Result<std::collections::BTreeMap<String, serde_json::Value>> {
            match v.map(|v| v.to_json_value()).transpose()? {
                None => Ok(Default::default()),
                Some(serde_json::Value::Object(m)) => Ok(m.into_iter().collect()),
                Some(_) => Err(anyhow::anyhow!("trace(): {what} is a dict")),
            }
        };
        let o = crate::catalog::TraceOptions {
            seconds: seconds.0,
            options: dict(options, "options")?,
            filter: dict(filter, "filter")?,
            key: key.map(|k| k.items).unwrap_or_default(),
            sum: sum.map(|k| k.items).unwrap_or_default(),
            hist: hist.map(String::from),
            top: top.clamp(1, 1000) as usize,
            examples: examples.clamp(0, 20) as usize,
        };
        let v = ctx(eval).host.trace(entry, &o).map_err(|e| host_error(eval, e))?;
        Ok(eval.heap().alloc(v))
    }

    /// A keytab as `klist -k -t -e` shows it: {format, entries: [{principal, kvno, enctype, timestamp, name_type,
    /// key_bytes}]}. Never the keys. A file that is not a keytab is a failure "format".
    fn keytab<'v>(path: &str, eval: &mut Evaluator<'v, '_, '_>) -> starlark::Result<Value<'v>> {
        transformed(eval, "keytab", path)
    }

    /// The certificates in a PEM (a chain, in order) or DER file: {format, certificates: [{subject, issuer, serial,
    /// not_before, not_after, sans, is_ca, self_signed, key, key_bits, signature, fingerprint_sha256,
    /// public_key_sha256}], other_blocks}.
    fn certificate<'v>(path: &str, eval: &mut Evaluator<'v, '_, '_>) -> starlark::Result<Value<'v>> {
        transformed(eval, "certificate", path)
    }

    /// What a private key is, never the key: {format, label, algorithm, encrypted, der_bytes}; OpenSSH keys also
    /// {cipher, kdf, keys, public_fingerprint}.
    fn private_key<'v>(path: &str, eval: &mut Evaluator<'v, '_, '_>) -> starlark::Result<Value<'v>> {
        transformed(eval, "private_key", path)
    }

    /// Metadata of the secret files on this host (never content): path, kind, mode, uid, gid, size, mtime.
    fn secrets<'v>(eval: &mut Evaluator<'v, '_, '_>) -> starlark::Result<Value<'v>> {
        let list = ctx(eval).host.secrets().map_err(|e| host_error(eval, e))?;
        let heap = eval.heap();
        let items: Vec<Value<'v>> = list
            .into_iter()
            .map(|s| {
                heap.alloc(AllocStruct([
                    ("path", heap.alloc(s.path)),
                    ("kind", heap.alloc(s.kind)),
                    ("mode", heap.alloc(s.mode)),
                    ("uid", heap.alloc(s.uid)),
                    ("gid", heap.alloc(s.gid)),
                    ("size", heap.alloc(s.size)),
                    ("mtime", heap.alloc(s.mtime)),
                ]))
            })
            .collect();
        Ok(heap.alloc(items))
    }

    // --- pure helpers (§4.5) -----------------------------------------------------------------------------------

    /// Arithmetic total of a list of numbers: all ints give an int, any float gives a float, an empty list gives 0.
    /// A non-number element is an error. (The coreutils `sum` checksum tool is still reachable via `pipe(["sum", ...])`.)
    fn sum<'v>(items: UnpackList<Value<'v>>, heap: Heap<'v>) -> starlark::Result<Value<'v>> {
        let mut acc = heap.alloc(0);
        for (i, item) in items.items.iter().enumerate() {
            match item.get_type() {
                "int" | "float" => acc = acc.add(*item, heap)?,
                _ => return Err(starlark::Error::new_other(anyhow::anyhow!("sum: element {i} is not a number"))),
            }
        }
        Ok(acc)
    }

    /// First match of a regex (Rust `regex` syntax): [whole match, group 1, ...] (None for an unmatched group), or
    /// None if there is no match.
    fn re_match<'v>(pattern: &str, s: &str, heap: Heap<'v>) -> anyhow::Result<Value<'v>> {
        let re = regex::Regex::new(pattern)?;
        Ok(match re.captures(s) {
            Some(c) => {
                let groups: Vec<Value<'v>> = c
                    .iter()
                    .map(|g| g.map_or(Value::new_none(), |m| heap.alloc(m.as_str())))
                    .collect();
                heap.alloc(groups)
            }
            None => Value::new_none(),
        })
    }

    /// Every match: group 1 if the regex has a group, else the whole match.
    fn re_find_all(pattern: &str, s: &str) -> anyhow::Result<Vec<String>> {
        let re = regex::Regex::new(pattern)?;
        let g = if re.captures_len() > 1 { 1 } else { 0 };
        Ok(re.captures_iter(s).filter_map(|c| c.get(g).map(|m| m.as_str().to_string())).collect())
    }

    /// Replaces every match; `$1` in `replacement` is group 1.
    fn re_sub(pattern: &str, replacement: &str, s: &str) -> anyhow::Result<String> {
        Ok(regex::Regex::new(pattern)?.replace_all(s, replacement).into_owned())
    }

    /// Joins path parts with "/"; a part starting with "/" starts over.
    fn path_join(#[starlark(args)] parts: UnpackTuple<String>) -> anyhow::Result<String> {
        let mut out = String::new();
        for p in parts.items {
            if p.starts_with('/') || out.is_empty() {
                out = p;
            } else {
                if !out.ends_with('/') {
                    out.push('/');
                }
                out.push_str(&p);
            }
        }
        Ok(out)
    }

    /// Everything before the last "/", like `dirname`.
    fn path_dirname(path: &str) -> anyhow::Result<String> {
        let t = path.trim_end_matches('/');
        Ok(match t.rfind('/') {
            Some(0) => "/".into(),
            Some(i) => t[..i].into(),
            None => ".".into(),
        })
    }

    /// The part after the last "/", like `basename`.
    fn path_basename(path: &str) -> anyhow::Result<String> {
        Ok(path.trim_end_matches('/').rsplit('/').next().unwrap_or("").into())
    }

    /// Epoch seconds as "YYYY-MM-DDTHH:MM:SSZ".
    fn iso_utc(epoch: i64) -> anyhow::Result<String> {
        Ok(iso_utc(epoch))
    }
}

/// Epoch seconds to ISO 8601 UTC, without a calendar library (Howard Hinnant's days-to-civil).
pub fn iso_utc(epoch: i64) -> String {
    let days = epoch.div_euclid(86_400);
    let secs = epoch.rem_euclid(86_400);
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!("{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z", secs / 3_600, secs % 3_600 / 60, secs % 60)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn iso_utc() {
        assert_eq!(super::iso_utc(0), "1970-01-01T00:00:00Z");
        assert_eq!(super::iso_utc(1_759_449_600), "2025-10-03T00:00:00Z");
        assert_eq!(super::iso_utc(951_782_400), "2000-02-29T00:00:00Z");
    }

    /// Evaluate `x = <expr>` against globals built from `tools`; return the result's (type, string repr) or error.
    fn eval_with(tools: &[String], expr: &str) -> Result<(String, String), String> {
        let g = globals(tools);
        let src = format!("x = {expr}\n");
        Module::with_temp_heap(|m| -> Result<(String, String), String> {
            let ast = AstModule::parse("t.star", src.clone(), &dialect()).map_err(|e| e.to_string())?;
            {
                let mut eval = Evaluator::new(&m);
                eval.eval_module(ast, &g).map_err(|e| e.to_string())?;
            }
            let v = m.get("x").ok_or_else(|| "no x".to_string())?;
            Ok((v.get_type().to_string(), v.to_str()))
        })
    }

    fn eval(expr: &str) -> Result<(String, String), String> {
        eval_with(&[], expr)
    }

    #[test]
    fn sum_builtin() {
        // All ints -> int.
        assert_eq!(eval("sum([1, 2, 3])").unwrap(), ("int".to_string(), "6".to_string()));
        // Any float -> float.
        assert_eq!(eval("sum([1, 2.0, 3])").unwrap(), ("float".to_string(), "6.0".to_string()));
        // Empty list -> int 0.
        assert_eq!(eval("sum([])").unwrap(), ("int".to_string(), "0".to_string()));
        // A non-number element -> error naming the position.
        let err = eval("sum([1, \"x\"])").unwrap_err();
        assert!(err.contains("sum: element 1 is not a number"), "unexpected error: {err}");
        // `sum` resolves to the arithmetic builtin, not the coreutils tool wrapper.
        assert_eq!(eval("sum([1, 2, 3]) == 6").unwrap(), ("bool".to_string(), "True".to_string()));
    }

    #[test]
    fn coreutils_sum_filtered_from_globals() {
        // Once `sum` is a beat builtin it is in `taken`, so the coreutils `sum` tool is not bound as a global; it
        // stays reachable only via pipe(["sum", ...]). Here `sum` is the arithmetic builtin even with the tool present.
        let taken: std::collections::HashSet<String> = base().build().names().map(|n| n.as_str().to_string()).collect();
        assert!(taken.contains("sum"), "sum should be a base global (beat builtin)");
        // Build globals that offer the coreutils `sum` tool: it must be filtered out, so `sum` is still arithmetic.
        assert_eq!(eval_with(&["sum".to_string()], "sum([1, 2, 3])").unwrap(), ("int".to_string(), "6".to_string()));
    }
}
