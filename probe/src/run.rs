//! One probe run: checks, evaluation of `main()`, and the run result (docs/probes.md §5, §9).
//!
//! Memory and CPU limits on the evaluator come from the process it runs in (§8): `beat-probe run` is meant to be one
//! child process per run, inside a cgroup. Here only the call depth is bounded.

use std::cell::RefCell;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use serde_json::{json, Value as Json};
use starlark::environment::Module;
use starlark::eval::Evaluator;
use starlark::syntax::AstModule;
use starlark::ErrorKind;

use crate::builtins::{globals, iso_utc, Ctx, DiagPrint, RunState};
use crate::check::{check, dialect};
use crate::host::Host;

/// Deep enough for any probe; recursion is rejected by the checks, so this only catches what they cannot see.
pub const MAX_CALLSTACK: usize = 100;

pub fn probe_id(source: &str) -> String {
    use sha2::Digest;
    sha2::Sha256::digest(source.as_bytes()).iter().map(|b| format!("{b:02x}")).collect()
}

fn now() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

/// One run, its host calls timed in `timings` (crate::timed).
pub fn run(name: &str, source: &str, host: Box<dyn Host>) -> Json {
    run_timed(name, source, host, false, &[])
}

/// One run. `profile`: time each host call on its own too, and report the slowest as records (crate::timed).
/// `before`: what the caller spent before this run, in ms by step (beat-probe: loading the tools), for `timings`.
pub fn run_timed(name: &str, source: &str, host: Box<dyn Host>, profile: bool, before: &[(&str, u64)]) -> Json {
    let started = now();
    let t0 = Instant::now();
    let id = probe_id(source);
    let (host, stats) = crate::timed::Timed::new(host, profile);
    let host: Box<dyn Host> = Box::new(host);
    let steps: RefCell<Vec<(&str, u64)>> = RefCell::new(before.to_vec());
    let step = |name: &'static str, since: Instant| steps.borrow_mut().push((name, crate::timed::ms(since.elapsed())));
    let result = |outcome: &str, st: &RunState, error: Json, notes: Vec<String>, secrets: Option<Json>| {
        let mut r = json!({
            "probe": id, "name": name, "started": iso_utc(started), "finished": iso_utc(now()),
            "outcome": outcome,
            "records": st.records, "failures": st.failures, "error": error,
            "diag": st.diag, "notes": notes,
            "usage": {"wall_ms": t0.elapsed().as_millis() as u64},
            "timings": timings(&steps.borrow(), &stats.borrow()),
        });
        // Only when gate 1 found something, so that clean answers hash as before (docs/security.md).
        if let Some(s) = secrets {
            r["secrets"] = s;
        }
        r
    };

    let compiling = Instant::now();
    let tools = host.tools();
    let diags = check(name, source, &tools);
    if !diags.is_empty() {
        let message: Vec<String> = diags.iter().map(|d| d.to_string()).collect();
        let error = json!({"kind": "rejected", "message": message.join("\n"), "span": ""});
        return result("error", &RunState::default(), error, Vec::new(), None);
    }
    let ast = match AstModule::parse(name, source.to_owned(), &dialect()) {
        Ok(a) => a,
        Err(e) => {
            let error = json!({"kind": "rejected", "message": e.to_string(), "span": ""});
            return result("error", &RunState::default(), error, Vec::new(), None);
        }
    };

    let globals = globals(&tools);
    step("compile", compiling);
    let evaluating = Instant::now();
    let ctx = Ctx { host, state: RefCell::new(RunState::default()) };
    let print = DiagPrint(&ctx.state);
    let outcome: Result<(), starlark::Error> = Module::with_temp_heap(|module| {
        let mut eval = Evaluator::new(&module);
        eval.extra = Some(&ctx);
        eval.set_print_handler(&print);
        eval.set_max_callstack_size(MAX_CALLSTACK).map_err(starlark::Error::new_other)?;
        eval.eval_module(ast, &globals)?;
        let main = module.get("main").ok_or_else(|| starlark::Error::new_other(anyhow::anyhow!("no main()")))?;
        eval.eval_function(main, &[], &[])?;
        Ok(())
    });

    step("eval", evaluating);
    let notes = ctx.host.notes();
    let mut st = ctx.state.borrow_mut();
    // A profiled run's calls are records, before gate 1: their arguments are paths and queries, masked like the rest.
    st.records.extend(crate::timed::profile_records(&stats.borrow()));
    let masking = Instant::now();
    let secrets = crate::secrets::gate(&mut st);
    step("mask", masking);
    match outcome {
        Ok(()) if st.failures.is_empty() => result("ok", &st, Json::Null, notes, secrets),
        Ok(()) => result("partial", &st, Json::Null, notes, secrets),
        // A failure outside `each` ended the probe ([F2]): recorded already, not an error.
        Err(_) if st.unwinding => result("partial", &st, Json::Null, notes, secrets),
        Err(e) => {
            let kind = match (e.kind(), &st.error_kind) {
                (ErrorKind::StackOverflow(_), _) => "limit".to_string(),
                (_, Some(k)) => k.clone(),
                (ErrorKind::Native(_) | ErrorKind::Other(_), None) => "internal".to_string(),
                _ => "type".to_string(),
            };
            let span = e.span().map(|s| s.to_string()).unwrap_or_default();
            let error = json!({"kind": kind, "message": format!("{}", e.without_diagnostic()), "span": span,
                               "stack": e.call_stack().to_string()});
            result("error", &st, error, notes, secrets)
        }
    }
}

/// The run result's `timings`: the steps in ms (tools, compile, eval, mask), `probe` (eval less the host calls: the
/// probe's own Starlark), CPU ms of this process and of the children it waited for, bytes read from storage, and each
/// builtin's {ms, calls}. Not part of the answer (the sensor sends it as a header).
fn timings(steps: &[(&str, u64)], stats: &crate::timed::Stats) -> Json {
    let mut t = serde_json::Map::new();
    for (k, v) in steps {
        t.insert(k.to_string(), json!(v));
    }
    if let Some(eval) = t.get("eval").and_then(|v| v.as_u64()) {
        t.insert("probe".into(), json!(eval.saturating_sub(crate::timed::ms(stats.busy()))));
    }
    let (cpu, children, read) = crate::timed::usage();
    for (k, v) in [("cpu", cpu), ("cpu_children", children), ("read_bytes", read)] {
        if let Some(v) = v {
            t.insert(k.into(), json!(v));
        }
    }
    t.insert("builtins".into(), crate::timed::totals_json(stats));
    Json::Object(t)
}
