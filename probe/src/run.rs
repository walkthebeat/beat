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

pub fn run(name: &str, source: &str, host: Box<dyn Host>) -> Json {
    let started = now();
    let t0 = Instant::now();
    let id = probe_id(source);
    let result = |outcome: &str, st: &RunState, error: Json, notes: Vec<String>, secrets: Option<Json>| {
        let mut r = json!({
            "probe": id, "name": name, "started": iso_utc(started), "finished": iso_utc(now()),
            "outcome": outcome,
            "records": st.records, "failures": st.failures, "error": error,
            "diag": st.diag, "notes": notes,
            "usage": {"wall_ms": t0.elapsed().as_millis() as u64},
        });
        // Only when gate 1 found something, so that clean answers hash as before (docs/security.md).
        if let Some(s) = secrets {
            r["secrets"] = s;
        }
        r
    };

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

    let notes = ctx.host.notes();
    let mut st = ctx.state.borrow_mut();
    let secrets = crate::secrets::gate(&mut st);
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
