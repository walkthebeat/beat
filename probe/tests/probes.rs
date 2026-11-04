//! The probes in tests/probes against the fixture host in tests/root. Tests that need WASM tools run when
//! BEAT_WASM_TOOLS names a directory with coreutils.wasm (the flake check sets it; `nix build .#wasm-coreutils`).
//! BEAT_WASM_CACHE, if set, keeps compiled tools between test runs. The osq() test needs BEAT_OSQUERYI (osqueryi).

use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};

use beat_probe::check::check;
use beat_probe::local::{LocalConfig, LocalHost};
use beat_probe::run::run;
use beat_probe::tools::{default_tools, ToolLimits, Tools};
use serde_json::Value;

fn dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests")
}

fn tools() -> Option<Arc<Tools>> {
    static TOOLS: OnceLock<Option<Arc<Tools>>> = OnceLock::new();
    TOOLS
        .get_or_init(|| {
            let d = std::env::var("BEAT_WASM_TOOLS").ok()?;
            let cache = std::env::var_os("BEAT_WASM_CACHE").map(PathBuf::from);
            Some(Arc::new(Tools::load(Path::new(&d), cache.as_deref()).expect("load tools")))
        })
        .clone()
}

fn source(name: &str) -> String {
    std::fs::read_to_string(dir().join("probes").join(name)).unwrap()
}

fn run_probe(name: &str) -> Value {
    let host = LocalHost::new(LocalConfig {
        root: dir().join("root"),
        maps: vec!["/etc".to_string(), "/var/log".to_string(), "/proc".to_string()],
        tools: tools(),
        limits: ToolLimits::default(),
        osqueryi: std::env::var_os("BEAT_OSQUERYI").map(PathBuf::from),
        journalctl: Some(dir().join("fake-journalctl")),
        bpf_tools: None,
    })
    .unwrap();
    run(name, &source(name), Box::new(host))
}

fn messages_with(name: &str, tools: &[String]) -> String {
    check(name, &source(name), tools).iter().map(|d| d.to_string()).collect::<Vec<_>>().join("\n")
}

fn messages(name: &str) -> String {
    messages_with(name, &default_tools())
}

fn records(r: &Value) -> Vec<(String, String, String)> {
    r["records"]
        .as_array()
        .unwrap()
        .iter()
        .map(|x| (x["subject"].as_str().unwrap().into(), x["key"].as_str().unwrap().into(), x["value"].as_str().unwrap().into()))
        .collect()
}

fn has(r: &Value, subject: &str, key: &str, value: &str) -> bool {
    records(r).contains(&(subject.into(), key.into(), value.into()))
}

#[test]
fn checks_pass_good_probes() {
    for p in ["nginx.star", "failures.star", "pipes.star", "osq.star", "journal.star", "tool_functions.star", "live_ssh.star",
              "checklist.star", "sample_secret.star", "trace.star"] {
        assert_eq!(messages(p), "", "{p}");
    }
}

#[test]
fn checks_reject_top_level_code() {
    let m = messages("bad_toplevel.star");
    assert_eq!(m.matches("may only define functions and constants").count(), 2, "{m}");
}

#[test]
fn checks_reject_recursion() {
    let m = messages("bad_recursion.star");
    assert!(m.contains("recursion is not allowed") && m.contains("a -> b -> a"), "{m}");
    assert!(m.contains("c -> c"), "passing a function to `each` counts as a reference: {m}");
}

#[test]
fn checks_reject_unknown_names() {
    let m = messages("bad_names.star");
    assert!(m.contains("`rm` not found") && m.contains("`open` not found"), "{m}");
}

#[test]
fn checks_reject_wrong_types() {
    let m = messages("bad_types.star");
    assert!(m.contains("Expected type `str` but got `int`"), "{m}");
    assert!(m.contains("Missing required parameter `value`"), "{m}");
}

#[test]
fn checks_reject_missing_main() {
    assert!(messages("no_main.star").contains("no main()"));
}

#[test]
fn checks_reject_unknown_tools() {
    let tools: Vec<String> = ["cat", "sort"].iter().map(|s| s.to_string()).collect();
    let m = messages_with("bad_tool.star", &tools);
    assert!(m.contains("`rm` is not a tool") && m.contains("`grep` is not a tool") && !m.contains("`cat`"), "{m}");
}

#[test]
fn rejected_probe_does_not_run() {
    let r = run_probe("bad_toplevel.star");
    assert_eq!(r["outcome"], "error");
    assert_eq!(r["error"]["kind"], "rejected");
}

#[test]
fn failures_are_isolated_by_each() {
    let r = run_probe("failures.star");
    assert_eq!(r["outcome"], "partial", "{r:#}");
    assert!(has(&r, "file:/etc/passwd", "lines", "2"), "{r:#}");
    assert!(has(&r, "file:/etc/group", "lines", "2"), "an item after two failures still runs: {r:#}");
    assert!(has(&r, "host:self", "secret_files", "3"), "shadow, ssl/private, site.key: {r:#}");
    assert!(!records(&r).iter().any(|x| x.1 == "unreachable"), "a failure outside each ends the probe");
    let kinds: Vec<&str> = r["failures"].as_array().unwrap().iter().map(|f| f["kind"].as_str().unwrap()).collect();
    assert_eq!(kinds, ["denied", "missing", "assertion"], "{r:#}");
    assert!(r["failures"][2]["message"].as_str().unwrap().contains("expected one thing, got 0"));
    assert!(r["failures"][0]["span"].as_str().unwrap().starts_with("failures.star:4"), "{r:#}");
}

#[test]
fn nginx_probe() {
    if tools().is_none() {
        eprintln!("skipped: BEAT_WASM_TOOLS not set");
        return;
    }
    let r = run_probe("nginx.star");
    assert_eq!(r["outcome"], "ok", "{r:#}");
    for f in ["/etc/nginx/nginx.conf", "/etc/nginx/conf.d/tls.conf", "/etc/nginx/sites-enabled/default"] {
        assert!(has(&r, "unit:nginx.service", "loads", &format!("file:{f}")), "{f}: {r:#}");
    }
    assert!(has(&r, "file:/etc/nginx/sites-enabled/default", "server_name", "example.test"), "through a symlink: {r:#}");
    assert!(has(&r, "file:/etc/nginx/conf.d/tls.conf", "ssl_certificate_key", "/etc/ssl/private/site.key"), "{r:#}");
    let sha = records(&r).into_iter().find(|x| x.0 == "file:/etc/nginx/nginx.conf" && x.1 == "sha256").unwrap().2;
    assert_eq!(sha.len(), 16, "{sha}");
}

#[test]
fn pipes() {
    if tools().is_none() {
        eprintln!("skipped: BEAT_WASM_TOOLS not set");
        return;
    }
    let r = run_probe("pipes.star");
    assert_eq!(r["outcome"], "ok", "{r:#}");
    assert!(has(&r, "pipe", "first_sorted", "include /etc/nginx/conf.d/*.conf;"), "{r:#}");
    assert!(has(&r, "pipe", "status", "[0, 0, 0]"), "{r:#}");
    assert!(has(&r, "pipe", "test_status", "[1]") && has(&r, "pipe", "test_ok", "False"), "{r:#}");
    assert!(has(&r, "pipe", "wc", "3"), "{r:#}");
    assert!(has(&r, "pipe", "escape_ok", "False"), "a tool cannot follow a symlink out of the mapping: {r:#}");
    assert!(has(&r, "stat", "escape_kind", "link"), "{r:#}");
    assert!(has(&r, "stat", "unmapped", "None"), "{r:#}");
    let notes = r["notes"].to_string();
    assert!(notes.contains("/root/.bashrc: outside the mapped directories"), "{notes}");
}

#[test]
fn tool_functions_are_checked() {
    let m = messages("bad_tool_functions.star");
    assert!(m.contains("`grep` not found"), "a tool missing on the target is an unknown name: {m}");
    assert!(!m.contains("sort"), "argument types of tool functions are checked at run time only: {m}");
}

#[test]
fn tool_functions() {
    if tools().is_none() {
        eprintln!("skipped: BEAT_WASM_TOOLS not set");
        return;
    }
    let r = run_probe("tool_functions.star");
    assert_eq!(r["outcome"], "ok", "{r:#}");
    assert!(has(&r, "tools", "sorted", "c,b,a"), "{r:#}");
    assert!(records(&r).iter().any(|x| x.1 == "sha256" && x.2.len() == 16), "{r:#}");
    assert!(has(&r, "tools", "readlink_is_builtin", "../sites-available/default"), "{r:#}");
}

#[test]
fn osq() {
    if std::env::var_os("BEAT_OSQUERYI").is_none() {
        eprintln!("skipped: BEAT_OSQUERYI not set");
        return;
    }
    let r = run_probe("osq.star");
    assert_eq!(r["outcome"], "ok", "{r:#}");
    assert!(has(&r, "osq", "n", "2 int"), "typed, and `?` bound: {r:#}");
    assert!(has(&r, "osq", "s", "it's"), "quoted on the host side: {r:#}");
    assert!(has(&r, "osq", "z", "None") && has(&r, "osq", "f", "float"), "{r:#}");
    assert!(has(&r, "osq", "pid_type", "int"), "{r:#}");
    assert!(has(&r, "osq", "empty", "[]"), "{r:#}");
}

#[test]
fn journal() {
    let r = run_probe("journal.star");
    assert_eq!(r["outcome"], "ok", "{r:#}");
    let ts: Vec<String> = records(&r).into_iter().map(|x| x.1).collect();
    let mut sorted = ts.clone();
    sorted.sort();
    assert_eq!(ts, sorted, "oldest first, whatever order journalctl printed");
    assert!(has(&r, "journal", "2025-10-03T00:00:00Z", "nginx.service|42|6|Reloading nginx"), "{r:#}");
    assert!(has(&r, "journal", "2025-10-03T00:01:00Z", "nginx.service|None|6|hi"), "bytes decoded: {r:#}");
    let args = records(&r).into_iter().find(|x| x.2.contains("args:")).unwrap().2;
    for a in ["--output=json", "--lines=5", "--unit=nginx.service", "--since=-30d", "--grep=Reload"] {
        assert!(args.contains(a), "{a} missing: {args}");
    }
    assert!(!args.contains("--dmesg"), "{args}");
    let kernel = records(&r).into_iter().find(|x| x.0 == "journal_kernel").unwrap().2;
    assert!(kernel.contains("--dmesg"), "{kernel}");
}

fn has_drain() -> bool {
    tools().is_some_and(|t| t.manifest().contains_key("drain"))
}

#[test]
fn log_builtins_need_the_drain_tool() {
    assert!(messages("logs.star").contains("log_summary"), "without drain.wasm the log built-ins are unknown names");
    let mut with = default_tools();
    with.push("drain".into());
    assert_eq!(messages_with("logs.star", &with), "");
}

#[test]
fn logs() {
    if !has_drain() {
        eprintln!("skipped: BEAT_WASM_TOOLS has no drain.wasm");
        return;
    }
    let r = run_probe("logs.star");
    assert_eq!(r["outcome"], "ok", "{r:#}");
    let log = "log:/var/log/auth.log";
    assert!(has(&r, log, "lines_count", "11"), "{r:#}");
    assert!(has(&r, log, "lines_read_count", "11") && has(&r, log, "first_time", "Oct  7 09:00:01"), "span: {r:#}");
    assert!(has(&r, log, "last_time", "Oct  7 09:10:01"), "span: {r:#}");
    let invalid = "<TIME> <SELF> sshd[<PID>]: Invalid user <*> from <IP>";
    // the template's subject carries its id; the double-spaced `Invalid user  0101` is the same template
    let subj = records(&r).into_iter().find(|x| x.1 == "template" && x.2 == invalid).expect("template").0;
    assert!(subj.starts_with(&format!("{log}#")), "{subj}");
    assert!(has(&r, &subj, "lines_count", "3"), "{r:#}");
    assert!(has(&r, &subj, "p0", "admin") && has(&r, &subj, "p0_distinct_count", "3"), "{r:#}");
    let x = "extract:/var/log/auth.log";
    assert!(has(&r, x, "matched_count", "3"), "{r:#}");
    assert!(has(&r, x, "line", "Oct  7 09:05:02 legacy-web-1 sshd[1262]: Invalid user  0101 from 198.51.100.4"), "raw, last: {r:#}");
    assert!(!has(&r, x, "line", "Oct  7 09:00:01 legacy-web-1 sshd[1201]: Invalid user admin from 203.0.113.9"), "limit 2: {r:#}");
    assert!(has(&r, &format!("curated:{invalid}"), "new", "no"), "{r:#}");
    assert!(records(&r).iter().any(|x| x.0.starts_with("curated:") && x.2 == "yes"), "lines outside the curated set are new: {r:#}");
    assert!(has(&r, "journal", "lines_count", "3"), "{r:#}");
    let kind = |key: &str| r["records"].as_array().unwrap().iter().find(|x| x["subject"] == log && x["key"] == key)
        .map(|x| x["kind"].clone());
    assert_eq!(kind("lines_count"), Some(Value::from("metric")), "declared kinds");
    assert_eq!(kind("first_time"), Some(Value::from("time")));
    let undeclared = r["records"].as_array().unwrap().iter().find(|x| x["subject"] == "journal").unwrap();
    assert!(undeclared.get("kind").is_none(), "no kind unless declared: {undeclared}");
}

#[test]
fn emit_rejects_an_unknown_kind() {
    let host = LocalHost::new(LocalConfig {
        root: dir().join("root"), maps: vec![], tools: None, limits: ToolLimits::default(), osqueryi: None, journalctl: None,
        bpf_tools: None,
    })
    .unwrap();
    let src = "def main() -> None:\n    emit(\"s\", \"k\", \"v\", \"x\", kind = \"metric\")\n    emit(\"s\", \"k2\", \"v\", \"x\", kind = \"size\")\n";
    let r = run("kinds.star", src, Box::new(host));
    assert_eq!(r["outcome"], "error", "{r:#}");
    assert!(r["error"]["message"].as_str().unwrap().contains("kind must be one of"), "{r:#}");
}

#[test]
fn osq_without_osquery_is_an_error() {
    let host = LocalHost::new(LocalConfig {
        root: dir().join("root"),
        maps: vec!["/etc".into()],
        tools: None,
        limits: ToolLimits::default(),
        osqueryi: None,
        journalctl: None,
        bpf_tools: None,
    })
    .unwrap();
    let r = run("osq.star", &source("osq.star"), Box::new(host));
    assert_eq!(r["outcome"], "error");
    assert_eq!(r["error"]["kind"], "source", "{r:#}");
}

/// The live host's /proc and /sys, as the sensor maps them (it maps all of `/`). The Nix build sandbox has no /sys.
fn run_on_this_host(name: &str) -> Value {
    let host = LocalHost::new(LocalConfig {
        root: PathBuf::from("/"),
        maps: ["/proc", "/sys"].iter().filter(|d| Path::new(d).is_dir()).map(|d| d.to_string()).collect(),
        tools: None,
        limits: ToolLimits::default(),
        osqueryi: None,
        journalctl: None,
        bpf_tools: None,
    })
    .unwrap();
    run(name, &source(name), Box::new(host))
}

#[test]
fn checklist() {
    let r = run_on_this_host("checklist.star");
    assert_eq!(r["outcome"], "ok", "{r:#}");
    let recs = records(&r);
    for (subject, key) in [("host", "seconds"), ("host", "forks_per_s"), ("cpu", "busy_pct"), ("cpu:0", "idle_pct"),
                           ("memory", "used_pct"), ("tcp", "retrans_per_s")] {
        assert!(recs.iter().any(|x| x.0 == subject && x.1 == key), "{subject} {key} missing: {r:#}");
    }
    assert!(r["records"].as_array().unwrap().iter().all(|x| x["kind"] == "metric"), "all declared metrics");
}

#[test]
fn sample_denies_secrets() {
    let r = run_on_this_host("sample_secret.star");
    assert_eq!(r["outcome"], "partial", "{r:#}");
    assert_eq!(r["failures"][0]["kind"], "denied", "{r:#}");
}

#[test]
fn checks_require_literal_catalog_entries() {
    let m = messages("bad_trace.star");
    assert!(m.contains("takes the catalog entry as a literal"), "{m}");
    assert!(m.contains("`bpftrace` is not a catalog entry"), "{m}");
}

#[test]
fn needs_reads_the_entries_from_the_text() {
    assert_eq!(beat_probe::check::trace_entries(&source("trace.star")), ["biolatency", "execsnoop"]);
    assert!(beat_probe::check::trace_entries(&source("checklist.star")).is_empty());
    assert!(beat_probe::check::trace_entries("def main(:").is_empty(), "does not parse: needs nothing");
}

#[test]
fn trace_without_a_catalog_is_an_error() {
    let r = run_probe("trace.star");
    assert_eq!(r["outcome"], "error", "{r:#}");
    assert_eq!(r["error"]["kind"], "source", "{r:#}");
}

#[test]
fn environ_gives_names_safe_values_and_tokens() {
    let r = run_probe("environ.star");
    let text = r.to_string();
    assert!(has(&r, "env:PATH", "value", "/usr/bin"), "{r:#}");
    assert!(has(&r, "env:DB_PASSWORD", "hidden", "True"), "{r:#}");
    assert!(!text.contains("hunter2") && !text.contains("Sup3rS3cret!"), "{r:#}");
    assert!(text.contains("beat-env-value:") && text.contains("beat-env-option:masked"), "{r:#}");
    assert_eq!(r["failures"].as_array().unwrap().len(), 1, "a process gone is a failure: {r:#}");
    assert!(r["secrets"]["flagged"].as_array().unwrap().iter().any(|f| f["rule"] == "beat-env-value" && f["action"] == "hash"), "{r:#}");
}
