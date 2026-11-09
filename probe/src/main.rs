//! beat-probe: check and run Starlark probes (docs/probes.md).
//!
//!   beat-probe check FILE... [--tools DIR]
//!       Checks before sending (§6), against the tools in DIR (default: the uutils coreutils list). Exit 1 on any
//!       problem.
//!   beat-probe run FILE [--root DIR] [--map /etc]... [--tools DIR] [--osqueryi PATH] [--journalctl PATH]
//!       Runs main() and prints the run result as JSON (§9). Files are read under --root (default /), only in the
//!       --map directories (default /etc), read-only. --tools: a directory of .wasm tools (coreutils.wasm).
//!       --cache: where compiled tools are kept (default $XDG_CACHE_HOME/beat-probe or ~/.cache/beat-probe).
//!       --osqueryi, --journalctl: the programs behind osq() and journal(); they read the live host, not --root.
//!       Without them, those builtins fail with an error of kind "source". --bpf-tools: the catalog's directory
//!       behind trace() (libbpf-tools and timeout); it needs CAP_BPF and CAP_PERFMON.
//!       FILE may be `-`: the probe is read from stdin (--name sets the name used in spans and errors).
//!       The result's `timings` say where the run's time went; --profile adds each host call, the slowest as records.
//!   beat-probe needs FILE
//!       The capabilities the probe's trace() entries need, as JSON ({"entries": [...], "capabilities": [...]}): what
//!       a sensor adds to the question's unit. FILE may be `-` (stdin). A probe that does not parse needs nothing.
//!   beat-probe guide [--tools DIR]
//!       The builtins reference for agents (what the sensor's `run` tool describes), with the tool list.
//!   beat-probe tools --tools DIR
//!       The tools part of the manifest (§7): name and SHA-256 of the .wasm providing it.
//!   beat-probe secrets [--root DIR] [--map /]... [--live | --walk] [--budget-s N] [--budget-entries N]
//!       Metadata of the secret files a probe must not read, as JSON lines (path kind mode uid gid size mtime): what a
//!       sensor reads outside its sandbox, to hide those files and pass their metadata in (BEAT_SECRETS_FILE). --live: the
//!       fixed paths and single-level globs, cheap, for every question. --walk: the recursive patterns, in the background
//!       (scan.rs). A last line {"scan": ...} says what was left out.

use std::path::PathBuf;
use std::process::ExitCode;

use beat_probe::{check, local::{LocalConfig, LocalHost}, run, scan::Budget, tools::{default_tools, ToolLimits, Tools}};

struct Args {
    files: Vec<String>,
    root: PathBuf,
    maps: Vec<String>,
    tools: Option<PathBuf>,
    cache: Option<PathBuf>,
    osqueryi: Option<PathBuf>,
    journalctl: Option<PathBuf>,
    bpf_tools: Option<PathBuf>,
    name: Option<String>,
    profile: bool,
    scope: Option<Scope>,
    budget: Budget,
}

/// Which secret files `beat-probe secrets` enumerates; neither flag: both.
#[derive(Clone, Copy, PartialEq)]
enum Scope {
    Live,
    Walk,
}

fn parse(argv: &[String]) -> anyhow::Result<Args> {
    let mut a = Args { files: Vec::new(), root: PathBuf::from("/"), maps: Vec::new(), tools: None, cache: None,
                        osqueryi: None, journalctl: None, bpf_tools: None, name: None, profile: false, scope: None, budget: Budget::default() };
    let mut it = argv.iter();
    while let Some(x) = it.next() {
        let mut val = || it.next().cloned().ok_or_else(|| anyhow::anyhow!("{x} needs a value"));
        match x.as_str() {
            "--root" => a.root = PathBuf::from(val()?),
            "--map" => a.maps.push(val()?),
            "--tools" => a.tools = Some(PathBuf::from(val()?)),
            "--cache" => a.cache = Some(PathBuf::from(val()?)),
            "--osqueryi" => a.osqueryi = Some(PathBuf::from(val()?)),
            "--journalctl" => a.journalctl = Some(PathBuf::from(val()?)),
            "--bpf-tools" => a.bpf_tools = Some(PathBuf::from(val()?)),
            "--name" => a.name = Some(val()?),
            "--profile" => a.profile = true,
            "--live" => a.scope = Some(Scope::Live),
            "--walk" => a.scope = Some(Scope::Walk),
            "--budget-s" => a.budget.seconds = val()?.parse()?,
            "--budget-entries" => a.budget.entries = val()?.parse()?,
            s if s.starts_with("--") => anyhow::bail!("unknown option {s}"),
            _ => a.files.push(x.clone()),
        }
    }
    if a.maps.is_empty() {
        a.maps.push("/etc".into());
    }
    if a.cache.is_none() {
        a.cache = std::env::var_os("XDG_CACHE_HOME")
            .map(PathBuf::from)
            .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".cache")))
            .map(|c| c.join("beat-probe"));
    }
    Ok(a)
}

fn main() -> ExitCode {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    match real_main(&argv) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("beat-probe: {e:#}");
            ExitCode::from(2)
        }
    }
}

fn real_main(argv: &[String]) -> anyhow::Result<ExitCode> {
    let (cmd, rest) = argv.split_first().ok_or_else(|| anyhow::anyhow!("usage: beat-probe check|run|tools ..."))?;
    let a = parse(rest)?;
    let loading = std::time::Instant::now();
    // `tools` checks every file and writes the cache's index; the other commands use the index when it is current
    let load = if cmd == "tools" { Tools::verify } else { Tools::load };
    let tools = a.tools.as_ref().map(|d| load(d, a.cache.as_deref())).transpose()?.map(std::sync::Arc::new);
    let tools_ms = loading.elapsed().as_millis() as u64;
    match cmd.as_str() {
        "check" => {
            let names: Vec<String> = tools.as_ref().map(|t| t.manifest().into_keys().collect()).unwrap_or_else(default_tools);
            let mut bad = false;
            for f in &a.files {
                let src = std::fs::read_to_string(f)?;
                let diags = check::check(f, &src, &names);
                for d in &diags {
                    println!("{d}");
                }
                if diags.is_empty() {
                    println!("{f}: ok");
                }
                bad |= !diags.is_empty();
            }
            Ok(if bad { ExitCode::from(1) } else { ExitCode::SUCCESS })
        }
        "run" => {
            let [f] = a.files.as_slice() else { anyhow::bail!("run takes one probe file") };
            let src = if f == "-" {
                let mut s = String::new();
                std::io::Read::read_to_string(&mut std::io::stdin(), &mut s)?;
                s
            } else {
                std::fs::read_to_string(f)?
            };
            let f = a.name.as_deref().unwrap_or(if f == "-" { "probe.star" } else { f });
            let host = LocalHost::new(LocalConfig {
                root: a.root.clone(),
                maps: a.maps.clone(),
                tools,
                limits: ToolLimits::default(),
                osqueryi: a.osqueryi.clone(),
                journalctl: a.journalctl.clone(),
                bpf_tools: a.bpf_tools.clone(),
            })?;
            let r = run::run_timed(f, &src, Box::new(host), a.profile, &[("tools", tools_ms)]);
            println!("{}", serde_json::to_string_pretty(&r)?);
            Ok(match r["outcome"].as_str() {
                Some("ok") => ExitCode::SUCCESS,
                Some("partial") => ExitCode::from(1),
                _ => ExitCode::from(3),
            })
        }
        "needs" => {
            let [f] = a.files.as_slice() else { anyhow::bail!("needs takes one probe file") };
            let src = if f == "-" {
                let mut s = String::new();
                std::io::Read::read_to_string(&mut std::io::stdin(), &mut s)?;
                s
            } else {
                std::fs::read_to_string(f)?
            };
            let entries = check::trace_entries(&src);
            let caps = beat_probe::catalog::capabilities(entries.iter().map(String::as_str));
            println!("{}", serde_json::json!({"entries": entries, "capabilities": caps}));
            Ok(ExitCode::SUCCESS)
        }
        "guide" => {
            let names: Vec<String> = tools.as_ref().map(|t| t.manifest().into_keys().collect()).unwrap_or_else(default_tools);
            print!("{}", include_str!("guide.md").replace("{tools}", &names.join(" ")));
            Ok(ExitCode::SUCCESS)
        }
        "tools" => {
            let t = tools.ok_or_else(|| anyhow::anyhow!("tools needs --tools DIR"))?;
            for (name, sha) in t.manifest() {
                println!("{name}\t{sha}");
            }
            Ok(ExitCode::SUCCESS)
        }
        "secrets" => {
            if std::env::var_os(beat_probe::local::SECRETS_FILE).is_some() {
                anyhow::bail!("secrets: {} is set; this command finds secrets itself", beat_probe::local::SECRETS_FILE);
            }
            let host = LocalHost::new(LocalConfig {
                root: a.root.clone(),
                maps: a.maps.clone(),
                tools: None,
                limits: ToolLimits::default(),
                osqueryi: None,
                journalctl: None,
                bpf_tools: None,
            })?;
            let e = |e| anyhow::anyhow!("{e:?}");
            let (mut list, mut report) = (Vec::new(), serde_json::Map::new());
            if a.scope != Some(Scope::Walk) {
                let (live, skipped) = host.secrets_live().map_err(e)?;
                list.extend(live);
                report.insert("skipped".into(), serde_json::json!(skipped));
            }
            if a.scope != Some(Scope::Live) {
                let (walked, r) = host.secrets_walk(&a.budget).map_err(e)?;
                list.extend(walked);
                report = serde_json::to_value(&r)?.as_object().cloned().unwrap_or_default();
            }
            list.sort_by(|x, y| x.path.cmp(&y.path));
            list.dedup_by(|x, y| x.path == y.path);
            for s in list {
                let mut row = serde_json::json!({"path": s.path, "kind": s.kind, "mode": s.mode, "uid": s.uid,
                                                 "gid": s.gid, "size": s.size, "mtime": s.mtime});
                // Transformer answers for the sandbox, which covers these files (docs/security.md).
                if let serde_json::Value::Object(extra) = host.prepare(&s) {
                    row.as_object_mut().unwrap().extend(extra);
                }
                println!("{row}");
            }
            println!("{}", serde_json::json!({"scan": report}));
            Ok(ExitCode::SUCCESS)
        }
        other => anyhow::bail!("unknown command {other}"),
    }
}
