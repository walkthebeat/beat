# Probes: Starlark programs, beat built-ins

The specification of what a question is and what it may do. Rules are numbered (`[B3]`, `[F2]`) and the code cites
them; decisions are marked **D1**, **D2** ... and collected in §10. How a question reaches a host and who may ask
one: `docs/security.md`. Evidence for the claims about `starlark-rust` below: §11.

## 1. What this is

A **probe** is a Starlark file. Starlark is the Python dialect Bazel uses for build files: designed to run code
that is not fully trusted, deterministic, with no input or output of its own. A probe can only do what the
**beat builtins** let it do, and the builtins only read: they run WASM tools, read the file system through the
sensor's read-only mapping, and query live state through osquery and the journal. Every builtin is native code in
the sensor; some of them reach a separate native program (osqueryi, journalctl), which the probe never sees.

```
 CLIENT (beat, beat-mcp, an agent)                      SENSOR (one per host)
 ┌──────────────────────────────────────────┐          ┌──────────────────────────────────────────────────┐
 │ nginx.star                               │          │ 1. the same checks again (§6)                    │
 │   parse → resolve names → typecheck      │ question │ 2. one transient systemd unit per run (§8):      │
 │   → reject recursion (beat-probe check)  │ ───────► │    starlark-rust evaluator + beat builtins       │
 │   → sign (docs/security.md)              │ via the  │      ├─ pipe(): WASM tool instances, wired       │
 │ errors appear here, before anything is   │ service  │      │  stdout → stdin by the sensor (§4.1)       │
 │ sent                                     │ ◄─────── │      ├─ stat/read/glob: read-only mapping (§4.2) │
 └──────────────────────────────────────────┘  answer  │      └─ osq, journal, secrets: live state (§4.3) │
                                                       │ 3. records, failures, text, usage (§9)           │
                                                       └──────────────────────────────────────────────────┘
```

Why Starlark: sh and nu need fork/exec to run a pipe, and neither can run tools that are WASM instances; a root
process should not evaluate a shell. A typed IR compiled from sh would solve that, at the cost of owning a language.
Starlark gives the same properties with an existing specification, two maintained implementations (Rust, Go), and
a syntax that agents and admins already read. What stays ours is the part that is ours anyway: the builtins, the failure model, the
limits and the records.

Non-goals: no shell or nu frontend (the probe *is* Starlark); no writes, network or processes, ever ([P2]);
not a general-purpose platform (real computation goes into sandboxed tools and osquery's SQL).

## 2. Design rules

A change to this spec that breaks one of these needs a reason here.

- **[P1] Bounded.** Every run ends: Starlark has no `while`, loops run over finite values, recursion is rejected
  (§6), and OS limits plus wasmtime fuel bound the rest (§8).
- **[P2] Read-only.** No builtin can change the host. There is no builtin for writing, deleting, signalling or
  connecting, and Starlark has none of its own.
- **[P3] Deterministic.** For the same host state, a probe emits the same records in the same order. Starlark
  dicts keep insertion order; builtins return sorted lists where the host has no order (`glob`, `list_dir`).
- **[P4] Nothing is spliced.** Tools get argument lists, never a command line to re-parse; `osq` gets bound
  parameters. A value from a file never becomes code.
- **[P5] Checked before sent.** Unknown names, wrong argument types and arity, and recursion are found on the client
  (§6), and again on the sensor before running.

## 3. A probe

```python
"""nginx: unit, config files (found from the running master), certificates.

Applies to: hosts running nginx under systemd (nginx.service), Debian/Ubuntu package layout.
Assumes: exactly one nginx master; config from its `-c` flag, else /etc/nginx/nginx.conf.
Cannot see: who connects to it; includes nested deeper than one level.
"""

UNIT = "unit:nginx.service"

def config_files(conf: str) -> list[str]:
    files = {conf: None}                                  # a dict keeps order and drops duplicates
    for line in read(conf).splitlines():
        m = re_match(r"^\s*include\s+([^;]+);", line)
        if m:
            pat = m[1] if m[1].startswith("/") else path_join(path_dirname(conf), m[1])
            for f in glob(pat):                           # no match: [] (sh gives the pattern back)
                files[f] = None
    return list(files)

def main() -> None:
    master = one(osq("select start_time, cmdline from processes where name = ? and cmdline like ?",
                     "nginx", "nginx: master process%"),
                 "expected one nginx master")
    emit(UNIT, "process_started", iso_utc(master["start_time"]), "osq.processes")

    m = re_match(r"-c (\S+)", master["cmdline"])
    conf = m[1] if m else "/etc/nginx/nginx.conf"
    s = stat(conf)
    expect(s != None and s.readable, "nginx config %s not readable" % conf)

    for f in config_files(conf):
        s = stat(f)
        if s == None or s.kind != "file":
            continue
        emit("file:" + f, "mtime", iso_utc(s.mtime), "stat")
        emit("file:" + f, "sha256", pipe(["sha256sum", f]).stdout[:16], "sha256sum")
```

- **[S1]** A probe is one `.star` file. Its docstring is the header (what it covers, applies to, assumes, cannot see),
  so a reader knows its scope before its code.
- **[S2]** The sensor calls `main()`. Probe code lives in functions: top-level statements may only bind constants and
  define functions. Reason: `starlark-rust` checks types statically only inside `def` bodies (§11).
- **[S3]** `load()` is allowed only for shared libraries (`load("//lib/systemd.star", "unit_files")`), sent with the
  probe and covered by its hash and signature. **D5.** Not built: sensors refuse a question with libraries.

## 4. The builtins

Signatures in Starlark's type syntax. A **failure** (§5) means the host differs from what the probe assumes.

### 4.1 Tools

```python
pipe(*stages: list[str], stdin: str = "") -> ToolResult
# ToolResult: .stdout: str, .stderr: str, .status: list[int], .ok: bool  (all statuses 0)
```

- **[B1]** Each stage is `[tool, arg, ...]`: one fresh WASM instance of that tool. The sensor connects stage *n*'s
  stdout to stage *n+1*'s stdin and runs them concurrently. This is a Kahn process network: blocking reads on FIFO
  channels, so the output does not depend on scheduling. `pipe(["grep", "-E", re, conf], ["sed", "-E", expr])` is
  the `grep | sed` of a shell.
- **[B1a]** Every tool is also a function: `sort("-u", stdin = text)` is `pipe(["sort", "-u"], stdin = text)`,
  `sha256sum(path)` is `pipe(["sha256sum", path])`. The functions come from the target sensor's manifest, so a tool
  that is missing there is an unknown name to the checks (§6). A tool whose name is already taken (`readlink`,
  `dir`) is reached through `pipe()` only.
- **[B2]** Arguments are passed as given, one string each; nothing is split, globbed or quoted ([P4]).
- **[B3]** A non-zero exit status is a value, not a failure: `grep` finding nothing exits 1, and the probe decides
  what that means (`.status`, `.ok`). **D4.**
- **[B4]** Instances see only the sensor's read-only mapping, no network, no processes, a fixed environment
  (`LC_ALL=C.UTF-8`, `TZ=UTC`). Only tools in the sensor's manifest exist (§7).
- **[B5]** Streams between stages are not held in memory; `.stdout` and `.stderr` are, and are bounded (§8).
  `pipe(["cat", log], ["grep", "x"])` works on a large log; `read(log)` may not. **D3.**
- **[B6]** Output is decoded as UTF-8; invalid bytes become U+FFFD (open question, §10).

### 4.2 File system

```python
stat(path: str) -> Stat | None      # None: missing. .kind ("file", "dir", "link", "other"), .size, .mode,
                                    #   .uid, .gid, .user, .group, .mtime (epoch seconds), .readable, .secret
read(path: str) -> str              # bounded; secret path: failure "denied"; missing: failure "missing"
glob(pattern: str) -> list[str]     # sorted; no match: []
list_dir(path: str) -> list[str]    # sorted
readlink(path: str) -> str | None
```

- **[B7]** Paths are absolute and resolve inside the sensor's mapping. Outside it, a path behaves as missing and the
  run's notes say so, so that the reviewer can tell "unmapped" from "missing". `stat` follows symlinks that stay
  inside the mapping (`sites-enabled/default`); a dangling one, or one that leads outside, is reported as kind
  `link`, and tools cannot follow it either.
- **[B8]** `readable` means the sensor would serve the content: it exists, is mapped, and is not secret.
- **[B9]** Secret paths (shadow, private keys, keytabs, `/proc/*/environ`) have metadata but no content: `read` is a
  failure of kind `denied`; a tool opening one gets `EACCES`. Files of known meaning are read for what they mean
  through `transform` (C23), and everything a probe emits passes gate 1 (`docs/security.md`, Secrets).

### 4.3 Live state: osquery, the journal, secrets

```python
osq(query: str, *params) -> list[dict[str, typing.Any]]
journal(kernel: bool = False, unit: str | None = None, since: str | None = None, grep: str | None = None,
        limit: int = 1000) -> list[dict[str, typing.Any]]      # .ts, .unit, .pid, .priority, .message
secrets() -> list[Secret]           # .path, .kind, .mode, .uid, .gid, .size, .mtime
environ(pid: int) -> list[EnvVar]   # .name; .value (known-safe names, passwords masked) or .hash (a token: docs/security.md)
sample(patterns: list[str], seconds: float = 1.0) -> Sample   # .seconds .before .after ({path: content})
```

- **[B10]** `osq` is osquery's SQL (its SQLite dialect, joins included), straight to osquery: no other engine
  in between. `?` take the extra arguments, bound on the sensor's side ([P4]). Rows come back as dicts keyed by
  column name, with typed values (int, float, str, None), so `iso_utc(row["start_time"])` needs no conversion.
  One read per call: a `select` (or `with ... select`, `values`), with no `;` inside. Every call of a run goes to
  one `osqueryi` session (since 2026-11-08; one process per call cost about 0.36 s before any work, and made
  discovery's seven calls take 6 s on the lab's hosts, 0.5-0.8 s since), so no call may change what the next sees.
- **[B11]** `journal` reads the systemd journal: the newest `limit` entries matching `unit`, `since` (as journalctl
  takes it: `-30d`, `2026-10-01`) and `grep` (a regex on the message), oldest first.
- **[B11a]** `journal(kernel=True)` is the kernel's messages of this boot (`journalctl --dmesg`): what dmesg shows.
- **[B11b]** `sample` reads the files matching `patterns` (globs), then reads them again `seconds` later (at most
  60): counters in /proc and /sys, for rates. `seconds` is measured, not the one asked for. A file gone by the second
  read (a process that exited) is missing from `after` only; a secret path is a failure "denied", as for `read`.
- **[B12]** Like every builtin, these are read-only and bounded (a timeout and an output limit, §8). They read
  the live host, not the file mapping: osquery sees all processes and sockets as the sensor's user does.
- Later sources (tcpdump, eBPF summaries) are added the same way: a builtin, native code behind `Host`.
- **Logs** (C21, `docs/security.md`): the `drain` WASM tool summarizes log lines into templates, counts,
  parameter values and example lines (`pipe(["cat", log], ["drain", "--self", host, "--header", "3"])`, or
  `drain(stdin = ...)` over `journal()` messages; output is JSON for `json.decode`). Over it, three built-ins in
  Starlark (`probe/src/logs.star`, defined only on sensors with `drain.wasm`, so elsewhere they are unknown names to
  the checks):

```python
log_summary(path=None, lines=None, tail=0, self_names=[], header=0, templates=None, masks={}, sim=0.4, depth=4,
            top=200, cap=8, examples=3) -> dict        # .lines .skipped .omitted .templates[{id template count
                                                       #   params[{distinct values min max}] examples new}]
log_extract(path=None, lines=None, tail=0, templates=None, grep=None, limit=20, first=False, self_names=[],
            header=0, masks={}) -> dict                # .matched .lines (as written: C22)
emit_log_summary(name, summary, source="drain")        # records: log:<name>#<template id> template, lines_count,
                                                       #   p<i>, p<i>_distinct_count, p<i>_min/_max, example, new
```

- **[B13]** The working loop (C21): `log_summary` to explore; the person or agent picks templates; the next
  question passes them as `templates=[...]`, so every host reports the same templates (and mines the rest, marked
  `new`); `log_extract` returns the lines behind a template or a pattern. Nothing is kept on the sensor between
  questions: a question's window is its input (`tail=`, or `journal(since=...)`).
- **Gregg's 60-second checklist**: two built-ins in Starlark over `sample()`
  (`probe/src/checklist.star`, defined on every sensor). `checklist(seconds=5, top=10, cgroup_depth=4)` returns the
  USE method's reading (`use`: per resource, utilization, saturation, errors, as text) and its numbers: load, CPU
  and per CPU, memory, pressure (PSI), whole disks with I/O (as iostat -xz), interfaces with traffic, TCP and UDP
  counters, the busiest commands (grouped by command, with the busiest and idlest process of each), and cgroup CPU
  throttling. `emit_checklist(c)` turns it into records, all declared metrics. Network counters are PID 1's
  (`/proc/1/net`): a question runs with `PrivateNetwork=yes`, where `/proc/net` shows only its own loopback.
- **[B11c] `trace(entry, seconds, ...)`**, the catalog of B. Gregg's tools (`probe/src/catalog.rs`; libbpf-tools in
  the sensor's closure, `sensor/libbpf-tools.nix`). The entry is a literal (a check), so the entries a probe uses, and
  the capabilities they need, are read from its text: the sensor adds `CAP_BPF CAP_PERFMON` to that question's unit
  only (`beat-probe needs`). The answer is a reduction made as the tool's output streams: histograms with
  percentiles, or events filtered, keyed (with coarsenings), counted, summed and bounded, with what it saw (seen,
  matched, unparsed, lost, its own left out).
- No SQL engine beyond osquery's is part of the sensor. Starlark covers what probes need (time formatting, regex,
  scanning files, "last one wins"); if log analytics need more, it comes as a tool or a builtin.

### 4.4 Records and checks

```python
emit(subject: str, key: str, value: str, source: str, kind: str = "") -> None   # kind: semantic metric time identity
one(items: list[T], message: str) -> T          # exactly one element, else a failure "expected ..., got N"
expect(condition: bool, message: str) -> None   # a failure if condition is False
fail(message: str) -> typing.Never             # always a failure; replaces Starlark's own fail
each(items: list[T], fn: typing.Callable[[T], None]) -> None    # failures end one call, not the probe (§5)
print(*args) -> None                            # goes to the run's diagnostic text, not to the records
```

### 4.4.1 Records that compare well across a fleet

One host's records are read by a person; a survey's are compared across hundreds of hosts. The service groups
answers by their semantic part and factors the groups into dimensions: slots (subject, key) whose values divide the
hosts the same way. It copes with probes that ignore the rules below, but each rule removes a guess:

- **[R1] One fact per record.** A value that packs several facts (`"orderbatch 1.5.0 starting, interval=10s"`, a
  list of `KEY=value` pairs in one string) can only be compared as a whole. Emit `app_version 1.5.0` and
  `batch_interval 10`. Several values of one key (a unit's `Environment=` lines) are several records, not one.
- **[R2] Configured and observed, separately, for the same fact.** `server sched02` from the config file and
  `connected_server sched01` from the process or its log. Where they agree on every host but one, that host has a
  change not applied, a stale process or a second config: the strongest finding there is, and only visible if
  both are emitted.
- **[R3] Stable subjects and keys.** No PID, ephemeral port, timestamp, generated id or hostname in a subject or a
  key: `unit:sched-agent.service`, not `pid:4762`. Volatile things are values. A subject that changes between runs
  makes every run a new slot (and drift that is not drift).
- **[R4] Say what a number is.** A measurement (counts, sizes, percentages, ages) is not configuration even when it
  takes few values (`starts_7d` 0-3 looks like a port). Declare it (`emit(..., kind = "metric")`, below), name
  such keys as measurements (`_count`, `_pct`, `_bytes`, `_7d`), and keep configuration values verbatim.
- **[R5] One form per kind of value.** Numbers as plain digits (`2048`, not `2 KB`); times as epoch seconds or
  `iso_utc`, the same for a key everywhere; booleans as `yes`/`no`.
- **[R6] Absence that matters is a record.** `present no` for a file that should be there reads better than a
  missing record, and says the probe looked.

`emit(subject, key, value, source, kind=...)` (built 2026-10-07) declares a record's kind, one of `semantic`,
`metric`, `time`, `identity`: the probe's declaration wins, the service infers the rest (§10). The record carries `"kind"` only when declared. `beat-probe check` warns on R1
(`=` pairs or several version-like tokens in one constant-shaped value) and R3 (digits that look like a PID or a
port in a subject).

### 4.5 Pure helpers

Small functions Starlark lacks, all pure (no access to the host): `re_match`, `re_find_all`, `re_sub` (Rust
`regex` syntax), `path_join`, `path_dirname`, `path_basename`, `iso_utc(epoch)`, `from_json`, `to_json`
(the `json` module may cover the last two). Added when a probe needs one, only if pure.

## 5. Failures and errors

Failures (the host differs from the probe's assumptions): `assertion` (`one`, `expect`, `fail`), `denied`
(content of a secret path), `missing` (`read` or `list_dir` of a path that does not exist).

- **[F1]** A failure is recorded as `{kind, message, span, stack}`: the Starlark call stack, with file and line.
- **[F2]** A failure ends the probe, unless it happens inside `each(items, fn)`: then it ends that one call of `fn`,
  and `each` goes on with the next item. Records emitted before a failure are kept.
- **[F3]** A run with failures and no error has outcome `partial`.

**D1.** Starlark has no try/except, so isolation has to be a builtin. `each` makes it explicit where one bad item
(one unreadable certificate) must not hide the others; a failure outside `each` means the probe's main assumption
broke, and going on would produce noise.

Errors (the probe, the sensor or a limit broke): `rejected` (checks of §6 on the sensor; nothing ran), `limit` (§8),
`type` (a Starlark runtime type error), `tool` (a WASM trap, not a non-zero exit), `source` (osquery or the journal
failed, or the host has none), `internal`.

- **[F4]** An error ends the run at once with outcome `error`. Records and failures so far are returned, marked as
  from an incomplete run.

## 6. Checks before running

Run on the client when the probe is written or changed (`beat-probe check`), and again on the sensor before evaluation ([P5]). One
Rust crate does both, so they cannot disagree.

1. **Parse** with the `Extended` dialect, types enabled.
2. **Resolve names** against the beat globals: an unknown function (`open`, `rm`, `exec`) is an error.
3. **Typecheck** (`AstModule::typecheck`) against the builtins' signatures: wrong types, missing arguments.
4. **Structure**: top level only binds constants and defines functions ([S2]); `main` exists.
5. **No recursion**: no cycle in the call graph of the probe's functions. Calls through function values (a
   function passed to `each` calling `each` with itself) cannot all be seen statically; the call-stack limit
   (§8) catches the rest.
6. **Capabilities**: every tool named in a literal `pipe` stage, or called as a function ([B1a]), is in the target
   sensor's manifest (§7). Without the manifest, the client checks against the uutils coreutils list.

## 7. Manifest and trust

- **[M1]** A sensor publishes a manifest: the beat builtins version, tools by name with the SHA-256 of their
  `.wasm`, the osquery version, its limit policy.
- **[M2]** From the syntax tree the client lists what a probe touches: tools, osquery tables, literal paths, and paths
  computed at run time with the expression that computes them: what a reviewer of a question needs. It is exact for
  literals and only descriptive for computed values.
- **[M3]** What travels is `{probe source, loaded libraries, builtins version, signature}`. The probe's id is the
  SHA-256 of the source and libraries; every record of a run carries it, so a record traces back to a reviewed file.
- **[M4]** A sensor runs only questions signed by a member of the org it obeys and countersigned by the service
  (**D2**; `docs/security.md` H16, C14).

## 8. Limits

`starlark-rust` has no instruction or memory limit of its own (§11). Limits come from where the evaluator runs.

| Limit | Applies to | How |
| --- | --- | --- |
| memory, CPU time, wall time | the evaluator and everything it holds | one transient systemd unit per run (`MemoryMax`, `CPUQuota`, `TasksMax`, `RuntimeMaxSec`; `sensor/src/runner.rs`) |
| call depth | Starlark recursion that §6 could not see | `Evaluator::set_max_callstack_size` |
| fuel, memory, wall time | each WASM tool instance | wasmtime fuel, memory limit, epoch interruption |
| bytes per value | `read`, `.stdout`, `.stderr` | builtin checks; over the limit is an error, never a silent truncation |
| records, text bytes | the run result | builtin checks |

- **[L1]** A probe may ask for limits; the sensor applies `min(requested, policy)`.
- **[L2]** Hitting a limit is an error of kind `limit` naming which one (§5).

## 9. The run result

One run result becomes one **answer** (`docs/protocol.md`, C17: what is hashed and what moves to the headers). The
service normalizes its records into semantics, metrics, identity and text.

```
{ probe: <sha256>, sensor: {host, version}, started, finished,
  outcome: "ok" | "partial" | "error",
  records:  [{subject, key, value, source, span}],     -- span: the `emit` call that produced it
  failures: [{kind, message, span, stack}],
  error:    {kind, message, span, stack}?,
  diag: <text from print>, notes: ["unmapped path /srv/app treated as missing", ...],
  usage: {wall_ms, cpu_ms, peak_mem, tool_instances, fuel, bytes_read},
  timings: {tools, compile, eval, mask, probe, cpu, cpu_children, read_bytes,   -- not part of the answer
            builtins: {osq: {ms, calls}, journal: {ms, calls}, ...}} }
```

`timings` says where the run's time went (docs/hosted.md H25 in the private repo): `tools` loading the WASM tools,
`compile` the checks and parsing, `eval` running `main()`, `mask` gate 1, `probe` what `eval` spent outside host
calls (the probe's own Starlark), CPU ms of beat-probe and of the children it waited for (osqueryi's session is not
one: it is killed, never waited for), bytes read from storage, and each builtin's time and calls. The sensor sends it
in the answer's Beat-Phases header, never in the answer, so equal answers stay equal.

`beat-probe run --profile` (a question asked with Beat-Profile: `beat run --profile`, `beat ask --profile`, MCP
`run` with `profile`) also times each host call, and adds the slowest 50 as records: subject
`beat:profile:<builtin>#<rank>`, keys `ms` (a metric), `call` (its arguments, shortened to 160 characters) and
`failed`; then `beat:profile` `calls` and `reported`. They pass gate 1 like any record. The client takes them out of
the answer's records, so they never reach an estate's facts.

## 10. Decisions and open questions

To confirm:
- **D1** Failures end the probe, except inside `each`, where they end one item ([F2]).
- **D2** Signing: the member who asks signs, the service countersigns ([M4]; `docs/security.md` H16, C14).
- **D3** Only tool-to-tool streams are unbounded by size; every value a probe holds is bounded ([B5]).
- **D4** Tool exit statuses are values ([B3]).
- **D5** Shared libraries through `load()` ([S3]), or one self-contained file per probe.

Open:
- **Builtins when the evaluator runs as WASM** (a later step, §12).
- **Invalid UTF-8** in tool output and files: replace silently, note it, or offer `read_bytes`.
- **Record kinds**: both declared and inferred. Inference from a survey's history separates
  configuration from measurements and keeps rollouts, but a new question has no history, and a measurement that
  rarely changes looks like configuration; a declaration is exact. `emit` gains an optional `kind` (§4.4.1).
- **Time values** are strings (`iso_utc`); a time type would let central checks compare without parsing.
- **osquery's own file reads** (tables like `file`, `augeas`, `yaml`) are invisible to the file mapping and to the
  manifest's paths ([M2]); the manifest can list the tables a query names.
- **Nested includes** need recursion in the obvious form; a bounded `closure(seed, step, depth)` builtin would cover
  them without giving up [P1].
- **osquery startup**: one `osqueryi` per call costs ~0.3 s, twice for typed rows (§13); a running `osqueryd` over
  its extension socket would remove it.

## 11. Evidence: `starlark-rust` 0.14.2 (tested 2026-10-03)

Tested with the nixpkgs CLI and a small embedding with three builtins (`emit`, `read`, `fail`):

| Property | Result |
| --- | --- |
| `while` | parse error ("reserved keyword"), in both dialects |
| recursion | **allowed**; only a "call stack overflow" error ends it (the Go implementation forbids it) |
| changing a list while iterating over it | error |
| module values after load | frozen ("Immutable") |
| unknown names (`open`, `rm`) | error before running |
| `load()` without a loader | error |
| memory | **no limit**: a comprehension allocated 5.8 GB; `ulimit -v` stopped it at 512 MB (exit 101) |
| steps | **no limit**: `for i in range(10**8)` ran 4 s; `ulimit -t` ended it (SIGXCPU). The per-statement hook is not public API |
| static types | `AstModule::typecheck` catches wrong types and missing arguments **inside `def` bodies only** |
| dialect | `Standard` forbids top-level `for` and type annotations; we use `Extended` with types enabled |
| build | pin `starlark = "=0.14.2"` (0.14.0 resolves mismatched sibling crates); release build ~2 min, 13 MB binary |
| `*args: str` | checked per element by `typecheck`, but against the whole tuple at run time: no annotation passes both |

## 12. Later: the evaluator as WASM

Both Starlark implementations build for WASM, so the evaluator can later run as a WASM guest with precise fuel and
memory limits, as one more untrusted program. The language and the probes do not change; the builtins split in two:

- **Guest side** (inside the evaluator): everything that only computes: `one`, `expect`, `fail`, `each`, the pure
  helpers (§4.5), and building the run result. `each` calls back into Starlark, so it must live where Starlark runs.
- **Host side** (the native sensor): everything that touches the host: `pipe`, `stat`, `read`, `glob`, `list_dir`,
  `readlink`, `osq`, `journal`, `secrets`. The guest calls them as imports; the sensor instantiates the tools and wires the
  pipes, so no fork or exec is needed anywhere.

The host-side calls take and return plain data (strings, integers, lists, records), never Starlark values or
callbacks, so they can be described as a WebAssembly Component Model interface (WIT) later. To keep that step
small, the first, native implementation already puts the host-side builtins behind one Rust trait (`Host`): the
native sensor implements it directly, and a WASM evaluator would implement it with imports.

## 13. Implementation status

`probe/` is the Rust crate `beat-probe` (`nix build .#beat-probe`; runbook in `probe/README.md`):

| Part | State |
| --- | --- |
| Checks (§6) | All six, shared by `beat-probe check` and the runner: parse, names, types, structure, recursion, tools. |
| Builtins (§4) | All, including one function per tool ([B1a]), `osq` (osqueryi) and `journal` (journalctl). |
| Failures (§5) | As specified, including `each` isolation; tested in `probe/tests/probes/failures.star`. |
| `pipe()` | uutils coreutils (WASM) under wasmtime 49: read-only preopens, fuel, memory, output bounded. |
| Limits (§8) | Call depth, tool fuel/memory/output, records, print output; under beat-sensor, a sandboxed systemd unit per question (`--map /`, `sensor/src/runner.rs`). |
| Manifest (§7) | Tools only (`beat-probe tools`). Signing: `docs/security.md`. |
| WASM tools | uutils coreutils, jq (jaq), awk (goawk), drain (ours: log templates), strings. No grep or sed: GNU's don't build for WASI. |

Where the first version (2026-10-03) fell short of this spec, and may still:
- **Stages of a pipe run one after another** over in-memory buffers, so intermediate streams are bounded too
  ([B5] wants them unbounded). Same output by Kahn's theorem; concurrency later.
- **Tools have no `/proc/<pid>`** (`docs/security.md`, Processes' environments): they get a copy of `/proc`'s own small
  files when a pipe names `/proc`, and its directories. Probes read the rest with `read()` and `sample()` and may pass it
  on as `stdin`.
- **Tools can read secret files** under a mapped directory ([B9] wants `EACCES`); `read` and `stat` enforce it.
  Under beat-sensor the sandbox covers them with placeholders (`sensor/src/runner.rs`), with the limits
  `docs/security.md` states (new files under recursive patterns wait for the next walk; container storage and network
  mounts are not walked); `beat-probe run` on its own does not.
- **`osq` runs `osqueryi` twice per call**: `--json` gives every value as a string (NULL as ""), so the first call
  gets the column names and the second wraps the query in SQLite's `json_object()` for typed values. ~0.6 s per
  `osq`; a live run with 2 queries and a journal read took 2.5 s.
- **Argument types of tool functions are checked at run time only**: starlark-rust 0.14.2 checks `*args: str` per
  element statically but against the whole tuple at run time, so the generated functions leave `*args` untyped.
- **Compiled tools are cached** on disk (`--cache`): compiling coreutils.wasm takes ~17 s, loading it ~0.1 s. The
  cache is trusted like the binary, so it must be writable by the sensor only.
