# beat-probe: Starlark probes, runbook

`beat-probe` checks and runs probes written in Starlark (spec: `docs/probes.md`). This page walks through it
by hand, against the fixture host in `tests/root`. Nothing touches a target.

## The pieces

```
 beat-probe check nginx.star            (the client, before anything is sent)
   parse → names → types → structure → recursion → tools        errors with file:line:col, exit 1
 beat-probe run nginx.star              (the sensor, in a transient unit per run)
   the same checks, then main() in the Starlark evaluator (starlark-rust)
     ├─ emit, one, expect, fail, each, re_*, path_*, iso_utc     computed in the evaluator
     └─ Host trait: pipe, stat, read, glob, list_dir, readlink, osq, journal, secrets
          LocalHost: files under --root, only the --map directories, read-only (cap-std)
          pipe(), sort(...), sha256sum(...) ...: each a wasmtime instance of a WASM tool, same directories
          osq(): osqueryi --json, journal(): journalctl -o json (both read the live host)
   prints the run result: records, failures, error, notes, usage   (JSON)
```

Source: `src/check.rs` (§6), `src/builtins.rs` (§4, §5), `src/logs.star` (the log built-ins over the `drain`
tool), `src/host.rs` (the line of §12), `src/local.rs`,
`src/tools.rs`, `src/sources.rs` (osquery, journal), `src/run.rs` (§9).

## Set up

```sh
nix build .#beat-probe                                 # about a minute once dependencies are built
nix build .#checks.x86_64-linux.beat-probe-test        # the tests below, with all WASM tools
P=$PWD/result/bin/beat-probe
T=$(nix build .#wasm-coreutils --print-out-paths)      # coreutils.wasm: the tools behind pipe()
O=$(nix build nixpkgs#osquery --print-out-paths)/bin/osqueryi
cd probe
```

For editing the code: `nix develop` has `cargo`; `cargo build --release -j2` (the box is small) and
`BEAT_WASM_TOOLS=$T BEAT_OSQUERYI=$O cargo test --release -j2`.

## 1. Checks: problems found before anything runs

```sh
$P check tests/probes/nginx.star --tools $T            # tests/probes/nginx.star: ok
$P check tests/probes/bad_*.star --tools $T            # one line per problem, exit 1
```

What each bad probe shows:
- `bad_names.star`: `rm`, `open` do not exist. A probe can only call builtins; there is nothing to write or open.
- `bad_types.star`: `emit` with an int, `emit` with an argument missing. Checked only inside `def` bodies, which is
  why probe code lives in `main()`.
- `bad_toplevel.star`: code at the top level; only constants and functions may be there.
- `bad_recursion.star`: `a -> b -> a`, and `c` passing itself to `each`.
- `bad_tool.star`: `rm` and `grep` are not tools on this sensor (rm is left out on purpose; grep is not built yet).
- `bad_tool_functions.star`: every tool is also a function (`sort(...)`), so `grep(...)` is simply an unknown name.
  Without `--tools`, `check` uses the uutils coreutils list.

## 2. A run

```sh
$P run tests/probes/nginx.star --root tests/root --map /etc --tools $T | less
```

- `records`: one per `emit`, each with the `span` of the `emit` that produced it.
- The first run takes ~17 s: wasmtime compiles coreutils.wasm. The compiled code is kept in `~/.cache/beat-probe`,
  so the next run takes ~0.1 s.
- `/etc/nginx/missing.d/*.conf` matched nothing, and `glob` gave `[]` (sh would give the pattern back).
- `sites-enabled/default` is a symlink inside `/etc`: followed.

## 3. Failures

```sh
$P run tests/probes/failures.star --root tests/root --map /etc
```

- `failures`: `denied` (`/etc/shadow` is secret: metadata only), `missing` (`/etc/nope`), then `assertion` from
  `one([], ...)`.
- The first two happened inside `each`: the item after them (`/etc/group`) still ran.
- The third is outside `each`: the probe ended there, so no `unreachable` record. Outcome: `partial`.

## 4. The sandbox

```sh
$P run tests/probes/pipes.star --root tests/root --map /etc --tools $T
```

- `tests/root/etc/escape` is a symlink to `/etc/hostname` on the real host. `cat` (a WASM tool) cannot open it, and
  `stat` reports it as `link`: neither leaves the mapping.
- `stat("/root/.bashrc")` is `None`, and `notes` says the path is outside the mapped directories.
- `test -e /etc/nope` gives status `[1]` and `ok` False: an exit code is a value, not a failure.

A tool that runs away hits a limit and the run ends with an error naming it:

```sh
cat > /tmp/runaway.star <<'EOF'
def main() -> None:
    pipe(["seq", "1", "100000000000"])
EOF
$P run /tmp/runaway.star --root tests/root --tools $T  # error: limit: output of `coreutils seq ...` over 16777216 bytes
```

## 5. Live state: osquery and the journal

`osq()` and `journal()` read the live host, not `--root`. Run them as root, as the sensor will: as an ordinary user,
osquery cannot attribute root's sockets to processes, and the journal hides system entries.

```sh
$P run tests/probes/osq.star --osqueryi $O             # "2 int", None, float: typed; `?` bound on our side
sudo $P run tests/probes/live_ssh.star --osqueryi $O --journalctl $(which journalctl)
```

`live_ssh.star` reads ssh.service's state, joins `listening_ports` with `processes` in osquery's own SQL (port 22 on
IPv4 and IPv6, `sshd[pid]`), and reads its last journal lines. It takes ~2.5 s: each `osq()` runs `osqueryi` twice
(~0.3 s each), because `--json` gives every value as a string and the second call wraps the query in
`json_object()` for typed values.

## Not yet

The per-run process with cgroup limits, tools that cannot read secret files, osqueryd instead of one osqueryi per
call, signing. See §13 of the spec.
