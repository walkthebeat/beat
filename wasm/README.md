# WASM tools: stage 0 runbook

The probes' toolkit is meant to run as WebAssembly (`docs/probes.md` §4.1): every tool is a `.wasm` file, and a
runner on the host decides what each one may touch. This page lets you see that sandbox from the outside, by hand,
before any of our own runner code exists. Nothing below touches a host's state.

## The pieces

```
 your shell
   │  wasmtime run [grants] program.wasm args...
   ▼
 wasmtime  (native program: the WASI host, our runner later)
   │  decides what exists for the program: --dir (directories), --env (variables), limits (-W)
   │  answers the program's WASI calls: fd_read, path_open, clock_time_get, ... (34 functions for coreutils)
   ▼
 program.wasm  (portable bytecode: same file on x86_64 and ARM, no /nix/store paths, libc compiled in)
   can only call the WASI functions it imports; there is no "spawn" or "socket" function to call
```

Two programs:
- `wasm-demo` (`wasm/demo`, ours, about 50 lines of Rust): each subcommand tries one thing, so you can see what is
  allowed. Built by Nix with the prebuilt Rust toolchain (`rust-overlay`), target `wasm32-wasip1`.
- `coreutils` (uutils 0.12.0): upstream's own `wasm32-wasip1` release, downloaded and pinned by hash. One file with
  about 90 tools inside, used as `coreutils.wasm <tool> args`. No `stat`, `du`, `df`, `id`.

## Set up

```sh
cd ~/beat && nix develop                               # wasmtime is in the dev shell
D=$(nix build .#wasm-demo --print-out-paths)/wasm-demo.wasm
C=$(nix build .#wasm-coreutils --print-out-paths)/coreutils.wasm
mkdir -p /tmp/w && echo hello > /tmp/w/f               # a scratch directory to grant
ls -l $D $C                                            # 124 KB and 10 MB
```

## 1. Files: only what you grant exists

```sh
wasmtime run $D cat /etc/hostname                      # No such file or directory: nothing is mapped at all
wasmtime run --dir /etc::/etc $D cat /etc/hostname     # works: host /etc mapped to guest /etc
wasmtime run --dir /tmp/w::/w $D cat /w/../../etc/hostname   # Operation not permitted: no escaping with ..
wasmtime run --dir /etc::/etc $D write /etc/x          # Permission denied: but only because you are not root
wasmtime run --dir /tmp/w::/w $D write /w/new          # works: a mapped directory is as writable as Unix allows
```

`--dir HOST::GUEST` is the whole file permission model of the CLI, and it has **no read-only option** (checked in
wasmtime 32 and 48; `HOST::GUEST:readonly` just names the guest directory `GUEST:readonly`). Read-only exists one
level down, in wasmtime's library API: each mapped directory carries directory and file permissions (read, mutate).
So read-only is a setting of *our* runner, not something the CLI gives us; stage 2 (a minimal runner in Rust) is
where it gets tested.

Symlinks that point outside a mapping are refused too: `/etc/os-release` links to `../usr/lib/os-release`, so
`wasmtime run --dir /etc::/etc $C head -2 /etc/os-release` fails while `/etc/passwd` reads fine. `/etc` is full of
such links, so what a probe gets mapped is a design decision for the runner.

## 2. Environment, processes, network: not there unless granted

```sh
wasmtime run $D env                                    # prints nothing: no host variables leak in
wasmtime run --env FOO=bar $D env                      # FOO=bar: only what you pass
wasmtime run $D spawn /bin/ls                          # operation not supported: WASI has no "start a process"
wasmtime run $D net 127.0.0.1:22                       # operation not supported: no sockets in WASI preview 1
wasmtime run -S inherit-network $D net 127.0.0.1:22    # still not supported: the program has nothing to call
```

No process spawning also means no pipes between programs inside WASM: `cat | grep` has to be done by the runner,
which starts each tool as its own instance and connects their stdin and stdout. That is the shell runner to build.

## 3. Limits: the host stops runaway programs

```sh
wasmtime run -W timeout=2s $D spin                     # wasm trap: interrupt (wall clock)
wasmtime run -W fuel=100000000 $D spin                 # wasm trap: all fuel consumed (instruction budget)
wasmtime run -W max-memory-size=67108864 $D eat 256    # trap after 64 MiB: the allocation fails, the program aborts
```

Fuel counts instructions, so it is deterministic: the same script on the same input stops at the same point,
unlike a timeout.

## 4. The real tools, and a pipe

```sh
echo 'hello world' | wasmtime run $C wc                # 1 2 12
wasmtime run --dir /etc::/etc $C sort /etc/shells | head -3
wasmtime run --dir /etc::/etc $C grep x /etc/passwd   # coreutils: unknown program 'grep' (not in uutils)
wasmtime run --dir /etc::/etc $C cat /etc/passwd | wasmtime run $D upper | head -2   # a pipe, done by your shell
```

The tools import `path_unlink_file`, `path_rename` and friends (`rm` and `mv` are in the same file). Under our
runner they must fail because the mapping is read-only: **the tools are untrusted; the runner enforces the contract.**

## Checks

`nix flake check` runs `checks.wasm-coreutils` (the prebuilt tools start and read a mapped directory). Correctness of
the tools themselves is upstream's job; the checks we own are about the sandbox.

## Since then (2026-10-03)

Stage 2 is built: `beat-probe` (`probe/`) embeds wasmtime and runs these tools behind Starlark probes, with read-only
directories, fuel and memory limits (`probe/README.md`). The tool set is `.#wasm-tools`: uutils coreutils, jq (jaq,
built here for wasm32-wasip1), awk (goawk, Go's wasip1 port) and drain (ours, `wasm/drain`: log template
summaries over the pinned `drain3` crate; usage in its `src/main.rs` header, pinned in its
`Cargo.toml`). GNU grep and sed do not build for WASI yet (`wasm/default.nix`).

Try drain by hand (`nix develop`):

```sh
W=$(nix build .#wasm-drain --print-out-paths)/drain.wasm
journalctl -n 2000 -o cat | wasmtime run $W --top 10 --examples 1 | jq '.templates[] | [.count, .template]'
# a syslog file: the host's names as <SELF>, its 3 header tokens counted
wasmtime run --dir /var/log::/var/log $W --self "$(hostname)" --header 3 < /var/log/auth.log | jq .
```
