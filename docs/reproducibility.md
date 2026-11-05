# Reproducing the sensor image

**Status: TODO.** The image is meant to rebuild bit for bit from its tag, and it does not yet: a few of the eBPF
tools inside it can come out with their type information in a different order. Everything else matches. This page
tells how we got here, what is fixed, and what is left.

## The promise

The sensor runs as root on your hosts, so you should not have to trust our build machine. The release publishes the
image (`beat-sensor.raw`) and its dm-verity root hash (`beat-sensor.roothash`), a hash over every block of the
image. The promise: run `nix build .#beat-sensor-image` at the release's tag, on your own machine, and you get the
same root hash. Equal hashes mean the bytes you install are the bytes this source builds, with nothing added on the
way.

Nix makes most of that easy. Every input (sources, compilers, libraries) is pinned by hash, so two machines build
from exactly the same inputs. Nix does not make the *outputs* equal: that also needs every compiler to be
deterministic and to write nothing about where or when it ran.

## How we found out

An early release matched between GitHub's runner and our development machine. A later one did not: 2 files of 2064 differed,
`jq.wasm` and `beat-probe`. Both machines had used the same store paths, the same compilers and the same sources.

## Cause 1: the build directory (fixed)

Nix builds each package in a scratch directory. Determinate Nix, on our machine, always names it `/build`. Upstream
Nix, on GitHub's runner and probably on yours, names it `/nix/var/nix/builds/nix-<pid>-<random>`, which is different on
every build.

Rust writes paths into binaries, for panic messages and for files that build scripts generate. So GitHub's
`beat-probe` contained `/nix/var/nix/builds/nix-2196-668621892/…`, ours `/build/…`, and nobody else's could match
either.

**Fix:** every Rust build runs the compiler through a wrapper that adds
`--remap-path-prefix=$NIX_BUILD_TOP=/build` (`wasm/default.nix`), so the path in the binary is `/build` whatever the
directory was. It is a wrapper, not `RUSTFLAGS`, because cargo fingerprints `RUSTFLAGS`: the dependencies and the
package are built in two different random directories, and a flag that differed between them would make cargo
recompile every dependency. Checked: GitHub's Rust binaries and WASM tools now equal ours.

## Cause 2: the eBPF tools' source paths (fixed)

The eBPF tools (libbpf-tools, the catalog behind `trace()`) embed small BPF programs, compiled by clang. Their type
information (BTF) names the source files by full path, so it had the build directory in it too.

**Fix:** clang's `-ffile-prefix-map` makes the paths relative to `libbpf-tools/` (`sensor/libbpf-tools.nix`).
Relative, not mapped to `/build`, because LLVM reads source lines back through the mapped path to put them in the
BTF: under upstream Nix `/build/...` does not exist, and those lines silently went missing.

## Cause 3: the order of BTF types (open)

With paths gone, some tools still differed, and only in one way: a few kernel structs that the program refers to by
pointer only (`kmem_cache`, `css_set`, `perf_raw_record`, …) got their BTF type ids in a different order.

The code is in LLVM's BPF backend, `llvm/lib/Target/BPF/BTFDebug.h`:

```
std::map<const DICompositeType *, std::vector<...>> FixupDerivedTypes;
```

Those structs are collected in a map keyed by pointer, and emitted by iterating it: in **memory address order**.
Where LLVM's allocator puts each one depends on the lengths of strings the process handled, on the C library's
allocator, and on the machine, so the order does too. What we measured, with LLVM 23 compiling one and the same
input (identical bytes) for `tcpconnect`:

| Where llc runs | Output |
| --- | --- |
| our machine, input from stdin | `5b45b9d8…`, every time |
| our machine, input from a file | `5a95767d…`, every time |
| GitHub's runner, input from stdin | `5a95767d…`, every time |

Each is stable, and they disagree. LLVM 21, which nixpkgs uses by default, is worse: it changes from run to run on
the same machine (5 different outputs in 6 runs).

**Tried, and not enough:** LLVM 23; compiling in two steps (clang to IR, which *is* identical everywhere, then llc);
running llc in `/` from stdin to stdout with an empty environment; turning address randomization off; glibc malloc
settings. Each moved the result; none fixed it, because the order is decided by allocation layout, not by anything we
pass in. They are not in the build: they added complexity without the guarantee.

**What would fix it:**

1. *Patch LLVM* (likely): make that map keep insertion order (`MapVector` instead of `std::map`), so the order follows
   the input, which is the same everywhere. One line, correct by construction, and worth reporting upstream. The cost:
   we build our own `llc` (BPF target only; an estimated hour or two, once, then cached), and so does anyone who
   reproduces the image.
2. *Sort after compiling:* a small step that orders those types by name and renumbers every reference to them in
   the object. No LLVM build, but it is our own code rewriting what the kernel's loader reads.

## Checking it yourself

```
nix build .#beat-sensor-image
cat result/beat-sensor.roothash          # compare with the release's
```

Until cause 3 is fixed the hashes will usually differ. To see that the difference is only that, unpack both images
(`unsquashfs`) and compare the files: everything should be equal except some of
`libbpf-tools-*/bin/*`, and in those only the `.BTF` section of the BPF program they embed.
