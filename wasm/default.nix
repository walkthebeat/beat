# WASM tools for probes (stages 0 and 1, see wasm/README.md). Everything here builds for wasm32-wasip1: one .wasm
# file per program, the same file for every CPU architecture, run by a WASI host (wasmtime now, our runner later).
#
# Rust programs build with the official prebuilt toolchain (rust-overlay), because nixpkgs' own WASI Rust is not in
# the binary cache and would compile rustc from source. Sources and vendored dependencies come from nixpkgs where
# the program is packaged there, so versions stay pinned by flake.lock.
{ pkgs, rust-bin, crane }:
let

  target = "wasm32-wasip1";
  rust = rust-bin.stable.latest.minimal.override { targets = [ target ]; };
  # crane over the same toolchain: dependencies and our crates in separate derivations (flake.nix, decision B1)
  craneLib = (crane.mkLib pkgs).overrideToolchain (_: rust);

  # cargo build --target wasm32-wasip1 over vendored dependencies; installs the named binaries as $out/<name>.wasm.
  buildWasm = { pname, version, src, cargoDeps, bins, cargoFlags ? "" }: pkgs.stdenv.mkDerivation {
    inherit pname version src cargoDeps;
    nativeBuildInputs = [ rust pkgs.rustPlatform.cargoSetupHook ];
    buildPhase = ''
      runHook preBuild
      cargo build --release --offline --target ${target} ${cargoFlags}
      runHook postBuild
    '';
    installPhase = ''
      mkdir -p $out
      for b in ${toString bins}; do cp target/${target}/release/$b.wasm $out/; done
    '';
  };
in
rec {
  inherit rust craneLib;

  # Stage 0: one program that tries files, environment, processes, network and resource use (wasm/demo).
  demo = buildWasm {
    pname = "wasm-demo";
    version = "0.1.0";
    src = ./demo;
    cargoDeps = pkgs.rustPlatform.importCargoLock { lockFile = ./demo/Cargo.lock; };
    bins = [ "wasm-demo" ];
  };

  # uutils coreutils, upstream's own wasm32-wasip1 release build: one multicall binary (`coreutils.wasm cat FILE`).
  # Prebuilt on purpose: a .wasm has no /nix/store references (libc is compiled in, it imports only WASI functions),
  # so the release file is as good as our own build. The hash pins exactly the file we reviewed.
  coreutils = pkgs.stdenvNoCC.mkDerivation rec {
    pname = "uutils-coreutils-wasm";
    version = "0.12.0";
    src = pkgs.fetchurl {
      url = "https://github.com/uutils/coreutils/releases/download/${version}/coreutils-${version}-${target}.tar.gz";
      hash = "sha256-1QKrLHkcYfXIawRKFbg+ogZPfVHTXzFFg2dlPexsJsk=";
    };
    installPhase = ''
      mkdir -p $out
      cp coreutils.wasm LICENSE $out/
    '';
  };

  # jq: jaq (Rust, mostly jq-compatible), without its default features (mimalloc is C and not needed). Installed as
  # jq.wasm. Pinned to 2.2.0, the version probes were tested with (nixpkgs 25.05's; source and vendored-crate hashes
  # from its recipe): nixpkgs 26.05 has 3.1.2, whose binary needs rustyline with file history, which pulls in fd-lock,
  # which does not build for WASI. Moving to jaq 3 means patching its prompt out: its own change, with a probe check.
  jq = let version = "2.2.0"; src = pkgs.fetchFromGitHub {
    owner = "01mf02";
    repo = "jaq";
    tag = "v${version}";
    hash = "sha256-mVC2aggfcEpCtriuz/s4JL8mYkrlyAQLnaN5vyfcW3s=";
  }; in buildWasm {
    pname = "jaq-wasm";
    inherit version src;
    cargoDeps = pkgs.rustPlatform.fetchCargoVendor { inherit src; hash = "sha256-ZZLp3Vwq013MPxKy9gTZ1yMi2O0QcDPgFw5YnrYt90I="; };
    bins = [ "jaq" ];
    cargoFlags = "-p jaq --no-default-features";
  };
  jqTool = pkgs.runCommand "jq-wasm-${jq.version}" { } ''
    mkdir -p $out && cp ${jq}/jaq.wasm $out/jq.wasm
  '';

  # awk: goawk (Go, POSIX awk), built by Go's own wasip1 port. Installed as awk.wasm.
  awk = (pkgs.goawk.overrideAttrs (o: {
    env = (o.env or { }) // { GOOS = "wasip1"; GOARCH = "wasm"; CGO_ENABLED = "0"; };
    doCheck = false;
    postInstall = ''
      f=$(find $out/bin -name goawk -type f | head -n 1)
      mkdir -p $out/wasm && cp "$f" $out/wasm/awk.wasm
    '';
  }));
  awkTool = pkgs.runCommand "awk-wasm-${pkgs.goawk.version}" { } ''
    mkdir -p $out && cp ${awk}/wasm/awk.wasm $out/awk.wasm
  '';

  # drain: log template summaries (docs/security.md C21), ours, over the pinned drain3 crate (wasm/drain).
  # crane, as the native crates: the dependencies (drain3, regex, serde_json) are built once per Cargo.lock.
  drainArgs = { pname = "beat-drain"; version = "0.1.0"; src = ./drain; strictDeps = true; };
  drainWasmArgs = drainArgs // { CARGO_BUILD_TARGET = target; doCheck = false; };
  drainDeps = craneLib.buildDepsOnly drainWasmArgs;
  drain = craneLib.buildPackage (drainWasmArgs // {
    pname = "beat-drain-wasm";
    cargoArtifacts = drainDeps;
    installPhaseCommand = "mkdir -p $out && cp target/${target}/release/drain.wasm $out/";
  });
  # its unit tests, natively (a check in flake.nix)
  drainTestDeps = craneLib.buildDepsOnly drainArgs;
  drainTest = craneLib.cargoTest (drainArgs // { cargoArtifacts = drainTestDeps; });

  # strings(1): printable runs in a binary (wasm/strings, ours, no dependencies).
  strings = buildWasm {
    pname = "beat-strings-wasm";
    version = "0.1.0";
    src = ./strings;
    cargoDeps = pkgs.rustPlatform.importCargoLock { lockFile = ./strings/Cargo.lock; };
    bins = [ "strings" ];
  };

  # Everything behind pipe(): one directory of .wasm files (beat-probe --tools).
  tools = pkgs.symlinkJoin {
    name = "beat-wasm-tools";
    paths = [ coreutils jqTool awkTool drain strings ];
    # No grep or sed yet: GNU grep and sed cross-built for WASI (nixpkgs pkgsCross.wasi32) fail on missing POSIX
    # (pcre2 needs sys/wait.h, then signals, then dup(); sed: umask, then gnulib's fcntl). awk and the Starlark
    # re_* builtins cover their uses; a Rust grep/sed is the likelier route.
  };
}
