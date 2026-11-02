{
  description = "beat: the sensor (answers signed, read-only questions about a Linux host) and the client that asks";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-26.05";

    # uv2nix turns uv.lock into Nix derivations, so `uv lock` stays the single source of Python dependency versions.
    pyproject-nix = {
      url = "github:pyproject-nix/pyproject.nix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    uv2nix = {
      url = "github:pyproject-nix/uv2nix";
      inputs.pyproject-nix.follows = "pyproject-nix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    pyproject-build-systems = {
      url = "github:pyproject-nix/build-system-pkgs";
      inputs.pyproject-nix.follows = "pyproject-nix";
      inputs.uv2nix.follows = "uv2nix";
      inputs.nixpkgs.follows = "nixpkgs";
    };

    # Official prebuilt Rust toolchains, for building WASM tools (wasm/default.nix).
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };

    # Rust builds in two derivations: dependencies (keyed on Cargo.toml/Cargo.lock only) and the crate itself, so a
    # source change recompiles only our code, not wasmtime and starlark.
    # Pinned to a release; move it with nixpkgs.
    crane.url = "github:ipetkov/crane/v0.24.0";
  };

  outputs = { self, nixpkgs, pyproject-nix, uv2nix, pyproject-build-systems, rust-overlay, crane, ... }:
    let
      system = "x86_64-linux"; # the sensor is Linux; the client runs on macOS too, to add when CI has a Mac
      pkgs = nixpkgs.legacyPackages.${system};
      lib = nixpkgs.lib;
      python = pkgs.python312;

      # Git revision of this build: only in the top-level derivation (beat-sensor), which is a thin wrapper;
      # in an inner one (beat-probe) every commit would force its rebuild with identical code.
      rev = self.shortRev or self.dirtyShortRev or "unknown";
      # The release: the tag v<release> publishes it (.github/workflows/release.yml checks they agree).
      release = (builtins.fromTOML (builtins.readFile ./pyproject.toml)).project.version; # one version: client and sensor

      # WASM tools for probes (wasm/README.md).
      wasm = import ./wasm { inherit pkgs crane; rust-bin = rust-overlay.lib.mkRustBin { } pkgs; };
      craneLib = wasm.craneLib; # the same prebuilt Rust for native crates

      # Starlark probes with beat builtins (docs/probes.md): `beat-probe check|run|tools`. Built with the same
      # prebuilt Rust as the WASM tools (nixpkgs' rustc is older than starlark-rust needs). Dependencies are their own
      # derivation (probeDeps, rebuilt only when Cargo.lock changes); the package skips the tests, which are the check
      # beat-probe-test: the probes in probe/tests against a fixture host, with the real tools behind pipe() and
      # osqueryi behind osq().
      probeArgs = { pname = "beat-probe"; version = release; src = ./probe; strictDeps = true; env = wasm.reproducible; };
      sensorArgs = { pname = "beat-sensor-bin"; version = release; src = ./sensor; strictDeps = true; env = wasm.reproducible; };
      probeDeps = craneLib.buildDepsOnly probeArgs;
      sensorDeps = craneLib.buildDepsOnly sensorArgs;
      probe = craneLib.buildPackage (probeArgs // { cargoArtifacts = probeDeps; doCheck = false; });
      probeTest = craneLib.cargoTest (probeArgs // {
        cargoArtifacts = probeDeps;
        env = probeArgs.env // {
          BEAT_WASM_TOOLS = "${wasm.tools}"; # all of them: the log built-ins need drain.wasm
          BEAT_OSQUERYI = "${pkgs.osquery}/bin/osqueryi"; # the osq() test
        };
      });

      # --- beat-sensor: the sensor with its probe, tools, osquery and eBPF catalog ----------------------------------
      # Connects out to NATS and answers questions with beat-probe in a transient systemd unit
      # (docs/security.md). The placeholders are what a question sees instead of a secret file or directory.
      sensorBin = craneLib.buildPackage (sensorArgs // {
        cargoArtifacts = sensorDeps;
        doCheck = false; # the check beat-sensor-test
      });
      # The sensor's tests, with the protocol's test vectors (tests/, shared with the client's tests).
      sensorTest = craneLib.cargoTest (sensorArgs // {
        cargoArtifacts = sensorDeps;
        env = sensorArgs.env // { BEAT_TEST_VECTORS = "${./tests}"; };
      });
      libbpfTools = pkgs.callPackage ./sensor/libbpf-tools.nix { }; # the catalog behind trace()
      sensor = pkgs.stdenvNoCC.mkDerivation {
        pname = "beat-sensor";
        version = "${release}+g${rev}";
        dontUnpack = true;
        installPhase = ''
          mkdir -p $out/bin $out/share/beat-sensor/placeholders/dir
          echo "beat: secret material is not readable by questions; secrets() lists its metadata" \
            > $out/share/beat-sensor/placeholders/file
          cp $out/share/beat-sensor/placeholders/file \
            $out/share/beat-sensor/placeholders/dir/BEAT-SECRET-DIRECTORY-NOT-READABLE
          cat > $out/bin/beat-sensor-run <<EOF
          #!${pkgs.runtimeShell}
          # The service's entry point: beat-sensor with this build's beat-probe, tools, osquery and eBPF catalog.
          exec ${sensorBin}/bin/beat-sensor --nats "\$BEAT_NATS" --api "\$BEAT_API" --name "\$BEAT_SENSOR_NAME" \\
            --version "$(basename $out)" --probe ${probe}/bin/beat-probe --tools ${wasm.tools} \\
            --cache /var/lib/beat-sensor/wasm-cache --osqueryi ${pkgs.osquery}/bin/osqueryi \\
            --journalctl /usr/bin/journalctl --bpf-tools ${libbpfTools}/bin \\
            --placeholders $out/share/beat-sensor/placeholders \\
            --key /var/lib/beat-sensor/keys/sensor.key --roots /etc/beat-sensor/roots --deny /var/lib/beat-sensor/state/deny.json \\
            --collector-keys /etc/beat-sensor/collectors \\
            \''${BEAT_IMAGE:+--unit-property "MountImages=\$BEAT_IMAGE:/nix/store"}  # installed from the image (M16)
          EOF
          substitute ${./packaging/nix/beat-sensor.service} $out/share/beat-sensor/beat-sensor.service \
            --replace-fail @out@ $out
          substitute ${./packaging/nix/activate.sh} $out/bin/beat-sensor-activate \
            --replace-fail @out@ $out --replace-fail @shell@ ${pkgs.runtimeShell} \
            --replace-fail @probe@ ${probe}/bin/beat-probe --replace-fail @tools@ ${wasm.tools} \
            --replace-fail @sensor@ ${sensorBin}/bin/beat-sensor
          chmod +x $out/bin/*
          ln -s ${sensorBin}/bin/beat-sensor $out/bin/beat-sensor  # the operator's: enroll, keygen
        '';
      };

      # --- Python, from uv.lock: the client `beat` (beat, beat-mcp, the signer and the protocol) ------------------
      workspace = uv2nix.lib.workspace.loadWorkspace { workspaceRoot = ./.; };
      pythonSet = (pkgs.callPackage pyproject-nix.build.packages { inherit python; }).overrideScope (
        lib.composeManyExtensions [
          pyproject-build-systems.overlays.default
          (workspace.mkPyprojectOverlay { sourcePreference = "wheel"; }) # manylinux wheels, patched by Nix
        ]
      );
      beat = pythonSet.mkVirtualEnv "beat-env" { walkthebeat = [ ]; };  # the user's machine: beat, beat-mcp
      beatDev = pythonSet.mkVirtualEnv "beat-dev-env" workspace.deps.all; # + pytest
    in
    {
      packages.${system} = {
        default = beat;
        inherit beat;
        beat-sensor = sensor;
        beat-probe = probe;
        # The sensor as an image for hosts without Nix (packaging/sensor).
        beat-sensor-image = import ./packaging/sensor/image.nix {
          inherit pkgs sensor sensorBin probe; tools = wasm.tools; base = "https://github.com/walkthebeat/beat/releases/download/v${release}";
        };
        libbpf-tools = libbpfTools;
        wasm-tools = wasm.tools; # every tool behind pipe(), one directory
        wasm-demo = wasm.demo;
        wasm-coreutils = wasm.coreutils;
        wasm-jq = wasm.jqTool;
        wasm-awk = wasm.awkTool;
        wasm-drain = wasm.drain;
        wasm-strings = wasm.strings;
        # The compiled dependencies of the Rust crates, in one place to keep as a GC root: without one, a garbage
        # collection deletes them, and the next build recompiles wasmtime (~20 min).
        build-cache = pkgs.linkFarm "beat-build-cache" [
          { name = "beat-probe-deps"; path = probeDeps; }
          { name = "beat-sensor-bin-deps"; path = sensorDeps; }
          { name = "beat-drain-wasm-deps"; path = wasm.drainDeps; }
          { name = "beat-drain-test-deps"; path = wasm.drainTestDeps; }
        ];
      };

      apps.${system} = {
        default = { type = "app"; program = "${beat}/bin/beat"; };
      };

      checks.${system} = {
        beat-probe-test = probeTest;
        beat-sensor-test = sensorTest;
        # Prebuilt WASM coreutils: starts under wasmtime and reads a mapped directory. Only a smoke run: the tools'
        # correctness is upstream's job, we own the sandbox.
        wasm-coreutils = pkgs.runCommand "beat-wasm-coreutils" { } ''
          export HOME=$TMPDIR
          mkdir d && printf 'b\na\n' > d/f
          r=$(${pkgs.wasmtime}/bin/wasmtime run --dir d::/d ${wasm.coreutils}/coreutils.wasm sort /d/f | tr '\n' ' ')
          [ "$r" = "a b " ] || { echo "unexpected: $r"; exit 1; }
          touch $out
        '';
        # drain (ours): its unit tests natively, then the .wasm under wasmtime on a double-spaced line.
        wasm-drain-test = wasm.drainTest;
        wasm-drain = pkgs.runCommand "beat-wasm-drain" { } ''
          export HOME=$TMPDIR
          r=$(printf 'Invalid user  0101 from 10.0.0.1\nInvalid user admin from 10.0.0.2\n' \
            | ${pkgs.wasmtime}/bin/wasmtime run ${wasm.drain}/drain.wasm | ${pkgs.jq}/bin/jq -r '.templates[0].template')
          [ "$r" = "Invalid user <*> from <IP>" ] || { echo "unexpected: $r"; exit 1; }
          touch $out
        '';
        # The default pack (src/beat/pack): every probe parses and calls only builtins and tools that exist.
        pack = pkgs.runCommand "beat-pack-check" { } ''
          ${probe}/bin/beat-probe check ${./src/beat/pack}/*.star --tools ${wasm.tools}
          touch $out
        '';
        pytest = pkgs.runCommand "beat-pytest" {
          nativeBuildInputs = [ beatDev pkgs.openssl pkgs.git ];
          GIT_AUTHOR_NAME = "beat-check"; GIT_AUTHOR_EMAIL = "check@beat"; GIT_COMMITTER_NAME = "beat-check"; GIT_COMMITTER_EMAIL = "check@beat";
        } ''
          cp -r ${./.}/. src && chmod -R u+w src && cd src
          pytest -q -p no:cacheprovider
          touch $out
        '';
      };

      # `nix develop`, then `uv run ...`. uv builds .venv on Nix's Python; manylinux wheels expect libstdc++ and zlib
      # from the system, which LD_LIBRARY_PATH supplies here.
      devShells.${system}.default = pkgs.mkShell {
        packages = [
          python
          pkgs.uv
          pkgs.jq
          pkgs.wasmtime   # runs the WASM tools by hand (wasm/README.md)
          wasm.rust       # cargo for probe/ and sensor/; also builds for wasm32-wasip1
        ];
        env = {
          UV_PYTHON = "${python}/bin/python";
          UV_PYTHON_DOWNLOADS = "never";
          LD_LIBRARY_PATH = lib.makeLibraryPath [ pkgs.stdenv.cc.cc.lib pkgs.zlib ];
        };
      };
    };
}
