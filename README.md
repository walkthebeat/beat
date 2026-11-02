# beat

beat lets an agent, or a person, ask questions of Linux hosts: small, read-only Starlark programs that run in a
sandbox on each host and return records. This repository is the open part of beat:

- **the sensor** (`sensor/`, `probe/`, `wasm/`): the daemon on each host, the Starlark runtime and its built-ins,
  the WASM tools they run;
- **the client** (`src/beat/`): `beat` and `beat-mcp` (for Claude), which sign the questions you ask;
- **the protocol** between them, and the packaging (`packaging/`).

The service the sensors answer to (collector, store, analysis) is walkthebeat's, at
[walkthebeat.ai](https://walkthebeat.ai). Start with the guide: [`docs/guide/getting-started.md`](docs/guide/getting-started.md).

## The sensor runs as root on your hosts: please review it

That is the reason this code is open. The sensor:

- listens on no port; it connects out to the service's message bus;
- runs only questions signed by a member of your org, whose credential your org root signed, and countersigned by
  the service, so neither the service nor walkthebeat can make it run anything on their own;
- runs each question in its own systemd unit: read-only file system, no network, no devices, limits on memory,
  tasks and time; secret files replaced by placeholders;
- masks known secrets in what it returns, and seals each answer to a key only the service holds for that survey.

What to read, and where the code is:

| | |
| --- | --- |
| [`docs/security.md`](docs/security.md) | the security model: whom the sensor obeys, what a question can do, what leaves the host, what a compromised service can and cannot do |
| [`docs/protocol.md`](docs/protocol.md) | the messages, signatures and sealing, with test vectors both implementations pass |
| [`docs/probes.md`](docs/probes.md) | the probe language: what a question can call, its limits and failures |
| `sensor/src/main.rs` (`admit`), `sensor/src/seal.rs` | the checks every question passes before it runs |
| `sensor/src/runner.rs` | the sandbox of each question |
| `probe/src/secrets.rs`, `probe/src/transform.rs` | secret files and masking |
| `packaging/sensor/` | the image and the installer |

Found a problem? [`SECURITY.md`](SECURITY.md).

## Build

With Nix (x86_64 Linux):

```
nix build .#beat                 # the client: beat, beat-mcp
nix build .#beat-sensor          # the sensor, for a host with Nix
nix build .#beat-sensor-image    # the sensor's image and installer, for a host without
nix flake check                  # every test
```

**The image is meant to be reproducible, and is not yet:** building `.#beat-sensor-image` from a release's tag
should give the release's `beat-sensor.roothash`, so that equal root hashes prove the image you install is the one
this source builds. Today a few of the eBPF tools inside it can differ in the order of their type information, a bug
in LLVM's BPF backend; everything else matches. `docs/reproducibility.md` tells the story and what is left.

Without Nix: `cargo build --release` in `sensor/` and `probe/` (Rust stable), `uv sync` for the client (Python 3.12).

## Licence

Apache 2.0 (`LICENSE`). `probe/rules/betterleaks.json` is derived from Betterleaks' rules, MIT
(`probe/rules/LICENSE.betterleaks`).
