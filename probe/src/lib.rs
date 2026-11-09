//! Starlark probes with beat builtins (docs/probes.md).
//!
//! - `environ`: a process's environment as questions may see it: names, keyed hashes, known-safe values.
//! - `check`: what the console and the sensor verify before a probe runs (§6).
//! - `builtins`: the Starlark globals (§4, §5).
//! - `host`: the host-side builtins as a Rust trait (§12); `local` implements it on this machine, `tools` runs the
//!   WASM tools behind `pipe()`, `sources` runs osquery and journalctl for `osq()` and `journal()`.
//! - `catalog`: the tools behind `trace()` (libbpf-tools), their output reduced as it streams.
//! - `run`: one run, from source to run result (§9).
//! - `transform`: files of known meaning (keytabs, certificates, private keys) read for what they mean (C23).
//! - `secrets`: gate 1, what the run result says is scanned and masked before it leaves (docs/security.md).

pub mod builtins;
pub mod catalog;
pub mod check;
pub mod environ;
pub mod host;
pub mod local;
pub mod run;
pub mod scan;
pub mod secrets;
pub mod sources;
pub mod timed;
pub mod tools;
pub mod transform;
