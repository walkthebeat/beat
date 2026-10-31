//! WASM tools for `pipe()` (docs/probes.md §4.1): each stage is a fresh wasmtime instance that sees only the
//! read-only mapped directories, no network, no processes, a fixed environment.
//!
//! Version 0 runs the stages of a pipe one after another over in-memory buffers. By Kahn's theorem the output is the
//! same as running them concurrently; the difference is that every intermediate stream is bounded by `value_bytes`
//! ([B5] wants only `.stdout`/`.stderr` bounded). Streaming stages is a later step.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use wasmtime::{Config, Engine, Linker, Module, Store, StoreLimits, StoreLimitsBuilder, Trap};
use wasmtime_wasi::p1::{self, WasiP1Ctx};
use wasmtime_wasi::p2::pipe::{MemoryInputPipe, MemoryOutputPipe};
use wasmtime_wasi::{FsPerms, I32Exit, WasiCtxBuilder};

use crate::host::{HostError, HostResult, ToolResult};

/// uutils programs that write, delete or never end. The read-only mapping would stop the writers anyway; leaving them
/// out of the manifest makes a probe that names one fail the checks instead of failing on the host.
const EXCLUDED: &[&str] = &[
    "cp", "csplit", "dd", "link", "ln", "mkdir", "mktemp", "mv", "rm", "rmdir", "shred", "sleep", "split", "tee",
    "touch", "truncate", "unlink", "yes",
];

/// The programs in uutils coreutils 0.12.0 (`coreutils.wasm --list`). The console checks against this list when it
/// does not have the target sensor's manifest.
pub const UUTILS: &[&str] = &[
    "arch", "b2sum", "base32", "base64", "basename", "basenc", "cat", "cksum", "comm", "cp", "csplit", "cut", "date",
    "dd", "dir", "dircolors", "dirname", "echo", "expand", "expr", "factor", "false", "fmt", "fold", "head", "hostid",
    "join", "link", "ln", "ls", "md5sum", "mkdir", "mktemp", "mv", "nice", "nl", "nproc", "numfmt", "od", "paste",
    "pathchk", "pr", "printenv", "printf", "ptx", "pwd", "readlink", "realpath", "rm", "rmdir", "seq", "sha1sum",
    "sha224sum", "sha256sum", "sha384sum", "sha512sum", "shred", "shuf", "sleep", "sort", "split", "sum", "tail",
    "tee", "test", "touch", "tr", "true", "truncate", "tsort", "tty", "uname", "unexpand", "uniq", "unlink", "vdir",
    "wc", "yes",
];

/// The tool names a sensor with uutils coreutils provides.
pub fn default_tools() -> Vec<String> {
    UUTILS.iter().filter(|t| !EXCLUDED.contains(t)).map(|t| t.to_string()).collect()
}

#[derive(Debug, Clone)]
pub struct ToolLimits {
    pub fuel: u64,
    pub memory_bytes: usize,
    pub value_bytes: usize,
}

impl Default for ToolLimits {
    fn default() -> Self {
        ToolLimits { fuel: 20_000_000_000, memory_bytes: 256 << 20, value_bytes: 16 << 20 }
    }
}

struct Tool {
    module: Module,
    argv0: Vec<String>, // ["coreutils", "sort"] for a multicall binary, ["jaq"] for a single program
    sha256: String,
}

struct StoreData {
    wasi: WasiP1Ctx,
    limits: StoreLimits,
}

pub struct Tools {
    engine: Engine,
    linker: Linker<StoreData>,
    tools: BTreeMap<String, Arc<Tool>>,
}

impl Tools {
    /// Loads every `<name>.wasm` in `dir`. `coreutils.wasm` is the uutils multicall binary: it provides one tool per
    /// program it lists, minus `EXCLUDED`.
    ///
    /// Compiling a module takes seconds (coreutils.wasm: ~17 s), so compiled code is kept in `cache` when given:
    /// `<sha256 of the .wasm>-<engine compatibility hash>.cwasm`. The cache directory must be writable only by the
    /// sensor: loading compiled code trusts it as much as the sensor binary.
    pub fn load(dir: &Path, cache: Option<&Path>) -> anyhow::Result<Tools> {
        let mut config = Config::new();
        config.consume_fuel(true);
        let engine = Engine::new(&config)?;
        let mut linker = Linker::new(&engine);
        p1::add_to_linker_sync(&mut linker, |d: &mut StoreData| &mut d.wasi)?;
        let mut tools = Tools { engine, linker, tools: BTreeMap::new() };
        let mut files: Vec<PathBuf> = std::fs::read_dir(dir)?
            .filter_map(|e| e.ok().map(|e| e.path()))
            .filter(|p| p.extension().is_some_and(|x| x == "wasm"))
            .collect();
        files.sort();
        for file in files {
            let name = file.file_stem().unwrap().to_string_lossy().to_string();
            let bytes = std::fs::read(&file)?;
            let sha256 = sha256_hex(&bytes);
            let module = tools.compile(&bytes, &sha256, cache)?;
            if name == "coreutils" {
                let lister = Tool { module: module.clone(), argv0: vec!["coreutils".into()], sha256: sha256.clone() };
                let out = tools.run(&lister, &["--list".to_string()], Vec::new(), &[], &ToolLimits::default())?;
                for prog in String::from_utf8_lossy(&out.0).split_whitespace() {
                    if prog.chars().all(|c| c.is_ascii_alphanumeric()) && !EXCLUDED.contains(&prog) {
                        let t = Tool { module: module.clone(), argv0: vec!["coreutils".into(), prog.into()], sha256: sha256.clone() };
                        tools.tools.insert(prog.to_string(), Arc::new(t));
                    }
                }
            } else {
                tools.tools.insert(name.clone(), Arc::new(Tool { module, argv0: vec![name], sha256 }));
            }
        }
        Ok(tools)
    }

    fn compile(&self, bytes: &[u8], sha256: &str, cache: Option<&Path>) -> anyhow::Result<Module> {
        let Some(cache) = cache else { return Ok(Module::new(&self.engine, bytes)?) };
        let compat = {
            use std::hash::{Hash, Hasher};
            let mut h = std::collections::hash_map::DefaultHasher::new();
            self.engine.precompile_compatibility_hash().hash(&mut h);
            h.finish()
        };
        let file = cache.join(format!("{sha256}-{compat:016x}.cwasm"));
        if file.exists() {
            // SAFETY: the file was written by `precompile_module` below, for this engine configuration, in a
            // directory only the sensor can write.
            if let Ok(m) = unsafe { Module::deserialize_file(&self.engine, &file) } {
                return Ok(m);
            }
        }
        // Compile, and keep the result if the cache is writable (a sandboxed run sees it read-only: then the sensor
        // is expected to have filled it beforehand, and a miss only costs time).
        let compiled = self.engine.precompile_module(bytes)?;
        let tmp = file.with_extension(format!("tmp{}", std::process::id()));
        if std::fs::create_dir_all(cache).and_then(|_| std::fs::write(&tmp, &compiled)).and_then(|_| std::fs::rename(&tmp, &file)).is_err() {
            let _ = std::fs::remove_file(&tmp);
        }
        // SAFETY: produced by `precompile_module` of this engine just above.
        Ok(unsafe { Module::deserialize(&self.engine, &compiled)? })
    }

    /// The tools part of the sensor's manifest ([M1]): name -> SHA-256 of the `.wasm` that provides it.
    pub fn manifest(&self) -> BTreeMap<String, String> {
        self.tools.iter().map(|(k, t)| (k.clone(), t.sha256.clone())).collect()
    }

    /// Runs a pipe: `maps` are (host directory, guest path) pairs, mapped read-only into every instance.
    pub fn pipe(&self, stages: &[Vec<String>], stdin: &[u8], maps: &[(PathBuf, String)], limits: &ToolLimits)
        -> HostResult<ToolResult> {
        if stages.is_empty() {
            return Err(HostError::Tool("pipe() needs at least one stage".into()));
        }
        let mut input = stdin.to_vec();
        let mut result = ToolResult::default();
        for stage in stages {
            let name = stage.first().ok_or_else(|| HostError::Tool("empty pipe stage".into()))?;
            let tool = self.tools.get(name)
                .ok_or_else(|| HostError::Tool(format!("`{name}` is not a tool on this sensor")))?;
            let (out, err, status) = self.run(tool, &stage[1..], input, maps, limits)
                .map_err(|e| match e.downcast::<HostError>() {
                    Ok(h) => h,
                    Err(e) => HostError::Tool(format!("{name}: {e:#}")),
                })?;
            result.stderr.push_str(&String::from_utf8_lossy(&err));
            result.status.push(status);
            input = out;
        }
        result.stdout = String::from_utf8_lossy(&input).into_owned();
        Ok(result)
    }

    fn run(&self, tool: &Tool, args: &[String], stdin: Vec<u8>, maps: &[(PathBuf, String)], limits: &ToolLimits)
        -> anyhow::Result<(Vec<u8>, Vec<u8>, i32)> {
        let stdout = MemoryOutputPipe::new(limits.value_bytes + 1);
        let stderr = MemoryOutputPipe::new(64 << 10);
        let argv: Vec<String> = tool.argv0.iter().chain(args).cloned().collect();
        let mut b = WasiCtxBuilder::new();
        b.args(&argv)
            .env("LC_ALL", "C.UTF-8")
            .env("TZ", "UTC")
            .stdin(MemoryInputPipe::new(stdin))
            .stdout(stdout.clone())
            .stderr(stderr.clone());
        for (host, guest) in maps {
            b.preopened_dir(host, guest, FsPerms::ReadOnly)?;
        }
        let limiter = StoreLimitsBuilder::new().memory_size(limits.memory_bytes).instances(1).build();
        let mut store = Store::new(&self.engine, StoreData { wasi: b.build_p1(), limits: limiter });
        store.limiter(|d| &mut d.limits);
        store.set_fuel(limits.fuel)?;
        let instance = self.linker.instantiate(&mut store, &tool.module)?;
        let start = instance.get_typed_func::<(), ()>(&mut store, "_start")?;
        let status = match start.call(&mut store, ()) {
            Ok(()) => 0,
            Err(e) => {
                if let Some(exit) = e.downcast_ref::<I32Exit>() {
                    exit.0
                } else if matches!(e.downcast_ref::<Trap>(), Some(Trap::OutOfFuel)) {
                    return Err(HostError::Limit(format!("fuel of `{}`", argv.join(" "))).into());
                } else {
                    return Err(e.into());
                }
            }
        };
        drop(store);
        let out = stdout.contents().to_vec();
        if out.len() > limits.value_bytes {
            return Err(HostError::Limit(format!("output of `{}` over {} bytes", argv.join(" "), limits.value_bytes)).into());
        }
        Ok((out, stderr.contents().to_vec(), status))
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::Digest;
    let d = sha2::Sha256::digest(bytes);
    d.iter().map(|b| format!("{b:02x}")).collect()
}
