//! wasm-demo: each subcommand tries one thing and prints what happened. Built for wasm32-wasip1 and run under
//! wasmtime, it shows the sandbox from the inside: only what the host granted works, everything else fails.
use std::io::{Read, Write};

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let arg = |i: usize| args.get(i).map(String::as_str).unwrap_or("");
    let r: Result<String, String> = match arg(1) {
        // Files: only directories the host preopened (wasmtime --dir) exist for the program.
        "cat" => std::fs::read_to_string(arg(2)).map_err(|e| e.to_string()),
        "ls" => std::fs::read_dir(arg(2)).map_err(|e| e.to_string()).map(|d| {
            d.filter_map(|e| e.ok()).map(|e| e.file_name().to_string_lossy().into_owned() + "\n").collect()
        }),
        "write" => std::fs::write(arg(2), "written by wasm-demo\n").map(|_| format!("wrote {}\n", arg(2)))
            .map_err(|e| e.to_string()),
        "rm" => std::fs::remove_file(arg(2)).map(|_| format!("removed {}\n", arg(2))).map_err(|e| e.to_string()),
        // What the program sees of its environment: only variables the host passed (wasmtime --env).
        "env" => Ok(std::env::vars().map(|(k, v)| format!("{k}={v}\n")).collect()),
        // WASI has no way to start a process; std returns "unsupported".
        "spawn" => std::process::Command::new(arg(2)).output().map(|o| format!("ran: {:?}\n", o.status))
            .map_err(|e| e.to_string()),
        // No sockets unless the host grants them (preview1 has none at all).
        "net" => std::net::TcpStream::connect(arg(2)).map(|_| "connected\n".into()).map_err(|e| e.to_string()),
        // Limits: these never finish on their own; the host's fuel, timeout or memory cap stops them.
        "spin" => { let mut n: u64 = 0; loop { n = std::hint::black_box(n.wrapping_add(1)); } }
        "eat" => {
            let mb: usize = arg(2).parse().unwrap_or(1024);
            let mut v: Vec<Vec<u8>> = Vec::new();
            for i in 0..mb { v.push(vec![1u8; 1 << 20]); if i % 64 == 63 { eprintln!("{} MiB", i + 1); } }
            Ok(format!("allocated {mb} MiB\n"))
        }
        // A filter, for pipes: stdin to stdout, upper-cased.
        "upper" => { let mut s = String::new(); std::io::stdin().read_to_string(&mut s).map(|_| s.to_uppercase())
            .map_err(|e| e.to_string()) }
        _ => Err("usage: wasm-demo cat|ls|write|rm PATH | env | spawn CMD | net HOST:PORT | spin | eat MB | upper".into()),
    };
    match r {
        Ok(out) => { std::io::stdout().write_all(out.as_bytes()).unwrap(); }
        Err(e) => { eprintln!("wasm-demo {}: {e}", arg(1)); std::process::exit(1); }
    }
}
