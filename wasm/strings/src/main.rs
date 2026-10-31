//! `strings`: printable character runs in binary input, as binutils' strings(1) prints them by default.
//!
//!   strings [-n MIN]        stdin -> one run per line (runs of at least MIN bytes, default 4)
//!
//! A run is ASCII printable bytes (0x20..0x7e) and tabs, as GNU strings without --encoding. A probe feeds it a file:
//! `pipe(["cat", "/usr/sbin/x"], ["strings", "-n", "6"])`. Reads stdin whole (the probe's input limits apply).
use std::io::{self, Read, Write};

fn runs(data: &[u8], min: usize) -> Vec<&[u8]> {
    data.split(|&b| !(b == b'\t' || (0x20..0x7f).contains(&b))).filter(|r| r.len() >= min).collect()
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let min = match args.as_slice() {
        [] => 4,
        [f, n] if f == "-n" => match n.parse::<usize>() {
            Ok(n) if n > 0 => n,
            _ => {
                eprintln!("strings: -n needs a positive number, got {n}");
                std::process::exit(2);
            }
        },
        _ => {
            eprintln!("strings: usage: strings [-n MIN] < file");
            std::process::exit(2);
        }
    };
    let mut data = Vec::new();
    io::stdin().read_to_end(&mut data).expect("strings: reading stdin");
    let mut out = io::BufWriter::new(io::stdout().lock());
    for r in runs(&data, min) {
        out.write_all(r).unwrap();
        out.write_all(b"\n").unwrap();
    }
}

#[cfg(test)]
mod tests {
    use super::runs;

    #[test]
    fn printable_runs_of_at_least_min() {
        let bin = b"\x7fELF\x02\x01\x00/dev/shm/psm2_shm.%x\x00\x00ok\x00node-health: check %d\tfailed\x00";
        let r: Vec<&str> = runs(bin, 4).iter().map(|r| std::str::from_utf8(r).unwrap()).collect();
        assert_eq!(r, vec!["/dev/shm/psm2_shm.%x", "node-health: check %d\tfailed"]);
        assert_eq!(runs(bin, 2).len(), 4); // and "ELF", "ok"
    }
}
