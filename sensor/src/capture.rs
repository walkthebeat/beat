//! The capture broker (docs/spikes.md, Step 5 revised): a question's unit has a network namespace of its own, so it
//! cannot see the host's traffic; when its probe calls `capture()`, it asks the sensor over a unix socket, and the
//! sensor runs tcpdump in a unit of its own in the host's namespace and passes the pcap stream back. Nothing is kept:
//! the stream goes from tcpdump's stdout through the sensor to the question, which reduces it as it reads.
//!
//! The question asks with typed fields only (view, interface, host, port, proto, seconds); the sensor checks each and
//! writes the tcpdump filter itself, so no expression of the question's reaches tcpdump. The snaplen follows the view.
//! One capture at a time on a host: a second is refused while one runs.
//!
//! The capture unit runs tcpdump only, as a dynamic user with CAP_NET_RAW and nothing else, packet and unix sockets
//! only, the send system calls refused, and its stdout a regular file in the sensor's run directory, which the sensor
//! reads as it grows (`Growing`): what it has read is punched out of the file, so the tmpfs holds only what is not
//! read yet, and the end is the unit's end. Not a socket or a FIFO: systemd opens a unit's stdout as PID 1, and on
//! RHEL-family hosts SELinux lets init_t neither connect to the sensor's unix socket (unix_stream_socket connectto,
//! unconfined_service_t) nor write a FIFO in /run (fifo_file write, var_run_t), both dontaudit, so the unit failed at
//! 209/STDOUT with no AVC logged (AlmaLinux 9, 2026-11-13); a regular file there it may write, as the questions'
//! answers already are. Not `systemd-run --pipe` either, see runner.rs. Measured on systemd 255 / libpcap 1.10.4: libpcap
//! needs AF_UNIX for its ethtool ioctl; with AF_NETLINK allowed too the stream came back empty (not explained, not
//! needed). Refusing sendto/sendmsg/sendmmsg is defence in depth only: write() on a packet socket also sends.
//!
//! The socket protocol, one connection per capture (the question's side is beat-probe's capture.rs):
//!   question -> sensor  one JSON line: {"view", "interface"?, "host"?, "port"?, "proto"?, "seconds"}
//!   sensor -> question  one JSON line: {"error": "..."} and the end, or {"ok": {"view", "interface", "filter",
//!                       "snaplen", "seconds"}}, then the pcap stream in frames (u32 big-endian length, bytes), a frame
//!                       of length 0, and one JSON line: {"end", "bytes", "seconds", "captured", "received", "dropped",
//!                       "error"?}

use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::os::unix::fs::OpenOptionsExt;
use std::process::Stdio;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use serde_json::{json, Value};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use std::io::Read;
use std::os::fd::AsRawFd;
use tokio::process::Command;

/// The longest capture. A judgement: long enough for a retry cycle (SYN retries reach 31 s), short enough that a
/// question asking every host stays a question.
pub const MAX_SECONDS: u64 = 60;
/// What a capture may pass back; past it tcpdump is stopped and the end says `bytes`. A judgement: with snaplen 128,
/// about 1.6 million packets; the reducer keeps up with that on one CPU.
const MAX_BYTES: u64 = 256 << 20;
/// From the request to tcpdump's first bytes (the unit started, the interface opened).
const START_WITHIN: Duration = Duration::from_secs(10);
/// What a capture needs of the question's time beyond its seconds: starting, and the reduction after.
const MARGIN_S: u64 = 10;
static SEQ: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum View {
    Packets,
    Flows,
    Dns,
    Tls,
}

impl View {
    fn parse(s: &str) -> Option<View> {
        Some(match s {
            "packets" => View::Packets,
            "flows" => View::Flows,
            "dns" => View::Dns,
            "tls" => View::Tls,
            _ => return None,
        })
    }
    fn name(self) -> &'static str {
        match self {
            View::Packets => "packets",
            View::Flows => "flows",
            View::Dns => "dns",
            View::Tls => "tls",
        }
    }
    /// What the view's reducer reads of a packet. Headers fit in 128 (IPv6 with options and TCP with options); a DNS
    /// question with a long name does not, a TLS ClientHello with a post-quantum key share spans 1.5 KB and more.
    fn snaplen(self) -> u32 {
        match self {
            View::Packets | View::Flows => 128,
            View::Dns => 512,
            View::Tls => 4096,
        }
    }
}

#[derive(Debug, PartialEq)]
pub struct Request {
    pub view: View,
    pub interface: String,
    pub host: Option<IpAddr>,
    pub port: Option<u16>,
    pub proto: Option<&'static str>,
    pub seconds: u64,
}

/// What the host can tell the broker: whether an interface exists, and which one a destination is routed through.
pub trait Net {
    fn exists(&self, interface: &str) -> bool;
    /// The interface of the route to `to`, or of the default route when None.
    fn route(&self, to: Option<IpAddr>) -> Option<String>;
}

/// The host's own: /sys/class/net and the main routing table in /proc.
pub struct HostNet;

impl Net for HostNet {
    fn exists(&self, interface: &str) -> bool {
        Path::new("/sys/class/net").join(interface).exists()
    }
    fn route(&self, to: Option<IpAddr>) -> Option<String> {
        match to {
            Some(a) if a.is_loopback() => Some("lo".into()),
            Some(IpAddr::V6(a)) => route_v6(&std::fs::read_to_string("/proc/net/ipv6_route").ok()?, a.into()),
            Some(IpAddr::V4(a)) => route_v4(&std::fs::read_to_string("/proc/net/route").ok()?, a.into()),
            None => route_v4(&std::fs::read_to_string("/proc/net/route").ok()?, 0)
                .or_else(|| route_v6(&std::fs::read_to_string("/proc/net/ipv6_route").ok()?, 0)),
        }
    }
}

/// The longest-prefix route in /proc/net/route; among equal prefixes the lowest metric.
fn route_v4(table: &str, to: u32) -> Option<String> {
    let mut best: Option<(u32, u32, String)> = None; // (prefix bits, metric, interface)
    for l in table.lines().skip(1) {
        let f: Vec<&str> = l.split_whitespace().collect();
        if f.len() < 8 {
            continue;
        }
        let hex = |s: &str| u32::from_str_radix(s, 16).ok();
        let (Some(dest), Some(flags), Some(mask)) = (hex(f[1]), hex(f[3]), hex(f[7])) else { continue };
        let metric: u32 = f[6].parse().unwrap_or(u32::MAX);
        // The kernel prints the address's bytes (network order) read as a host-order integer.
        let net = |x: u32| u32::from_be_bytes(x.to_ne_bytes());
        let (dest, mask) = (net(dest), net(mask));
        if flags & 1 == 0 || to & mask != dest & mask {
            continue;
        }
        let bits = mask.count_ones();
        if best.as_ref().is_none_or(|(b, m, _)| bits > *b || (bits == *b && metric < *m)) {
            best = Some((bits, metric, f[0].to_string()));
        }
    }
    best.map(|b| b.2)
}

/// The same in /proc/net/ipv6_route: destination, prefix length, source, its length, next hop, metric, refcount, use,
/// flags, interface. Rejecting routes (RTF_REJECT, the kernel's unreachable entries on lo) are not routes.
fn route_v6(table: &str, to: u128) -> Option<String> {
    let mut best: Option<(u32, u32, String)> = None;
    for l in table.lines() {
        let f: Vec<&str> = l.split_whitespace().collect();
        if f.len() < 10 {
            continue;
        }
        let (Ok(dest), Ok(bits), Ok(metric), Ok(flags)) = (u128::from_str_radix(f[0], 16), u32::from_str_radix(f[1], 16),
            u32::from_str_radix(f[5], 16), u32::from_str_radix(f[8], 16)) else { continue };
        if flags & 1 == 0 || flags & 0x200 != 0 || bits > 128 {
            continue;
        }
        let mask = if bits == 0 { 0 } else { u128::MAX << (128 - bits) };
        if to & mask != dest & mask {
            continue;
        }
        if best.as_ref().is_none_or(|(b, m, _)| bits > *b || (bits == *b && metric < *m)) {
            best = Some((bits, metric, f[9].to_string()));
        }
    }
    best.map(|b| b.2)
}

/// A name the kernel could give an interface: at most 15 bytes, no slash or space; and not an option to tcpdump.
fn interface_name(s: &str) -> bool {
    !s.is_empty() && s.len() <= 15 && !s.starts_with('-')
        && s.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-' | b'@' | b':'))
}

/// The request, checked field by field; every field is a value of its own type, or the request is refused.
pub fn parse_request(line: &[u8], net: &dyn Net) -> Result<Request, String> {
    let v: Value = serde_json::from_slice(line).map_err(|e| format!("not a capture request: {e}"))?;
    let o = v.as_object().ok_or("not a capture request: a JSON object is expected")?;
    for k in o.keys() {
        if !["view", "interface", "host", "port", "proto", "seconds"].contains(&k.as_str()) {
            return Err(format!("capture: unknown field {k:?}"));
        }
    }
    let text = |k: &str| -> Result<Option<&str>, String> {
        match o.get(k) {
            None | Some(Value::Null) => Ok(None),
            Some(Value::String(s)) => Ok(Some(s)),
            Some(_) => Err(format!("capture: {k} is a string")),
        }
    };
    let view = text("view")?.ok_or("capture: view is required (packets, flows, dns, tls)")?;
    let view = View::parse(view).ok_or_else(|| format!("capture: no view {view:?} (packets, flows, dns, tls)"))?;
    let seconds = match o.get("seconds") {
        None | Some(Value::Null) => 5,
        Some(s) => s.as_u64().filter(|s| (1..=MAX_SECONDS).contains(s))
            .ok_or_else(|| format!("capture: seconds is a whole number from 1 to {MAX_SECONDS}"))?,
    };
    let host = text("host")?.map(|h| h.parse::<IpAddr>().map_err(|_| format!("capture: host {h:?} is not an IP address")))
        .transpose()?;
    let port = match o.get("port") {
        None | Some(Value::Null) => None,
        Some(p) => Some(p.as_u64().filter(|p| (1..=65535).contains(p))
            .ok_or("capture: port is a number from 1 to 65535")? as u16),
    };
    let proto = match text("proto")? {
        None => None,
        Some("tcp") => Some("tcp"),
        Some("udp") => Some("udp"),
        Some("icmp") => Some("icmp"),
        Some(p) => return Err(format!("capture: no proto {p:?} (tcp, udp, icmp)")),
    };
    if proto == Some("icmp") && port.is_some() {
        return Err("capture: icmp has no ports".into());
    }
    match (view, proto) {
        (View::Tls, Some(p)) if p != "tcp" => return Err("capture: the tls view reads tcp".into()),
        (View::Dns, Some("icmp")) => return Err("capture: the dns view reads udp".into()),
        _ => {}
    }
    let interface = match text("interface")? {
        Some("any") => "any".to_string(),
        Some(i) if !interface_name(i) => return Err(format!("capture: {i:?} is not an interface name")),
        Some(i) if !net.exists(i) => return Err(format!("capture: this host has no interface {i:?}")),
        Some(i) => i.to_string(),
        None => net.route(host).ok_or_else(|| match host {
            Some(h) => format!("capture: no route to {h} on this host: give the interface"),
            None => "capture: this host has no default route: give the interface".to_string(),
        })?,
    };
    Ok(Request { view, interface, host, port, proto, seconds })
}

/// The tcpdump filter, written from the checked fields. ICMP errors are kept in the packets and flows views whatever
/// the rest says: a frag-needed comes from a router, not from the host asked about, and is what an MTU blackhole lacks.
pub fn filter(r: &Request) -> String {
    let mut parts = Vec::new();
    if let Some(h) = r.host {
        parts.push(format!("host {h}"));
    }
    let port = r.port.or(if r.view == View::Dns { Some(53) } else { None });
    let proto = r.proto.or(match r.view {
        View::Dns => Some("udp"),
        View::Tls => Some("tcp"),
        _ => None,
    });
    match (proto, port) {
        (Some("icmp"), _) => parts.push("(icmp or icmp6)".into()),
        (Some(p), Some(n)) => parts.push(format!("{p} port {n}")),
        (Some(p), None) => parts.push(p.into()),
        (None, Some(n)) => parts.push(format!("port {n}")),
        (None, None) => {}
    }
    let main = parts.join(" and ");
    let errors = "(icmp and (icmp[0] == 3 or icmp[0] == 11 or icmp[0] == 12)) or \
                  (icmp6 and (icmp6[0] == 1 or icmp6[0] == 2 or icmp6[0] == 3 or icmp6[0] == 4))";
    match r.view {
        View::Packets | View::Flows if !main.is_empty() && proto != Some("icmp") => format!("({main}) or {errors}"),
        _ => main,
    }
}

/// The capture unit's properties: tcpdump as a dynamic user with CAP_NET_RAW, nothing else it could use.
const CAPTURE_UNIT: [&str; 22] = [
    "DynamicUser=yes", "AmbientCapabilities=CAP_NET_RAW", "CapabilityBoundingSet=CAP_NET_RAW", "NoNewPrivileges=yes",
    "RestrictAddressFamilies=AF_PACKET AF_UNIX", "SystemCallFilter=~sendto sendmsg sendmmsg", "SystemCallArchitectures=native",
    "ProtectSystem=strict", "ProtectHome=yes", "PrivateTmp=yes", "PrivateDevices=yes", "ProtectKernelTunables=yes",
    "ProtectKernelModules=yes", "ProtectControlGroups=yes", "RestrictNamespaces=yes", "RestrictSUIDSGID=yes",
    "LockPersonality=yes", "MemoryDenyWriteExecute=yes", "TasksMax=4", "MemoryMax=256M", "CPUQuota=50%",
    "StandardInput=null",
];

pub struct Broker {
    pub tcpdump: PathBuf,
    pub systemd: PathBuf,
    /// The question units' extra properties (MountImages= when installed from an image: tcpdump is in its store).
    pub unit_props: Vec<String>,
    /// Files no unit may see (the sensor's key).
    pub hide: Vec<PathBuf>,
    pub run_dir: PathBuf,
    pub net: Box<dyn Net + Send + Sync>,
    busy: tokio::sync::Mutex<()>,
}

/// Stops a capture unit that is still running when its capture is abandoned (the question ended, the sensor erred).
struct Running {
    systemctl: PathBuf,
    unit: String,
    done: bool,
}

impl Drop for Running {
    fn drop(&mut self) {
        if !self.done {
            let _ = std::process::Command::new(&self.systemctl).args(["stop", "--no-block", &self.unit])
                .stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null()).status();
        }
    }
}

struct Removed(Vec<PathBuf>);

impl Drop for Removed {
    fn drop(&mut self) {
        for p in &self.0 {
            let _ = std::fs::remove_file(p);
        }
    }
}

impl Broker {
    pub fn new(tcpdump: PathBuf, systemd: PathBuf, unit_props: Vec<String>, hide: Vec<PathBuf>, run_dir: PathBuf) -> Broker {
        Broker { tcpdump, systemd, unit_props, hide, run_dir, net: Box::new(HostNet), busy: Default::default() }
    }

    /// A question's socket: its requests one after the other until the question ends (the task is dropped with it).
    /// `deadline`: when the question's time is up; a capture must end before.
    pub async fn serve(&self, listener: UnixListener, deadline: Instant) {
        while let Ok((conn, _)) = listener.accept().await {
            if let Err(e) = self.handle(conn, deadline).await {
                eprintln!("capture: {e}");
            }
        }
    }

    async fn handle(&self, conn: UnixStream, deadline: Instant) -> Result<(), String> {
        let (rd, mut wr) = conn.into_split();
        let mut line = Vec::new();
        let mut rd = BufReader::new(rd).take(4096);
        let read = rd.read_until(b'\n', &mut line);
        tokio::time::timeout(Duration::from_secs(5), read).await.map_err(|_| "no request".to_string())?
            .map_err(|e| e.to_string())?;
        let req = match parse_request(&line, self.net.as_ref()) {
            Ok(r) => r,
            Err(e) => return refuse(&mut wr, e).await,
        };
        let left = deadline.saturating_duration_since(Instant::now()).as_secs();
        if req.seconds + MARGIN_S > left {
            return refuse(&mut wr, format!("capture: the question has {left} s left; a capture of {} s needs {} s",
                                  req.seconds, req.seconds + MARGIN_S)).await;
        }
        let Ok(_one) = self.busy.try_lock() else {
            return refuse(&mut wr, "capture: another capture is running on this host; one at a time".into()).await;
        };
        let filter = filter(&req);
        let id = format!("{}-{}", std::process::id(), SEQ.fetch_add(1, Ordering::Relaxed));
        let (pcap, err) = (self.run_dir.join(format!("{id}.pcap")), self.run_dir.join(format!("{id}.tcpdump-err")));
        let _files = Removed(vec![pcap.clone(), err.clone()]);
        let _ = std::fs::remove_file(&pcap);
        let file = std::fs::OpenOptions::new().read(true).write(true).create_new(true)
            .mode(0o600).open(&pcap).map_err(|e| format!("{}: {e}", pcap.display()))?;
        let mut stream = Growing { file, read: 0, punched: 0, ended: false };
        let unit = format!("beat-capture-{id}");
        let argv = self.argv(&req, &filter, &unit, &pcap, &err);
        let mut child = Command::new(&argv[0]).args(&argv[1..]).stdin(Stdio::null()).stdout(Stdio::null())
            .stderr(Stdio::piped()).kill_on_drop(true).spawn().map_err(|e| format!("cannot start {}: {e}", argv[0]))?;
        let mut running = Running { systemctl: self.systemd.join("systemctl"), unit: unit.clone(), done: false };
        let started = Instant::now();

        // tcpdump's first bytes (the pcap header) once it opened the interface. If it fails first (or systemd could
        // not start it), the unit ends with nothing written, and the reason is in tcpdump's stderr or systemd-run's.
        let mut buf = vec![0u8; 65536];
        let n = match tokio::time::timeout(START_WITHIN, stream.read(&mut buf, &mut child)).await {
            Ok(Ok(n)) if n > 0 => n,
            _ => {
                let _ = tokio::time::timeout(Duration::from_secs(5), child.wait()).await;
                return refuse(&mut wr, format!("capture: tcpdump did not start: {}", tail(&err, &mut child).await)).await;
            }
        };
        buf.truncate(n);
        let header = json!({"ok": {"view": req.view.name(), "interface": req.interface, "filter": filter,
                                   "snaplen": req.view.snaplen(), "seconds": req.seconds}});
        wr.write_all(format!("{header}\n").as_bytes()).await.map_err(|e| e.to_string())?;

        let (mut bytes, mut end, mut stopping) = (0u64, "exited", false);
        let mut chunk = buf;
        let until = tokio::time::Instant::now() + Duration::from_secs(req.seconds);
        let mut gone = false;
        loop {
            if !chunk.is_empty() && !gone && end != "bytes" {
                if bytes + chunk.len() as u64 > MAX_BYTES {
                    end = "bytes";
                    stopping = self.stop(&unit, stopping).await;
                } else {
                    bytes += chunk.len() as u64;
                    let mut frame = (chunk.len() as u32).to_be_bytes().to_vec();
                    frame.extend_from_slice(&chunk);
                    if wr.write_all(&frame).await.is_err() {
                        // The question went away: stop, and drain so tcpdump is not blocked on a full socket.
                        gone = true;
                        end = "gone";
                        stopping = self.stop(&unit, stopping).await;
                    }
                }
            }
            let mut buf = vec![0u8; 65536];
            tokio::select! {
                n = stream.read(&mut buf, &mut child) => match n {
                    Ok(0) | Err(_) => break,
                    Ok(n) => { buf.truncate(n); chunk = buf; }
                },
                _ = tokio::time::sleep_until(until), if !stopping => {
                    end = "time";
                    stopping = self.stop(&unit, stopping).await;
                    chunk = Vec::new();
                }
            }
        }
        let status = tokio::time::timeout(Duration::from_secs(10), child.wait()).await;
        running.done = matches!(status, Ok(Ok(_)));
        if gone {
            return Ok(());
        }
        let stderr = std::fs::read_to_string(&err).unwrap_or_default();
        let mut trailer = stats(&stderr);
        trailer["end"] = json!(end);
        trailer["bytes"] = json!(bytes);
        trailer["seconds"] = json!((started.elapsed().as_secs_f64() * 10.0).round() / 10.0);
        if end == "exited" {
            trailer["error"] = json!(last_lines(&stderr));
        }
        wr.write_all(&0u32.to_be_bytes()).await.map_err(|e| e.to_string())?;
        wr.write_all(format!("{trailer}\n").as_bytes()).await.map_err(|e| e.to_string())?;
        Ok(())
    }

    /// SIGINT to tcpdump: it flushes what it buffered, prints its counts and exits. To the whole unit (tcpdump is all
    /// it runs): `--kill-whom=` is systemd 252's name, 249 knows only `--kill-who=` and refused the call, and the
    /// capture then ran to RuntimeMaxSec (api-1, Ubuntu 22.04, 2026-11-11).
    async fn stop(&self, unit: &str, already: bool) -> bool {
        if !already {
            let _ = Command::new(self.systemd.join("systemctl")).args(["kill", "--signal=SIGINT", unit])
                .stdin(Stdio::null()).output().await;
        }
        true
    }

    fn argv(&self, req: &Request, filter: &str, unit: &str, pcap: &Path, err: &Path) -> Vec<String> {
        let mut props: Vec<String> = CAPTURE_UNIT.iter().map(|s| s.to_string()).collect();
        props.push(format!("RuntimeMaxSec={}", req.seconds + MARGIN_S));
        props.extend(self.hide.iter().map(|p| format!("InaccessiblePaths={}", p.display())));
        props.extend(self.unit_props.iter().cloned());
        props.push(format!("StandardOutput=file:{}", pcap.display()));
        props.push(format!("StandardError=file:{}", err.display()));
        let mut argv = vec![self.systemd.join("systemd-run").display().to_string()];
        argv.extend(["--quiet", "--wait", "--collect", "--service-type=exec"].map(String::from));
        argv.push(format!("--unit={unit}"));
        argv.push(format!("--description=beat capture {} on {}", req.view.name(), req.interface));
        for p in props {
            argv.extend(["-p".into(), p]);
        }
        argv.push(self.tcpdump.display().to_string());
        // -p: not promiscuous (the host's own traffic); -n: no lookups; -U: each packet written when captured.
        argv.extend(["-i".into(), req.interface.clone(), "-p".into(), "-n".into(), "-U".into(),
                     "-s".into(), req.view.snaplen().to_string(), "-w".into(), "-".into()]);
        if !filter.is_empty() {
            argv.push(filter.to_string());
        }
        argv
    }
}

/// The pcap file as tcpdump writes it: each read returns what is new, waiting while the unit runs (`child`, systemd-run
/// --wait, ends when the unit has), and 0 once it has ended and everything is read. Every PUNCH bytes read are
/// punched out of the file (its size stays, its pages go), so a capture holds at most about PUNCH of the host's memory
/// in the tmpfs plus what tcpdump wrote ahead of the reader. Reads of a tmpfs file are memory copies: done inline.
struct Growing {
    file: std::fs::File,
    read: u64,
    punched: u64,
    ended: bool,
}

const PUNCH: u64 = 1 << 20;
/// How often a reader at the end looks again: tcpdump -U writes each packet as it comes.
const POLL: Duration = Duration::from_millis(20);

impl Growing {
    async fn read(&mut self, buf: &mut [u8], child: &mut tokio::process::Child) -> std::io::Result<usize> {
        loop {
            let n = self.file.read(buf)?;
            if n > 0 {
                self.read += n as u64;
                if self.read - self.punched >= PUNCH {
                    self.punch();
                }
                return Ok(n);
            }
            if self.ended {
                return Ok(0);
            }
            // Once the unit has ended, the next read takes what it wrote last, and the one after is 0.
            tokio::select! {
                _ = child.wait() => self.ended = true,
                _ = tokio::time::sleep(POLL) => {}
            }
        }
    }

    fn punch(&mut self) {
        let len = (self.read - self.punched) as libc::off_t;
        // SAFETY: fallocate on a file descriptor we own; it changes only the file's blocks.
        let r = unsafe {
            libc::fallocate(self.file.as_raw_fd(), libc::FALLOC_FL_PUNCH_HOLE | libc::FALLOC_FL_KEEP_SIZE,
                            self.punched as libc::off_t, len)
        };
        if r == 0 {
            self.punched = self.read;
        }
    }
}

/// The capture's answer when there is none: one line, and the connection ends.
async fn refuse(wr: &mut tokio::net::unix::OwnedWriteHalf, msg: String) -> Result<(), String> {
    let _ = wr.write_all(format!("{}\n", json!({"error": msg})).as_bytes()).await;
    Ok(())
}

/// Why tcpdump did not start: its own stderr, else systemd-run's.
async fn tail(err: &Path, child: &mut tokio::process::Child) -> String {
    let own = std::fs::read_to_string(err).unwrap_or_default();
    if !own.trim().is_empty() {
        return last_lines(&own);
    }
    let mut s = String::new();
    if let Some(mut e) = child.stderr.take() {
        let _ = tokio::time::timeout(Duration::from_secs(1), e.read_to_string(&mut s)).await;
    }
    if s.trim().is_empty() { "no reason given".into() } else { last_lines(&s) }
}

fn last_lines(s: &str) -> String {
    let lines: Vec<&str> = s.lines().filter(|l| !l.trim().is_empty()).collect();
    lines[lines.len().saturating_sub(3)..].join("; ")
}

/// tcpdump's counts at exit: "N packets captured", "N packets received by filter", "N packets dropped by kernel"
/// (and, from some drivers, "N packets dropped by interface").
fn stats(stderr: &str) -> Value {
    let mut out = json!({});
    for l in stderr.lines() {
        let Some((n, rest)) = l.trim().split_once(' ') else { continue };
        let Ok(n) = n.parse::<u64>() else { continue };
        let key = match rest.trim_start_matches("packets ").trim_start_matches("packet ") {
            "captured" => "captured",
            "received by filter" => "received",
            "dropped by kernel" => "dropped",
            "dropped by interface" => "dropped_interface",
            _ => continue,
        };
        out[key] = json!(n);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Fake;
    impl Net for Fake {
        fn exists(&self, i: &str) -> bool {
            ["eth0", "ens5", "lo"].contains(&i)
        }
        fn route(&self, to: Option<IpAddr>) -> Option<String> {
            match to {
                Some(a) if a.is_loopback() => Some("lo".into()),
                Some(IpAddr::V4(a)) if a.octets()[0] == 10 => Some("ens5".into()),
                Some(_) => None,
                None => Some("eth0".into()),
            }
        }
    }

    fn req(s: &str) -> Result<Request, String> {
        parse_request(s.as_bytes(), &Fake)
    }

    #[test]
    fn requests_are_typed_and_checked() {
        let r = req(r#"{"view":"flows","host":"10.0.0.5","port":443,"proto":"tcp","seconds":10}"#).unwrap();
        assert_eq!((r.interface.as_str(), r.seconds, r.port, r.proto), ("ens5", 10, Some(443), Some("tcp")));
        assert_eq!(req(r#"{"view":"dns"}"#).unwrap().interface, "eth0", "no host: the default route");
        assert_eq!(req(r#"{"view":"dns","host":"::1"}"#).unwrap().interface, "lo");
        assert_eq!(req(r#"{"view":"dns","interface":"any"}"#).unwrap().interface, "any");
        for (bad, why) in [
            (r#"{"view":"flows","host":"10.0.0.5 or port 22"}"#, "not an IP"),
            (r#"{"view":"flows","interface":"-w/etc/x"}"#, "not an interface name"),
            (r#"{"view":"flows","interface":"eth9"}"#, "no interface"),
            (r#"{"view":"flows","port":0}"#, "port"),
            (r#"{"view":"flows","port":"22"}"#, "port"),
            (r#"{"view":"flows","seconds":61}"#, "seconds"),
            (r#"{"view":"flows","seconds":1.5}"#, "seconds"),
            (r#"{"view":"flows","proto":"sctp"}"#, "no proto"),
            (r#"{"view":"flows","proto":"icmp","port":1}"#, "no ports"),
            (r#"{"view":"tls","proto":"udp"}"#, "tcp"),
            (r#"{"view":"flows","filter":"tcp"}"#, "unknown field"),
            (r#"{"view":"strace"}"#, "no view"),
            (r#"{"host":"10.0.0.5"}"#, "view is required"),
            (r#"{"view":"flows","host":"192.0.2.1"}"#, "no route"),
            (r#"["flows"]"#, "JSON object"),
        ] {
            let e = req(bad).expect_err(bad);
            assert!(e.contains(why), "{bad}: {e}");
        }
    }

    #[test]
    fn filters_are_written_from_the_fields() {
        let f = |s: &str| filter(&req(s).unwrap());
        assert_eq!(f(r#"{"view":"dns"}"#), "udp port 53");
        assert_eq!(f(r#"{"view":"dns","host":"10.0.0.2"}"#), "host 10.0.0.2 and udp port 53");
        assert_eq!(f(r#"{"view":"tls","port":8443}"#), "tcp port 8443");
        assert_eq!(f(r#"{"view":"flows"}"#), "");
        assert_eq!(f(r#"{"view":"flows","proto":"icmp"}"#), "(icmp or icmp6)");
        let flows = f(r#"{"view":"flows","host":"10.0.0.5","port":5432,"proto":"tcp"}"#);
        assert!(flows.starts_with("(host 10.0.0.5 and tcp port 5432) or (icmp and (icmp[0] == 3"), "{flows}");
        assert!(f(r#"{"view":"packets","host":"::1"}"#).starts_with("(host ::1) or "));
    }

    #[test]
    fn routes_from_proc() {
        // A host with a default route on ens5, its subnet, and a docker bridge.
        let v4 = "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n\
                  ens5\t00000000\t0100000A\t0003\t0\t0\t100\t00000000\t0\t0\t0\n\
                  ens5\t0000000A\t00000000\t0001\t0\t0\t100\t0000FFFF\t0\t0\t0\n\
                  docker0\t000011AC\t00000000\t0001\t0\t0\t0\t0000FFFF\t0\t0\t0\n";
        let ip = |s: &str| u32::from(s.parse::<std::net::Ipv4Addr>().unwrap());
        assert_eq!(route_v4(v4, ip("10.0.3.4")).as_deref(), Some("ens5"));
        assert_eq!(route_v4(v4, ip("172.17.0.2")).as_deref(), Some("docker0"));
        assert_eq!(route_v4(v4, ip("8.8.8.8")).as_deref(), Some("ens5"));
        assert_eq!(route_v4(v4, 0).as_deref(), Some("ens5"));
        let v6 = "00000000000000000000000000000000 00 00000000000000000000000000000000 00 fe800000000000000000000000000001 00000400 00000001 00000000 00000003  ens5\n\
                  fe800000000000000000000000000000 40 00000000000000000000000000000000 00 00000000000000000000000000000000 00000100 00000001 00000000 00000001  ens5\n\
                  00000000000000000000000000000000 00 00000000000000000000000000000000 00 00000000000000000000000000000000 ffffffff 00000001 00000000 00200200       lo\n";
        let ip6 = |s: &str| u128::from(s.parse::<std::net::Ipv6Addr>().unwrap());
        assert_eq!(route_v6(v6, ip6("2001:db8::1")).as_deref(), Some("ens5"));
        assert_eq!(route_v6(v6, ip6("fe80::5")).as_deref(), Some("ens5"));
    }

    #[test]
    fn tcpdump_counts() {
        let s = "tcpdump: listening on lo, link-type EN10MB (Ethernet), snapshot length 128 bytes\n12 packets captured\n\
                 24 packets received by filter\n0 packets dropped by kernel\n";
        assert_eq!(stats(s), json!({"captured": 12, "received": 24, "dropped": 0}));
        assert_eq!(stats("1 packet captured\n"), json!({"captured": 1}));
    }

    /// A writer that pauses and then writes more than PUNCH: every byte comes back once, in order, the end only after
    /// the writer has, and what was read is no longer held (on a tmpfs, where captures are).
    #[tokio::test]
    async fn the_pcap_file_is_read_as_it_grows_and_punched() {
        let dir = Path::new("/dev/shm");
        let path = dir.join(format!("beat-growing-test-{}", std::process::id()));
        let _gone = Removed(vec![path.clone()]);
        let file = std::fs::OpenOptions::new().read(true).write(true).create_new(true).mode(0o600).open(&path).unwrap();
        let out = std::fs::OpenOptions::new().write(true).open(&path).unwrap();
        let mut child = Command::new("sh").args(["-c", "printf abc; sleep 0.3; printf def; head -c 3000000 /dev/zero"])
            .stdout(out).spawn().unwrap();
        let mut g = Growing { file, read: 0, punched: 0, ended: false };
        let (mut all, mut buf) = (Vec::new(), vec![0u8; 65536]);
        loop {
            let n = g.read(&mut buf, &mut child).await.unwrap();
            if n == 0 { break; }
            all.extend_from_slice(&buf[..n]);
        }
        assert_eq!(&all[..6], b"abcdef");
        assert_eq!(all.len(), 6 + 3_000_000);
        assert!(g.ended);
        use std::os::unix::fs::MetadataExt;
        let m = std::fs::metadata(&path).unwrap();
        assert_eq!(m.len(), 3_000_006);
        assert!(m.blocks() * 512 <= PUNCH + 4096, "{} bytes still held", m.blocks() * 512);
    }

    #[test]
    fn the_unit_runs_tcpdump_alone_with_the_written_filter() {
        let b = Broker::new("/x/tcpdump".into(), "/usr/bin".into(), vec![], vec!["/k".into()], "/run/b".into());
        let r = req(r#"{"view":"tls","host":"10.0.0.5","port":443}"#).unwrap();
        let argv = b.argv(&r, &filter(&r), "beat-capture-1", Path::new("/run/b/1.pcap"), Path::new("/run/b/1.err"));
        let tail: Vec<&str> = argv.iter().skip_while(|a| *a != "/x/tcpdump").map(String::as_str).collect();
        assert_eq!(tail, ["/x/tcpdump", "-i", "ens5", "-p", "-n", "-U", "-s", "4096", "-w", "-", "host 10.0.0.5 and tcp port 443"]);
        assert!(argv.contains(&"StandardOutput=file:/run/b/1.pcap".to_string()));
        assert!(argv.contains(&"InaccessiblePaths=/k".to_string()));
        assert!(argv.contains(&"RuntimeMaxSec=15".to_string()));
    }
}
