//! The reducer behind `capture()` (docs/probes.md, to come; design: beat's docs/spikes.md, Step 5 revised): a pcap
//! stream, as tcpdump writes it with `-w -`, reduced as it arrives into one of three views, then grouped by the
//! reduction vocabulary `trace()` uses (`catalog::Reducer`). Packets never leave the host; the answer is counts,
//! bounded groups and a few examples, and it says what it saw.
//!
//! What is parsed: link (Ethernet, Linux cooked v1 and v2, raw IP), IPv4, IPv6 (extension headers skipped), TCP,
//! UDP, ICMP and ICMPv6 headers, and DNS's header and question. Application payload is never parsed or emitted:
//! only its length. Parsers are written here, not taken from a crate: no dependency, every read bounds-checked (a
//! frame is hostile input), small enough to review.
//!
//! Views:
//! - `packets`: one event per packet (addresses, ports, tcpdump's flag letters, sizes, ICMP type and code).
//! - `flows`: one event per flow at the end (per 5-tuple, both directions: packets, bytes, SYNs, resets, retransmits,
//!   zero windows, handshake time, the largest segment, ICMP errors about it).
//! - `dns`: one event per query, matched to its response by (client, port, server, id): name, type, rcode, latency.
//!
//! Offloads (seen on veth, tests/pcap/README.md): a sender's capture holds TSO's segments (up to 64 KB, before the
//! NIC cuts them), a receiver's GRO's merged ones. Sizes are then the kernel's, not the wire's (`over_1514` counts
//! them), and a receiver's retransmit count is a lower bound: a retransmitted segment merged with new data is not
//! seen as one.

use std::collections::HashMap;
use std::io::Read;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use serde_json::{json, Map, Value};

use crate::catalog::{Reducer, TraceOptions};
use crate::host::{HostError, HostResult};

/// The largest frame a record may claim; beyond it the stream is taken as corrupt (tcpdump's own maximum snaplen).
const MAX_FRAME: u32 = 262_144;
/// Flows and DNS queries tracked at once; packets of further ones are counted, not tracked.
pub const MAX_FLOWS: usize = 100_000;
/// A query sent less than this before the capture's end is in flight, not unanswered.
const IN_FLIGHT_S: f64 = 1.0;

pub const PACKET_NUMERIC: &[&str] = &["len", "payload", "win", "t"];
pub const FLOW_NUMERIC: &[&str] = &[
    "packets", "pkts_c2s", "pkts_s2c", "bytes_c2s", "bytes_s2c", "syn", "syn_retrans", "synack", "rst", "fin",
    "retrans_c2s", "retrans_s2c", "zero_win", "handshake_ms", "duration_ms", "max_seg_c2s", "max_seg_s2c",
    "icmp_errors", "t",
];
pub const DNS_NUMERIC: &[&str] = &["latency_ms", "sends", "answers", "t"];

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum View {
    Packets,
    Flows,
    Dns,
}

impl View {
    pub fn parse(s: &str) -> HostResult<View> {
        match s {
            "packets" => Ok(View::Packets),
            "flows" => Ok(View::Flows),
            "dns" => Ok(View::Dns),
            _ => Err(HostError::Source(format!("capture(): view {s:?}: views are packets, flows, dns"))),
        }
    }
    pub fn numeric(self) -> &'static [&'static str] {
        match self {
            View::Packets => PACKET_NUMERIC,
            View::Flows => FLOW_NUMERIC,
            View::Dns => DNS_NUMERIC,
        }
    }
}

// --- reading: big-endian fields, bounds-checked --------------------------------------------------------------------

fn u8_at(b: &[u8], i: usize) -> Option<u8> {
    b.get(i).copied()
}
fn u16_at(b: &[u8], i: usize) -> Option<u16> {
    Some(u16::from_be_bytes(b.get(i..i + 2)?.try_into().ok()?))
}
fn u32_at(b: &[u8], i: usize) -> Option<u32> {
    Some(u32::from_be_bytes(b.get(i..i + 4)?.try_into().ok()?))
}

// --- pcap -----------------------------------------------------------------------------------------------------------

/// A record: its time (seconds), its length on the wire, the bytes captured (at most the snaplen).
pub struct Frame {
    pub ts: f64,
    pub orig_len: u32,
    pub data: Vec<u8>,
}

/// The classic pcap format (tcpdump `-w`): a 24-byte header, then records of a 16-byte header and the bytes.
pub struct PcapReader<R: Read> {
    r: R,
    swap: bool,
    nanos: bool,
    pub linktype: u32,
}

impl<R: Read> PcapReader<R> {
    pub fn new(mut r: R) -> Result<Self, String> {
        let mut h = [0u8; 24];
        r.read_exact(&mut h).map_err(|e| format!("pcap header: {e}"))?;
        let magic = u32::from_le_bytes(h[0..4].try_into().unwrap());
        let (swap, nanos) = match magic {
            0xa1b2c3d4 => (false, false),
            0xa1b23c4d => (false, true),
            0xd4c3b2a1 => (true, false),
            0x4d3cb2a1 => (true, true),
            0x0a0d0d0a => return Err("pcapng is not read: capture with tcpdump -w (classic pcap)".into()),
            _ => return Err(format!("not a pcap stream (magic {magic:#010x})")),
        };
        let word = |i: usize| {
            let w = u32::from_le_bytes(h[i..i + 4].try_into().unwrap());
            if swap { w.swap_bytes() } else { w }
        };
        Ok(PcapReader { r, swap, nanos, linktype: word(20) & 0x0fff_ffff })
    }

    /// The next record; None at the end of the stream (a record cut short by the end is the end too).
    pub fn next_frame(&mut self) -> Option<Result<Frame, String>> {
        let mut h = [0u8; 16];
        if self.r.read_exact(&mut h).is_err() {
            return None;
        }
        let word = |i: usize| {
            let w = u32::from_le_bytes(h[i..i + 4].try_into().unwrap());
            if self.swap { w.swap_bytes() } else { w }
        };
        let (sec, frac, caplen, orig_len) = (word(0), word(4), word(8), word(12));
        if caplen > MAX_FRAME {
            return Some(Err(format!("a record of {caplen} bytes: the stream is corrupt")));
        }
        let mut data = vec![0u8; caplen as usize];
        if self.r.read_exact(&mut data).is_err() {
            return None;
        }
        let ts = sec as f64 + frac as f64 / if self.nanos { 1e9 } else { 1e6 };
        Some(Ok(Frame { ts, orig_len: orig_len.max(caplen), data }))
    }
}

// --- decoding -------------------------------------------------------------------------------------------------------

#[derive(Debug, Clone, Copy)]
pub struct Tcp {
    pub seq: u32,
    pub ack: u32,
    pub flags: u8,
    pub win: u16,
}

const FIN: u8 = 0x01;
const SYN: u8 = 0x02;
const RST: u8 = 0x04;
const PSH: u8 = 0x08;
const ACK: u8 = 0x10;
const URG: u8 = 0x20;
const ECE: u8 = 0x40;
const CWR: u8 = 0x80;

/// tcpdump's notation: S F R P U E W, and `.` for ACK ("S." is a SYN-ACK).
pub fn flag_letters(f: u8) -> String {
    let mut s = String::new();
    for (bit, c) in [(SYN, 'S'), (FIN, 'F'), (RST, 'R'), (PSH, 'P'), (URG, 'U'), (ECE, 'E'), (CWR, 'W')] {
        if f & bit != 0 {
            s.push(c);
        }
    }
    if f & ACK != 0 {
        s.push('.');
    }
    if s.is_empty() { "none".into() } else { s }
}

/// An ICMP error's quoted packet: the flow it is about.
#[derive(Debug, Clone, Copy)]
pub struct Quoted {
    pub proto: u8,
    pub src: IpAddr,
    pub dst: IpAddr,
    pub sport: u16,
    pub dport: u16,
}

#[derive(Debug)]
pub struct Packet<'a> {
    pub ts: f64,
    /// From the cooked header's packet type: "in", "out", "broadcast", "multicast", "other_host"; None on Ethernet.
    pub dir: Option<&'static str>,
    pub ifindex: Option<u32>,
    pub len: u32,
    pub proto: u8,
    pub src: IpAddr,
    pub dst: IpAddr,
    pub sport: u16,
    pub dport: u16,
    pub tcp: Option<Tcp>,
    pub icmp: Option<(u8, u8)>,
    pub quoted: Option<Quoted>,
    /// The payload's length by the headers, whatever the snaplen kept.
    pub payload_len: u32,
    /// The payload bytes captured (at most the snaplen's share).
    pub payload: &'a [u8],
    /// Captured bytes are fewer than the headers say.
    pub truncated: bool,
}

/// Why a frame gave no packet: counted in the answer.
#[derive(Debug, PartialEq)]
pub enum Skip {
    /// Not IP (ARP, LLDP...): its ethertype.
    NotIp(u16),
    /// A fragment after the first: no transport header.
    Fragment,
    /// Headers cut short or inconsistent.
    Malformed,
    /// A link type not read here.
    Link(u32),
}

const ETH_IPV4: u16 = 0x0800;
const ETH_IPV6: u16 = 0x86dd;

fn direction(pkttype: u16) -> &'static str {
    match pkttype {
        0 => "in",
        1 => "broadcast",
        2 => "multicast",
        3 => "other_host",
        4 => "out",
        _ => "unknown",
    }
}

/// Link layer: (direction, interface index, ethertype, the network layer's bytes).
fn link(linktype: u32, d: &[u8]) -> Result<(Option<&'static str>, Option<u32>, u16, &[u8]), Skip> {
    match linktype {
        1 => {
            let mut et = u16_at(d, 12).ok_or(Skip::Malformed)?;
            let mut off = 14;
            for _ in 0..2 {
                if et == 0x8100 || et == 0x88a8 {
                    et = u16_at(d, off + 2).ok_or(Skip::Malformed)?;
                    off += 4;
                }
            }
            Ok((None, None, et, d.get(off..).ok_or(Skip::Malformed)?))
        }
        113 => {
            let pt = u16_at(d, 0).ok_or(Skip::Malformed)?;
            let et = u16_at(d, 14).ok_or(Skip::Malformed)?;
            Ok((Some(direction(pt)), None, et, d.get(16..).ok_or(Skip::Malformed)?))
        }
        276 => {
            let et = u16_at(d, 0).ok_or(Skip::Malformed)?;
            let ifindex = u32_at(d, 4).ok_or(Skip::Malformed)?;
            let pt = u8_at(d, 10).ok_or(Skip::Malformed)? as u16;
            Ok((Some(direction(pt)), Some(ifindex), et, d.get(20..).ok_or(Skip::Malformed)?))
        }
        101 | 12 | 14 => match d.first().map(|b| b >> 4) {
            Some(4) => Ok((None, None, ETH_IPV4, d)),
            Some(6) => Ok((None, None, ETH_IPV6, d)),
            _ => Err(Skip::Malformed),
        },
        other => Err(Skip::Link(other)),
    }
}

/// The network layer: (protocol, source, destination, the transport bytes captured, the transport's length by the
/// headers, a later fragment).
fn network(et: u16, d: &[u8]) -> Result<(u8, IpAddr, IpAddr, &[u8], u32, bool), Skip> {
    match et {
        ETH_IPV4 => {
            let vihl = u8_at(d, 0).ok_or(Skip::Malformed)?;
            let ihl = ((vihl & 0x0f) as usize) * 4;
            if vihl >> 4 != 4 || ihl < 20 {
                return Err(Skip::Malformed);
            }
            let total = u16_at(d, 2).ok_or(Skip::Malformed)? as usize;
            let frag = u16_at(d, 6).ok_or(Skip::Malformed)? & 0x1fff;
            let proto = u8_at(d, 9).ok_or(Skip::Malformed)?;
            let src = Ipv4Addr::from(u32_at(d, 12).ok_or(Skip::Malformed)?);
            let dst = Ipv4Addr::from(u32_at(d, 16).ok_or(Skip::Malformed)?);
            // total 0: TSO's segments as captured on the way out may carry it; the frame's own length then counts
            let l4_len = if total >= ihl { total - ihl } else { d.len().saturating_sub(ihl) };
            let l4 = d.get(ihl..).ok_or(Skip::Malformed)?;
            Ok((proto, src.into(), dst.into(), l4, l4_len as u32, frag != 0))
        }
        ETH_IPV6 => {
            if u8_at(d, 0).ok_or(Skip::Malformed)? >> 4 != 6 {
                return Err(Skip::Malformed);
            }
            let plen = u16_at(d, 4).ok_or(Skip::Malformed)? as usize;
            let mut next = u8_at(d, 6).ok_or(Skip::Malformed)?;
            let src: [u8; 16] = d.get(8..24).ok_or(Skip::Malformed)?.try_into().unwrap();
            let dst: [u8; 16] = d.get(24..40).ok_or(Skip::Malformed)?.try_into().unwrap();
            let mut off = 40;
            let mut later_fragment = false;
            for _ in 0..8 {
                match next {
                    0 | 43 | 60 => {
                        let n = u8_at(d, off).ok_or(Skip::Malformed)?;
                        let l = (u8_at(d, off + 1).ok_or(Skip::Malformed)? as usize + 1) * 8;
                        next = n;
                        off += l;
                    }
                    44 => {
                        let n = u8_at(d, off).ok_or(Skip::Malformed)?;
                        later_fragment = u16_at(d, off + 2).ok_or(Skip::Malformed)? >> 3 != 0;
                        next = n;
                        off += 8;
                    }
                    51 => {
                        let n = u8_at(d, off).ok_or(Skip::Malformed)?;
                        let l = (u8_at(d, off + 1).ok_or(Skip::Malformed)? as usize + 2) * 4;
                        next = n;
                        off += l;
                    }
                    _ => break,
                }
            }
            let l4 = d.get(off..).ok_or(Skip::Malformed)?;
            let l4_len = (40 + plen).saturating_sub(off) as u32;
            Ok((next, Ipv6Addr::from(src).into(), Ipv6Addr::from(dst).into(), l4, l4_len, later_fragment))
        }
        other => Err(Skip::NotIp(other)),
    }
}

/// The flow an ICMP error quotes: the inner IP header and the first 8 bytes of its transport header.
fn quoted(inner: &[u8], v6: bool) -> Option<Quoted> {
    let et = if v6 { ETH_IPV6 } else { ETH_IPV4 };
    let (proto, src, dst, l4, _, _) = network(et, inner).ok()?;
    let (sport, dport) = match proto {
        6 | 17 => (u16_at(l4, 0)?, u16_at(l4, 2)?),
        _ => (0, 0),
    };
    Some(Quoted { proto, src, dst, sport, dport })
}

pub fn decode<'a>(linktype: u32, f: &'a Frame) -> Result<Packet<'a>, Skip> {
    let (dir, ifindex, et, l3) = link(linktype, &f.data)?;
    let (proto, src, dst, l4, l4_len, later_fragment) = network(et, l3)?;
    if later_fragment {
        return Err(Skip::Fragment);
    }
    let mut p = Packet { ts: f.ts, dir, ifindex, len: f.orig_len, proto, src, dst, sport: 0, dport: 0, tcp: None,
                         icmp: None, quoted: None, payload_len: 0, payload: &[], truncated: false };
    let hdr = match proto {
        6 => {
            let off = ((u8_at(l4, 12).ok_or(Skip::Malformed)? >> 4) as usize) * 4;
            if off < 20 {
                return Err(Skip::Malformed);
            }
            p.sport = u16_at(l4, 0).ok_or(Skip::Malformed)?;
            p.dport = u16_at(l4, 2).ok_or(Skip::Malformed)?;
            p.tcp = Some(Tcp {
                seq: u32_at(l4, 4).ok_or(Skip::Malformed)?,
                ack: u32_at(l4, 8).ok_or(Skip::Malformed)?,
                flags: u8_at(l4, 13).ok_or(Skip::Malformed)?,
                win: u16_at(l4, 14).ok_or(Skip::Malformed)?,
            });
            off
        }
        17 => {
            p.sport = u16_at(l4, 0).ok_or(Skip::Malformed)?;
            p.dport = u16_at(l4, 2).ok_or(Skip::Malformed)?;
            8
        }
        1 | 58 => {
            let (t, c) = (u8_at(l4, 0).ok_or(Skip::Malformed)?, u8_at(l4, 1).ok_or(Skip::Malformed)?);
            p.icmp = Some((t, c));
            // errors quoting a packet: v4 unreachable 3, time exceeded 11; v6 unreachable 1, too big 2, time exceeded 3
            let error = if proto == 1 { matches!(t, 3 | 11) } else { matches!(t, 1 | 2 | 3) };
            if error {
                p.quoted = l4.get(8..).and_then(|inner| quoted(inner, proto == 58));
            }
            8
        }
        _ => 0,
    };
    p.payload_len = l4_len.saturating_sub(hdr as u32);
    p.payload = l4.get(hdr..).unwrap_or(&[]);
    if (p.payload.len() as u32) < p.payload_len || l4.len() < hdr {
        p.truncated = true;
        p.payload = &p.payload[..p.payload.len().min(p.payload_len as usize)];
    }
    Ok(p)
}

pub fn proto_name(p: u8) -> String {
    match p {
        1 => "icmp".into(),
        6 => "tcp".into(),
        17 => "udp".into(),
        58 => "icmp6".into(),
        n => format!("ip{n}"),
    }
}

/// Milliseconds to the microsecond.
fn ms(s: f64) -> f64 {
    (s * 1e6).round() / 1e3
}

/// Seconds to the millisecond: an event's time from the capture's start.
fn secs(s: f64) -> f64 {
    (s * 1e3).round() / 1e3
}

// --- packets --------------------------------------------------------------------------------------------------------

fn packet_event(p: &Packet, t0: f64) -> Map<String, Value> {
    let mut m = Map::new();
    m.insert("t".into(), json!(secs(p.ts - t0)));
    m.insert("proto".into(), json!(proto_name(p.proto)));
    m.insert("src".into(), json!(p.src.to_string()));
    m.insert("dst".into(), json!(p.dst.to_string()));
    if matches!(p.proto, 6 | 17) {
        m.insert("sport".into(), json!(p.sport));
        m.insert("dport".into(), json!(p.dport));
    }
    if let Some(t) = p.tcp {
        m.insert("flags".into(), json!(flag_letters(t.flags)));
        m.insert("win".into(), json!(t.win));
    }
    if let Some((t, c)) = p.icmp {
        m.insert("icmp".into(), json!(format!("{t}/{c}")));
    }
    if let Some(d) = p.dir {
        m.insert("dir".into(), json!(d));
    }
    if let Some(i) = p.ifindex {
        m.insert("ifindex".into(), json!(i));
    }
    m.insert("len".into(), json!(p.len));
    m.insert("payload".into(), json!(p.payload_len));
    m
}

// --- flows ----------------------------------------------------------------------------------------------------------

#[derive(Default)]
struct Side {
    packets: u64,
    bytes: u64,
    syn: u64,
    rst: u64,
    fin: u64,
    retrans: u64,
    zero_win: u64,
    max_seg: u32,
    /// The highest sequence number sent so far plus its length.
    next_seq: Option<u32>,
}

struct Flow {
    /// The client's side (address, port), as far as it can be told.
    client: (IpAddr, u16),
    server: (IpAddr, u16),
    proto: u8,
    /// How the client was told: "syn" (it sent the SYN), "port" (a guess: the higher port is the client's).
    orient: &'static str,
    c2s: Side,
    s2c: Side,
    synack: u64,
    syn_ts: Option<f64>,
    synack_ts: Option<f64>,
    first: f64,
    last: f64,
    icmp_errors: u64,
}

type FlowKey = (u8, IpAddr, u16, IpAddr, u16);

fn flow_key(proto: u8, a: (IpAddr, u16), b: (IpAddr, u16)) -> FlowKey {
    let (x, y) = if a <= b { (a, b) } else { (b, a) };
    (proto, x.0, x.1, y.0, y.1)
}

fn update_side(s: &mut Side, p: &Packet) {
    s.packets += 1;
    s.bytes += p.payload_len as u64;
    s.max_seg = s.max_seg.max(p.payload_len);
    let Some(t) = p.tcp else { return };
    if t.flags & SYN != 0 && t.flags & ACK == 0 {
        s.syn += 1;
    }
    if t.flags & RST != 0 {
        s.rst += 1;
    }
    if t.flags & FIN != 0 {
        s.fin += 1;
    }
    if t.win == 0 && t.flags & (SYN | RST) == 0 {
        s.zero_win += 1;
    }
    // A segment with data ending at or before what this side already sent is a retransmission (or arrived out of
    // order: a capture cannot tell them apart without timing).
    if p.payload_len > 0 {
        let end = t.seq.wrapping_add(p.payload_len);
        match s.next_seq {
            Some(n) if (n.wrapping_sub(end) as i32) >= 0 => s.retrans += 1,
            _ => s.next_seq = Some(end),
        }
    } else if t.flags & (SYN | FIN) != 0 {
        let end = t.seq.wrapping_add(1);
        if s.next_seq.is_none_or(|n| (end.wrapping_sub(n) as i32) > 0) {
            s.next_seq = Some(end);
        }
    }
}

fn flow_event(f: &Flow, t0: f64) -> Map<String, Value> {
    let mut m = Map::new();
    m.insert("t".into(), json!(secs(f.first - t0)));
    m.insert("proto".into(), json!(proto_name(f.proto)));
    m.insert("client".into(), json!(f.client.0.to_string()));
    m.insert("cport".into(), json!(f.client.1));
    m.insert("server".into(), json!(f.server.0.to_string()));
    m.insert("port".into(), json!(f.server.1));
    m.insert("orient".into(), json!(f.orient));
    m.insert("packets".into(), json!(f.c2s.packets + f.s2c.packets));
    m.insert("pkts_c2s".into(), json!(f.c2s.packets));
    m.insert("pkts_s2c".into(), json!(f.s2c.packets));
    m.insert("bytes_c2s".into(), json!(f.c2s.bytes));
    m.insert("bytes_s2c".into(), json!(f.s2c.bytes));
    m.insert("duration_ms".into(), json!(ms(f.last - f.first)));
    m.insert("icmp_errors".into(), json!(f.icmp_errors));
    if f.proto == 6 {
        m.insert("syn".into(), json!(f.c2s.syn));
        m.insert("syn_retrans".into(), json!(f.c2s.syn.saturating_sub(1)));
        m.insert("synack".into(), json!(f.synack));
        m.insert("rst".into(), json!(f.c2s.rst + f.s2c.rst));
        m.insert("rst_by".into(), json!(match (f.c2s.rst > 0, f.s2c.rst > 0) {
            (true, true) => "both", (true, false) => "client", (false, true) => "server", _ => "",
        }));
        m.insert("fin".into(), json!(f.c2s.fin + f.s2c.fin));
        m.insert("retrans_c2s".into(), json!(f.c2s.retrans));
        m.insert("retrans_s2c".into(), json!(f.s2c.retrans));
        m.insert("zero_win".into(), json!(f.c2s.zero_win + f.s2c.zero_win));
        m.insert("max_seg_c2s".into(), json!(f.c2s.max_seg));
        m.insert("max_seg_s2c".into(), json!(f.s2c.max_seg));
        if let (Some(a), Some(b)) = (f.syn_ts, f.synack_ts) {
            m.insert("handshake_ms".into(), json!(ms(b - a)));
        }
        let state = if f.c2s.rst + f.s2c.rst > 0 {
            "reset"
        } else if f.c2s.syn > 0 && f.synack == 0 {
            "syn_unanswered"
        } else if f.c2s.fin > 0 && f.s2c.fin > 0 {
            "closed"
        } else if f.c2s.syn == 0 && f.synack == 0 {
            "mid" // began before the capture
        } else {
            "open"
        };
        m.insert("state".into(), json!(state));
    }
    m
}

// --- dns ------------------------------------------------------------------------------------------------------------

pub fn qtype_name(t: u16) -> String {
    match t {
        1 => "A".into(), 2 => "NS".into(), 5 => "CNAME".into(), 6 => "SOA".into(), 12 => "PTR".into(),
        15 => "MX".into(), 16 => "TXT".into(), 28 => "AAAA".into(), 33 => "SRV".into(), 64 => "SVCB".into(),
        65 => "HTTPS".into(), 255 => "ANY".into(),
        n => format!("TYPE{n}"),
    }
}

pub fn rcode_name(r: u8) -> String {
    match r {
        0 => "NOERROR".into(), 1 => "FORMERR".into(), 2 => "SERVFAIL".into(), 3 => "NXDOMAIN".into(),
        4 => "NOTIMP".into(), 5 => "REFUSED".into(),
        n => format!("RCODE{n}"),
    }
}

/// A DNS message's header and first question: (id, response, rcode, truncated, answers, name, type).
pub struct Dns {
    pub id: u16,
    pub response: bool,
    pub rcode: u8,
    pub tc: bool,
    pub answers: u16,
    pub qname: String,
    pub qtype: u16,
}

/// A name in DNS's label format, lowercased, bytes outside printable ASCII escaped as \DDD. Compression pointers are
/// followed, at most 16 of them, so a loop ends.
fn dns_name(msg: &[u8], mut i: usize) -> Option<(String, usize)> {
    let mut out = String::new();
    let mut end = None;
    let mut jumps = 0;
    loop {
        let l = u8_at(msg, i)? as usize;
        if l == 0 {
            return Some((if out.is_empty() { ".".into() } else { out }, end.unwrap_or(i + 1)));
        }
        if l & 0xc0 == 0xc0 {
            jumps += 1;
            if jumps > 16 {
                return None;
            }
            end.get_or_insert(i + 2);
            i = (u16_at(msg, i)? & 0x3fff) as usize;
            continue;
        }
        if l > 63 {
            return None;
        }
        let label = msg.get(i + 1..i + 1 + l)?;
        if !out.is_empty() {
            out.push('.');
        }
        for &b in label {
            match b {
                b'A'..=b'Z' => out.push((b + 32) as char),
                0x21..=0x7e if b != b'.' && b != b'\\' => out.push(b as char),
                _ => out.push_str(&format!("\\{b:03}")),
            }
        }
        if out.len() > 255 {
            return None;
        }
        i += 1 + l;
    }
}

pub fn parse_dns(msg: &[u8]) -> Option<Dns> {
    let id = u16_at(msg, 0)?;
    let flags = u16_at(msg, 2)?;
    if u16_at(msg, 4)? == 0 {
        return None;
    }
    let (qname, end) = dns_name(msg, 12)?;
    Some(Dns {
        id,
        response: flags & 0x8000 != 0,
        rcode: (flags & 0x000f) as u8,
        tc: flags & 0x0200 != 0,
        answers: u16_at(msg, 6)?,
        qname,
        qtype: u16_at(msg, end)?,
    })
}

struct Query {
    first: f64,
    sends: u64,
    qname: String,
    qtype: u16,
}

type QueryKey = (IpAddr, u16, IpAddr, u16);

fn dns_event(q: &Query, client: IpAddr, server: IpAddr, t0: f64) -> Map<String, Value> {
    let mut m = Map::new();
    m.insert("t".into(), json!(secs(q.first - t0)));
    m.insert("qname".into(), json!(q.qname));
    m.insert("qtype".into(), json!(qtype_name(q.qtype)));
    m.insert("client".into(), json!(client.to_string()));
    m.insert("server".into(), json!(server.to_string()));
    m.insert("sends".into(), json!(q.sends));
    m
}

// --- the reduction --------------------------------------------------------------------------------------------------

#[derive(Default)]
struct Counts {
    frames: u64,
    packets: u64,
    not_ip: HashMap<u16, u64>,
    fragments: u64,
    malformed: u64,
    truncated: u64,
    over_1514: u64,
    largest: u32,
    untracked: u64,
    dns_unparsed: u64,
    dns_unmatched: u64,
}

pub struct Capture {
    view: View,
    reducer: Reducer,
    counts: Counts,
    t0: Option<f64>,
    t_last: f64,
    flows: HashMap<FlowKey, Flow>,
    queries: HashMap<QueryKey, Query>,
}

impl Capture {
    pub fn new(view: View, o: &TraceOptions) -> HostResult<Capture> {
        Ok(Capture { view, reducer: Reducer::new(o, view.numeric())?, counts: Counts::default(), t0: None,
                     t_last: 0.0, flows: HashMap::new(), queries: HashMap::new() })
    }

    pub fn frame(&mut self, linktype: u32, f: &Frame) {
        self.counts.frames += 1;
        let t0 = *self.t0.get_or_insert(f.ts);
        self.t_last = self.t_last.max(f.ts);
        self.counts.largest = self.counts.largest.max(f.orig_len);
        if f.orig_len > 1514 {
            self.counts.over_1514 += 1;
        }
        let p = match decode(linktype, f) {
            Ok(p) => p,
            Err(Skip::NotIp(et)) => {
                *self.counts.not_ip.entry(et).or_default() += 1;
                return;
            }
            Err(Skip::Fragment) => {
                self.counts.fragments += 1;
                return;
            }
            Err(Skip::Malformed) | Err(Skip::Link(_)) => {
                self.counts.malformed += 1;
                return;
            }
        };
        self.counts.packets += 1;
        if p.truncated {
            self.counts.truncated += 1;
        }
        match self.view {
            View::Packets => self.reducer.event(packet_event(&p, t0)),
            View::Flows => self.flow(&p),
            View::Dns => self.dns(&p, t0),
        }
    }

    fn flow(&mut self, p: &Packet) {
        if let Some(q) = p.quoted {
            let k = flow_key(q.proto, (q.src, q.sport), (q.dst, q.dport));
            if let Some(f) = self.flows.get_mut(&k) {
                f.icmp_errors += 1;
            }
        }
        let a = (p.src, p.sport);
        let b = (p.dst, p.dport);
        let k = flow_key(p.proto, a, b);
        if !self.flows.contains_key(&k) {
            if self.flows.len() >= MAX_FLOWS {
                self.counts.untracked += 1;
                return;
            }
            let syn = p.tcp.is_some_and(|t| t.flags & SYN != 0 && t.flags & ACK == 0);
            let synack = p.tcp.is_some_and(|t| t.flags & (SYN | ACK) == SYN | ACK);
            let (client, server, orient) = if syn {
                (a, b, "syn")
            } else if synack {
                (b, a, "syn")
            } else if a.1 >= b.1 {
                (a, b, "port")
            } else {
                (b, a, "port")
            };
            self.flows.insert(k, Flow { client, server, proto: p.proto, orient, c2s: Side::default(),
                                        s2c: Side::default(), synack: 0, syn_ts: None, synack_ts: None,
                                        first: p.ts, last: p.ts, icmp_errors: 0 });
        }
        let f = self.flows.get_mut(&k).expect("inserted");
        f.last = f.last.max(p.ts);
        let from_client = a == f.client;
        if let Some(t) = p.tcp {
            if t.flags & SYN != 0 && t.flags & ACK == 0 && from_client {
                f.orient = "syn";
                f.syn_ts.get_or_insert(p.ts);
            }
            if t.flags & (SYN | ACK) == SYN | ACK && !from_client {
                f.synack += 1;
                f.synack_ts.get_or_insert(p.ts);
            }
        }
        update_side(if from_client { &mut f.c2s } else { &mut f.s2c }, p);
    }

    fn dns(&mut self, p: &Packet, t0: f64) {
        if p.proto != 17 || (p.sport != 53 && p.dport != 53) {
            return;
        }
        let Some(m) = parse_dns(p.payload) else {
            self.counts.dns_unparsed += 1;
            return;
        };
        if !m.response {
            let k = (p.src, p.sport, p.dst, m.id);
            if let Some(q) = self.queries.get_mut(&k) {
                q.sends += 1;
            } else if self.queries.len() >= MAX_FLOWS {
                self.counts.untracked += 1;
            } else {
                self.queries.insert(k, Query { first: p.ts, sends: 1, qname: m.qname, qtype: m.qtype });
            }
            return;
        }
        let k = (p.dst, p.dport, p.src, m.id);
        let Some(q) = self.queries.remove(&k) else {
            self.counts.dns_unmatched += 1;
            return;
        };
        let mut ev = dns_event(&q, p.dst, p.src, t0);
        ev.insert("rcode".into(), json!(rcode_name(m.rcode)));
        ev.insert("latency_ms".into(), json!(ms(p.ts - q.first)));
        ev.insert("answers".into(), json!(m.answers));
        if m.tc {
            ev.insert("tc".into(), json!(true));
        }
        self.reducer.event(ev);
    }

    /// The answer. `seconds`: the capture's length as asked; None: the span of the frames seen.
    pub fn finish(mut self, seconds: Option<f64>) -> Value {
        let t0 = self.t0.unwrap_or(0.0);
        let span = self.t_last - t0;
        let end = seconds.map_or(self.t_last, |s| t0 + s);
        let flows = self.flows.len();
        let mut pending: Vec<(f64, Map<String, Value>)> = Vec::new();
        for f in std::mem::take(&mut self.flows).into_values() {
            pending.push((f.first, flow_event(&f, t0)));
        }
        for ((client, _, server, _), q) in std::mem::take(&mut self.queries) {
            let mut ev = dns_event(&q, client, server, t0);
            let status = if end - q.first < IN_FLIGHT_S { "in_flight" } else { "no_answer" };
            ev.insert("rcode".into(), json!(status));
            pending.push((q.first, ev));
        }
        // in time order, so a group's examples are its first events
        pending.sort_by(|a, b| a.0.total_cmp(&b.0));
        for (_, ev) in pending {
            self.reducer.event(ev);
        }
        let seconds = seconds.unwrap_or(span).max(0.001);
        let mut out = self.reducer.finish(seconds);
        let c = &self.counts;
        let mut not_ip: Vec<(String, u64)> = c.not_ip.iter().map(|(et, n)| (match et {
            0x0806 => "arp".to_string(), 0x88cc => "lldp".to_string(), e => format!("{e:#06x}"),
        }, *n)).collect();
        not_ip.sort();
        let not_ip: Map<String, Value> = not_ip.into_iter().map(|(k, n)| (k, json!(n))).collect();
        let mut cap = json!({
            "view": match self.view { View::Packets => "packets", View::Flows => "flows", View::Dns => "dns" },
            "seconds": (seconds * 1000.0).round() / 1000.0,
            "frames": c.frames,
            "packets": c.packets,
            "not_ip": not_ip,
            "fragments": c.fragments,
            "malformed": c.malformed,
            "truncated": c.truncated,
            "largest": c.largest,
            "over_1514": c.over_1514,
        });
        let m = cap.as_object_mut().unwrap();
        match self.view {
            View::Flows => {
                m.insert("flows".into(), json!(flows));
                m.insert("untracked_packets".into(), json!(c.untracked));
            }
            View::Dns => {
                m.insert("unparsed".into(), json!(c.dns_unparsed));
                m.insert("responses_unmatched".into(), json!(c.dns_unmatched));
                m.insert("untracked_queries".into(), json!(c.untracked));
            }
            View::Packets => {}
        }
        out.as_object_mut().unwrap().insert("capture".into(), cap);
        out
    }
}

/// Reduces a whole pcap stream (`beat-probe pcap`, and the sensor's stream once the broker exists).
pub fn reduce(r: impl Read, view: View, o: &TraceOptions, seconds: Option<f64>) -> HostResult<Value> {
    let mut pr = PcapReader::new(r).map_err(HostError::Source)?;
    let mut c = Capture::new(view, o)?;
    let linktype = pr.linktype;
    let mut error = None;
    while let Some(f) = pr.next_frame() {
        match f {
            Ok(f) => c.frame(linktype, &f),
            Err(e) => {
                error = Some(e);
                break;
            }
        }
    }
    let mut out = c.finish(seconds);
    out["capture"]["linktype"] = json!(linktype);
    if let Some(e) = error {
        out["capture"]["stopped"] = json!(e);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Builds pcap streams: Ethernet frames of IPv4 packets.
    struct Pcap(Vec<u8>);

    impl Pcap {
        fn new(linktype: u32) -> Pcap {
            let mut v = Vec::new();
            v.extend(0xa1b2c3d4u32.to_le_bytes());
            v.extend(2u16.to_le_bytes());
            v.extend(4u16.to_le_bytes());
            v.extend([0u8; 8]);
            v.extend(65535u32.to_le_bytes());
            v.extend(linktype.to_le_bytes());
            Pcap(v)
        }
        fn record(&mut self, ts: f64, data: &[u8], orig: usize) {
            self.0.extend((ts as u32).to_le_bytes());
            self.0.extend((((ts.fract()) * 1e6).round() as u32).to_le_bytes());
            self.0.extend((data.len() as u32).to_le_bytes());
            self.0.extend((orig as u32).to_le_bytes());
            self.0.extend(data);
        }
    }

    fn ip4(src: [u8; 4], dst: [u8; 4], proto: u8, l4: &[u8], l4_len: usize) -> Vec<u8> {
        let mut v = vec![0x45, 0, 0, 0, 0, 0, 0x40, 0, 64, proto, 0, 0];
        v[2..4].copy_from_slice(&((20 + l4_len) as u16).to_be_bytes());
        v.extend(src);
        v.extend(dst);
        v.extend(l4);
        v
    }

    fn eth(ip: &[u8]) -> Vec<u8> {
        let mut v = vec![0u8; 12];
        v.extend(ETH_IPV4.to_be_bytes());
        v.extend(ip);
        v
    }

    fn tcp(sport: u16, dport: u16, seq: u32, ack: u32, flags: u8, win: u16, payload: usize) -> (Vec<u8>, usize) {
        let mut v = Vec::new();
        v.extend(sport.to_be_bytes());
        v.extend(dport.to_be_bytes());
        v.extend(seq.to_be_bytes());
        v.extend(ack.to_be_bytes());
        v.extend([0x50, flags]);
        v.extend(win.to_be_bytes());
        v.extend([0u8; 4]);
        let len = v.len() + payload;
        (v, len)
    }

    const C: [u8; 4] = [10, 0, 0, 1];
    const S: [u8; 4] = [10, 0, 0, 2];

    fn seg(p: &mut Pcap, ts: f64, from_client: bool, seq: u32, ack: u32, flags: u8, payload: usize) {
        let (sp, dp, a, b) = if from_client { (40000, 5432, C, S) } else { (5432, 40000, S, C) };
        let (t, len) = tcp(sp, dp, seq, ack, flags, 65000, payload);
        let frame = eth(&ip4(a, b, 6, &t, len));
        // a short snaplen: headers only, the payload's length from the IP header
        p.record(ts, &frame, frame.len() + payload);
    }

    fn opts(key: &[&str]) -> TraceOptions {
        TraceOptions { key: key.iter().map(|s| s.to_string()).collect(), top: 20, examples: 1, ..Default::default() }
    }

    #[test]
    fn flows_handshake_and_mtu_blackhole() {
        let mut p = Pcap::new(1);
        seg(&mut p, 100.000, true, 1000, 0, SYN, 0);
        seg(&mut p, 100.002, false, 5000, 1001, SYN | ACK, 0);
        seg(&mut p, 100.003, true, 1001, 5001, ACK, 0);
        seg(&mut p, 100.004, true, 1001, 5001, PSH | ACK, 100); // the query
        seg(&mut p, 100.010, false, 5001, 1101, ACK, 200); // a small reply arrives
        // a large reply: the same full-size segment again and again, never acknowledged
        for i in 0..4 {
            seg(&mut p, 100.2 + 0.2 * (1u32 << i) as f64, false, 5201, 1101, ACK, 1448);
        }
        let v = reduce(&p.0[..], View::Flows, &opts(&["server", "port", "state"]), None).unwrap();
        let g = &v["groups"][0];
        assert_eq!(g["key"], json!({"server": "10.0.0.2", "port": "5432", "state": "open"}));
        let f = &g["examples"][0];
        assert_eq!(f["client"], "10.0.0.1");
        assert_eq!(f["orient"], "syn");
        assert_eq!(f["handshake_ms"], 2.0);
        assert_eq!(f["retrans_s2c"], 3);
        assert_eq!(f["retrans_c2s"], 0);
        assert_eq!(f["max_seg_s2c"], 1448);
        assert_eq!(f["icmp_errors"], 0);
        assert_eq!(v["capture"]["packets"], 9);
        assert_eq!(v["capture"]["truncated"], 6, "the snaplen cut the payloads");
    }

    #[test]
    fn syn_retransmits_and_unanswered() {
        let mut p = Pcap::new(1);
        // a listen queue full: SYNs at 0, 1 and 3 s, answered the third time
        seg(&mut p, 10.0, true, 1000, 0, SYN, 0);
        seg(&mut p, 11.0, true, 1000, 0, SYN, 0);
        seg(&mut p, 13.0, true, 1000, 0, SYN, 0);
        seg(&mut p, 13.001, false, 7000, 1001, SYN | ACK, 0);
        let mut o = opts(&["state"]);
        o.hist = Some("handshake_ms".into());
        let v = reduce(&p.0[..], View::Flows, &o, None).unwrap();
        let f = &v["groups"][0]["examples"][0];
        assert_eq!(f["syn"], 3);
        assert_eq!(f["syn_retrans"], 2);
        assert_eq!(f["handshake_ms"], 3001.0, "from the first SYN: what the client waited");
        assert_eq!(f["retrans_c2s"], 0, "a SYN again is counted as syn_retrans, not as data");
    }

    #[test]
    fn icmp_error_attributed_to_its_flow() {
        let mut p = Pcap::new(1);
        seg(&mut p, 1.0, true, 1000, 0, SYN, 0);
        seg(&mut p, 1.001, false, 5000, 1001, SYN | ACK, 0);
        // frag needed (3/4) from a router, quoting the server's packet to the client
        let (t, len) = tcp(5432, 40000, 5001, 1001, ACK, 65000, 0);
        let inner = ip4(S, C, 6, &t[..8], len);
        let mut icmp = vec![3, 4, 0, 0, 0, 0, 0x05, 0xdc];
        icmp.extend(&inner);
        let frame = eth(&ip4([10, 0, 0, 254], S, 1, &icmp, icmp.len()));
        p.record(1.5, &frame, frame.len());
        let v = reduce(&p.0[..], View::Flows, &opts(&["proto"]), None).unwrap();
        let tcp_group = v["groups"].as_array().unwrap().iter().find(|g| g["key"]["proto"] == "tcp").unwrap();
        assert_eq!(tcp_group["examples"][0]["icmp_errors"], 1);
        let pk = reduce(&p.0[..], View::Packets, &opts(&["proto", "icmp"]), None).unwrap();
        assert!(pk["groups"].as_array().unwrap().iter().any(|g| g["key"]["icmp"] == "3/4"));
    }

    fn dns_msg(id: u16, response: bool, rcode: u8, name: &str, qtype: u16, answers: u16) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend(id.to_be_bytes());
        let flags: u16 = if response { 0x8180 | rcode as u16 } else { 0x0100 };
        v.extend(flags.to_be_bytes());
        v.extend(1u16.to_be_bytes());
        v.extend(answers.to_be_bytes());
        v.extend([0, 0, 0, 0]);
        for l in name.split('.') {
            v.push(l.len() as u8);
            v.extend(l.as_bytes());
        }
        v.push(0);
        v.extend(qtype.to_be_bytes());
        v.extend(1u16.to_be_bytes());
        v
    }

    fn udp(p: &mut Pcap, ts: f64, src: [u8; 4], sport: u16, dst: [u8; 4], dport: u16, payload: &[u8]) {
        let mut u = Vec::new();
        u.extend(sport.to_be_bytes());
        u.extend(dport.to_be_bytes());
        u.extend(((8 + payload.len()) as u16).to_be_bytes());
        u.extend([0, 0]);
        u.extend(payload);
        let frame = eth(&ip4(src, dst, 17, &u, u.len()));
        p.record(ts, &frame, frame.len());
    }

    #[test]
    fn dns_aaaa_blackhole() {
        let r = [10, 0, 0, 53];
        let mut p = Pcap::new(1);
        // glibc's parallel A and AAAA: A answered in 1 ms, AAAA never; after 5 s it asks AAAA again
        udp(&mut p, 0.0, C, 41000, r, 53, &dns_msg(7, false, 0, "DB.internal", 1, 0));
        udp(&mut p, 0.0, C, 41000, r, 53, &dns_msg(8, false, 0, "db.internal", 28, 0));
        udp(&mut p, 0.001, r, 53, C, 41000, &dns_msg(7, true, 0, "db.internal", 1, 1));
        udp(&mut p, 5.0, C, 41000, r, 53, &dns_msg(8, false, 0, "db.internal", 28, 0));
        udp(&mut p, 5.2, C, 41001, r, 53, &dns_msg(9, false, 0, "other.internal", 1, 0)); // in flight at the end
        udp(&mut p, 5.3, r, 53, C, 41002, &dns_msg(99, true, 3, "x.internal", 1, 0)); // matches nothing
        let mut o = opts(&["qtype", "rcode"]);
        o.hist = Some("latency_ms".into());
        let v = reduce(&p.0[..], View::Dns, &o, Some(6.0)).unwrap();
        let g = v["groups"].as_array().unwrap();
        let find = |t: &str, r: &str| g.iter().find(|x| x["key"]["qtype"] == t && x["key"]["rcode"] == r).unwrap();
        let a = find("A", "NOERROR");
        assert_eq!(a["examples"][0]["qname"], "db.internal", "lowercased");
        assert_eq!(a["examples"][0]["latency_ms"], 1.0);
        assert_eq!(find("AAAA", "no_answer")["examples"][0]["sends"], 2);
        assert_eq!(find("A", "in_flight")["count"], 1);
        assert_eq!(v["capture"]["responses_unmatched"], 1);
    }

    #[test]
    fn dns_names_hostile() {
        // a compression loop: the name points at itself
        let mut m = dns_msg(1, false, 0, "a", 1, 0);
        m.truncate(12);
        m.extend([0xc0, 12, 0, 1, 0, 1]);
        assert!(parse_dns(&m).is_none());
        let mut m = dns_msg(1, false, 0, "a", 1, 0);
        m[13] = b'\n';
        assert_eq!(parse_dns(&m).unwrap().qname, "\\010");
        assert!(parse_dns(&[0u8; 5]).is_none());
    }

    #[test]
    fn hostile_frames_do_not_panic() {
        // every prefix of real frames, and garbage, decodes or is skipped
        let (t, len) = tcp(1, 2, 3, 4, SYN, 5, 0);
        let frame = eth(&ip4(C, S, 6, &t, len));
        for lt in [1, 113, 276, 101, 999] {
            for n in 0..frame.len() {
                let f = Frame { ts: 0.0, orig_len: n as u32, data: frame[..n].to_vec() };
                let _ = decode(lt, &f);
            }
        }
        let mut junk = Pcap::new(1);
        junk.record(0.0, &[0xff; 60], 60);
        let v = reduce(&junk.0[..], View::Packets, &opts(&[]), None).unwrap();
        assert_eq!(v["capture"]["frames"], 1);
        assert!(reduce(&b"not a pcap at all......."[..], View::Packets, &opts(&[]), None).is_err());
    }

    /// Recorded on beat-dev's loopback (tcpdump -s 128, in each link type): two HTTP requests to a local server,
    /// DNS through the local stub (A, AAAA, NXDOMAIN), a connect to a closed port.
    #[test]
    fn recorded_loopback() {
        let files: [(&[u8], u32); 3] = [
            (include_bytes!("../tests/pcap/loopback-lo.pcap"), 1),
            (include_bytes!("../tests/pcap/loopback-sll.pcap"), 113),
            (include_bytes!("../tests/pcap/loopback-sll2.pcap"), 276),
        ];
        for (bytes, linktype) in files {
            let v = reduce(bytes, View::Flows, &opts(&["port", "state"]), None).unwrap();
            assert_eq!(v["capture"]["linktype"], linktype);
            assert_eq!(v["capture"]["malformed"], 0);
            let g = v["groups"].as_array().unwrap();
            let find = |port: &str| g.iter().find(|x| x["key"]["port"] == port).unwrap();
            assert_eq!(find("18080")["key"]["state"], "closed");
            assert_eq!(find("18080")["count"], 2);
            assert_eq!(find("18099")["key"]["state"], "reset");
            assert_eq!(find("18099")["examples"][0]["rst_by"], "server");
            let d = reduce(bytes, View::Dns, &opts(&["qtype", "rcode"]), None).unwrap();
            let rc: Vec<String> = d["groups"].as_array().unwrap().iter()
                .map(|x| format!("{}/{}", x["key"]["qtype"].as_str().unwrap(), x["key"]["rcode"].as_str().unwrap())).collect();
            assert!(rc.contains(&"AAAA/NOERROR".into()) && rc.contains(&"A/NXDOMAIN".into()), "{rc:?}");
        }
    }

    fn recorded(name: &str) -> Vec<u8> {
        std::fs::read(format!("{}/tests/pcap/{name}.pcap", env!("CARGO_MANIFEST_DIR"))).unwrap()
    }

    fn tcp_flows(v: &Value) -> Vec<Value> {
        v["groups"].as_array().unwrap().iter().filter(|g| g["key"]["proto"] == "tcp")
            .flat_map(|g| g["examples"].as_array().unwrap().clone()).collect()
    }

    /// The scenarios' faults as the kernel made them (tests/pcap/record/record.sh).
    #[test]
    fn recorded_faults() {
        let all = |n: usize| TraceOptions { examples: n, ..opts(&["proto", "port", "state"]) };
        // MTU blackhole: the big response's flow stays open, retransmits, and no ICMP ever names it
        let v = reduce(&recorded("mtu-blackhole")[..], View::Flows, &all(10), None).unwrap();
        let f = tcp_flows(&v);
        let stuck = f.iter().find(|e| e["state"] == "open").expect("the big response's flow");
        assert!(stuck["retrans_s2c"].as_u64().unwrap() >= 3, "{stuck}");
        assert_eq!(stuck["icmp_errors"], 0);
        assert!(f.iter().any(|e| e["state"] == "closed" && e["retrans_s2c"] == 0), "the small one completes");
        // with ICMP allowed: frag-needed attributed to the flow, and it completes
        let v = reduce(&recorded("mtu-control")[..], View::Flows, &all(10), None).unwrap();
        assert!(tcp_flows(&v).iter().any(|e| e["state"] == "closed" && e["icmp_errors"].as_u64().unwrap() >= 1));
        // loss: retransmits seen from the client; GRO's merged segments flagged
        let v = reduce(&recorded("loss")[..], View::Flows, &TraceOptions { sum: vec!["retrans_s2c".into()], ..all(0) }, None).unwrap();
        assert!(v["groups"][0]["sum"]["retrans_s2c"].as_f64().unwrap() >= 1.0);
        assert!(v["capture"]["over_1514"].as_u64().unwrap() > 0);
        // listen queue: connects beyond the backlog get no SYN-ACK, their SYNs retried
        let v = reduce(&recorded("listen-queue")[..], View::Flows, &all(10), None).unwrap();
        let f = tcp_flows(&v);
        let unanswered: Vec<_> = f.iter().filter(|e| e["state"] == "syn_unanswered").collect();
        assert!(!unanswered.is_empty() && unanswered.iter().all(|e| e["syn_retrans"].as_u64().unwrap() >= 2));
        assert!(f.iter().any(|e| e["synack"] == 1), "the backlog's own connects are answered");
        // AAAA blackhole: A answered, AAAA never, asked again
        let v = reduce(&recorded("aaaa-blackhole")[..], View::Dns, &opts(&["qtype", "rcode"]), None).unwrap();
        let g = v["groups"].as_array().unwrap();
        assert!(g.iter().any(|x| x["key"] == json!({"qtype": "A", "rcode": "NOERROR"})));
        let aaaa = g.iter().find(|x| x["key"] == json!({"qtype": "AAAA", "rcode": "no_answer"})).unwrap();
        assert!(aaaa["examples"][0]["sends"].as_u64().unwrap() >= 2);
    }

    #[test]
    fn flags() {
        assert_eq!(flag_letters(SYN), "S");
        assert_eq!(flag_letters(SYN | ACK), "S.");
        assert_eq!(flag_letters(PSH | ACK), "P.");
        assert_eq!(flag_letters(RST), "R");
        assert_eq!(flag_letters(0), "none");
    }
}
