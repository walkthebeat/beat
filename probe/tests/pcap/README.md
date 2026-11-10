# Recorded captures

Fixtures for `src/capture.rs`'s tests and for `beat-probe pcap`. Snaplen 128: headers and a DNS question, no
application payload beyond a few bytes (the HTTP bodies are random bytes).

- `loopback-{lo,sll,sll2}.pcap`: beat-dev's loopback in the three link types tcpdump writes (`-i lo`; `-i any -y
  LINUX_SLL`; `-i any -y LINUX_SLL2`): two HTTP requests to a local server, DNS through the stub resolver (A, AAAA,
  NXDOMAIN), a connect to a closed port. Port 22 filtered out.
- The scenarios' faults, made by `record/record.sh OUTDIR` (as root) in three network namespaces,
  `cli 10.99.1.2 -- rtr -- srv 10.99.2.2`, on veth links; nothing touches the host's interfaces, and the script
  removes what it made (namespaces, `/etc/netns/bc-cli`, `/tmp/bc-www`):
  - `mtu-blackhole.pcap` (the server's side): the router's link to the client has MTU 1400 and the router drops
    ICMP frag-needed; a small response arrives, a 300 KB one never does.
  - `mtu-control.pcap`: the same with ICMP allowed: two frag-needed from the router, the transfer completes.
  - `loss.pcap` (the client's side): netem loss 3% on the server's egress, five 300 KB downloads.
  - `listen-queue.pcap` (the client's side): a server with backlog 1 that never accepts; six connects.
  - `aaaa-blackhole.pcap` (the client's side): a resolver that answers A and drops AAAA; `getent ahosts` (6 s).

What the real kernel showed that synthetic frames did not:
- A narrow link next to an endpoint is no blackhole: the endpoint's MSS follows its own MTU. The narrow hop must be
  in the path (here the router's side of the link only).
- Offloads: on the sending side tcpdump sees TSO's segments (up to 64 KB, before the NIC cuts them), on the
  receiving side GRO's merged ones. `max_seg_*` is the size handed down, not the wire's; `over_1514` says it
  happened. On a receiver, a retransmitted segment merged with new data is not counted as a retransmit.
