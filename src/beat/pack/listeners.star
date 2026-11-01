"""Listening sockets with their owning process and unit, and established TCP connections coarsened to
(process, remote port) for outbound ones and (process, local port) for inbound ones.

Applies to: any Linux host with a beat sensor.
Assumes: osquery listening_ports / process_open_sockets see the host's network namespace (the sensor's own
  namespace holds only lo; osquery reads per-process sockets, so host sockets do show).
Cannot see: UDP "connections" (connectionless), short-lived connections between runs (use trace("tcpconnect")),
  hostnames of remote IPs (no reverse lookup). Remote IPs of cloud endpoints (SSM) rotate: expect drift there.
beat's default pack (first written by Claude in a discovery, 2026-10-31; reviewed).
"""

LISTEN_SQL = """select distinct p.name, l.address, l.port, l.protocol, p.cgroup_path
                from listening_ports l join processes p using (pid)
                where l.port != 0 and l.protocol in (6, 17) and p.cgroup_path not like '%beat-question-%'"""
ESTAB_SQL = """select p.name, s.local_port, s.remote_address, s.remote_port, p.cgroup_path
               from process_open_sockets s join processes p using (pid)
               where s.state = 'ESTABLISHED' and s.family in (2, 10) and p.cgroup_path not like '%beat-question-%'"""
PROTO = {6: "tcp", 17: "udp"}

def unit_of(cg):
    # /system.slice/ssh.service -> ssh.service; session scopes generalised
    parts = [x for x in (cg or "").split("/") if x]
    if not parts:
        return "-"
    return re_sub(r"session-[0-9]+\.scope", "session-N.scope", parts[-1])

def main():
    # listeners: one record set per protocol/address/port
    ls = osq(LISTEN_SQL)
    expect(len(ls) > 0, "no listening sockets visible (namespace?)")
    listen_ports = {}
    for r in ls:
        proto = PROTO[r["protocol"]]
        listen_ports[(proto, r["port"])] = 1
        s = "listen:%s/%s/%d" % (proto, r["address"], r["port"])
        emit(s, "process", r["name"], "osq.listening_ports", kind = "semantic")
        emit(s, "unit", unit_of(r["cgroup_path"]), "osq.processes.cgroup_path", kind = "semantic")
    # established: inbound if the local port is one we listen on, else outbound
    inbound = {}
    outbound = {}
    remotes = {}
    for r in osq(ESTAB_SQL):
        if ("tcp", r["local_port"]) in listen_ports:
            k = "%s:%d" % (r["name"], r["local_port"])
            inbound[k] = inbound.get(k, 0) + 1
        else:
            k = "%s:%d" % (r["name"], r["remote_port"])
            outbound[k] = outbound.get(k, 0) + 1
            remotes["%s|%s" % (k, r["remote_address"])] = 1
    emit("tcp", "inbound_established_count", str(sum(inbound.values())), "osq.process_open_sockets", kind = "metric")
    emit("tcp", "outbound_established_count", str(sum(outbound.values())), "osq.process_open_sockets", kind = "metric")
    for k, n in inbound.items():
        emit("inbound:" + k, "established_count", str(n), "osq.process_open_sockets", kind = "metric")
    for k, n in outbound.items():
        emit("outbound:" + k, "established_count", str(n), "osq.process_open_sockets", kind = "metric")
    for kr in remotes.keys():
        k, _, ip = kr.partition("|")
        emit("outbound:" + k, "remote_address", ip, "osq.process_open_sockets", kind = "semantic")
