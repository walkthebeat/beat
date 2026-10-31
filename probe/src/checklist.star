"""Gregg's 60-second checklist over `sample()` (docs/probes.md §4.3): the USE method's numbers for one interval.

uptime, vmstat, mpstat, pidstat, iostat, free, sar -n DEV and sar -n TCP,ETCP all read counters in /proc; this reads
the same counters twice, `seconds` apart, and returns rates and percentages, plus pressure stall information (PSI)
and cgroup CPU throttling, which the classic checklist predates. top is the procs table; dmesg is
journal(kernel=True), summarized with log_summary.
Network counters are PID 1's (/proc/1/net): a question runs in a private network namespace, where /proc/net shows
only its own loopback. A source this kernel lacks (PSI before 4.20, cgroup v1) leaves its part empty, with a note.
"""

_CL_FILES = [
    "/proc/stat", "/proc/loadavg", "/proc/meminfo", "/proc/vmstat",
    "/proc/pressure/cpu", "/proc/pressure/memory", "/proc/pressure/io",
    "/proc/diskstats", "/proc/1/net/dev", "/proc/1/net/snmp", "/proc/1/net/netstat",
    "/proc/[0-9]*/stat", "/proc/sys/kernel/hostname",
]

def _cl_r(x: float) -> float:
    """One decimal."""
    return int(x * 10 + (0.5 if x >= 0 else -0.5)) / 10.0

def _cl_num(x: typing.Any) -> str:
    """Plain digits for whole numbers (2048, not 2048.0), as records want them."""
    if type(x) == "float" and x == int(x):
        return str(int(x))
    return str(x)

def _cl_kv(text: str) -> dict[str, int]:
    """'Key: 123 kB' or 'key 123' lines."""
    out = {}
    for line in text.splitlines():
        f = line.replace(":", " ").split()
        if len(f) >= 2 and f[1].isdigit():
            out[f[0]] = int(f[1])
    return out

def _cl_table(text: str) -> dict[str, dict[str, int]]:
    """/proc/net/snmp and netstat: a header line and a value line per protocol."""
    out = {}
    lines = text.splitlines()
    for i in range(0, len(lines) - 1, 2):
        names = lines[i].split()
        values = lines[i + 1].split()
        if len(names) == len(values) and names and names[0] == values[0]:
            out[names[0].rstrip(":")] = {n: int(v) for n, v in zip(names[1:], values[1:]) if v.lstrip("-").isdigit()}
    return out

def _cl_cpu_lines(text: str) -> dict[str, list[int]]:
    return {f[0]: [int(x) for x in f[1:9]] for f in [l.split() for l in text.splitlines()] if f and f[0].startswith("cpu")}

def _cl_cpu(b: list[int], a: list[int]) -> dict[str, float]:
    """user nice system idle iowait irq softirq steal (guest is inside user)."""
    d = [a[i] - b[i] for i in range(8)]
    t = 0
    for x in d:
        t += x
    t = max(t, 1)
    idle = d[3] * 100.0 / t
    iowait = d[4] * 100.0 / t
    return {
        "usr": _cl_r((d[0] + d[1]) * 100.0 / t), "sys": _cl_r((d[2] + d[5] + d[6]) * 100.0 / t),
        "iowait": _cl_r(iowait), "steal": _cl_r(d[7] * 100.0 / t), "idle": _cl_r(idle),
        "busy": _cl_r(100.0 - idle - iowait),
    }

def _cl_psi(b: str, a: str, seconds: float) -> dict[str, float]:
    """Share of the interval in which some (or all: full) runnable tasks stalled on the resource."""
    def totals(text):
        return {f[0]: int(f[-1].split("=")[1]) for f in [l.split() for l in text.splitlines()] if f and f[-1].startswith("total=")}
    tb, ta = totals(b), totals(a)
    return {k: _cl_r((ta[k] - tb[k]) / 1e6 / seconds * 100) for k in ta if k in tb}

def _cl_procs(before: dict[str, str], after: dict[str, str], seconds: float, hz: float, me: str, top: int) -> tuple:
    """Per command (pidstat, top): processes, CPU % in all and of the busiest and idlest of them, R and D states,
    major faults. Grouped by command so that subjects compare across hosts; max and min show one rank of many."""
    def parse(text):
        i = text.rfind(")")
        rest = text[i + 2:].split()
        return text[text.find("(") + 1:i], rest
    groups = {}
    gone = 0
    for path, text in before.items():
        if not path.endswith("/stat") or not path.startswith("/proc/") or path.count("/") != 3:
            continue
        pid = path.split("/")[2]
        if pid == me:
            continue
        if path not in after:
            gone += 1
            continue
        comm, rb = parse(text)
        _, ra = parse(after[path])
        if len(ra) < 18 or ra[1] == me:
            continue
        cpu = ((int(ra[11]) + int(ra[12])) - (int(rb[11]) + int(rb[12]))) / hz / seconds * 100
        g = groups.setdefault(comm, {"command": comm, "procs": 0, "cpu_pct": 0.0, "cpu_max_pct": 0.0, "cpu_min_pct": 1e9,
                                     "running": 0, "blocked": 0, "threads": 0, "majflt_per_s": 0.0})
        g["procs"] += 1
        g["cpu_pct"] += cpu
        g["cpu_max_pct"] = max(g["cpu_max_pct"], cpu)
        g["cpu_min_pct"] = min(g["cpu_min_pct"], cpu)
        g["running"] += 1 if ra[0] == "R" else 0
        g["blocked"] += 1 if ra[0] == "D" else 0
        g["threads"] += int(ra[17])
        g["majflt_per_s"] += (int(ra[9]) - int(rb[9])) / seconds
    rows = []
    for g in groups.values():
        rows.append({k: (_cl_r(v) if type(v) == "float" else v) for k, v in g.items()})
    rows = sorted(rows, key = lambda g: (-g["cpu_pct"], -g["blocked"], g["command"]))
    shown = rows[:top] + [g for g in rows[top:] if g["blocked"] > 0][:top]
    return shown, len(rows), gone

def _cl_cgroup_name(path: str, host: str) -> str:
    """A cgroup's path, comparable across hosts: the host's own name as <SELF> (Slurm's
    <node>_slurmstepd.scope), job and step ids as <N>."""
    name = path[len("/sys/fs/cgroup"):-len("/cpu.stat")] or "/"
    if host:
        name = name.replace(host, "<SELF>")
    return re_sub(r"\b(job|step|task)_[0-9]+", "${1}_<N>", name)

def _cl_cgroups(s: typing.Any, top: int) -> list[dict[str, typing.Any]]:
    """cgroup v2 cpu.stat: CPU used, time throttled (a quota reached), and the quota (cpu.max), busiest first."""
    host = s.after.get("/proc/sys/kernel/hostname", "").strip()
    rows = []
    for path, text in s.after.items():
        if not path.endswith("/cpu.stat") or path not in s.before:
            continue
        b, a = _cl_kv(s.before[path]), _cl_kv(text)
        if "usage_usec" not in a:
            continue
        used = (a["usage_usec"] - b["usage_usec"]) / 1e6 / s.seconds * 100
        thr = (a.get("throttled_usec", 0) - b.get("throttled_usec", 0)) / 1e6 / s.seconds * 100
        periods = a.get("nr_periods", 0) - b.get("nr_periods", 0)
        nthr = a.get("nr_throttled", 0) - b.get("nr_throttled", 0)
        if used < 0.5 and nthr == 0:
            continue
        quota = s.after.get(path[:-len("cpu.stat")] + "cpu.max", "max").split()
        rows.append({
            "cgroup": _cl_cgroup_name(path, host),
            "cpu_pct": _cl_r(used), "throttled_pct": _cl_r(thr),
            "throttled_periods_pct": _cl_r(nthr * 100.0 / periods) if periods > 0 else 0.0,
            "quota_cpus": _cl_r(int(quota[0]) / int(quota[1])) if len(quota) == 2 and quota[0] != "max" else None,
        })
    return sorted(rows, key = lambda r: (-r["throttled_pct"], -r["cpu_pct"], r["cgroup"]))[:top]

def checklist(seconds: int | float = 5, top: int = 10, cgroup_depth: int = 4) -> dict[str, typing.Any]:
    """The checklist for one interval of `seconds`: {"seconds", "use", "load", "cpu", "cpus", "memory", "psi",
    "disks", "nics", "tcp", "procs", "cgroups", "notes"}.
    "use" is the USE method's reading, one row per resource: {resource, utilization, saturation, errors}, as text.
    The other parts are the numbers, rates per second and percentages of the interval:
      cpu, cpus[]: usr sys iowait steal idle busy (%), per CPU too; load: load1 load5 load15 runnable cpus
      ctxt_per_s intr_per_s forks_per_s (new processes: short-lived ones show here, not in procs) procs_running
      procs_blocked
      memory: total_mb available_mb used_pct swap_used_mb dirty_mb swapin_per_s swapout_per_s majflt_per_s
      pgscan_per_s oom_kills
      psi: cpu_some memory_some memory_full io_some io_full (% of the interval stalled)
      disks[] (whole disks with I/O in the interval, as iostat -xz): r_per_s w_per_s rkb_per_s wkb_per_s r_await_ms
      w_await_ms queue_len util_pct
      nics[] (with traffic): rx_kb_per_s tx_kb_per_s rx_pkt_per_s tx_pkt_per_s rx_errs tx_errs rx_drop tx_drop
      tcp: active_opens_per_s passive_opens_per_s retrans_per_s retrans_pct curr_estab in_errs out_rsts_per_s
      listen_drops timeouts udp_in_errors udp_rcvbuf_errors (counts are over the interval)
      procs[] (the `top` busiest commands, and any with a process in D state): command procs cpu_pct cpu_max_pct
      cpu_min_pct running blocked threads majflt_per_s
      cgroups[] (cgroup v2, `cgroup_depth` levels, the `top` most throttled then busiest; the host's name in a path as
      <SELF>, job and step ids as <N>, so paths compare across hosts): cgroup cpu_pct
      throttled_pct throttled_periods_pct quota_cpus
    The question's own process is left out."""
    if seconds < 1 or seconds > 30:
        fail("checklist: seconds must be 1 to 30")
    cg = ["/sys/fs/cgroup" + "/*" * d + "/cpu.stat" for d in range(1, cgroup_depth + 1)]
    cg += ["/sys/fs/cgroup" + "/*" * d + "/cpu.max" for d in range(1, cgroup_depth + 1)]
    s = sample(_CL_FILES + cg, seconds = seconds)
    b, a, t = s.before, s.after, s.seconds
    notes = []
    me = readlink("/proc/self") or ""

    # CPU (mpstat, vmstat) and load (uptime)
    cb, ca = _cl_cpu_lines(b.get("/proc/stat", "")), _cl_cpu_lines(a.get("/proc/stat", ""))
    if "cpu" not in ca:
        fail("checklist: /proc/stat is not readable here")
    cpus = [dict(cpu = int(k[3:]), **_cl_cpu(cb[k], ca[k])) for k in sorted(ca, key = lambda k: (len(k), k)) if k != "cpu" and k in cb]
    ncpu = max(len(cpus), 1)
    total = 0
    for i in range(8):
        total += ca["cpu"][i] - cb["cpu"][i]
    hz = max(total / ncpu / t, 1.0)
    sb, sa = _cl_kv(b["/proc/stat"]), _cl_kv(a["/proc/stat"])
    la = a.get("/proc/loadavg", "0 0 0 0/0 0").split()
    ld = {
        "load1": float(la[0]), "load5": float(la[1]), "load15": float(la[2]),
        "runnable": int(la[3].split("/")[0]), "cpus": ncpu,
        "ctxt_per_s": _cl_r((sa.get("ctxt", 0) - sb.get("ctxt", 0)) / t),
        "intr_per_s": _cl_r((sa.get("intr", 0) - sb.get("intr", 0)) / t),
        "forks_per_s": _cl_r((sa.get("processes", 0) - sb.get("processes", 0)) / t),
        "procs_running": sa.get("procs_running", 0), "procs_blocked": sa.get("procs_blocked", 0),
    }
    cpu = _cl_cpu(cb["cpu"], ca["cpu"])
    busy = [c["busy"] for c in cpus] or [0.0]

    # memory (free, vmstat)
    m = _cl_kv(a.get("/proc/meminfo", ""))
    vb, va = _cl_kv(b.get("/proc/vmstat", "")), _cl_kv(a.get("/proc/vmstat", ""))
    def vrate(key):
        return _cl_r((va.get(key, 0) - vb.get(key, 0)) / t)
    scan = 0
    for k in va:
        if k.startswith("pgscan_"):
            scan += va[k] - vb.get(k, 0)
    memory = {
        "total_mb": m.get("MemTotal", 0) // 1024, "available_mb": m.get("MemAvailable", 0) // 1024,
        "used_pct": _cl_r(100.0 - m.get("MemAvailable", 0) * 100.0 / max(m.get("MemTotal", 1), 1)),
        "swap_used_mb": (m.get("SwapTotal", 0) - m.get("SwapFree", 0)) // 1024, "dirty_mb": m.get("Dirty", 0) // 1024,
        "swapin_per_s": vrate("pswpin"), "swapout_per_s": vrate("pswpout"), "majflt_per_s": vrate("pgmajfault"),
        "pgscan_per_s": _cl_r(scan / t), "oom_kills": va.get("oom_kill", 0) - vb.get("oom_kill", 0),
    }

    # pressure (PSI)
    psi = {}
    for r in ["cpu", "memory", "io"]:
        p = "/proc/pressure/" + r
        if p in a and p in b:
            for k, v in _cl_psi(b[p], a[p], t).items():
                if r != "cpu" or k == "some":
                    psi[r + "_" + k] = v
    if not psi:
        notes.append("no pressure stall information (/proc/pressure): kernel before 4.20, or psi=0")

    # disks (iostat -xz): whole disks only, as /sys/block lists them
    whole = [path_basename(p) for p in glob("/sys/block/*")]
    disks = []
    idle_disks = 0
    db = {f[2]: f for f in [l.split() for l in b.get("/proc/diskstats", "").splitlines()] if len(f) >= 14}
    for f in [l.split() for l in a.get("/proc/diskstats", "").splitlines()]:
        if len(f) < 14 or f[2] not in db or f[2] not in whole or f[2].startswith("loop") or f[2].startswith("ram"):
            continue
        d = [int(f[i]) - int(db[f[2]][i]) for i in range(3, 14)]
        reads, writes = d[0], d[4]
        if reads + writes == 0:
            idle_disks += 1
            continue
        disks.append({
            "disk": f[2], "r_per_s": _cl_r(reads / t), "w_per_s": _cl_r(writes / t),
            "rkb_per_s": _cl_r(d[2] / 2 / t), "wkb_per_s": _cl_r(d[6] / 2 / t),
            "r_await_ms": _cl_r(d[3] / reads) if reads else 0.0, "w_await_ms": _cl_r(d[7] / writes) if writes else 0.0,
            "queue_len": _cl_r(d[10] / 1000.0 / t), "util_pct": _cl_r(min(d[9] / 10.0 / t, 100.0)),
        })
    if idle_disks:
        notes.append("%d disks without I/O in the interval left out" % idle_disks)

    # network interfaces (sar -n DEV)
    def nets(text):
        out = {}
        for l in text.splitlines()[2:]:
            name, _, rest = l.partition(":")
            v = rest.split()
            if len(v) >= 16:
                out[name.strip()] = [int(x) for x in v]
        return out
    nb, na = nets(b.get("/proc/1/net/dev", "")), nets(a.get("/proc/1/net/dev", ""))
    nics = []
    for name in sorted(na):
        if name not in nb:
            continue
        d = [na[name][i] - nb[name][i] for i in range(16)]
        if d[1] + d[9] == 0:
            continue
        nics.append({
            "nic": name, "rx_kb_per_s": _cl_r(d[0] / 1024.0 / t), "tx_kb_per_s": _cl_r(d[8] / 1024.0 / t),
            "rx_pkt_per_s": _cl_r(d[1] / t), "tx_pkt_per_s": _cl_r(d[9] / t),
            "rx_errs": d[2], "tx_errs": d[10], "rx_drop": d[3], "tx_drop": d[11],
        })
    if "/proc/1/net/dev" not in a:
        notes.append("/proc/1/net is not readable: no network counters")

    # TCP and UDP (sar -n TCP,ETCP)
    pb, pa = _cl_table(b.get("/proc/1/net/snmp", "")), _cl_table(a.get("/proc/1/net/snmp", ""))
    xb, xa = _cl_table(b.get("/proc/1/net/netstat", "")), _cl_table(a.get("/proc/1/net/netstat", ""))
    def delta(tb, ta, proto, key):
        return ta.get(proto, {}).get(key, 0) - tb.get(proto, {}).get(key, 0)
    out_segs = delta(pb, pa, "Tcp", "OutSegs")
    retrans = delta(pb, pa, "Tcp", "RetransSegs")
    tcp = {
        "active_opens_per_s": _cl_r(delta(pb, pa, "Tcp", "ActiveOpens") / t),
        "passive_opens_per_s": _cl_r(delta(pb, pa, "Tcp", "PassiveOpens") / t),
        "retrans_per_s": _cl_r(retrans / t), "retrans_pct": _cl_r(retrans * 100.0 / out_segs) if out_segs > 0 else 0.0,
        "curr_estab": pa.get("Tcp", {}).get("CurrEstab", 0), "in_errs": delta(pb, pa, "Tcp", "InErrs"),
        "out_rsts_per_s": _cl_r(delta(pb, pa, "Tcp", "OutRsts") / t),
        "listen_drops": delta(xb, xa, "TcpExt", "ListenDrops"), "timeouts": delta(xb, xa, "TcpExt", "TCPTimeouts"),
        "udp_in_errors": delta(pb, pa, "Udp", "InErrors"), "udp_rcvbuf_errors": delta(pb, pa, "Udp", "RcvbufErrors"),
    }

    # processes (pidstat, top) and cgroups
    procs, ncomm, gone = _cl_procs(b, a, t, hz, me, top)
    if gone:
        notes.append("%d processes exited during the interval (their CPU is not counted)" % gone)
    if ncomm > len(procs):
        notes.append("%d of %d commands shown" % (len(procs), ncomm))
    cgroups = _cl_cgroups(s, top)
    if not glob("/sys/fs/cgroup/cgroup.controllers"):
        notes.append("not cgroup v2: no throttling figures")

    # the USE reading
    use = [{
        "resource": "cpu",
        "utilization": "busy %s%% (per CPU %s-%s%%), steal %s%%" % (cpu["busy"], min(busy), max(busy), cpu["steal"]),
        "saturation": "runnable %d on %d CPUs, load1 %s, psi some %s%%; %s forks/s" % (ld["runnable"], ncpu, ld["load1"], psi.get("cpu_some", "?"), ld["forks_per_s"]),
        "errors": "",
    }, {
        "resource": "memory",
        "utilization": "used %s%% of %d MB" % (memory["used_pct"], memory["total_mb"]),
        "saturation": "swap in/out %s/%s per s, scan %s pages/s, psi some %s%%" % (memory["swapin_per_s"], memory["swapout_per_s"], memory["pgscan_per_s"], psi.get("memory_some", "?")),
        "errors": "oom kills %d" % memory["oom_kills"],
    }]
    for d in disks:
        use.append({"resource": "disk:" + d["disk"], "utilization": "util %s%%" % d["util_pct"],
                    "saturation": "queue %s, await r %s w %s ms, psi io some %s%%" % (d["queue_len"], d["r_await_ms"], d["w_await_ms"], psi.get("io_some", "?")),
                    "errors": ""})
    for n in nics:
        use.append({"resource": "nic:" + n["nic"], "utilization": "rx %s tx %s KB/s" % (n["rx_kb_per_s"], n["tx_kb_per_s"]),
                    "saturation": "drops rx %d tx %d" % (n["rx_drop"], n["tx_drop"]),
                    "errors": "errors rx %d tx %d" % (n["rx_errs"], n["tx_errs"])})
    use.append({"resource": "tcp", "utilization": "%d established, %s active opens/s" % (tcp["curr_estab"], tcp["active_opens_per_s"]),
                "saturation": "listen drops %d" % tcp["listen_drops"],
                "errors": "retransmits %s/s (%s%% of segments), timeouts %d, resets out %s/s" % (tcp["retrans_per_s"], tcp["retrans_pct"], tcp["timeouts"], tcp["out_rsts_per_s"])})
    throttled = [c for c in cgroups if c["throttled_pct"] > 0]
    if throttled:
        use.append({"resource": "cgroups", "utilization": "",
                    "saturation": "throttled: " + ", ".join(["%s %s%%" % (c["cgroup"], c["throttled_pct"]) for c in throttled[:3]]),
                    "errors": ""})

    return {
        "seconds": _cl_r(t), "use": use, "load": ld, "cpu": cpu, "cpus": cpus, "memory": memory, "psi": psi,
        "disks": disks, "nics": nics, "tcp": tcp, "procs": procs, "cgroups": cgroups, "notes": notes,
    }

def emit_checklist(c: dict[str, typing.Any], source: str = "checklist") -> None:
    """Records for a checklist, every value a declared metric: subjects host (load), cpu, cpu:<n>, memory, psi,
    disk:<name>, nic:<name>, tcp, proc:<command>, cgroup:<path>; keys as in checklist(), with _pct, _per_s, _ms,
    _mb, _len, _cpus or _count (counts over the interval). The interval itself: host seconds."""
    def put(subject, row, skip):
        for k, v in row.items():
            if k in skip or v == None:
                continue
            key = k
            if not (k.startswith("load") or [x for x in ["_pct", "_per_s", "_ms", "_mb", "_len", "_cpus"] if k.endswith(x)]):
                key = k + ("_pct" if subject.startswith("cpu") or subject == "psi" else "_count")
            emit(subject, key, _cl_num(v), source, kind = "metric")
    emit("host", "seconds", _cl_num(c["seconds"]), source, kind = "metric")
    put("host", c["load"], [])
    put("cpu", c["cpu"], [])
    for x in c["cpus"]:
        put("cpu:%d" % x["cpu"], x, ["cpu"])
    put("memory", c["memory"], [])
    put("psi", c["psi"], [])
    for d in c["disks"]:
        put("disk:" + d["disk"], d, ["disk"])
    for n in c["nics"]:
        put("nic:" + n["nic"], n, ["nic"])
    put("tcp", c["tcp"], [])
    for p in c["procs"]:
        put("proc:" + p["command"], p, ["command"])
    for g in c["cgroups"]:
        put("cgroup:" + g["cgroup"], g, ["cgroup"])
