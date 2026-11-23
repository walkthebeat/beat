"""Kubernetes, on a node: the pods this question was asked about (beat ask --cluster C --selector S), as the node sees
them. For each one running here: its cgroup's CPU throttling, memory (current, limit, peak, OOM kills), pressure
(PSI), and per container its processes (pid, name, state, threads, RSS) and its log files (how many the kubelet kept:
the current one and the one before a restart). A pod the cluster placed on this node but whose cgroup is not here is
reported as not found (it moved, or ended, since it was selected).

Applies to: node sensors (<cluster>_<node>), asked with --cluster and --selector; asked by host it has no pods and
  answers nothing.
Assumes: cgroup v2; the kubelet's systemd driver (kubepods-...-pod<uid with _>.slice) or its cgroupfs driver
  (pod<uid>); a container's cgroup named by its id; logs under /var/log/pods/<namespace>_<name>_<uid>/<container>/.
  This node's name is its hostname (the kubelet's default).
Cannot see: command lines (left out until a value from a Secret on one is hashed on nodes); what is in the logs (ask
  log_summary of the paths it gives); why the API thinks what it does (ask the cluster sensor). Pod names carry a
  generated suffix: compare replicas by their owner record, not by name.
beat's default pack (first written by Claude, 2026-11-23).
"""

SRC = "k8s.node"
CPU = ("nr_periods", "nr_throttled", "throttled_usec", "usage_usec")
MEMORY_EVENTS = ("oom", "oom_kill", "max", "high")

# A file's text, "" when it is missing (a process gone, PSI off: RHEL 9 boots without it): read() of a missing file
# is a failure, which would end the probe.
def text(path):
    return read(path) if stat(path) else ""

def first_line(path):
    return text(path).split("\n")[0].strip()

def fields(path):
    out = {}
    for line in text(path).split("\n"):
        parts = line.split(" ")
        if len(parts) == 2:
            out[parts[0]] = parts[1]
    return out

def pod_cgroup(uid):
    found = glob("/sys/fs/cgroup/kubepods*/**/*pod" + uid.replace("-", "_") + ".slice")
    if not found:
        found = glob("/sys/fs/cgroup/kubepods*/**/pod" + uid)
    return found[0] if found else None

def pressure(s, cg):
    for res in ("cpu", "memory", "io"):
        for line in text(cg + "/" + res + ".pressure").split("\n"):
            if line.startswith("some "):
                emit(s, res + ".pressure.some_avg10", line.split(" ")[1].split("=")[1], SRC, kind="metric")

def resources(s, cg):
    cpu = fields(cg + "/cpu.stat")
    for k in CPU:
        if k in cpu:
            emit(s, "cpu." + k, cpu[k], SRC, kind="metric")
    for k in ("cpu.max", "memory.max"):
        if stat(cg + "/" + k):
            emit(s, k, first_line(cg + "/" + k), SRC)
    for k in ("memory.current", "memory.peak"):
        if stat(cg + "/" + k):
            emit(s, k, first_line(cg + "/" + k), SRC, kind="metric")
    ev = fields(cg + "/memory.events")
    for k in MEMORY_EVENTS:
        if k in ev:
            emit(s, "memory.events." + k, ev[k], SRC, kind="metric")

def processes(s, cg):
    pids = [p for p in text(cg + "/cgroup.procs").split("\n") if p]
    emit(s, "processes", str(len(pids)), SRC, kind="metric")
    for pid in pids:
        st = fields_colon("/proc/" + pid + "/status")
        if not st:
            continue  # exited since the cgroup was read
        p = s + " pid " + pid
        emit(p, "name", st.get("Name", ""), SRC)
        emit(p, "state", st.get("State", ""), SRC)
        emit(p, "threads", st.get("Threads", ""), SRC, kind="metric")
        emit(p, "rss", st.get("VmRSS", ""), SRC, kind="metric")

def fields_colon(path):
    out = {}
    for line in text(path).split("\n"):
        k, sep, v = line.partition(":")
        if sep:
            out[k] = v.strip()
    return out

def logs(s, pod, container):
    d = "/var/log/pods/%s_%s_%s/%s" % (pod["namespace"], pod["name"], pod["uid"], container)
    files = [f for f in list_dir(d) if f.endswith(".log")] if stat(d) else []
    emit(s, "log.files", str(len(files)), SRC, kind="metric")
    for f in files:
        st = stat(d + "/" + f)
        emit(s + " log " + f, "path", d + "/" + f, SRC, kind="identity")
        emit(s + " log " + f, "size", str(st.size), SRC, kind="metric")
        emit(s + " log " + f, "mtime", iso_utc(st.mtime), SRC, kind="time")

def main():
    me = first_line("/proc/sys/kernel/hostname")
    for pod in subjects():
        s = "pod %s/%s" % (pod["namespace"], pod["name"])
        cg = pod_cgroup(pod["uid"])
        if not cg:
            if pod.get("node") == me:
                emit(s, "here", "not found: no cgroup for uid " + pod["uid"], SRC)
            continue
        emit(s, "here", "yes", SRC)
        emit(s, "uid", pod["uid"], SRC, kind="identity")
        emit(s, "owner", pod.get("owner") or "", SRC)
        emit(s, "cgroup", cg, SRC, kind="identity")
        resources(s, cg)
        pressure(s, cg)
        for c in pod.get("containers") or []:
            cs = s + " container " + c["name"]
            found = glob(cg + "/*" + c["id"] + "*") if c.get("id") else []
            if not found:
                emit(cs, "running", "no", SRC)
                logs(cs, pod, c["name"])
                continue
            emit(cs, "running", "yes", SRC)
            resources(cs, found[0])
            processes(cs, found[0])
            logs(cs, pod, c["name"])
