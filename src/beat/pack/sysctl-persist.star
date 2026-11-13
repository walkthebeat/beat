"""sysctl: persisted values (sysctl.d in systemd-sysctl order) vs live /proc/sys, plus a watchlist of live values
that are often tuned by hand (a live change with no persisted value is lost on reboot; drift between surveys shows it).

Applies to: any systemd Linux host.
Assumes: systemd-sysctl semantics: files from /usr/lib, /run, /etc sysctl.d (a name in /etc overrides the same
  name elsewhere), applied in file-name order, then /etc/sysctl.conf; later assignments win.
Cannot see: on a sensor whose questions run in a network namespace of their own (before 0.2.3), net.* live values of
  the host: /proc/sys/net (and osquery system_controls) show that namespace; they are then skipped and counted, never
  compared (net_keys_not_observable_count). Keys only root may read (mode 0600, e.g. vm.mmap_rnd_bits,
  net.core.bpf_jit_harden) when the question is not root, as since 0.2.3: sysctl checks the mode itself, and
  CAP_DAC_READ_SEARCH does not pass it; they are reported live_unreadable and counted (unreadable_count). Also values
  set by other tools at boot (tuned, cloud-init, kubelet), and glob keys (net.ipv4.conf.*.x).
beat's default pack (first written by Claude in a discovery, 2026-10-31; reviewed).
"""

DIRS = ["/usr/lib/sysctl.d", "/run/sysctl.d", "/etc/sysctl.d"]
NETNS_PREFIX = "net."        # per network namespace: the host's only when the question runs in the host's
WATCH = ["vm.swappiness", "vm.overcommit_memory", "vm.max_map_count", "vm.dirty_ratio",
         "fs.file-max", "fs.inotify.max_user_watches", "kernel.pid_max", "kernel.panic"]

def norm(v):
    return " ".join(v.split())

# the value each key gets at boot, and the file that sets it
def persisted():
    by_name = {}
    for d in DIRS:                       # later directories override earlier ones by file name
        for f in glob(d + "/*.conf"):
            by_name[path_basename(f)] = f
    files = [by_name[n] for n in sorted(by_name.keys())]
    if stat("/etc/sysctl.conf"):
        files.append("/etc/sysctl.conf")
    want = {}
    src = {}
    for f in files:
        for l in read(f).splitlines():
            l = l.strip()
            if not l or l[0] in "#;" or "=" not in l:
                continue
            k, _, v = l.partition("=")
            k = k.strip().lstrip("-").replace("/", ".")
            if "*" in k:
                continue
            want[k] = norm(v)
            src[k] = f
    return want, src

UNREADABLE = "(unreadable)"

# the live value, None if the kernel has no such key, or UNREADABLE if this question may not read it
def live(k, root):
    p = "/proc/sys/" + k.replace(".", "/")
    st = stat(p)
    if not st:
        return None
    if not root and int(st.mode, 8) & 4 == 0:   # sysctl's own check: a non-root reader needs the "other" read bit
        return UNREADABLE
    return norm(read(p))

def main():
    want, src = persisted()
    expect(len(want) > 0, "no persisted sysctls found")
    emit("sysctl", "persisted_count", str(len(want)), "sysctl.d", kind = "metric")
    differ = 0
    skipped = 0
    unreadable = 0
    root = stat("/proc/self/").uid == 0
    own_ns = readlink("/proc/self/ns/net")
    host_net = own_ns != None and own_ns == readlink("/proc/1/ns/net")
    emit("sysctl", "network_namespace", "host" if host_net else "own", "/proc/self/ns/net", kind = "semantic")
    for k in sorted(want.keys()):
        if k.startswith(NETNS_PREFIX) and not host_net:
            skipped += 1
            continue
        lv = live(k, root)
        if lv == None:
            emit("sysctl:" + k, "live_missing", "yes", src[k], kind = "semantic")
        elif lv == UNREADABLE:
            unreadable += 1
            emit("sysctl:" + k, "live_unreadable", "yes", src[k], kind = "semantic")
        elif lv != want[k]:
            differ += 1
            emit("sysctl:" + k, "persisted", want[k], src[k], kind = "semantic")
            emit("sysctl:" + k, "live", lv, "/proc/sys", kind = "semantic")
    emit("sysctl", "live_differs_count", str(differ), "sysctl.d vs /proc/sys", kind = "metric")
    emit("sysctl", "net_keys_not_observable_count", str(skipped), "sensor netns", kind = "metric")
    emit("sysctl", "unreadable_count", str(unreadable), "/proc/sys modes", kind = "metric")
    for k in WATCH:
        lv = live(k, root)
        emit("sysctl:" + k, "live", lv if lv != None else "(absent)", "/proc/sys", kind = "semantic")
        emit("sysctl:" + k, "persisted_in", path_basename(src[k]) if k in src else "(none)", "sysctl.d", kind = "semantic")
