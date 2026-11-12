"""Host base: OS, kernel (running vs installed), boot, hardware, filesystems, network, DNS, time sync, login users.

Applies to: any Linux host with a beat sensor (first written on Ubuntu 24.04 on EC2); on NixOS, which keeps no
  /boot/vmlinuz-*, the booted, current and next-boot system generations instead (from walkthebeat's own estate,
  NixOS 26.05, 2026-11-02).
Assumes: osquery tables os_version, system_info, kernel_info, uptime, mounts, users; a question runs in its own
  mount namespace (and, before sensor 0.2.3, network namespace), so the host's mounts, interfaces and routes are read
  from /proc/1/ (PID 1's view), right on every sensor.
Cannot see: chrony's live sync state (no chronyc; only config and unit state), IPv6 addresses, authorized_keys
  content (secret: only stat), password state of accounts (shadow is secret).
beat's default pack (first written by Claude in a discovery, 2026-10-31; reviewed).
"""

REAL_FS = ["ext4", "xfs", "vfat", "btrfs"]
SUDOERS = ["/etc/sudoers"]
SUDOERS_GLOB = "/etc/sudoers.d/*"
CHRONY_CONF = "/etc/chrony/chrony.conf"
CHRONY_CONFD = "/etc/chrony/conf.d/*.conf"
NOLOGIN = ["nologin", "false", "sync"]   # by basename: NixOS shells live under /run/current-system/sw/bin or the store
NIXOS_CURRENT = "/run/current-system"
NIXOS_BOOTED = "/run/booted-system"
NIXOS_PROFILE = "/nix/var/nix/profiles/system"

# OS release, running kernel vs the images in /boot, reboot-required flag
def os_and_kernel():
    o = one(osq("select name, version, codename from os_version"), "expected one os_version row")
    emit("os", "name", o["name"], "osq.os_version", kind = "semantic")
    emit("os", "version", o["version"], "osq.os_version", kind = "semantic")
    emit("os", "codename", o["codename"] or "", "osq.os_version", kind = "semantic")
    k = one(osq("select version, arguments from kernel_info"), "expected one kernel_info row")
    running = k["version"]
    emit("kernel", "running", running, "osq.kernel_info", kind = "semantic")
    emit("kernel", "cmdline", k["arguments"], "osq.kernel_info", kind = "semantic")
    if stat(NIXOS_CURRENT):
        nixos_generations(running)
        return
    images = [path_basename(p)[len("vmlinuz-"):] for p in glob("/boot/vmlinuz-*")]
    expect(len(images) > 0, "no /boot/vmlinuz-* images")
    for v in images:
        emit("kernel", "installed_image", v, "glob:/boot/vmlinuz-*", kind = "semantic")
    newest = sorted(images)[-1]   # lexical: fine within one ABI series; a hint, not a verdict
    emit("kernel", "newest_installed_image", newest, "glob:/boot/vmlinuz-*", kind = "semantic")
    emit("kernel", "running_is_newest", "yes" if newest == running else "no", "kernel_info vs /boot", kind = "semantic")
    expect(running in images, "running kernel %s has no image in /boot" % running)
    emit("host", "reboot_required_flag", "yes" if stat("/var/run/reboot-required") else "no", "stat:/var/run/reboot-required", kind = "semantic")

# NixOS keeps no /boot/vmlinuz-*: both sides are system closures. booted = what the kernel started from,
# current = what is activated now, profile = what the next boot's bootloader entry comes from.
def nixos_generations(running):
    for name, link in [("booted", NIXOS_BOOTED), ("current", NIXOS_CURRENT)]:
        target = readlink(link)
        expect(target != None, "expected %s to be a symlink" % link)
        emit("nixos:" + name, "system", target, "readlink:" + link, kind = "semantic")
        modules = list_dir(link + "/kernel-modules/lib/modules")
        emit("nixos:" + name, "kernel", one(modules, "expected one kernel in " + link), link + "/kernel-modules/lib/modules", kind = "semantic")
    profile = readlink(NIXOS_PROFILE)
    expect(profile != None, "expected %s to be a symlink" % NIXOS_PROFILE)
    emit("nixos:profile", "generation", profile, "readlink:" + NIXOS_PROFILE, kind = "semantic")
    generation = stat(path_join(path_dirname(NIXOS_PROFILE), profile))
    expect(generation != None, "profile generation missing: " + profile)
    emit("nixos:profile", "system", readlink(path_join(path_dirname(NIXOS_PROFILE), profile)) or "", "readlink", kind = "semantic")
    emit("nixos:profile", "generations_count", str(len(glob(NIXOS_PROFILE + "-*-link"))), "glob", kind = "metric")

# hostname, hardware, memory, uptime and boot time
def boot_and_hardware():
    s = one(osq("select hostname, hardware_vendor, hardware_model, cpu_brand, cpu_logical_cores, physical_memory from system_info"), "expected one system_info row")
    emit("host", "hostname", s["hostname"], "osq.system_info", kind = "identity")
    emit("host", "hardware_vendor", s["hardware_vendor"], "osq.system_info", kind = "semantic")
    emit("host", "hardware_model", s["hardware_model"], "osq.system_info", kind = "semantic")
    emit("host", "cpu_brand", s["cpu_brand"].replace("\x00", "").strip(), "osq.system_info", kind = "semantic")
    emit("host", "cpu_logical_count", str(s["cpu_logical_cores"]), "osq.system_info", kind = "semantic")
    emit("host", "memory_bytes", str(s["physical_memory"]), "osq.system_info", kind = "semantic")
    u = one(osq("select total_seconds, strftime('%s','now') - total_seconds as boot from uptime"), "expected one uptime row")
    emit("host", "uptime_s", str(u["total_seconds"]), "osq.uptime", kind = "metric")
    emit("host", "boot_time", iso_utc(int(u["boot"])), "osq.uptime", kind = "time")

# real filesystems as the host sees them (/proc/1/mounts), usage from statfs
def filesystems():
    host_mounts = []
    for l in read("/proc/1/mounts").splitlines():
        f = l.split(" ")
        if len(f) >= 4 and f[2] in REAL_FS:
            host_mounts.append(f)
    expect(len(host_mounts) > 0, "no real filesystems in /proc/1/mounts")
    usage = {}
    for r in osq("select path, blocks_size, blocks, blocks_available, inodes, inodes_free from mounts"):
        usage[r["path"]] = r
    def one_fs(f):
        dev, path, fstype, opts = f[0], f[1], f[2], f[3]
        subj = "fs:" + path
        emit(subj, "device", dev, "/proc/1/mounts", kind = "semantic")
        emit(subj, "fstype", fstype, "/proc/1/mounts", kind = "semantic")
        emit(subj, "mode", opts.split(",")[0], "/proc/1/mounts", kind = "semantic")
        r = usage.get(path)
        expect(r != None, "no statfs row for " + path)
        total = r["blocks"] * r["blocks_size"]
        used = (r["blocks"] - r["blocks_available"]) * r["blocks_size"]
        emit(subj, "size_bytes", str(total), "osq.mounts", kind = "metric")
        emit(subj, "used_pct", str(int(100 * used / total)) if total else "0", "osq.mounts", kind = "metric")
        if r["inodes"]:
            emit(subj, "inodes_used_pct", str(int(100 * (r["inodes"] - r["inodes_free"]) / r["inodes"])), "osq.mounts", kind = "metric")
    each(host_mounts, one_fs)

def hex_ip(h):
    # /proc/net/route little-endian hex -> dotted quad
    return ".".join([str(int(h[i:i + 2], 16)) for i in (6, 4, 2, 0)])

# NICs, IPv4 addresses, default route, DNS: from PID 1's network namespace
def network():
    for l in read("/proc/1/net/dev").splitlines()[2:]:
        name = l.split(":")[0].strip()
        if name != "lo":
            emit("nic:" + name, "present", "yes", "/proc/1/net/dev", kind = "semantic")
    # host-local IPv4 addresses: "/32 host LOCAL" leaves of fib_trie's Main table
    trie = read("/proc/1/net/fib_trie").split("Local:")[0]
    addrs = re_find_all(r"\|-- ([0-9.]+)\n\s+/32 host LOCAL", trie)
    for a in sorted({a: 1 for a in addrs if not a.startswith("127.")}.keys()):
        emit("host", "ipv4_address", a, "/proc/1/net/fib_trie", kind = "identity")
    gws = [l.split("\t") for l in read("/proc/1/net/route").splitlines()[1:] if l.split("\t")[1] == "00000000"]
    for g in gws:
        emit("route:default", "gateway", hex_ip(g[2]), "/proc/1/net/route", kind = "semantic")
        emit("route:default", "interface", g[0], "/proc/1/net/route", kind = "semantic")
    emit("dns", "resolv_conf_target", readlink("/etc/resolv.conf") or "(file)", "readlink:/etc/resolv.conf", kind = "semantic")
    up = read("/run/systemd/resolve/resolv.conf") if stat("/run/systemd/resolve/resolv.conf") else read("/etc/resolv.conf")
    for l in up.splitlines():
        f = l.split()
        if len(f) >= 2 and f[0] == "nameserver":
            emit("dns", "upstream_nameserver", f[1], "/run/systemd/resolve/resolv.conf", kind = "semantic")
        if len(f) >= 2 and f[0] == "search":
            for d in f[1:]:
                emit("dns", "search_domain", d, "/run/systemd/resolve/resolv.conf", kind = "semantic")

# timezone, the one active time daemon, chrony sources from its config
def time_sync():
    emit("time", "timezone", readlink("/etc/localtime") or "(file)", "readlink:/etc/localtime", kind = "semantic")
    u = osq("select id, active_state from systemd_units where id in ('chrony.service','systemd-timesyncd.service','ntp.service','ntpsec.service') and active_state = 'active'")
    emit("time", "active_daemon_count", str(len(u)), "osq.systemd_units", kind = "metric")  # 1 is normal
    for r in u:
        emit("time", "daemon", r["id"], "osq.systemd_units", kind = "semantic")
    if stat(CHRONY_CONF):
        for f in [CHRONY_CONF] + glob(CHRONY_CONFD):
            for l in read(f).splitlines():
                w = l.split()
                if len(w) >= 2 and w[0] in ("server", "pool", "peer"):
                    emit("time", "chrony_" + w[0], w[1], f, kind = "semantic")

# accounts with a login shell, authorized_keys presence, sudo rules
def users():
    rows = osq("select username, uid, shell, directory from users")
    logins = [r for r in rows if path_basename(r["shell"]) not in NOLOGIN]
    emit("users", "login_shell_count", str(len(logins)), "osq.users", kind = "metric")
    for r in logins:
        s = "user:" + r["username"]
        emit(s, "uid", str(r["uid"]), "osq.users", kind = "semantic")
        emit(s, "shell", r["shell"], "osq.users", kind = "semantic")
        home = r["directory"]
        # the sensor hides secret directories: stat of a file inside one gives None, the same as missing
        ssh_dir = stat(home + "/.ssh")
        if ssh_dir != None and (ssh_dir.secret or not ssh_dir.readable):
            emit(s, "authorized_keys_present", "hidden", "stat:" + home + "/.ssh", kind = "semantic")
        else:
            emit(s, "authorized_keys_present", "yes" if stat(home + "/.ssh/authorized_keys") else "no", "stat", kind = "semantic")
        # NixOS declares keys here (users.users.<name>.openssh.authorizedKeys), and sshd reads both
        emit(s, "authorized_keys_d_present", "yes" if stat("/etc/ssh/authorized_keys.d/" + r["username"]) else "no", "stat", kind = "semantic")
    for f in SUDOERS + glob(SUDOERS_GLOB):
        st = stat(f)
        if st == None or not st.readable or f.endswith("README"):
            continue
        for l in read(f).splitlines():
            l = l.strip()
            if not l or l.startswith("#") or l.startswith("Defaults") or l.startswith("@include"):
                continue
            who = l.split()[0]
            emit("sudo:" + who, "rule", l, f, kind = "semantic")
            emit("sudo:" + who, "nopasswd", "yes" if "NOPASSWD" in l else "no", f, kind = "semantic")

def main():
    os_and_kernel()
    boot_and_hardware()
    filesystems()
    network()
    time_sync()
    users()
