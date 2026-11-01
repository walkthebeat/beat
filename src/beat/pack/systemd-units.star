"""systemd units and processes: state counts, failed units, running services (unit file, user, start), timers,
enabled-but-inactive units, processes outside services (session scopes), deleted binaries, unit files newer than
the service's oldest process.

Applies to: any systemd host with a beat sensor.
Assumes: osquery systemd_units and processes; a service's processes sit in cgroup /system.slice/<unit>.
Cannot see: drop-in (*.d/*.conf) mtimes and `systemctl daemon-reload` state; config files a service reads (see the
  per-workload probes); user-manager units (user@*.service children); services in sub-slices
  (getty@, serial-getty@: cgroup /system.slice/system-getty.slice/...) are not joined to processes.
beat's default pack (first written by Claude in a discovery, 2026-10-31; reviewed).
"""

STATE_SQL = """select active_state, sub_state, count(*) n from systemd_units
               where id not like 'beat-question-%' group by 1, 2"""
RUNNING_SQL = """select u.id, u.fragment_path, u.user as unit_user, us.username as proc_user,
                        min(p.start_time) as started, count(p.pid) as procs, sum(p.on_disk = 0) as deleted
                 from systemd_units u
                 join processes p on p.cgroup_path = '/system.slice/' || u.id
                 left join users us on us.uid = p.uid
                 where u.id like '%.service' and u.sub_state = 'running' and u.id not like 'beat-question-%'
                 group by u.id"""

# how many units are in each state
def counts():
    for r in osq(STATE_SQL):
        emit("units", "%s_%s_count" % (r["active_state"], r["sub_state"]), str(r["n"]), "osq.systemd_units", kind = "metric")

# failed units, by name
def failed():
    rows = osq("select id from systemd_units where active_state = 'failed'")
    emit("units", "failed_count", str(len(rows)), "osq.systemd_units", kind = "metric")
    for r in rows:
        emit("unit:" + r["id"], "active_state", "failed", "osq.systemd_units", kind = "semantic")

# running services: unit file, user, start time, unit file newer than the process (pending change)
def running():
    rows = osq(RUNNING_SQL)
    expect(len(rows) > 0, "no running services joined to processes (cgroup layout differs?)")
    def one_svc(r):
        s = "unit:" + r["id"]
        emit(s, "running", "yes", "osq.systemd_units", kind = "semantic")
        emit(s, "fragment_path", r["fragment_path"], "osq.systemd_units", kind = "semantic")
        emit(s, "run_user", r["proc_user"] or "", "osq.processes", kind = "semantic")
        emit(s, "started", iso_utc(int(r["started"])), "osq.processes", kind = "time")
        if r["deleted"]:
            emit(s, "deleted_binary_procs_count", str(r["deleted"]), "osq.processes.on_disk", kind = "metric")
        st = stat(r["fragment_path"])
        expect(st != None, "unit file missing: " + r["fragment_path"])
        emit(s, "unit_file_newer_than_process", "yes" if st.mtime > r["started"] else "no",
             "stat vs processes.start_time", kind = "semantic")
    each(rows, one_svc)

# enabled at boot but not active now
def enabled_inactive():
    rows = osq("""select id, sub_state from systemd_units where unit_file_state = 'enabled'
                  and active_state != 'active' and id not like 'beat-question-%'""")
    emit("units", "enabled_inactive_count", str(len(rows)), "osq.systemd_units", kind = "metric")
    for r in rows:
        emit("unit:" + r["id"], "enabled_but", r["sub_state"], "osq.systemd_units", kind = "semantic")

# timers and cron files
def timers():
    for r in osq("select id, active_state from systemd_units where id like '%.timer'"):
        emit("timer:" + r["id"], "active_state", r["active_state"], "osq.systemd_units", kind = "semantic")
    for f in glob("/etc/cron.d/*") + glob("/var/spool/cron/crontabs/*"):
        emit("cron:" + f, "present", "yes", "glob", kind = "semantic")

# processes started by hand (session scopes) and deleted binaries still running
def stray_processes():
    # processes in a login session scope (started by hand): lost on reboot. Shells and sshd are expected.
    rows = osq("""select p.name, us.username, p.cgroup_path from processes p left join users us on us.uid = p.uid
                  where p.cgroup_path like '%/session-%.scope'""")
    emit("processes", "session_scope_count", str(len(rows)), "osq.processes", kind = "metric")
    seen = {}
    for r in rows:
        if r["name"] in ("sshd", "bash", "zsh", "sh", "sudo", "su", "sd-pam", "(sd-pam)"):
            continue
        k = "%s:%s" % (r["username"], r["name"])
        if k not in seen:
            seen[k] = 1
            emit("scope_proc:" + k, "cgroup", re_sub(r"session-[0-9]+", "session-N", r["cgroup_path"]), "osq.processes", kind = "semantic")
    d = osq("select name, path, cgroup_path from processes where on_disk = 0 and cgroup_path not like '%beat-question-%'")
    emit("processes", "deleted_binary_count", str(len(d)), "osq.processes.on_disk", kind = "metric")
    for r in d:
        emit("deleted_binary:" + r["name"], "path", r["path"], "osq.processes", kind = "semantic")

def main():
    counts()
    failed()
    running()
    enabled_inactive()
    timers()
    stray_processes()
