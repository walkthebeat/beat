"""ssh on this box: unit state, the listening process, its last log lines."""

UNIT = "ssh.service"

def main() -> None:
    u = one(osq("select id, active_state, unit_file_state, fragment_path from systemd_units where id = ?", UNIT),
            "expected one %s unit" % UNIT)
    emit("unit:" + UNIT, "active_state", u["active_state"], "osq.systemd_units")
    for l in osq("""select l.address, l.port, p.name, p.pid, p.start_time
                    from listening_ports l join processes p using (pid)
                    where p.name = ? and l.protocol = 6""", "sshd"):
        emit("endpoint:%s:%d/tcp" % (l["address"], l["port"]), "process", "%s[%d]" % (l["name"], l["pid"]), "osq.listening_ports")
        emit("unit:" + UNIT, "process_started", iso_utc(l["start_time"]), "osq.processes")
    entries = journal(unit = UNIT, since = "-7d", limit = 3)
    emit("unit:" + UNIT, "journal_entries", str(len(entries)), "journal")
    for e in entries:
        emit("unit:" + UNIT, "log", e["ts"] + " " + e["message"][:60], "journal")
