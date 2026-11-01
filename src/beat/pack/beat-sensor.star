"""beat sensor: build (from the unit's image paths), configured bus/API endpoints (/etc/beat-sensor.env, key names
only for anything secret-looking), unit state, the NATS connection it holds, and the installed images.

Applies to: hosts with beat-sensor.service: installed from the release image (/opt/beat-sensor, MountImages=,
  /etc/beat-sensor.env) or otherwise (a Nix closure); the image's records only where it is one.
Assumes: the unit is beat-sensor.service (the question itself runs as its child, so the sensor is up).
Cannot see: the sensor key (secret), whether the NATS server name resolves to the connected IP (no DNS lookups).
beat's default pack (first written by Claude in a discovery, 2026-10-31; reviewed).
"""

UNIT = "beat-sensor.service"
ENV = "/etc/beat-sensor.env"
SECRETISH = r"(?i)(pass|token|secret|key|cred|seed|nkey)"
S = "service:beat-sensor"

# configured endpoints, from the release install's env file (secret-looking values masked)
def env_file():
    es = stat(ENV)
    emit("file:" + ENV, "present", "yes" if es else "no", "stat", kind = "semantic")
    if not es:
        return
    emit("file:" + ENV, "mode", es.mode, "stat", kind = "semantic")
    for l in read(ENV).splitlines():
        k, eq, v = l.partition("=")
        if not eq or k.strip().startswith("#"):
            continue
        emit(S, "env:" + k.strip(), "<set>" if re_match(SECRETISH, k) else v.strip(), ENV, kind = "semantic")

def main():
    # unit state and the image it mounts
    u = one(osq("select active_state, sub_state, unit_file_state, fragment_path from systemd_units where id = ?", UNIT),
            "expected one " + UNIT)
    emit(S, "active_state", u["active_state"], "osq.systemd_units", kind = "semantic")
    emit(S, "enabled", u["unit_file_state"], "osq.systemd_units", kind = "semantic")
    emit(S, "unit_file", u["fragment_path"], "osq.systemd_units", kind = "semantic")
    img = re_match(r"(?m)^MountImages=(\S+?):", read(u["fragment_path"]))
    emit(S, "install", "image" if img else "other", u["fragment_path"], kind = "semantic")
    if img:
        emit(S, "image", img[1], u["fragment_path"], kind = "semantic")
        emit(S, "image_present", "yes" if stat(img[1]) else "no", "stat", kind = "semantic")
        for d in glob("/opt/beat-sensor/*"):
            emit(S, "installed_version_dir", path_basename(d), "glob:/opt/beat-sensor/*", kind = "semantic")
    env_file()
    # running process and its bus connection
    p = osq("""select min(start_time) st, count(*) n from processes
               where cgroup_path = '/system.slice/' || ?""", UNIT)
    expect(p[0]["n"] > 0, "no beat-sensor processes")
    emit(S, "started", iso_utc(int(p[0]["st"])), "osq.processes", kind = "time")
    c = osq("""select s.remote_address, s.remote_port from process_open_sockets s join processes p using (pid)
               where p.cgroup_path = '/system.slice/' || ? and s.state = 'ESTABLISHED'""", UNIT)
    expect(len(c) >= 1, "no established connection from beat-sensor (bus down?)")
    for r in c:
        emit(S, "connected_bus", "%s:%d" % (r["remote_address"], r["remote_port"]), "osq.process_open_sockets", kind = "semantic")
