"""Journal: what normal looks like. Two log summaries: warnings and worse (priority <= 4) over the last day, and
the info-level stream in steady state (from SETTLE_S after boot), prefixed with the unit so templates keep it.

Applies to: any systemd host with a beat sensor.
Assumes: journal() returns this host's journal. beat's own footprint is left out, or every run adds lines: its
  beat-question-* units, beat-sensor.service, and the loop + dm-verity attach of the sensor image that each question
  triggers (modprobe@loop/dm_mod/dm_verity, "loopN: detected capacity change"); the count of those is kept.
Cannot see: lines beyond LIMIT in the window (window_truncated says so); files that bypass the journal
  (/var/log/* written directly by applications: per-workload probes); earlier boots' details.
beat's default pack (first written by Claude in a discovery, 2026-10-31; reviewed).
"""

SINCE = "-24h"
LIMIT = 20000
SETTLE_S = 600
SKIP_UNITS = ["beat-sensor.service", "modprobe@loop.service", "modprobe@dm_mod.service", "modprobe@dm_verity.service"]
SKIP_KERNEL = r"^loop[0-9]+: detected capacity change"

# beat's own lines: left out of the summaries
def is_beat(e):
    u = e["unit"] or ""
    if u.startswith("beat-question-") or u in SKIP_UNITS:
        return True
    return u == "" and re_match(SKIP_KERNEL, e["message"]) != None

# "<unit>: <message>", with session and user ids generalised
def tag(e):
    u = re_sub(r"session-[0-9]+\.scope", "session-N.scope", e["unit"] or "kernel")
    u = re_sub(r"user@[0-9]+\.service", "user@N.service", u)
    return "%s: %s" % (u, e["message"])

# the host's names, which log_summary turns into <SELF> so templates compare across hosts
def self_names():
    h = one(osq("select hostname from system_info"), "expected one system_info row")["hostname"]
    short = h.split(".")[0]
    return [h] if short == h else [h, short]

def main():
    names = self_names()
    boot = one(osq("select strftime('%s','now') - total_seconds as b from uptime"), "uptime")["b"]
    settled = iso_utc(int(boot) + SETTLE_S)
    alll = journal(since = SINCE, limit = LIMIT)
    expect(len(alll) > 0, "empty journal for " + SINCE)
    j = [e for e in alll if not is_beat(e)]
    emit("journal", "window_entries_count", str(len(alll)), "journal", kind = "metric")
    emit("journal", "beat_footprint_count", str(len(alll) - len(j)), "journal", kind = "metric")
    emit("journal", "window_truncated", "yes" if len(alll) >= LIMIT else "no", "journal", kind = "semantic")
    warn = [tag(e) for e in j if e["priority"] != None and int(e["priority"]) <= 4]
    emit("journal", "warning_or_worse_count", str(len(warn)), "journal", kind = "metric")
    emit_log_summary("journal-warn", log_summary(lines = warn, self_names = names, examples = 1, top = 30, minutes = 0))
    steady = [tag(e) for e in j if e["ts"] >= settled and e["priority"] != None and int(e["priority"]) > 4]
    emit("journal", "steady_info_count", str(len(steady)), "journal", kind = "metric")
    emit_log_summary("journal-steady", log_summary(lines = steady, self_names = names, examples = 1, top = 30, minutes = 0, levels = 4))
