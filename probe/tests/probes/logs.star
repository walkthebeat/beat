"""Log built-ins over the drain tool: a summary as records, an extract, and journal messages as input."""

LOG = "/var/log/auth.log"
SELF = ["legacy-web-1"]
INVALID = "<TIME> <SELF> sshd[<PID>]: Invalid user <*> from <IP>"

def main() -> None:
    s = log_summary(path = LOG, self_names = SELF, header = 3, examples = 1)
    emit_log_summary(LOG, s)
    x = log_extract(path = LOG, templates = [INVALID], self_names = SELF, header = 3, limit = 2)
    emit("extract:" + LOG, "matched_count", str(x["matched"]), "drain")
    for line in x["lines"]:
        emit("extract:" + LOG, "line", line, "drain")
    c = log_summary(path = LOG, templates = [INVALID], self_names = SELF, header = 3)
    for t in c["templates"]:
        emit("curated:" + t["template"], "new", "yes" if t.get("new") else "no", "drain")
    j = log_summary(lines = [e["message"] for e in journal(limit = 5)])
    emit("journal", "lines_count", str(j["lines"]), "drain")
