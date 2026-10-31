"""journal(): entries as dicts, options passed to journalctl."""

def main() -> None:
    for e in journal(unit = "nginx.service", since = "-30d", grep = "Reload", limit = 5):
        emit("journal", e["ts"], "%s|%s|%s|%s" % (e["unit"], e["pid"], e["priority"], e["message"]), "journal")
    for e in journal(kernel = True, limit = 5):
        if "args:" in e["message"]:
            emit("journal_kernel", "args", e["message"], "journal")
