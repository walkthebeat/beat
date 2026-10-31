"""pipe(): stages connected stdout to stdin, exit codes as values, stdin from the probe, no escape via symlinks."""

def main() -> None:
    r = pipe(["cat", "/etc/nginx/nginx.conf"], ["sort"], ["head", "-n", "1"])
    emit("pipe", "first_sorted", r.stdout.strip(), "sort|head")
    emit("pipe", "status", str(r.status), "sort|head")
    r = pipe(["test", "-e", "/etc/nope"])
    emit("pipe", "test_status", str(r.status), "test")
    emit("pipe", "test_ok", str(r.ok), "test")
    r = pipe(["wc", "-l"], stdin = "a\nb\nc\n")
    emit("pipe", "wc", r.stdout.strip(), "wc")
    r = pipe(["cat", "/etc/escape"])
    emit("pipe", "escape_ok", str(r.ok), "cat")
    s = stat("/etc/escape")
    emit("stat", "escape_kind", s.kind, "stat")
    emit("stat", "unmapped", str(stat("/root/.bashrc")), "stat")
