"""Failure handling: `each` isolates items, secret content is denied, a failure outside `each` ends the probe."""

def count_lines(path: str) -> None:
    emit("file:" + path, "lines", str(len(read(path).splitlines())), "read")

def main() -> None:
    each(["/etc/passwd", "/etc/shadow", "/etc/nope", "/etc/group"], count_lines)
    emit("host:self", "secret_files", str(len(secrets())), "secrets")
    one([], "expected one thing")
    emit("host:self", "unreachable", "x", "never")
