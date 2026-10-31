"""Every tool is also a function: sort(...) is pipe(["sort", ...])."""

def main() -> None:
    emit("tools", "sorted", sort("-r", stdin = "a\nc\nb\n").stdout.strip().replace("\n", ","), "sort")
    emit("tools", "sha256", sha256sum("/etc/passwd").stdout[:16], "sha256sum")
    emit("tools", "readlink_is_builtin", str(readlink("/etc/nginx/sites-enabled/default")), "readlink")
