def main() -> None:
    pipe(["rm", "-rf", "/etc"])
    pipe(["cat", "/etc/passwd"], ["grep", "root"])
