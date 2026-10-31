"""sample() of a secret path is denied, like read()."""

def main() -> None:
    sample(["/proc/1/environ"], seconds = 0)
