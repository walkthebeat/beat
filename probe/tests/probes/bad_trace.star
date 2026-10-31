"""trace(): the entry must be a literal catalog entry."""

def main() -> None:
    name = "biolatency"
    trace(name)
    trace("bpftrace", seconds = 1)
