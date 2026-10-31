"""trace(): a catalog entry, its output reduced on the host (runs only where the catalog and CAP_BPF are)."""

def main() -> None:
    r = trace("execsnoop", seconds = 1, key = ["comm"], top = 5)
    emit("trace", "execsnoop_seen_count", str(r["events"]["seen"]), "trace", kind = "metric")
    h = trace("biolatency", seconds = 1, options = {"per_disk": True})
    emit("trace", "biolatency_histograms_count", str(len(h.get("histograms", []))), "trace", kind = "metric")
