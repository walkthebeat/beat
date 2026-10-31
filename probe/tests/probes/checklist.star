"""checklist(): the 60-second checklist over sample(), on the host the test runs on."""

def main() -> None:
    c = checklist(seconds = 1, top = 3)
    cpu = c["cpu"]
    expect(abs(cpu["usr"] + cpu["sys"] + cpu["iowait"] + cpu["steal"] + cpu["idle"] - 100) < 1.5, "cpu shares add up: %s" % cpu)
    expect(len(c["cpus"]) == c["load"]["cpus"], "one row per CPU")
    expect(len(c["procs"]) <= 6, "top 3, and up to 3 with a process in D state")
    expect([r for r in c["use"] if r["resource"] == "cpu"] != [], "a USE row for the CPU")
    emit_checklist(c)
