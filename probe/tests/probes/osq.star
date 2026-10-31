"""osq(): typed values, `?` parameters bound on the host, joins in osquery's own SQL, no rows."""

def main() -> None:
    r = one(osq("select 1 + ? as n, ? as s, ? as z, 1.5 as f", 1, "it's", None), "expected one row")
    emit("osq", "n", "%s %s" % (r["n"], type(r["n"])), "osq")
    emit("osq", "s", r["s"], "osq")
    emit("osq", "z", str(r["z"]), "osq")
    emit("osq", "f", type(r["f"]), "osq")
    info = one(osq("select version, pid from osquery_info"), "expected one osquery_info row")
    emit("osq", "pid_type", type(info["pid"]), "osq")
    emit("osq", "empty", str(osq("select * from osquery_info where 1 = 0")), "osq")
