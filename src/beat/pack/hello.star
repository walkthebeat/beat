"""Hello: the first question to ask a new host. What it is (name, OS, kernel, hardware) and how long it has been up;
an answer proves the whole path: your signature, the sensor's enrolment, the answer back.

Applies to: every Linux host with a beat sensor.  Assumes: osquery's system_info, os_version, kernel_info, uptime.
Cannot see: anything else (by design: it is quick and reads almost nothing). beat's default pack.
"""

def main() -> None:
    s = one(osq("select hostname, hardware_vendor, hardware_model, cpu_logical_cores, physical_memory from system_info"),
            "expected one system_info row")
    o = one(osq("select name, version from os_version"), "expected one os_version row")
    k = one(osq("select version from kernel_info"), "expected one kernel_info row")
    u = one(osq("select total_seconds from uptime"), "expected one uptime row")
    emit("host", "hostname", s["hostname"], "osq.system_info", kind = "identity")
    emit("host", "os", "%s %s" % (o["name"], o["version"]), "osq.os_version", kind = "semantic")
    emit("host", "kernel", k["version"], "osq.kernel_info", kind = "semantic")
    emit("host", "hardware", ("%s %s" % (s["hardware_vendor"], s["hardware_model"])).strip(), "osq.system_info", kind = "semantic")
    emit("host", "cpu_logical_count", str(s["cpu_logical_cores"]), "osq.system_info", kind = "metric")
    emit("host", "memory_bytes", str(s["physical_memory"]), "osq.system_info", kind = "metric")
    emit("host", "uptime_s", str(u["total_seconds"]), "osq.uptime", kind = "metric")
