"""Kubernetes: what is not running, and the evidence for why. Every Pending pod with the scheduler's own reason and
what that reason points to (the pod's requests, node selector, tolerations and claims; each node's allocatable, the
requests already placed on it, its taints and pressure; each claim's StorageClass), the Events about it, and every
workload whose pods are not being created (FailedCreate: a quota, admission) with the quotas of its namespace. It
gathers the evidence; it does not re-run the scheduler.

Applies to: the cluster sensor (<cluster>_api).
Assumes: quantities as the API writes them (cpu in cores or m; memory in bytes, with SI or binary suffixes). A pod's
  request is its containers' sum, or its largest init container's when that is more, plus its overhead.
Cannot see: why a scheduled container does not start beyond its waiting reason (ask the node's sensor: the kubelet's
  and containerd's journals, the mounts); the scheduler's scores; Events older than the API keeps them (an hour by
  default); the cluster autoscaler beyond its Events. Pod names of ReplicaSets carry a generated suffix (R3): these
  records are for one cluster now, not for comparing clusters.
beat's default pack (first written by Claude for the cluster sensor, 2026-11-21).
"""

SRC = "k8s"
BINARY = [("Ki", 1024), ("Mi", 1048576), ("Gi", 1073741824), ("Ti", 1099511627776)]
DECIMAL = [("k", 1000), ("M", 1000000), ("G", 1000000000), ("T", 1000000000000)]
DONE = ("Succeeded", "Failed")
OWNERS = ("ReplicaSet", "StatefulSet", "DaemonSet", "Job", "ReplicationController")

# "500m" -> 500, "2" -> 2000, "0.5" -> 500
def millicores(q):
    if q.endswith("m"):
        return int(q[:-1])
    return int(float(q) * 1000)

# "64Mi" -> 67108864, "1G" -> 1000000000, "128974848" -> 128974848
def bytes_of(q):
    for suffix, n in BINARY + DECIMAL:
        if q.endswith(suffix):
            return int(float(q[:-len(suffix)]) * n)
    return int(float(q))

def requests(pod):
    def total(containers):
        cpu, mem = 0, 0
        for c in containers:
            r = (c.get("resources") or {}).get("requests") or {}
            cpu += millicores(r["cpu"]) if "cpu" in r else 0
            mem += bytes_of(r["memory"]) if "memory" in r else 0
        return cpu, mem
    spec = pod["spec"]
    cpu, mem = total(spec.get("containers") or [])
    for c in spec.get("initContainers") or []:
        icpu, imem = total([c])
        cpu, mem = max(cpu, icpu), max(mem, imem)
    o = spec.get("overhead") or {}
    return cpu + (millicores(o["cpu"]) if "cpu" in o else 0), mem + (bytes_of(o["memory"]) if "memory" in o else 0)

def ref(o):
    return "%s/%s" % (o["metadata"]["namespace"], o["metadata"]["name"])

def when(e):
    return e.get("lastTimestamp") or e.get("eventTime") or e["metadata"].get("creationTimestamp") or ""

# The latest Event of each reason about one object: reason, message, how many times.
def events_about(events, kind, ns, name):
    latest = {}
    for e in events:
        i = e.get("involvedObject") or {}
        if i.get("kind") == kind and i.get("name") == name and (ns == None or i.get("namespace") == ns):
            r = e.get("reason") or "?"
            if r not in latest or when(e) >= when(latest[r]):
                latest[r] = e
    return [latest[r] for r in sorted(latest)]

def emit_events(subject, evs):
    emit(subject, "events_count", str(len(evs)), SRC, kind = "metric")
    for e in evs:
        emit(subject, "event." + e.get("reason", "?"), e.get("message") or "", SRC + ".Event")
        emit(subject, "event.%s.type" % e.get("reason", "?"), e.get("type") or "", SRC + ".Event")
        emit(subject, "event.%s.count" % e.get("reason", "?"), str(e.get("count") or 1), SRC + ".Event", kind = "metric")
        emit(subject, "event.%s.last" % e.get("reason", "?"), when(e), SRC + ".Event", kind = "time")

def condition(o, t):
    for c in (o.get("status") or {}).get("conditions") or []:
        if c.get("type") == t:
            return c
    return None

def pending_pod(p, events, claims_seen):
    s = "pod:" + ref(p)
    spec, status = p["spec"], p.get("status") or {}
    emit(s, "phase", "Pending", SRC + ".Pod")
    emit(s, "created", p["metadata"].get("creationTimestamp") or "", SRC + ".Pod", kind = "time")
    for o in p["metadata"].get("ownerReferences") or []:
        emit(s, "owner", "%s/%s" % (o["kind"], o["name"]), SRC + ".Pod")
    if spec.get("nodeName"):
        emit(s, "node", spec["nodeName"], SRC + ".Pod")
    c = condition(p, "PodScheduled")
    emit(s, "scheduled", "yes" if c and c.get("status") == "True" else "no", SRC + ".Pod")
    if c and c.get("status") != "True":
        emit(s, "scheduled.reason", c.get("reason") or "", SRC + ".Pod")
        emit(s, "scheduled.message", c.get("message") or "", SRC + ".Pod")
    if spec.get("schedulerName", "default-scheduler") != "default-scheduler":
        emit(s, "scheduler_name", spec["schedulerName"], SRC + ".Pod")
    if status.get("nominatedNodeName"):
        emit(s, "nominated_node", status["nominatedNodeName"], SRC + ".Pod")
    if spec.get("priorityClassName"):
        emit(s, "priority_class", spec["priorityClassName"], SRC + ".Pod")
    cpu, mem = requests(p)
    emit(s, "cpu_request_m", str(cpu), SRC + ".Pod", kind = "metric")
    emit(s, "memory_request_bytes", str(mem), SRC + ".Pod", kind = "metric")
    for k, v in sorted((spec.get("nodeSelector") or {}).items()):
        emit(s, "node_selector." + k, v, SRC + ".Pod")
    if (spec.get("affinity") or {}).get("nodeAffinity") or (spec.get("affinity") or {}).get("podAntiAffinity"):
        emit(s, "affinity", json.encode(spec["affinity"]), SRC + ".Pod")
    if spec.get("topologySpreadConstraints"):
        emit(s, "topology_spread", json.encode(spec["topologySpreadConstraints"]), SRC + ".Pod")
    for t in spec.get("tolerations") or []:
        emit(s, "toleration", "%s%s%s:%s" % (t.get("key") or "*", "=" if t.get("value") else "", t.get("value") or "",
                                             t.get("effect") or "*"), SRC + ".Pod")
    for v in spec.get("volumes") or []:
        if v.get("persistentVolumeClaim"):
            claim = "%s/%s" % (p["metadata"]["namespace"], v["persistentVolumeClaim"]["claimName"])
            emit(s, "claim", claim, SRC + ".Pod")
            claims_seen[claim] = True
    for cs in (status.get("initContainerStatuses") or []) + (status.get("containerStatuses") or []):
        w = (cs.get("state") or {}).get("waiting")
        if w:
            emit(s, "container.%s.waiting" % cs["name"], w.get("reason") or "", SRC + ".Pod")
            if w.get("message"):
                emit(s, "container.%s.waiting_message" % cs["name"], w["message"], SRC + ".Pod")
    emit_events(s, events_about(events, "Pod", p["metadata"]["namespace"], p["metadata"]["name"]))
    return c != None and c.get("status") == "False"

def claim(key, claims, classes, events):
    s = "pvc:" + key
    c = claims.get(key)
    if c == None:
        emit(s, "present", "no", SRC + ".PersistentVolumeClaim")
        return
    emit(s, "present", "yes", SRC + ".PersistentVolumeClaim")
    emit(s, "phase", (c.get("status") or {}).get("phase") or "", SRC + ".PersistentVolumeClaim")
    sc = c["spec"].get("storageClassName")
    if sc == None:
        default = [n for n, k in classes.items()
                   if (k["metadata"].get("annotations") or {}).get("storageclass.kubernetes.io/is-default-class") == "true"]
        emit(s, "storage_class", "(none given; default: %s)" % (", ".join(default) or "none"), SRC + ".PersistentVolumeClaim")
    else:
        emit(s, "storage_class", sc, SRC + ".PersistentVolumeClaim")
        if sc != "":
            emit(s, "storage_class_present", "yes" if sc in classes else "no", SRC + ".StorageClass")
            if sc in classes:
                emit(s, "volume_binding_mode", classes[sc].get("volumeBindingMode") or "Immediate", SRC + ".StorageClass")
                emit(s, "provisioner", classes[sc].get("provisioner") or "", SRC + ".StorageClass")
    if c["spec"].get("volumeName"):
        emit(s, "volume", c["spec"]["volumeName"], SRC + ".PersistentVolumeClaim")
    ns, name = key.split("/")
    emit_events(s, events_about(events, "PersistentVolumeClaim", ns, name))

# Every node, as the scheduler weighs it: allocatable, requests already placed, taints, pressure, the labels pods select.
def nodes(pods, selected):
    placed = {}
    for p in pods:
        n = p["spec"].get("nodeName")
        if n and (p.get("status") or {}).get("phase") not in DONE:
            cpu, mem = requests(p)
            was = placed.get(n, (0, 0, 0))
            placed[n] = (was[0] + cpu, was[1] + mem, was[2] + 1)
    for n in k8s("Node"):
        name = n["metadata"]["name"]
        s = "node:" + name
        a = (n.get("status") or {}).get("allocatable") or {}
        cpu, mem, count = placed.get(name, (0, 0, 0))
        acpu, amem = millicores(a.get("cpu", "0")), bytes_of(a.get("memory", "0"))
        emit(s, "allocatable_cpu_m", str(acpu), SRC + ".Node", kind = "metric")
        emit(s, "allocatable_memory_bytes", str(amem), SRC + ".Node", kind = "metric")
        emit(s, "allocatable_pods_count", a.get("pods", "0"), SRC + ".Node", kind = "metric")
        emit(s, "requested_cpu_m", str(cpu), SRC + ".Pod", kind = "metric")
        emit(s, "requested_memory_bytes", str(mem), SRC + ".Pod", kind = "metric")
        emit(s, "pods_count", str(count), SRC + ".Pod", kind = "metric")
        emit(s, "free_cpu_m", str(acpu - cpu), SRC + ".Node - Pod", kind = "metric")
        emit(s, "free_memory_bytes", str(amem - mem), SRC + ".Node - Pod", kind = "metric")
        emit(s, "unschedulable", "yes" if n["spec"].get("unschedulable") else "no", SRC + ".Node")
        for t in n["spec"].get("taints") or []:
            emit(s, "taint", "%s%s%s:%s" % (t["key"], "=" if t.get("value") else "", t.get("value") or "", t["effect"]),
                 SRC + ".Node")
        for c in (n.get("status") or {}).get("conditions") or []:
            bad = c["status"] != "True" if c["type"] == "Ready" else c["status"] == "True"
            if bad:
                emit(s, "condition." + c["type"], "%s: %s" % (c["status"], c.get("message") or c.get("reason") or ""), SRC + ".Node")
        labels = n["metadata"].get("labels") or {}
        for k in sorted(selected):
            emit(s, "label." + k, labels.get(k, "(absent)"), SRC + ".Node")

# Workloads whose pods are not being created: their FailedCreate Events, named by the Deployment over a ReplicaSet.
def not_created(events, quotas_for):
    by_rs = {}
    for rs in k8s("ReplicaSet"):
        for o in rs["metadata"].get("ownerReferences") or []:
            if o.get("controller"):
                by_rs[ref(rs)] = "%s/%s" % (o["kind"], o["name"])
    seen = {}
    for e in events:
        i = e.get("involvedObject") or {}
        if e.get("reason") != "FailedCreate" or i.get("kind") not in OWNERS:
            continue
        key = "%s/%s" % (i.get("namespace"), i["name"])
        if key in seen:
            continue
        seen[key] = True
        s = "%s:%s" % (i["kind"].lower(), key)
        if i["kind"] == "ReplicaSet" and key in by_rs:
            emit(s, "owner", by_rs[key], SRC + ".ReplicaSet")
        emit_events(s, [x for x in events_about(events, i["kind"], i.get("namespace"), i["name"]) if x.get("reason") == "FailedCreate"])
        quotas_for[i.get("namespace")] = True
    return len(seen)

def quotas(namespaces):
    for q in k8s("ResourceQuota"):
        ns = q["metadata"]["namespace"]
        if ns not in namespaces:
            continue
        s = "quota:" + ref(q)
        st = q.get("status") or {}
        for k, v in sorted((st.get("hard") or {}).items()):
            emit(s, "hard." + k, v, SRC + ".ResourceQuota")
            emit(s, "used." + k, (st.get("used") or {}).get(k, ""), SRC + ".ResourceQuota")

def main():
    pods = k8s("Pod")
    events = k8s("Event")
    claims_seen, namespaces, selected = {}, {}, {}
    pending = [p for p in pods if (p.get("status") or {}).get("phase") == "Pending"]
    unschedulable = 0
    for p in pending:
        if pending_pod(p, events, claims_seen):
            unschedulable += 1
            for k in (p["spec"].get("nodeSelector") or {}):
                selected[k] = True
        namespaces[p["metadata"]["namespace"]] = True
    emit("cluster", "pending_pods_count", str(len(pending)), SRC + ".Pod", kind = "metric")
    emit("cluster", "unschedulable_pods_count", str(unschedulable), SRC + ".Pod", kind = "metric")
    if claims_seen:
        claims = {ref(c): c for c in k8s("PersistentVolumeClaim")}
        classes = {c["metadata"]["name"]: c for c in k8s("StorageClass")}
        for key in sorted(claims_seen):
            claim(key, claims, classes, events)
    if unschedulable:
        nodes(pods, selected)
    emit("cluster", "workloads_not_creating_count", str(not_created(events, namespaces)), SRC + ".Event", kind = "metric")
    quotas(namespaces)
