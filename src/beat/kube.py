"""Asking by label (`beat ask --cluster C --selector S`): the cluster sensor (`C_api`) says which pods the selector
matches and where they run, then the question goes to those nodes' sensors (`C_<node>`, the guide's naming) with the
pods as its subjects (Beat-Subjects; the probe's subjects()). Two surveys: the first is the record of what the
selector matched, and when. The pods are not part of the second's question: the same probe asked after a rollout is
the same question (beat-notes facts.md)."""
from __future__ import annotations

import json

from . import ask

# Asked of the cluster sensor with what to select as its subject: {selector, namespace}. One question whatever is
# selected, so its surveys are the history of what selectors matched.
SELECT = '''"""Which pods a label selector matches, and where they run (beat ask --cluster --selector): one record per pod,
its value JSON: namespace, name, uid, node, phase, owner (a Deployment over its ReplicaSet), labels, containers."""

def controller(o):
    for r in o["metadata"].get("ownerReferences") or []:
        if r.get("controller"):
            return r
    return None

def main():
    for want in subjects():
        ns = want.get("namespace")
        over = {}
        for rs in k8s("ReplicaSet", namespace=ns):
            c = controller(rs)
            if c:
                over[rs["metadata"]["namespace"] + "/" + rs["metadata"]["name"]] = c["kind"] + "/" + c["name"]
        for p in k8s("Pod", namespace=ns, selector=want.get("selector")):
            m, spec, st = p["metadata"], p.get("spec") or {}, p.get("status") or {}
            c = controller(p)
            owner = None
            if c:
                owner = over.get(m["namespace"] + "/" + c["name"], c["kind"] + "/" + c["name"]) if c["kind"] == "ReplicaSet" else c["kind"] + "/" + c["name"]
            containers = []
            for s in (st.get("initContainerStatuses") or []) + (st.get("containerStatuses") or []):
                containers.append({"name": s["name"], "id": (s.get("containerID") or "").partition("://")[2] or None})
            emit(m["namespace"] + "/" + m["name"], "pod", json.encode({
                "namespace": m["namespace"], "name": m["name"], "uid": m["uid"], "node": spec.get("nodeName"),
                "phase": st.get("phase"), "owner": owner, "labels": m.get("labels") or {}, "containers": containers,
            }), "k8s.Pod", kind="identity")
'''


def api_sensor(cluster: str) -> str:
    return f"{cluster}_api"


def node_sensor(cluster: str, node: str) -> str:
    return f"{cluster}_{node}"


async def select(cluster: str, selector: str | None, namespace: str | None = None, via: str = "beat ask",
                 timeout: int = 30) -> dict:
    """The pods `selector` (as kubectl -l takes it; None: every pod) matches in `namespace` (None: all), from the
    cluster sensor: {hosts: the node sensors to ask, subjects: the pods (scheduled ones), unscheduled: pods on no
    node yet, selector: how they were chosen, in words, survey: the survey that resolved them}."""
    want = {k: v for k, v in (("selector", selector), ("namespace", namespace)) if v}
    api = api_sensor(cluster)
    s = await ask.ask("k8s-select.star", SELECT, [api], timeout, via=via, subjects=[want],
                      selector=f"cluster:{cluster} resolve")
    a = (s["answers"].get(api) or {}).get("answer")
    if not a:
        why = ask.why_not(s, api) if api in s["expected"] else ""
        raise RuntimeError(f"the cluster sensor {api} did not answer which pods match{': ' + why if why else ''} "
                           f"(survey {s['survey']}; `beat sensors`)")
    if a.get("error"):
        raise RuntimeError(f"{api}: {a['error'].get('kind')}: {a['error'].get('message')} (survey {s['survey']})")
    pods = [json.loads(r["value"]) for r in a.get("records") or [] if r["key"] == "pod"]
    words = " ".join(f"{k}:{v}" for k, v in want.items())
    scheduled = [p for p in pods if p.get("node")]
    return {"hosts": sorted({node_sensor(cluster, p["node"]) for p in scheduled}),
            "subjects": sorted(scheduled, key=lambda p: (p["namespace"], p["name"])),
            "unscheduled": sorted(f"{p['namespace']}/{p['name']}" for p in pods if not p.get("node")),
            "selector": f"cluster:{cluster} {words or 'every pod'} (resolved by survey {s['survey']})",
            "survey": s["survey"]}


def summary(sel: dict) -> str:
    """One line for people: how many pods on how many nodes, and those on none."""
    n, h = len(sel["subjects"]), len(sel["hosts"])
    line = f"{sel['selector']}: {n} pod{'s' * (n != 1)} on {h} node{'s' * (h != 1)}"
    if sel["unscheduled"]:
        line += f"; not on a node yet (not asked): {', '.join(sel['unscheduled'])}"
    return line
