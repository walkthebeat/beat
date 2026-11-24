"""Two builds of drain over the same log files: does the new one only merge templates, and lose nothing?
  python3 wasm/drain/compare.py WASMTIME OLD.wasm NEW.wasm LOGFILE... [-- drain args]
For a change to how drain forms templates (docs/probes.md [B13a]); e.g. OLD from `nix build
git+file://$PWD?ref=main#wasm-drain`, NEW from `nix build .#wasm-drain`, wasmtime from the dev shell, and real logs
(not in this repository: they carry the hosts' particulars). Exit 1 when a check fails.
Per file: lines equal; every old template maps to the new template its text generalises to (merges only, never
splits), and the line counts of the old ones sum to the new one's; per new slot, distinct values >= the old slot's;
the parameters that stopped being categorical, with their values.
"""
import json
import re
import subprocess
import sys
from collections import defaultdict

args = sys.argv[1:]
extra = args[args.index("--") + 1:] if "--" in args else []
args = args[:args.index("--")] if "--" in args else args
wasmtime, old_w, new_w, files = args[0], args[1], args[2], args[3:]


def run(wasm, path):
    with open(path, "rb") as f:
        out = subprocess.run([wasmtime, "run", wasm] + extra, stdin=f, capture_output=True, check=True).stdout
    return json.loads(out)


def gen(text):
    """The rule under test (drain's `generalize`): a token holding a digit is a parameter."""
    return " ".join("<*>" if re.search(r"\d", t) else t for t in text.split(" "))


ok = True
total = {"old": 0, "new": 0, "lines": 0, "uncat": 0}
for path in files:
    a, b = run(old_w, path), run(new_w, path)
    new = {t["template"]: t for t in b["templates"]}
    total["old"] += len(a["templates"]); total["new"] += len(b["templates"]); total["lines"] += a["lines"]
    probs = []
    if a["lines"] != b["lines"]:
        probs.append(f"lines {a['lines']} != {b['lines']}")
    sums = defaultdict(int)
    for t in a["templates"]:
        g = gen(t["template"])
        if g not in new:
            if a["omitted"]["templates"] or b["omitted"]["templates"]:
                continue  # beyond `top`: not reported either way
            probs.append(f"split or lost: {t['template'][:80]!r} -> {g[:80]!r}")
            continue
        sums[g] += t["count"]
        n = new[g]
        # old slot i is new slot j: the j-th <*> of g that was a <*> in the old text
        old_tok, pos = t["template"].split(" "), [i for i, x in enumerate(g.split(" ")) if x == "<*>"]
        was = [k for k, i in enumerate(pos) if old_tok[i] == "<*>"]
        for i, j in enumerate(was):
            if i < len(t["params"]) and n["params"][j]["distinct"] < t["params"][i]["distinct"]:
                probs.append(f"fewer values: {g[:60]!r} slot {j}")
            if i < len(t["params"]) and t["params"][i].get("categorical") and not n["params"][j].get("categorical") and n["params"][j]["distinct"] <= 12:  # label rule
                total["uncat"] += 1
                print(f"  {path.split('/')[-1]}: no longer categorical: {g[:70]!r} p{j} "
                      f"{[v[0] for v in n['params'][j]['values']][:6]}")
    for g, s in sums.items():
        if s != new[g]["count"] and not (a["omitted"]["templates"] or b["omitted"]["templates"]):
            probs.append(f"count {s} != {new[g]['count']}: {g[:60]!r}")
    print(f"{path}: lines {a['lines']}, templates {len(a['templates'])} -> {len(b['templates'])}"
          + ("" if not probs else "\n    " + "\n    ".join(probs[:10])))
    ok &= not probs
print("TOTAL", total, "OK" if ok else "PROBLEMS")
sys.exit(0 if ok else 1)
