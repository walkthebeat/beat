"""Betterleaks' rules -> probe/rules/betterleaks.json, the rules gate 1 compiles (docs/security.md).

    python3 probe/rules/convert.py [--input betterleaks.toml] [--commit SHA]

Without --input, config/betterleaks.toml is fetched at the pinned commit. Kept per rule: id, regex, keywords,
confidence, the secret's group, and the filter terms this file can translate. Betterleaks filters are CEL; a filter
rejects a match when any term of its top-level `||` is true. Only three forms of term are translated:
    entropy(finding["secret"]) <= N              -> max_entropy
    matchesAny(finding["secret"], [`re`, ...])   -> reject_regex
    containsAny(finding["secret"], ["s", ...])   -> reject_contains
Every other term is dropped and counted. Dropping a term of a disjunction can only reject less, so the sensor masks
or flags more than Betterleaks would, never less. A term that is a `let` block is dropped whole, for the same reason.
Also dropped: rules restricted to a path (the sensor does not know a value's file at emit), and rules with no regex.
skipReport rules (parts of composite rules: client ids, endpoints) are kept as "low": a flag, never a mask.
"""
from __future__ import annotations

import argparse
import collections
import json
import re
import sys
import tomllib
import urllib.request
from pathlib import Path

COMMIT = "c613797a684337a014168063577bb6fa6e3b6296"
URL = "https://raw.githubusercontent.com/betterleaks/betterleaks/{}/config/betterleaks.toml"
OUT = Path(__file__).with_name("betterleaks.json")

ENTROPY = re.compile(r'^entropy\(finding\["secret"\]\)\s*<=?\s*([\d.]+)$')
LIST = re.compile(r'^(matchesAny|containsAny)\(finding\["secret"\],\s*\[(.*)\]\)$', re.S)


def strip_comments(f: str) -> str:
    return "\n".join(line for line in f.splitlines() if not line.strip().startswith("//"))


def split_top(expr: str, sep: str = "||") -> list[str]:
    """Splits on `sep` outside brackets, quotes and backticks."""
    parts, depth, quote, start, i = [], 0, "", 0, 0
    while i < len(expr):
        c = expr[i]
        if quote:
            if c == "\\" and quote != "`":
                i += 2
                continue
            if c == quote:
                quote = ""
        elif c in "\"'`":
            quote = c
        elif c in "([{":
            depth += 1
        elif c in ")]}":
            depth -= 1
        elif depth == 0 and expr.startswith(sep, i):
            parts.append(expr[start:i])
            start = i + len(sep)
            i += len(sep)
            continue
        i += 1
    parts.append(expr[start:])
    return [p.strip() for p in parts if p.strip()]


def unwrap(term: str) -> str:
    while term.startswith("(") and term.endswith(")") and len(split_top(term[1:-1])) and _balanced(term[1:-1]):
        term = term[1:-1].strip()
    return term


def _balanced(s: str) -> bool:
    depth = 0
    for c in s:
        depth += c in "([{"
        depth -= c in ")]}"
        if depth < 0:
            return False
    return depth == 0


def items(body: str) -> list[str]:
    out = []
    for raw in split_top(body, ","):
        raw = raw.strip()
        if raw[:1] == "`" and raw[-1:] == "`":
            out.append(raw[1:-1])
        elif raw[:1] == '"' and raw[-1:] == '"':
            out.append(json.loads(raw))
        else:
            raise ValueError(raw)
    return out


def translate(f: str, dropped: collections.Counter) -> dict:
    out = {"max_entropy": None, "reject_regex": [], "reject_contains": []}
    f = strip_comments(f or "").strip()
    if not f:
        return out
    stack = [f]
    while stack:
        term = unwrap(stack.pop())
        if re.match(r"let\b", term):
            dropped["let block"] += 1
            continue
        sub = split_top(term)
        if len(sub) > 1:
            stack.extend(sub)
            continue
        if m := ENTROPY.match(term):
            out["max_entropy"] = max(out["max_entropy"] or 0.0, float(m.group(1)))
        elif m := LIST.match(term):
            try:
                vals = items(m.group(2))
            except (ValueError, json.JSONDecodeError):
                dropped["unparsed list"] += 1
                continue
            out["reject_regex" if m.group(1) == "matchesAny" else "reject_contains"] += vals
        else:
            dropped[re.match(r"[\w!]*", term).group(0) or term[:20]] += 1
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--input", type=Path)
    ap.add_argument("--commit", default=COMMIT)
    a = ap.parse_args()
    raw = a.input.read_bytes() if a.input else urllib.request.urlopen(URL.format(a.commit)).read()
    cfg = tomllib.loads(raw.decode())
    dropped: collections.Counter = collections.Counter()
    rules, skipped = [], collections.Counter()
    for r in cfg["rules"]:
        if not r.get("regex"):
            skipped["no regex"] += 1
            continue
        if r.get("path"):
            skipped["restricted to a path"] += 1
            continue
        rules.append({
            "id": r["id"], "regex": r["regex"], "keywords": [k.lower() for k in r.get("keywords", [])],
            "confidence": "low" if r.get("skipReport") else r["confidence"],
            "group": int(r["valueGroup"]) if r.get("valueGroup") else None,
            **translate(r.get("filter", ""), dropped),
        })
    glob = translate(cfg.get("filter", ""), dropped)
    doc = {"source": f"betterleaks {URL.format(a.commit)}", "license": "MIT, LICENSE.betterleaks",
           "generated_by": "probe/rules/convert.py", "global": glob, "rules": rules}
    OUT.write_text(json.dumps(doc, indent=0, ensure_ascii=False) + "\n")
    conf = collections.Counter(r["confidence"] for r in rules)
    print(f"{len(rules)} rules ({dict(conf)}); skipped {dict(skipped)}", file=sys.stderr)
    print(f"filter terms dropped: {dict(dropped.most_common())}", file=sys.stderr)
    print(f"translated: {sum(r['max_entropy'] is not None for r in rules)} entropy, "
          f"{sum(bool(r['reject_regex'] or r['reject_contains']) for r in rules)} reject lists", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
