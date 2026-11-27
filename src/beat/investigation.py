"""Investigations from the client: `beat investigate` and the MCP's `investigate` and `investigations` tools, thin
clients of the service's investigation.* methods.

An investigation is what someone decided to find out ("why are orders slow?"); the surveys asked for it carry it and
a why (the hypothesis each tests); it concludes with a claim. Investigations form a DAG: a sub-question is part of
one or more headings. Discovery ("what runs here?") is one too, a root of its own kind.

Without an agent, the CLI keeps a current investigation per working directory, as a stack: `start` opens one under
the current and makes it current, `end` concludes it (or leaves it open) and returns to its parent, and every
`beat ask` in between is asked for the current one. BEAT_INVESTIGATION names one instead. Agents name theirs in each
call: no hidden state, so one agent may work several branches at once.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

ENV = "BEAT_INVESTIGATION"
WHY_ENV = "BEAT_WHY"  # `beat run --why`, `beat probes run --why`


def _file(cwd: Path | None = None) -> Path:
    base = Path(os.environ.get("XDG_STATE_HOME") or Path.home() / ".local" / "state") / "beat" / "investigations"
    here = str((cwd or Path.cwd()).resolve())
    return base / (hashlib.sha256(here.encode()).hexdigest()[:16] + ".json")


def stack(cwd: Path | None = None) -> list[str]:
    try:
        return list(json.loads(_file(cwd).read_text()).get("stack") or [])
    except (OSError, ValueError):
        return []


def _save(ids: list[str], cwd: Path | None = None) -> None:
    f = _file(cwd)
    if not ids:
        f.unlink(missing_ok=True)
        return
    f.parent.mkdir(parents=True, exist_ok=True)
    f.write_text(json.dumps({"cwd": str((cwd or Path.cwd()).resolve()), "stack": ids}) + "\n")


def current(cwd: Path | None = None) -> str | None:
    """The investigation a `beat ask` here is asked for: BEAT_INVESTIGATION, else the top of this directory's stack."""
    return os.environ.get(ENV) or (stack(cwd) or [None])[-1]


def intent() -> dict | None:
    """What `beat run` and `beat probes run` ask for: the current investigation (`--investigation` sets
    BEAT_INVESTIGATION) and BEAT_WHY (`--why`)."""
    iid, why = current(), os.environ.get(WHY_ENV)
    iid = None if iid == "none" else iid
    return {"investigation": iid, "why": why} if iid or why else None


def push(iid: str, cwd: Path | None = None) -> None:
    _save([*stack(cwd), iid], cwd)


def pop(iid: str, cwd: Path | None = None) -> str | None:
    """Takes `iid` off this directory's stack (wherever it is); returns the new current one."""
    ids = [i for i in stack(cwd) if i != iid]
    _save(ids, cwd)
    return ids[-1] if ids else None


def lines(node: dict, indent: str = "") -> list[str]:
    """An investigation's subgraph as text: each node, its surveys with their why, its conclusion, then its children."""
    state = node.get("state", "?")
    out = [f"{indent}{node['id']}  {node.get('kind')}  {state}  {node.get('text')}"]
    for s in node.get("surveys") or []:
        why = f"  why: {s['why']}" if s.get("why") else ""
        out.append(f"{indent}  survey {s['survey_id']}  {s.get('probe') or '?'}  {s.get('ok', 0)}/{s.get('targets', 0)} ok"
                   f"{why}")
    for c in node.get("claims") or []:
        mark = "concludes" if c.get("concludes") else "claim"
        out.append(f"{indent}  {mark} {c['id']} ({c.get('kind')}): {c.get('text')}")
    for ch in node.get("children") or []:
        out += lines(ch, indent + "    ")
    if node.get("children_not_shown"):
        out.append(f"{indent}    ... {node['children_not_shown']} more below (--depth)")
    return out
