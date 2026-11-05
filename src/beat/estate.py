"""The estate repository: a git repo where each host is a directory of files with clear provenance.

  hosts/<host>/facts/       observed: written only by `beat run <probe> <hosts>` (a survey's answers)
  hosts/<host>/model.md     interpreted: written by the agent during discovery, approved by a person
  hosts/<host>/questions.md what the agent could not tell; a person answers with annotations
  annotations/*.md          stated by people (through the agent or by hand), each with the hosts it applies to
  probes/*.star             collection code: written by the agent during discovery, approved by a person

Probes come from the estate's probes/ and, after it, beat's default pack (pack/: probes for any Linux host,
installed with beat and read-only, so its fixes reach every estate with `uv tool upgrade walkthebeat`). A probe of the estate
wins over the pack's of the same name; `beat probes fork <name>` makes the pack's the estate's, to change it.

`beat init <dir>` creates it from estate_template/ (CLAUDE.md, .mcp.json, the discover skill, the investigator
subagent). `beat run <probe> <hosts>` asks the probe of the hosts in one survey and commits each host's records only
if they changed, so `git log -p hosts/<host>/facts/` is the host's drift history: no timestamps or other per-run
values in them, so an unchanged host gives no diff.
"""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path


TEMPLATE = Path(__file__).parent / "estate_template"
PACK = Path(__file__).parent / "pack"
FORKED = "# Forked from beat's default pack"

class EstateError(Exception):
    pass


def root() -> Path:
    """The estate repository containing the working directory (it has hosts/ and probes/)."""
    here = Path.cwd().resolve()
    for d in (here, *here.parents):
        if (d / "hosts").is_dir() and (d / "probes").is_dir():
            return d
    raise EstateError("not inside an estate repository (no hosts/ + probes/ here or above); see `beat init`")


# beat's own commits (init, run results) when git knows no one here: a machine with no user.name or user.email
# would refuse them. Only for that commit (git -c), so the person's own identity, once set, is used again and nothing
# is written to their configuration.
FALLBACK_IDENTITY = ("-c", "user.name=beat", "-c", "user.email=beat@localhost")


def _git(repo: Path, *args: str, check: bool = True) -> str:
    pre: tuple[str, ...] = ()
    if args[:1] == ("commit",) and subprocess.run(["git", "-C", str(repo), "var", "GIT_COMMITTER_IDENT"],
                                                  capture_output=True).returncode != 0:
        pre = FALLBACK_IDENTITY
    p = subprocess.run(["git", "-C", str(repo), *pre, *args], capture_output=True, text=True)
    if check and p.returncode != 0:
        raise EstateError(f"git {' '.join(args)}: {p.stderr.strip()}")
    return p.stdout


def init(target: Path) -> None:
    target = target.resolve()
    if target.exists() and any(target.iterdir()):
        raise EstateError(f"{target} exists and is not empty")
    # Copy contents, not permissions: from a Nix-built beat the template is read-only.
    shutil.copytree(TEMPLATE, target, dirs_exist_ok=True, copy_function=shutil.copyfile)
    for p in (target, *target.rglob("*")):
        p.chmod(0o755 if p.is_dir() else 0o644)
    for d in ("hosts", "annotations", "probes"):
        (target / d).mkdir(exist_ok=True)
        (target / d / ".gitkeep").touch()
    # The tools this repo uses come from this beat installation: the MCP server and the CLI next to this Python.
    # The MCP server asks the beat service over HTTP (mcp.py, ask.py): the one `beat login URL` kept, so a new login
    # elsewhere moves Claude too; BEAT_API pins this estate to a service only when it is set now.
    bindir = Path(sys.executable).parent
    env = {"BEAT_API": os.environ["BEAT_API"]} if os.environ.get("BEAT_API") else {}
    mcp = {"mcpServers": {"beat": {"command": str(bindir / "beat-mcp"), "args": [], "env": env}}}
    (target / ".mcp.json").write_text(json.dumps(mcp, indent=1) + "\n")
    for f in (target / "CLAUDE.md", target / ".claude" / "skills" / "discover" / "SKILL.md",
              target / ".claude" / "skills" / "report" / "SKILL.md",
              target / ".claude" / "settings.json"):
        f.write_text(f.read_text().replace("@BEAT@", str(bindir / "beat")))
    _git(target, "init", "-q")
    _git(target, "add", "-A")
    _git(target, "commit", "-q", "-m", "beat init: empty estate")


def probe_path(repo: Path, probe: str) -> Path:
    """A probe by file path, or by name: the estate's probes/<name>.star, else the default pack's."""
    p = Path(probe)
    if p.exists() and p.suffix == ".star":
        return p.resolve()
    n = probe if probe.endswith(".star") else f"{probe}.star"
    for d in (repo / "probes", PACK):
        if (d / n).exists():
            return d / n
    raise EstateError(f"no probe {probe!r} (a .star file, probes/<name>.star, or the default pack's: `beat probes`)")


def origin(repo: Path, path: Path) -> str:
    """Where a probe comes from, as facts record it: probes/<name>.star, pack:<name>.star, or the file's path."""
    if path.parent == PACK:
        return f"pack:{path.name}"
    return str(path.relative_to(repo)) if path.is_relative_to(repo) else str(path)


def _summary(text: str) -> str:
    """A probe's first docstring line."""
    for line in text.splitlines():
        line = line.strip().strip('"').strip()
        if line and not line.startswith("#"):
            return line
    return ""


def probes(repo: Path) -> list[dict]:
    """Every probe a name finds: {name, origin ("estate", "pack", "estate, forked from the pack", "estate, over the
    pack's"), summary}, by name."""
    mine = {p.stem: p for p in (repo / "probes").glob("*.star")}
    pack = {p.stem: p for p in PACK.glob("*.star")}
    out = []
    for name in sorted(mine.keys() | pack.keys()):
        p = mine.get(name) or pack[name]
        text = p.read_text()
        where = "pack" if name not in mine else "estate" if name not in pack else (
            "estate, forked from the pack" if text.startswith(FORKED) else "estate, over the pack's")
        out.append({"name": name, "origin": where, "summary": _summary(text)})
    return out


def fork(repo: Path, name: str) -> Path:
    """The pack's probe copied into the estate's probes/, marked as forked: from now on it is the estate's (and
    the pack's upgrades no longer reach it). Not committed: the person reviews it like any change."""
    n = name if name.endswith(".star") else f"{name}.star"
    src, dst = PACK / n, repo / "probes" / n
    if not src.exists():
        raise EstateError(f"the default pack has no {n} (`beat probes`)")
    if dst.exists():
        raise EstateError(f"{dst.relative_to(repo)} exists already")
    text = src.read_text()
    sha = hashlib.sha256(text.encode()).hexdigest()[:16]
    dst.write_text(f"{FORKED} (pack:{n}, sha256 {sha}); the estate's now.\n{text}")
    return dst


def run_every(hosts: list[str], commit: bool = True, workers: int = 8) -> list[tuple[str, str | None, dict]]:
    """Every probe a name finds (`probes`), asked of the hosts at once: one survey per probe, all of them in
    flight together, then each host's facts written and committed as `run_probe` does. [(probe, survey id or None,
    {host: run_probe's result, or an EstateError})], by probe."""
    import asyncio
    from concurrent.futures import ThreadPoolExecutor
    from . import ask, seal
    repo = root()
    # Renewed once, before the threads each use them: the login, and the member credential (renewing it in each
    # thread at once would race, and could leave one thread's key with another's credential).
    asyncio.run(ask.whoami())
    seal.member()
    names = [p["name"] for p in probes(repo)]
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {n: pool.submit(ask_star, n, hosts) for n in names}
    out = []
    for n in names:  # facts and commits one at a time: git is not shared between threads
        try:
            survey, answers = futures[n].result()
        except EstateError as e:
            out.append((n, None, {h: e for h in hosts}))
            continue
        results = {}
        for h in hosts:
            try:
                results[h] = run_probe(n, h, commit=commit, answer=answers.get(h))
            except EstateError as e:
                results[h] = e
        out.append((n, survey, results))
    return out


def ask_star(probe: str, hosts: list[str]) -> tuple[str, dict]:
    """A .star probe asked of all `hosts` in one survey (ask.py), so the collector has them side by side for
    analysis.get / logs.get. (survey id, {host: answer with "seconds", or an EstateError for that host})."""
    import asyncio
    from . import ask
    path = probe_path(root(), probe)
    t0 = time.monotonic()
    s = asyncio.run(ask.ask(path.name, path.read_text(), hosts, via="beat run"))
    secs = round(time.monotonic() - t0, 2)
    out: dict = {}
    for host in hosts:
        if host not in s["answers"]:
            out[host] = EstateError(ask.why_not(s, host))
        else:
            out[host] = s["answers"][host]["answer"] | {"seconds": secs}
    return s["survey"], out


def run_probe(probe: str, host: str, commit: bool = True, answer: dict | None = None) -> dict:
    """A probe's answer from one host: its records become hosts/<host>/facts/<probe>.jsonl (sorted, one per line),
    and the run's outcome hosts/<host>/facts/<probe>.run.json. Commit both if they changed: git history is drift.
    The `answer` may come from ask_star (several hosts in one survey); else it is asked here."""
    repo = root()
    path = probe_path(repo, probe)
    script = path.read_text()
    if answer is None:
        _, answers = ask_star(probe, [host])
        answer = answers[host]
    if isinstance(answer, Exception):
        raise answer
    d = answer
    # run.json's fields from beat-probe's run result (docs/probes.md §9).
    err = d.get("error") or {}
    d = {"records": [{k: x[k] for k in ("subject", "key", "value", "source")} for x in d["records"]],
         "exit": {"ok": 0, "partial": 1}.get(d["outcome"], 3),
         "assertions_failed": [f"{f['kind']}: {f['message']} ({f['span']})" for f in d["failures"]],
         "notes": d["notes"] + ([f"error ({err.get('kind')}): {err.get('message')} ({err.get('span')})"]
                                 if err else []),
         "stderr": d.get("diag", ""), "stdout": d.get("diag", ""), "seconds": d["seconds"]}
    name = path.stem
    out = repo / "hosts" / host / "facts"
    out.mkdir(parents=True, exist_ok=True)
    recs = sorted(d["records"], key=lambda x: (x.get("subject", ""), x.get("key", ""), x.get("value", ""),
                                               x.get("source", "")))
    (out / f"{name}.jsonl").write_text("".join(json.dumps(x, sort_keys=True) + "\n" for x in recs))
    meta = {"probe": origin(repo, path),
            "probe_sha256": hashlib.sha256(script.encode()).hexdigest()[:16],
            "exit": d["exit"], "assertions_failed": d["assertions_failed"], "notes": d["notes"],
            "stderr": d["stderr"][-4000:], "records": len(recs)}
    (out / f"{name}.run.json").write_text(json.dumps(meta, indent=1) + "\n")
    result = {**meta, "seconds": d["seconds"], "stdout": d["stdout"], "commit": None,
              "path": str((out / f"{name}.jsonl").relative_to(repo))}
    if commit:
        rels = [str((out / f).relative_to(repo)) for f in (f"{name}.jsonl", f"{name}.run.json")]
        _git(repo, "add", "--", *rels)
        if subprocess.run(["git", "-C", str(repo), "diff", "--cached", "--quiet", "--", *rels]).returncode == 1:
            stat = _git(repo, "diff", "--cached", "--shortstat", "--", rels[0]).strip()
            _git(repo, "commit", "-q", "-m", f"run {name} on {host}: {len(recs)} records"
                 + (f", {stat}" if stat else "") + (f"\n\nassertions failed: {d['assertions_failed']}"
                                                    if d["assertions_failed"] else ""), "--", *rels)
            result["commit"] = _git(repo, "rev-parse", "--short", "HEAD").strip()
    return result
