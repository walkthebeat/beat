"""Asking a question (docs/protocol.md), as a client of the collector: the collector prepares the survey
(survey.prepare: its id, targets, deadline and key), the client signs the envelope with its member key and credential
(seal.py: only a member of the org asks), and the collector relays it (survey.start: it announces the survey and publishes the question), stores what
comes back and decides when the survey is over (collector.py, Store.tick). The asker never sees an answer before it is
stored.

Everything goes to the service over HTTP (`beat-service serve`, serve.py, at wire.api_url(): BEAT_API or `beat login URL`): the client is never on NATS.
Waiting here is for the person or agent asking: polling survey.status (counts, no content) until the survey is
sealed, past the deadline too while the collector is catching up (it decides late, never wrong: C25); then the answers
are read from the store, grouped by answer hash (categorization v0), with the targets that did not answer: down (no
fresh heartbeat), up with no answer (a finding: an up sensor answers), or not decided yet when the caller stopped
waiting. `standing` says what those counts point at, in words.
"""
from __future__ import annotations

import asyncio
import difflib
import getpass
import http.client
import json
import os
import shutil
import socket
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path


from . import estate, login, seal, wire

async def sensors(untrusted: bool = False) -> dict[str, dict]:
    """The directory: live sensors by name, the trusted ones (enrolled and fresh, as the service checks them:
    collector.py `directory`); `untrusted`: the others too, with the reason in their "untrusted" field."""
    return await api("sensors.list", {"untrusted": untrusted})


async def guide() -> str | None:
    """The builtins guide a trusted live sensor published (agents see it as the `run` tool's text): guide.get."""
    try:
        return (await api("guide.get"))["guide"]
    except Exception:
        return None


def asker(via: str) -> dict:
    """Who asks, as surveys record it: user@host (asserted, not authenticated yet), the tool, the directory."""
    return {"user": f"{getpass.getuser()}@{socket.gethostname()}", "via": via,
            "cwd": os.getcwd().replace(os.path.expanduser("~"), "~", 1)}


def not_live_reason(host: str, live: list[str]) -> str:
    """Why a host cannot answer, for people: no live sensor by that name, and the live names it resembles."""
    close = difflib.get_close_matches(host, live, n=3, cutoff=0.6)
    return (f"no live sensor named {host!r}" + (f" (did you mean {' or '.join(close)}?)" if close else "")
            + "; see `beat sensors`")


async def ask(name: str, source: str, hosts: list[str] | None = None, timeout: int = 120,
              via: str = "beat ask", wait: float | None = None, profile: bool = False) -> dict:
    """Asks every live sensor, or only `hosts`, through the collector, and waits until the survey is sealed (or
    `wait` seconds; without `wait`, past the deadline for as long as the collector is catching up, up to LATE_S).
    Returns the survey: id, question hash, expected, answers {target: {answer_hash, outcome, started, finished,
    sensor, answer}}, down, no_answer, running (not decided when the wait ended), not_live (expected hosts with no
    directory entry when asked: down from the start), live, sealed, behind (the collector's backlog, messages) and
    standing (what it all says, ask.standing). `profile`: each host times every host call (Beat-Profile, signed
    with the question); an answer's profiled calls are taken out of its records into its `profile` (split_profile)."""
    estate.pin_on_first_use()
    try:
        key, cred = seal.member()
    except seal.Refused as e:  # no credential here, or expired (no root on this machine): `beat creds init`
        raise RuntimeError(str(e)) from None
    r = await api("survey.prepare", {"name": name, "source": source, "targets": hosts or None,
                                     "timeout": timeout, **({"profile": True} if profile else {}), **asker(via)}, 30)
    survey = r["survey"]
    signature = sign_envelope(key, r["headers"], wire.question(name, source), survey, timeout, hosts, cred, profile)
    await api("survey.start", {"survey": survey, "signature": signature, "credential": cred}, 30)
    until = time.time() + (wait if wait is not None else
                           max(0.0, wire_time(r["deadline"]) - time.time()) + 5)
    last = settled = None  # past `until`: the collector's backlog at the previous check; when it was gone
    while True:
        st = await api("survey.status", {"survey": survey})
        if st["sealed"]:
            break
        now, behind = time.time(), (st.get("collector") or {}).get("behind") or 0
        if now >= until:  # past the deadline: wait on only while the collector is behind and catching up
            if wait is not None or now >= until + LATE_S:
                break
            if behind:
                if last is not None and behind >= last:
                    break  # not catching up
                last, settled = behind, None
            elif last is None:
                break  # never behind: nothing more to wait for
            else:  # caught up: it seals at its next idle check (collector: fetch's 2 s)
                settled = settled or now
                if now - settled > SETTLE_S:
                    break
        await asyncio.sleep(POLL_S)
    g = await api("survey.get", {"survey": survey})
    blobs: dict[str, dict] = {}
    answers = {}
    for t in g["targets"]:
        h = t["answer_hash"]
        if not h:
            continue
        if h not in blobs:
            blobs[h] = json.loads(await blob(h) or b"null")
        answers[t["target"]] = {"answer_hash": h, "outcome": t["outcome"], "started": t["started"],
                                "finished": t["finished"], "sensor": t["sensor_version"], "answer": blobs[h]}
        if t.get("phases"):  # where its time went (Beat-Phases): an older service or sensor has none
            answers[t["target"]]["phases"] = t["phases"]
        if profile and blobs[h]:
            answers[t["target"]]["answer"], answers[t["target"]]["profile"] = split_profile(blobs[h])
    by = lambda *states: [t["target"] for t in g["targets"] if t["outcome"] in states]  # noqa: E731
    out = {"survey": survey, "question": r["question"], "expected": r["expected"], "answers": answers,
           "down": by("down"), "no_answer": by("no_answer"), "running": by("pending", "running"),
           "not_live": r["not_live"], "live": r["live"], "sealed": bool(g["survey"].get("sealed_at")),
           "behind": (g.get("collector") or {}).get("behind") or 0,
           "maybe_lost": [t["target"] for t in g["targets"] if t.get("maybe_lost")]}
    if g.get("service_loss"):
        out["service_loss"] = g["service_loss"]
    counts: dict = {}
    for t in g["targets"]:
        counts[t["outcome"]] = counts.get(t["outcome"], 0) + 1
    out["standing"] = standing(counts, out["sealed"], out["behind"], out.get("service_loss"))
    return out


def sign_envelope(key, headers: dict, q: bytes, survey: str, timeout: int, hosts: list[str] | None,
                  cred: str, profile: bool = False) -> str:
    """The member's signature over a prepared envelope with its credential added (Beat-Cred, H16), once it says what
    was asked: this question (by its hash), these targets (none: every sensor), this time limit. The collector picks
    the rest (id, key, times). Beat-Profile only when the member asked for it."""
    want = {"Beat-Survey": survey, "Beat-Question": wire.sha256_hex(q), "Beat-Timeout": str(timeout),
            "Beat-Targets": ",".join(sorted(set(hosts))) if hosts else None, "Beat-Profile": "1" if profile else None}
    for k, v in want.items():
        if headers.get(k) != v:
            raise RuntimeError(f"the collector prepared {k} {headers.get(k)!r}, not {v!r}: not signed")
    unknown = set(headers) - set(want) - {"Beat-Key", "Beat-Issued", "Beat-Deadline"}
    if unknown:
        raise RuntimeError(f"the collector prepared headers the client does not sign: {', '.join(sorted(unknown))}")
    return seal.sign(key, "ask", {**headers, "Beat-Cred": cred}, q)["Beat-Signature"]


def wire_time(iso: str) -> float:
    """'2026-10-14T19:26:02Z' as epoch seconds."""
    import calendar
    return calendar.timegm(time.strptime(iso, "%Y-%m-%dT%H:%M:%SZ"))


POLL_S = 0.5   # how often `ask` asks survey.status while it waits
LATE_S = 300   # how long `ask` waits past the deadline for a collector that is behind but catching up
SETTLE_S = 5   # and once it has caught up, for the seal (it decides at its next idle check, within 2 s)


def standing(counts: dict, sealed: bool, behind: int = 0, service_loss: dict | None = None) -> list[str]:
    """What a survey's outcome counts say, in words, for people and agents (C25). An up sensor answers, so every one
    that did not is a finding. Where a pattern of them points: many at once (a tenth of the targets or more, a default
    to revise with data) points at beat or the bus before the hosts; many down at once at the estate. `service_loss`:
    the service dropped messages unread while the survey was open (H23), whatever the count: that points at beat."""
    n = sum(counts.values())
    undecided = counts.get("pending", 0) + counts.get("running", 0)
    no_answer = counts.get("no_answer", 0) + counts.get("silent", 0) + counts.get("lost", 0)  # the last two: pre-C25
    down = counts.get("down", 0)
    many = lambda k: k >= max(3, n / 10)  # noqa: E731
    out = []
    if not sealed:
        out.append(f"not complete: {undecided} of {n} targets not decided yet"
                   + (f"; the collector is {behind} messages behind (it decides late, never wrong): this is beat, "
                      "not the hosts; wait and read the survey again" if behind else
                      "; read the survey again after its deadline"))
    if no_answer:
        out.append(f"{no_answer} of {n} up (heartbeating) but did not answer by the deadline: an up sensor answers, "
                   "so each is a finding to investigate"
                   + (f"; the service dropped {service_loss.get('messages_dropped', 'some')} messages unread while this "
                      "survey was open, and theirs may be among them: this points at beat: ask again before looking "
                      "into those hosts" if service_loss else
                      "; this many at once points at beat (the bus, the sensors' queues) before the hosts"
                      if many(no_answer) else "; look at those sensors and their hosts (load, the sensor's queue)"))
    if down:
        out.append(f"{down} of {n} down (no fresh heartbeat in the directory)"
                   + ("; this many at once points at the estate (network, power, a rack)" if many(down) else ""))
    return out


def secret_walk_note(walk: dict | None) -> str:
    """What a heartbeat's `secret_walk` needs a reader to know, or "": nothing when it covered all it should. Skipped
    or cut trees were not looked in for secret files (docs/security.md)."""
    if not walk:
        return ""
    parts = []
    if walk.get("error"):
        parts.append(f"walk failing: {walk['error']}")
    elif not walk.get("at"):
        parts.append("first walk not finished")
    if walk.get("cut"):
        parts.append(f"walk cut short: {walk['cut']}")
    for name, key in (("not looked in", "skipped"), ("not covered", "uncovered")):
        if walk.get(key):  # skipped: [path, why] pairs; uncovered: paths
            parts.append(f"{name}: " + ", ".join(f"{i[0]} ({i[1]})" if isinstance(i, list) else str(i) for i in walk[key]))
    return "; ".join(parts)


def phases(text: str | None) -> dict[str, int]:
    """Beat-Phases as {step: value}: milliseconds, but `*_calls` (counts) and `*_bytes` (docs/protocol.md)."""
    out = {}
    for part in (text or "").split(","):
        k, _, v = part.partition("=")
        if k and v.lstrip("-").isdigit():
            out[k] = int(v)
    return out


def phases_line(text: str | None) -> str:
    """Where a host's time went, in one line: the sensor's steps, then beat-probe's, then its builtins by time."""
    p = phases(text)
    if not p:
        return ""
    sensor = [k for k in ("queue", "secrets", "needs", "prepare", "unit", "seal") if k in p]
    probe = [k for k in ("tools", "compile", "eval", "mask", "probe") if k in p]
    builtins = sorted((k for k in p if f"{k}_calls" in p), key=lambda k: -p[k])
    out = f"run {p.get('run', 0)} ms: " + ", ".join(f"{k} {p[k]}" for k in sensor)
    if probe:
        out += "; beat-probe: " + ", ".join(f"{k} {p[k]}" for k in probe)
    if builtins:
        out += "; " + ", ".join(f"{k} {p[k]} ({p[k + '_calls']} calls)" for k in builtins)
    if "cpu" in p:
        out += f"; cpu {p['cpu']} + children {p.get('cpu_children', 0)}"
    return out + (" (retried without placeholders)" if p.get("retry") else "")


def split_profile(answer: dict) -> tuple[dict, list[dict]]:
    """A profiled answer's own records, and its profiled calls (beat-probe --profile: `beat:profile:<builtin>#<rank>`
    records) as [{builtin, ms, call, failed}], slowest first. The calls are about beat, not the host: they stay out of
    the facts an estate keeps."""
    own, calls = [], {}
    for r in answer.get("records") or []:
        subject = str(r.get("subject", ""))
        if not subject.startswith("beat:profile"):
            own.append(r)
            continue
        builtin, _, rank = subject.removeprefix("beat:profile:").partition("#")
        if rank:
            c = calls.setdefault(rank, {"builtin": builtin, "ms": 0, "call": "", "failed": False})
            if r.get("key") == "ms":
                c["ms"] = int(r.get("value") or 0)
            elif r.get("key") == "call":
                c["call"] = r.get("value", "")
            elif r.get("key") == "failed":
                c["failed"] = True
    return {**answer, "records": own}, [calls[k] for k in sorted(calls)]


def why_not(survey: dict, host: str) -> str:
    """Why `host` has no answer in `survey`, for people."""
    if host in survey.get("not_live", []):
        return "down: " + not_live_reason(host, survey.get("live", []))
    if host in survey.get("maybe_lost", []):
        return ("up (heartbeating) with no recorded answer, and the service dropped messages unread while this survey "
                "was open: its answer may be among them. This points at beat, not the host: ask again before looking "
                "into it")
    if host in survey.get("no_answer", []):
        return ("up (heartbeating) but did not answer by the deadline: an up sensor answers, so this is a finding: "
                "look at the sensor and the host (its load, the sensor's queue)")
    if host in survey.get("running", []):
        return ("not decided when the wait ended" + (f" (the collector is {survey['behind']} messages behind)"
                                                     if survey.get("behind") else "")
                + ": its answer will be in the survey (beat survey show)")
    return "down: no fresh heartbeat in the directory by the deadline (the sensor stopped, or cannot reach the bus)"


def categories(survey: dict) -> list[dict]:
    """Answers grouped by hash: equal answers are one category. Largest first; not answering is its own category."""
    groups: dict[str, dict] = {}
    for target, a in survey["answers"].items():
        g = groups.setdefault(a["answer_hash"], {"answer_hash": a["answer_hash"], "outcome": a["outcome"],
                                                 "targets": [], "answer": a["answer"]})
        g["targets"].append(target)
    out = sorted(groups.values(), key=lambda g: (-len(g["targets"]), g["answer_hash"]))
    not_live = set(survey.get("not_live", []))
    for outcome, targets in (("no_answer", survey.get("no_answer", [])),
                             ("down", [t for t in survey.get("down", []) if t not in not_live]),
                             ("running", survey.get("running", []))):
        if targets:
            out.append({"answer_hash": None, "outcome": outcome, "targets": targets, "answer": None,
                        "why": [why_not(survey, targets[0])]})
    gone = [t for t in survey.get("down", []) if t in not_live]
    if gone:
        out.append({"answer_hash": None, "outcome": "down", "targets": gone, "answer": None,
                    "why": [why_not(survey, t) for t in gone]})
    return out


async def api(method: str, params: dict | None = None, timeout: float = 10) -> dict:
    """One call to the control plane's API (api.py, served by the collector, reached through serve.py). Raises
    RuntimeError on an error reply, or when the service does not answer."""
    status, data = await asyncio.to_thread(_http, f"/v1/{method}?timeout={timeout:g}", json.dumps(params or {}).encode(),
                                           timeout)
    try:
        r = json.loads(data)
    except ValueError:
        raise RuntimeError(f"the service replied {status} to {method}: {data[:200]!r}") from None
    if "error" in r:
        raise RuntimeError(r["error"])
    return r


async def whoami() -> dict:
    """The caller's login as the service checked it (GET /v1/whoami)."""
    status, data = await asyncio.to_thread(_http, "/v1/whoami", None, 10)
    try:
        return json.loads(data)
    except ValueError:
        raise RuntimeError(f"the service replied {status} to whoami: {data[:200]!r}") from None


async def sql(text: str, timeout: float = 10) -> dict:
    """SQL on the collector's store (beat.cp.sql through serve.py): {columns, rows} or {error}."""
    status, data = await asyncio.to_thread(_http, f"/v1/sql?timeout={timeout:g}", text.encode(), timeout)
    try:
        return json.loads(data)
    except ValueError:
        return {"error": f"the service replied {status}: {data[:200]!r}"}


async def blob(h: str) -> bytes | None:
    """A blob from the content store by its hash (beat.cp.blob through serve.py); None when there is none."""
    status, data = await asyncio.to_thread(_http, f"/v1/blob/{h}", None, 30)
    return data if status == 200 else None


def _http(path: str, body: bytes | None, timeout: float, method: str | None = None) -> tuple[int, bytes]:
    """A request to the service, with the login's access token (login.py): POST with a body, else GET or `method`; (status,
    body), an HTTP error's too. Raises RuntimeError when not signed in, or when the service refuses the login."""
    headers = {"Authorization": f"Bearer {login.access_token()}"}
    if body is not None:
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(wire.api_url() + path, data=body, method=method or ("GET" if body is None else "POST"),
                                 headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout + 10) as r:
            return r.status, r.read()
    except urllib.error.HTTPError as e:
        data = e.read()
        if e.code in (401, 403):
            try:
                raise RuntimeError(json.loads(data)["error"]) from None
            except (ValueError, KeyError):
                raise RuntimeError(f"the service refused the login ({e.code})") from None
        return e.code, data
    except OSError as e:  # URLError: refused, no route, DNS; a timeout
        api, why = wire.api_source()
        raise RuntimeError(f"the beat service is not answering at {api} ({why}; `beat login URL` changes it): "
                           f"{getattr(e, 'reason', e)}") from None


async def dataset(name: str, source: str, hosts: list[str] | None = None, timeout: int = 120,
                  via: str = "beat ask") -> dict:
    """A question asked of the fleet, answered as a pointer to its dataset (the service's dataset.get): where
    the survey's tables are and their shape, the outcomes counted; never the answers themselves."""
    s = await ask(name, source, hosts, timeout, via=via)
    if not s["answers"]:
        return {"survey": s["survey"], "asked": len(s["expected"]), "note": "no host answered"}
    return await with_live(await fetch(await api("dataset.get", {"survey": s["survey"]}, timeout=120)))


def dataset_standing(p: dict) -> dict:
    """The pointer with `standing` (ask.standing): whether the dataset is complete, and what its outcomes point at."""
    if "outcomes" in p:
        p["standing"] = standing(p["outcomes"], p.get("sealed", False), (p.get("collector") or {}).get("behind") or 0,
                                p.get("service_loss"))
    return p


NEXT = ("Analyse it as a dataset: load the tables (duckdb: select * from '{dir}/hosts.parquet'; pandas.read_parquet), "
        "describe them, group the hosts, compare the groups. `records` is every record in long form (host, subject, "
        "key, value); `run` one host only to confirm what the data shows. Before asking more hosts, look at `cost`: "
        "what this probe takes per host, and what it would take for every host.")


def cache_dir() -> Path:
    """Where downloaded datasets are kept: $XDG_CACHE_HOME/beat/datasets (default ~/.cache/beat/datasets)."""
    return Path(os.environ.get("XDG_CACHE_HOME") or Path.home() / ".cache") / "beat" / "datasets"


async def fetch(p: dict) -> dict:
    """Downloads a dataset.get pointer's files (its signed links) into the cache; the pointer then says where they are
    (`dataset`). A sealed survey's files already there, whole (same `written_at`, the sizes it states), are not
    downloaded again. The cache takes a dataset only when every file arrived whole, or not at all."""
    if "links" not in p:
        return p
    return await asyncio.to_thread(_fetch, p)


class _Short(Exception):
    """A download that ended early: a body shorter than the size stated for it."""


def _size(p: dict, name: str) -> int | None:
    """The size a sealed survey's pointer states for a file: final, as its files are. None when it states none (a
    pointer from an older service), or for an open survey, whose files a later dataset.get may write again."""
    if not p.get("sealed"):
        return None
    return ((p.get("tables") or {}).get(name.removesuffix(".parquet")) or {}).get("bytes")


def _whole(p: dict, d: Path) -> bool:
    """Whether a sealed survey's cached dataset is the one the pointer describes, with every file its stated size.
    A file cut short by an older client, kept as if complete, fails this and is downloaded again."""
    try:
        if json.loads((d / "dataset.json").read_text())["written_at"] != p["written_at"]:
            return False
        for name in p.get("tables") or {}:
            have, size = (d / f"{name}.parquet").stat().st_size, _size(p, f"{name}.parquet")
            if size is not None and have != size:
                return False
        return True
    except (OSError, ValueError, KeyError):
        return False


def _download(url: str, path: Path, size: int | None) -> None:
    """One file. A dropped connection ends a sized body with no error from urllib, so the bytes are counted, against
    the response's Content-Length and the size the pointer states: _Short when they differ."""
    with urllib.request.urlopen(url, timeout=120) as r, open(path, "wb") as out:
        shutil.copyfileobj(r, out)
        got, length = out.tell(), r.headers.get("Content-Length")
    for what, want in (("Content-Length", int(length) if length and length.isdigit() else None), ("the pointer", size)):
        if want is not None and got != want:
            raise _Short(f"got {got} bytes, {what} says {want}")


def _fetch(p: dict) -> dict:
    links = p.pop("links")
    p.pop("expires", None)
    d = cache_dir() / p["survey"]
    p = dict(p, dataset=str(d), next=NEXT.format(dir=d))
    if p.get("sealed") and _whole(p, d):
        return p
    tmp = d.with_name(d.name + ".tmp")
    shutil.rmtree(tmp, ignore_errors=True)
    tmp.mkdir(parents=True)
    try:
        for name, url in links.items():
            # A link is a path on the service (resolved against the service's URL), or a URL of its own
            url = urllib.parse.urljoin(wire.api_url() + "/", url)
            try:
                try:
                    _download(url, tmp / name, _size(p, name))
                except urllib.error.HTTPError:
                    raise  # the service's answer (403 bad link, 410 expired, 503): the same again
                except (_Short, OSError, http.client.HTTPException):  # the connection dropped: once more
                    _download(url, tmp / name, _size(p, name))
            except (_Short, OSError, http.client.HTTPException) as e:  # no datasets service, too
                raise RuntimeError(f"downloading {name} of {p['survey']} failed: {e}") from None
        (tmp / "dataset.json").write_text(json.dumps(p, indent=1) + "\n")
        shutil.rmtree(d, ignore_errors=True)
        tmp.rename(d)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    return p


async def with_live(p: dict) -> dict:
    """The pointer with `live`: how many sensors the directory has now, so its cost can be read for the whole estate
    (the store knows the hosts asked, not the estate); and `standing`."""
    dataset_standing(p)
    if "dataset" in p:
        try:
            p["live"] = len(await sensors())
        except Exception:
            pass
    return p


async def report(name: str, source: str, hosts: list[str] | None = None, timeout: int = 120, history: int = 3,
                 records: bool = False, via: str = "beat ask") -> dict:
    """A question asked of the fleet, answered as the comparison rather than the raw answers (MCP `survey`,
    `beat ask --analyze`): who answered what (categories by answer hash, with record counts and errors), the
    analysis across the hosts (analysis.get: groups, dimensions, rare values, inconsistencies, drift since this
    question's previous survey) and, when the probe emitted log summaries, the logs compared across hosts with a
    proposed curated template set (logs.get). Raw records only with `records`."""
    s = await ask(name, source, hosts, timeout, via=via)
    out: dict = {"survey": s["survey"], "asked": s["expected"], "answers": []}
    if s.get("standing"):
        out["standing"] = s["standing"]
    for c in categories(s):
        a = c["answer"] or {}
        row = {"hosts": sorted(c["targets"]), "outcome": c["outcome"], "records": len(a.get("records") or [])}
        if a.get("error"):
            row["error"] = a["error"]
        if a.get("failures"):
            row["failures"] = a["failures"]
        if c.get("why"):
            row["why"] = c["why"]
        if records and a:
            row["answer"] = a
        out["answers"].append(row)
    if not s["answers"]:
        return out
    a = await api("analysis.get", {"survey": s["survey"], "history": history})
    out["analysis"] = a["analysis"]
    out["history_surveys"] = a["history_surveys"]
    if "drift" in a:
        out["drift"] = a["drift"]
    logs = (await api("logs.get", {"survey": s["survey"]}))["logs"]
    if logs:
        out["logs"] = logs
    return out
