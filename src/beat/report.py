"""`beat report`: telling walkthebeat that something is wrong with beat. Two parts, each with its own yes, on purpose:

  a summary   a public issue at github.com/walkthebeat/feedback, by the user's own gh (or a link they open): no token
              of ours, and nothing of their hosts in it
  a transcript (optional) to the beat service, under the org's login, gzipped: walkthebeat's staff read it. It holds
              hostnames and configuration, and the masking here catches known kinds of secret, not every secret. The
              public issue names only the report's id.

`draft` writes everything to a local directory and sends nothing: an agent may run it (the `report` skill). `send` asks
the person at the terminal, on /dev/tty, with no flag to say yes: a command with no terminal, as an agent's has none,
cannot answer, and piping `yes` into it does not reach the question. The estate's settings also deny it to agents.
"""
from __future__ import annotations

import asyncio
import datetime as dt
import gzip
import json
import math
import os
import re
import secrets
import shutil
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request
import warnings
from collections import Counter
from functools import cache
from pathlib import Path

from . import login, wire

REPO = "walkthebeat/feedback"
URL_TEXT_MAX = 4000  # GitHub takes a link of about 8 KB; encoded text can double
SEND_TIMEOUT_S = 600
NOT_ALL = ("Masking catches known kinds of secret, not every secret: read it before you send it if it could hold "
           "something that matters.")


def reports_dir() -> Path:
    return Path(os.environ.get("XDG_CACHE_HOME") or Path.home() / ".cache") / "beat" / "reports"


# --- masking: the sensor's rule files (probe/rules), by the same reading as the service's gate 2 ---

def rules_dir() -> Path | None:
    """BEAT_RULES_DIR, the rules packaged with beat, or the source tree's."""
    for d in (os.environ.get("BEAT_RULES_DIR"), Path(__file__).parent / "rules",
              Path(__file__).parents[2] / "probe" / "rules"):
        if d and sorted(Path(d).glob("*.json")):
            return Path(d)
    return None


def _python(regex: str) -> str:
    """Go's syntax as Python's re takes it: \\z, and an (?i) part-way through, which here covers the whole pattern, so
    it matches a little more, and more is masked, not less."""
    regex = regex.replace(r"\z", r"\Z")
    return "(?i)" + regex.replace("(?i)", "") if "(?i)" in regex[1:] else regex


@cache
def _rules() -> tuple[tuple, tuple, dict, int]:
    """(rules as (id, regex, reject, keywords, rule)), the global rejects, the global filters, how many could not be
    compiled by Python's re."""
    d = rules_dir()
    if d is None:
        raise RuntimeError("beat's secret rules are not in this installation, so a transcript cannot be masked: "
                           "nothing was written (BEAT_RULES_DIR: the repo's probe/rules)")
    out, glob, skipped = [], {}, 0
    warnings.simplefilter("ignore", FutureWarning)  # what Python's re says of some Go syntax it still takes
    for f in sorted(d.glob("*.json")):
        data = json.loads(f.read_text())
        glob = data.get("global") or glob
        for r in data["rules"]:
            try:
                rx = re.compile(_python(r["regex"]))
            except re.error:  # Go syntax Python's re does not take: this rule masks nothing here, and the count says so
                skipped += 1
                continue
            reject = []
            for x in r.get("reject_regex") or []:
                try:
                    reject.append(re.compile(x))
                except re.error:  # one filter fewer: more is masked, not less
                    pass
            out.append((r["id"], rx, reject, [k.lower() for k in r.get("keywords") or []], r))
    reject = []
    for x in glob.get("reject_regex") or []:
        try:
            reject.append(re.compile(x))
        except re.error:
            pass
    return tuple(out), tuple(reject), glob, skipped


def _entropy(s: str) -> float:
    n = len(s)
    return -sum(c / n * math.log2(c / n) for c in Counter(s).values()) if n else 0.0


def _skip(rule: dict, reject: list, glob: dict, greject: tuple, s: str) -> bool:
    limits = [m for m in (rule.get("max_entropy"), glob.get("max_entropy")) if m is not None]
    return (any(_entropy(s) <= m for m in limits) or any(x.search(s) for x in reject) or any(x.search(s) for x in greject)
            or any(x in s for x in (rule.get("reject_contains") or []) + (glob.get("reject_contains") or [])))


def _mask_text(text: str, active: tuple, hits: Counter) -> str:
    _, greject, glob, _ = _rules()
    for rid, rx, reject, _, rule in active:
        spans = []
        for m in rx.finditer(text):
            g = rule.get("group")
            if g is None:
                g = next((i for i in range(1, rx.groups + 1) if m.start(i) >= 0), 0)
            s, e = m.span(g)
            if s >= 0 and text[s:e] and not _skip(rule, reject, glob, greject, text[s:e]):
                spans.append((s, e))
        for s, e in reversed(spans):
            text = text[:s] + f"[masked:{rid}]" + text[e:]
            hits[rid] += 1
    return text


def _active(lowered: str) -> tuple:
    return tuple(r for r in _rules()[0] if not r[3] or any(k in lowered for k in r[3]))


def mask(text: str, hits: Counter | None = None) -> str:
    """The text with what the rules recognise replaced by [masked:<rule>]."""
    return _mask_text(text, _active(text.lower()), Counter() if hits is None else hits)


def _mask_json(v, active: tuple, hits: Counter):
    if isinstance(v, str):
        return _mask_text(v, active, hits) if len(v) >= 8 else v
    if isinstance(v, list):
        return [_mask_json(x, active, hits) for x in v]
    if isinstance(v, dict):
        return {k: _mask_json(x, active, hits) for k, x in v.items()}
    return v


def mask_transcript(src: Path, dst: Path) -> Counter:
    """A JSONL transcript masked into dst, line by line. Strings are masked as decoded, since a key's newlines are \\n in
    the JSON; a line that is not JSON is masked as text."""
    hits: Counter = Counter()
    fd = os.open(dst, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with open(src, errors="replace") as f, os.fdopen(fd, "w") as out:
        for line in f:
            if not (active := _active(line.lower())):
                # keywords are matched on the line, whose escapes (\n, \") could only hide a keyword's own punctuation
                out.write(line)
                continue
            try:
                out.write(json.dumps(_mask_json(json.loads(line), active, hits), ensure_ascii=False) + "\n")
            except ValueError:
                out.write(_mask_text(line, active, hits))
    return hits


# --- the draft ---

def session_transcript() -> Path:
    """This directory's newest Claude Code session: ~/.claude/projects/<the path, its punctuation as dashes>/*.jsonl."""
    base = Path(os.environ.get("CLAUDE_CONFIG_DIR") or Path.home() / ".claude") / "projects"
    d = base / re.sub(r"[^A-Za-z0-9]", "-", str(Path.cwd()))
    found = sorted(d.glob("*.jsonl"), key=lambda p: p.stat().st_mtime) if d.is_dir() else []
    if not found:
        raise RuntimeError(f"no Claude Code session found for this directory (looked in {d}): give the file with "
                           "--transcript PATH")
    return found[-1]


def _sensor_info() -> tuple[set[str], set[str]]:
    """Names and versions of the org's live sensors, if the service can say; names only ever to warn, never sent."""
    from . import ask
    try:
        live = asyncio.run(ask.sensors())
    except Exception:  # not signed in, the service away: a report may be about exactly that
        return set(), set()
    return set(live), {str(e["version"]) for e in live.values() if isinstance(e, dict) and e.get("version")}


def draft(summary: str, title: str | None, surveys: list[str], transcript: Path | None, version: str) -> Path:
    """Writes the draft; sends nothing."""
    summary = summary.strip()
    if not summary:
        raise RuntimeError("a report needs a summary of what went wrong (--summary, --summary-file)")
    for s in surveys:
        if not re.fullmatch(r"[A-Za-z0-9_.-]+", s):
            raise RuntimeError(f"not a survey id: {s!r}")
    if transcript and not transcript.is_file():
        raise RuntimeError(f"no such transcript: {transcript}")
    rid = f"{dt.datetime.now():%Y%m%d-%H%M%S}-{secrets.token_hex(2)}"
    d = reports_dir() / rid
    d.mkdir(parents=True, mode=0o700)
    _, versions = _sensor_info()
    hits: Counter = Counter()
    summary = mask(summary, hits)
    first = title or summary.splitlines()[0]
    meta = {"title": mask(first, hits)[:120], "versions": f"{version}; sensors: {', '.join(sorted(versions)) or 'unknown'}",
            "surveys": surveys, "summary_masked": sum(hits.values())}
    (d / "summary.md").write_text(summary + "\n")
    if transcript:
        thits = mask_transcript(transcript, d / "transcript.masked.jsonl")
        meta["transcript"] = {"from": str(transcript), "bytes": (d / "transcript.masked.jsonl").stat().st_size,
                              "masked": sum(thits.values()), "by_rule": dict(thits.most_common(20)),
                              "rules": len(_rules()[0]), "rules_not_usable": _rules()[3]}
    (d / "draft.json").write_text(json.dumps(meta, indent=1) + "\n")
    return d


def _draft_dir(rid: str | None) -> Path:
    base = reports_dir()
    if rid:
        d = base / rid
        if not re.fullmatch(r"[0-9a-f-]+", rid) or not (d / "draft.json").is_file():
            raise RuntimeError(f"no draft {rid!r} in {base}")
        return d
    drafts = sorted(p.parent for p in base.glob("*/draft.json")) if base.is_dir() else []
    if not drafts:
        raise RuntimeError("no draft: `beat report draft --summary ...`")
    return drafts[-1]


def body(d: Path, report_id: str | None) -> str:
    """The issue, in the sections of the feedback repo's form."""
    m = json.loads((d / "draft.json").read_text())
    return (f"### What happened\n\n{(d / 'summary.md').read_text().strip()}\n\n### Versions\n\n{m['versions']}\n\n"
            f"### Survey id\n\n{', '.join(m['surveys']) or 'none'}\n\n"
            f"### Transcript\n\n{f'Held privately by walkthebeat: report {report_id}' if report_id else 'Not sent.'}\n")


def show(d: Path) -> str:
    m = json.loads((d / "draft.json").read_text())
    out = [f"Draft {d.name} in {d}. Nothing has been sent.", "",
           "--- public issue (edit summary.md to change it) ---", f"title: {m['title']}", "", body(d, None).rstrip(), "---"]
    if m.get("summary_masked"):
        out.append(f"{m['summary_masked']} value(s) in the summary were masked.")
    t = m.get("transcript")
    if t:
        out += ["", f"Transcript, masked copy: {d / 'transcript.masked.jsonl'}",
                f"  from {t['from']}: {t['bytes'] / 2**20:.1f} MiB, {t['masked']} value(s) masked by "
                f"{t['rules']} rules ({t['rules_not_usable']} could not be used here)."
                + (f" Most: {', '.join(f'{k} x{v}' for k, v in list(t['by_rule'].items())[:5])}." if t["by_rule"] else ""),
                f"  {NOT_ALL}"]
    return "\n".join(out)


# --- sending: only the person at the terminal ---

class Tty:
    """The controlling terminal, not stdin: what is piped into the command does not answer it."""

    def __enter__(self):
        try:
            self.f, self.r = open("/dev/tty", "w"), open("/dev/tty")
        except OSError:
            raise RuntimeError("`beat report send` asks you at a terminal, and this has none: nothing was sent. Run it "
                               "yourself, in your own terminal") from None
        return self

    def __exit__(self, *_):
        self.f.close()
        self.r.close()

    def confirm(self, question: str) -> bool:
        self.f.write(f"{question}\nType yes to send, anything else not to: ")
        self.f.flush()
        return self.r.readline().strip().lower() == "yes"


def _gh_ready() -> bool:
    if not shutil.which("gh"):
        return False
    return subprocess.run(["gh", "auth", "status"], capture_output=True).returncode == 0


def post_issue(title: str, text: str, body_file: Path, fields: dict | None = None) -> str:
    """The issue's URL when gh is here and signed in; otherwise a prefilled link the person opens themselves. `fields`:
    the feedback repo's form, which the link fills in (`what`, `versions`, `survey`)."""
    if _gh_ready():
        r = subprocess.run(["gh", "issue", "create", "-R", REPO, "--title", title, "--body-file", str(body_file)],
                           capture_output=True, text=True)
        if r.returncode == 0:
            return f"Posted: {r.stdout.strip()}"
        print(f"gh could not post it ({r.stderr.strip()[:200]}): use the link instead", file=sys.stderr)
    fields = dict(fields or {"what": text})
    if len(fields["what"]) > URL_TEXT_MAX:
        fields["what"] = fields["what"][:URL_TEXT_MAX] + f"\n\n[cut here; the rest is in {body_file}]"
    q = urllib.parse.urlencode({"template": "problem.yml", "title": title, **fields})
    return f"Open this to post it (nothing is posted until you press submit):\nhttps://github.com/{REPO}/issues/new?{q}"


def upload(d: Path, version: str) -> str:
    """The masked transcript, gzipped, to the service; the report's id."""
    gz = d / "transcript.masked.jsonl.gz"
    fd = os.open(gz, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with open(d / "transcript.masked.jsonl", "rb") as f, os.fdopen(fd, "wb") as raw, \
            gzip.GzipFile(fileobj=raw, mode="wb") as out:
        shutil.copyfileobj(f, out)
    with open(gz, "rb") as f:
        req = urllib.request.Request(
            wire.api_url() + "/v1/reports", data=f, method="POST",
            headers={"Authorization": f"Bearer {login.access_token()}", "Content-Type": "application/gzip",
                     "Content-Length": str(gz.stat().st_size), "Beat-Client": version})
        try:
            with urllib.request.urlopen(req, timeout=SEND_TIMEOUT_S) as r:
                return json.loads(r.read())["id"]
        except urllib.error.HTTPError as e:
            try:
                why = json.loads(e.read())["error"]
            except (ValueError, KeyError):
                why = f"HTTP {e.code}"
            raise RuntimeError(f"the service did not keep the transcript: {why}") from None
        except OSError as e:
            raise RuntimeError(f"the service did not keep the transcript: {getattr(e, 'reason', e)}") from None


def send(rid: str | None, version: str) -> None:
    d = _draft_dir(rid)
    sent = json.loads((d / "sent.json").read_text()) if (d / "sent.json").exists() else {}
    m = json.loads((d / "draft.json").read_text())
    with Tty() as tty:
        print(show(d), file=tty.f, flush=True)
        names, _ = _sensor_info()
        text = body(d, sent.get("report"))
        named = sorted(n for n in names if n in text or n in m["title"])
        hits: Counter = Counter()
        mask(text, hits)  # the summary may have been edited since the draft
        warn = (f"\nThis text names your hosts: {', '.join(named)}.\n" if named else "") + \
               (f"\nThis text looks like it holds a secret ({', '.join(hits)}).\n" if hits else "")
        want_t = "transcript" in m and "report" not in sent and tty.confirm(
            f"\nSend the transcript ({m['transcript']['bytes'] / 2**20:.1f} MiB) to walkthebeat's service, under your "
            f"org's login?\nwalkthebeat's staff will read it. It holds your hostnames and configuration, and possibly "
            f"secrets. {NOT_ALL}")
        want_i = "issue" not in sent and tty.confirm(
            f"{warn}\nPost the summary above as a PUBLIC issue on github.com/{REPO}? Anyone can read it.")
    if want_t:
        sent["report"] = upload(d, version)
        (d / "sent.json").write_text(json.dumps(sent) + "\n")
        print(f"Transcript kept by the service as report {sent['report']} (`beat report delete` removes it).")
    elif "transcript" in m and "report" not in sent:
        print("Transcript not sent.")
    if want_i:
        text = body(d, sent.get("report"))
        f = d / "issue.md"
        f.write_text(text)
        what = (d / "summary.md").read_text().strip()
        if sent.get("report"):
            what += f"\n\nTranscript held privately by walkthebeat: report {sent['report']}"
        sent["issue"] = post_issue(m["title"], text, f, {"what": what, "versions": m["versions"],
                                                         "survey": ", ".join(m["surveys"])})
        (d / "sent.json").write_text(json.dumps(sent) + "\n")
        print(sent["issue"])
    elif "issue" not in sent:
        print("Summary not posted.")


def main(a, version: str) -> None:
    from . import ask

    def refused(status: int, data: bytes) -> RuntimeError:
        try:
            return RuntimeError(json.loads(data)["error"])
        except (ValueError, KeyError):  # a service from before reports
            return RuntimeError(f"HTTP {status}: this service may not take reports yet")
    if a.report_cmd == "draft":
        text = a.summary
        if a.summary_file:
            text = sys.stdin.read() if a.summary_file == "-" else Path(a.summary_file).read_text()
        t = Path(a.transcript) if a.transcript else session_transcript() if a.session else None
        d = draft(text or "", a.title, a.survey, t, version)
        print(show(d))
        print(f"\nTo send: run `beat report send {d.name}` yourself, in your own terminal. It asks before each part.")
    elif a.report_cmd == "send":
        send(a.id, version)
    elif a.report_cmd == "list":
        status, data = ask._http("/v1/reports", None, 30)
        if status != 200:
            raise refused(status, data)
        for r in json.loads(data)["reports"]:
            print(f"{r['id']}  {r['at']}  {r['bytes']} bytes  by {r['who']}")
    elif a.report_cmd == "delete":
        status, data = ask._http(f"/v1/reports/{urllib.parse.quote(a.id, safe='')}", None, 30, method="DELETE")
        if status != 200:
            raise refused(status, data)
        print(f"deleted {a.id}")
