"""The wire protocol between control plane and sensors (docs/protocol.md). Sensor side: sensor/src/wire.rs.

A NATS message's payload is a content-addressed blob, byte for byte (a question, or an answer sealed to its survey's
key); its headers are the relations (survey, target, times). Receivers hash the payload they got, so writers only
need to write canonical JSON (sorted keys, no whitespace) for equal content to get equal bytes.
tests/wire_vectors.json keeps both sides in step. Floats are avoided in blobs written by both sides: Python and Rust
format some of them differently. Every message below but progress is signed (Beat-Signature over the kind, the other
Beat-* headers and the payload's hash: seal.py): the survey and the ask by the collector, acks and answers by the
sensor.

  beat.ask.all, beat.ask.host.<name>   core NATS   payload: question   Beat-Survey, Beat-Question, Beat-Key (the
                                                                        survey's public key), Beat-Timeout,
                                                                        Beat-Issued, Beat-Deadline, Beat-Targets
                                                                        (optional: only these answer)
  beat.ack.<survey>                    core NATS   no payload         Beat-Survey, Beat-Question, Beat-Target,
                                                                        Beat-Answer-By, Beat-Sensor (only when the
                                                                        answer is not out within a second)
  beat.answer.<survey>                 request     payload: sealed     Beat-Survey, Beat-Question, Beat-Target,
                                                   answer              Beat-Outcome, Beat-Started, Beat-Finished,
                                                                        Beat-Phases, Beat-Sensor (the answer's hash is computed
                                                                        by the collector, once opened); reply
                                                                        {"stored": true} once stored, or {"refused": why}
  beat.heartbeat.<name>                core NATS   payload: entry     sensor heartbeats: {name, sensor, labels, started, guide, sandbox, at, collectors, signature}; signed (kind heartbeat, over the entry without its signature); every collector keeps the enrolled and fresh (<35 s) ones in memory
  beat.guide.put                       request     payload: guide     the builtins guide a sensor's beat-probe prints; reply {"hash"}: kept by it
  beat.deny.get                        request     no payload         reply: the org root's deny list as signed (docs/security.md H16), or empty
  beat.api.<method>                    request/reply  the API (api.py), served by the collector; survey.start is the
                                                      only way to ask (the collector records and publishes).
                                                      Clients reach it over HTTP only (serve.py: POST /v1/<method>)

Nothing is kept on the bus (0.3; before it, JetStream kept surveys, acks and answers, and KV buckets the directory, the
guides and the deny list). The collector that asked a survey listens on its ack and answer subjects while it holds the
survey's key, until the deadline (a restarted one does not: no responders); a sensor sends its answer again until that
collector replies that it is stored, or the deadline passes. Nothing depends on the order messages arrive in.
"""
from __future__ import annotations

import hashlib
import json
import os
import secrets
import time
from pathlib import Path

DEFAULT_NATS = "nats://127.0.0.1:4222"
DEFAULT_API = "https://api.walkthebeat.ai"  # walkthebeat's hosted service (tier 1)
ASK_ALL = "beat.ask.all"
HEARTBEATS = "beat.heartbeat.*"
GUIDE_PUT = "beat.guide.put"
DENY_GET = "beat.deny.get"   # the org root's deny list (docs/security.md H16)


def services_dir() -> Path:
    """Where the control plane's services keep their state (NATS, the store, the dataset link key): BEAT_SERVICES,
    default /var/tmp/beat. Only the services read it; clients reach them over HTTP (api_url)."""
    return Path(os.environ.get("BEAT_SERVICES") or "/var/tmp/beat")


def nats_url() -> str:
    """Where the control plane's NATS is, for the services and sensors (never clients): BEAT_NATS, or this machine."""
    return os.environ.get("BEAT_NATS", DEFAULT_NATS)


def service_file() -> Path:
    """The service `beat login URL` last signed in to: this machine's default (one line, the URL)."""
    return Path(os.environ.get("XDG_CONFIG_HOME") or Path.home() / ".config") / "beat" / "service"


def api_source() -> tuple[str, str]:
    """Where clients reach the service (serve.py), and why: BEAT_API, else the one `beat login URL` recorded, else
    walkthebeat's hosted service."""
    if os.environ.get("BEAT_API"):
        return os.environ["BEAT_API"].rstrip("/"), "BEAT_API"
    try:
        url = service_file().read_text().strip()
    except OSError:
        url = ""
    return (url.rstrip("/"), str(service_file())) if url else (DEFAULT_API, "the default")


def api_url() -> str:
    return api_source()[0]


def remember_api(url: str) -> None:
    f = service_file()
    f.parent.mkdir(parents=True, exist_ok=True)
    f.write_text(url.rstrip("/") + "\n")


def ask_host(name: str) -> str:
    return f"beat.ask.host.{name}"


def answer_subject(survey: str) -> str:
    return f"beat.answer.{survey}"


def ack_subject(survey: str) -> str:
    return f"beat.ack.{survey}"


def heartbeat_subject(name: str) -> str:
    return f"beat.heartbeat.{name}"


def is_token(s: str) -> bool:
    """A name that can be one token of a subject: not empty, no `.`, space or wildcard."""
    return bool(s) and not any(c in s for c in ". *>")




def canonical(value) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def question(name: str, source: str, libraries: dict | None = None, params: dict | None = None) -> bytes:
    """A question blob. Its hash covers name, source, libraries and parameters (C17)."""
    return canonical({"v": 1, "name": name, "source": source, "libraries": libraries or {}, "params": params or {}})


HEADROOM = 8 * 1024  # room for the headers when an answer is checked against the server's message limit


def too_large(answer: dict, size: int, limit: int) -> dict:
    """The answer that replaces one over the server's message limit (sensor/src/wire.rs `answer_too_large`, the same
    text): how large it was and where the bytes are, by subject type, instead of a silent sensor."""
    by_type: dict[str, list[int]] = {}
    for r in answer.get("records") or []:
        e = by_type.setdefault((r.get("subject") or "").split(":")[0], [0, 0])
        e[0] += 1
        e[1] += len(canonical(r)) + 1
    top = sorted(by_type.items(), key=lambda kv: (-kv[1][1], kv[0]))[:3]
    parts = "; ".join(f"{t}: {n} records, {b // 1024} KB" for t, (n, b) in top)
    message = (f"answer too large: {size} bytes, {len(answer.get('records') or [])} records, over the {limit}-byte "
               f"message limit; most bytes by subject type: {parts}; aggregate in the probe (counts, quantiles, "
               "summaries) or emit fewer records")
    return {"v": 1, "outcome": "error", "records": [], "failures": [], "diag": "", "notes": answer.get("notes") or [],
            "error": {"kind": "too_large", "message": message, "span": ""}}


def new_survey_id() -> str:
    """Sortable by time, and a NATS subject token (no dots): 20261004T190312Z-a1b2c3."""
    return time.strftime("%Y%m%dT%H%M%SZ", time.gmtime()) + "-" + secrets.token_hex(3)


def iso(t: float | None = None) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() if t is None else t))
