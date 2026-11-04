"""MCP server: questions to the beat service over HTTP (ask.py, serve.py). Every tool asks through the same path as
`beat ask`.

Tools (descriptions say first when to use each: in the agent's terms, not beat's):
- `survey`: a Starlark question to several hosts (default every live one), answered as the comparison: categories,
  the analysis (analysis.get) and the logs across hosts (logs.get); raw records only on request (ask.report).
- `run`: a Starlark question to one host (a survey of one); the answer comes back, and the collector keeps it. An
  answer too large for a tool's output has its log summaries cut, and says so (`cut`).
- `inventory`: the live sensors (the service's directory), and whether this estate repository has the host.
- `catalog`, `describe_osquery_table`: osquery's tables and columns on a host, asked as questions too.
- `analyze`: a survey's answers across its hosts (slot kinds, groups, dimensions, rare values, inconsistencies,
  drift): the read API's analysis.get, as `beat analyze` calls it.
- `logs`: the log summaries in a survey's answers across its hosts, with a proposed curated template set: the read
  API's logs.get, as `beat logs` calls it (tool first, MCP second).
The `run` description is the builtins guide a sensor published (guide.get); this server only relays.
Env: BEAT_API (else the service `beat login URL` kept, else https://api.walkthebeat.ai).
"""
from __future__ import annotations

import asyncio
import json
import re

import mcp.types as types
from mcp.server import Server
from mcp.server.stdio import stdio_server

from . import ask, estate

HOST = {"type": "string", "description": "Target host: a live sensor's name (see `inventory`)."}

NO_GUIDE = ("Run a Starlark probe on one host: constants, functions and main(); emit() records. No sensor was live "
            "when this server started, so the builtins guide is missing: call `inventory`, then restart the session.")

CATALOG = """def main():
    for r in osq("select name from osquery_registry where registry = 'table' and active = 1 order by name"):
        emit("osquery", "table", r["name"], source = "osquery_registry")
"""

DESCRIBE = """def main():
    for c in osq("select name, type from pragma_table_info(?)", TABLE):
        emit(TABLE, c["name"], c["type"], source = "pragma_table_info")
"""


# Shown by the client in the agent's system prompt, even while the tools themselves are deferred (loaded on demand):
# so this is where the agent learns which tool answers which kind of question.
INSTRUCTIONS = """beat reaches this estate's hosts read-only, through sensors that run Starlark probes. Pick the tool by \
the question, and load it first if your client defers tools (e.g. ToolSearch select:mcp__beat__survey):
- About more than one host (what differs, which host is the odd one out, what normal looks like across a tier, what \
changed since last time, whether a deploy changed anything): `survey`. One call; the reply is the comparison: hosts \
grouped by identical answer, the differences with their hosts, rare values, inconsistencies, drift since the same \
question was last asked, and log templates per host. Give a saved probe by name (`probe`) so repeated surveys are \
the same question and show drift.
- One host, exploring or trying a probe before saving it: `run`.
- Logs: in the probe, `log_summary(...)` groups lines into templates on the host (restrict to a time window by \
passing the selected `lines=`), and `emit_log_summary(name, summary)` records it; `survey` then compares templates \
across hosts, `logs` (by survey id) proposes a curated template set, `log_extract` fetches the lines behind one.
- An earlier survey again (more history, other settings): `analyze` by survey id; its logs: `logs`.
- Everything recorded so far, across hosts, probes and time (every survey and run is kept): `query`, read-only SQL \
over the datasets `changes` (an event log), `series` (time series), `log_minutes` (log lines per minute), `log_values` (per value: 503s per minute) and \
`observations` (every record).
- Which hosts are live: `inventory`. osquery tables: `catalog`, `describe_osquery_table`.
Before asking every host, think about what the probe takes to collect and to analyse at that size: its answer's \
size and its time on a host (try it on one first), times the number of hosts. A probe returns what the question \
needs: counts, distributions and summaries for what is common, individual records only for the rare (failures, \
outliers); for raw detail, `run` the few hosts that stand out. An answer over about 1 MB comes back as a \
`too_large` error.
Hosts that did not answer: `down` (no heartbeat) or `no_answer` (up, and did not answer by the deadline). An up sensor answers, so each `no_answer` is a finding to look into, like a stalled worker; many at once points at beat or the bus before the hosts. A reply that says the survey is not complete (the collector is behind) is beat being slow, not the hosts: wait and read the survey again (`analyze`, `beat survey show`, `beat dataset`) before you analyse it.
Do not fetch raw records to compare, count or aggregate them yourself (jq, grep, regexes over many lines, loops \
over log lines): if `survey` or `logs` cannot show what you need, say what is missing, so beat can be improved."""

SURVEY = (
    "Ask several hosts (default: every live one) the same Starlark question and get back how they compare. Use it "
    "whenever the question is about more than one host: what differs between them, which host is the odd one out, "
    "what changed since this was last asked, what a log looks like across hosts, a baseline of the fleet. The reply "
    "is the comparison, not the raw records: `answers` (hosts grouped by identical answer, with record counts and "
    "errors); `analysis` (exact groups of hosts; the differences that explain them, each value with its hosts, rare "
    "values marked; inconsistencies: facts that agree on every host but a few, usually the finding; slot kinds, "
    "declared with emit(kind=) or inferred); `drift` since this question's previous survey; and, when the probe calls "
    "emit_log_summary, `logs`: each log's templates with per-host counts, parameters and examples, and a proposed "
    "curated template set. Prefer this to calling `run` host by host or to collecting raw answers and comparing them "
    "yourself (jq, grep, regexes): it is faster, and it remembers earlier surveys of the same question. If it cannot "
    "show what you need, say what is missing. records=true adds the raw records. Probe language and builtins: `run`.")

QUERY = (
    "Read-only SQL (DuckDB) over everything beat has recorded: every survey and run, each host's answer, over time. "
    "Datasets (views):\n"
    "- `changes`: the event log. One row per value that differs between a host's consecutive runs of a probe: t, "
    "since (the previous run), host, probe, subject, key, kind, change (added | removed | changed), was, now, "
    "probe_changed (the probe's source changed too, so the row may come from the probe), survey_id. Configuration, "
    "versions, states, times (as ISO), log templates appearing or vanishing; not measurements.\n"
    "- `series`: the time series. One row per measurement (kind metric) per host per run: t, host, probe, subject, "
    "key, about (the time a value is about, e.g. the minute of a per-minute count), value, delta and seconds since "
    "the host's previous run of the probe, label (a log template's text), "
    "survey_id. Counts over a whole file are counters (delta is a rate; negative when the file rotated); counts over "
    "a window (a log tail, the last 15 minutes) are levels.\n"
    "- `observations`: every record of every answer: survey_id, host, asked_at, observed_at, probe, subject, key, "
    "value, kind, source, subject_type, subject_name, part (`log:app-log#a1b2` -> log, app-log, a1b2), value_num, "
    "value_time (UTC timestamp, for kind time).\n"
    "- `log_minutes`: log lines per minute, from every probe that summarizes logs: host, log, template_id, "
    "template, minute, lines, surveys (how many surveys covered that minute; lines is the most any of them saw).\n"
    "- `log_values`: the same per value of a categorical log parameter (a status, a method, a level): host, log, "
    "template_id, template, param (p3: the template's 4th <*>), value, minute, lines, surveys.\n"
    "- `runs` (host, probe, survey_id, asked_at, previous run), `surveys` (survey_id, question_hash, selector, "
    "asked_by, asked_at, deadline), `survey_answers` (survey_id, target: the host, answer_hash, outcome, started, "
    "finished, sensor_version).\n"
    "Times are UTC timestamps. Some words are reserved as bare aliases or columns (`key`, `at`, `first`, `last`, "
    "`minutes`): write `as` and another name (`key as k`, `min(minute) as first_min`). Returns at most "
    "`limit` rows (default 200) and says when it cut.")

RUN_PREFIX = ("Run a probe on ONE host: to explore it, or to try a probe before asking the fleet. To compare hosts, "
              "or for anything you would otherwise aggregate yourself, use `survey`.\n\n")


def tool_defs(guide: str | None, hosts: list[str]) -> list[types.Tool]:
    host = dict(HOST, description=HOST["description"] + (f" Live now: {', '.join(hosts)}." if hosts else ""))
    return [
        types.Tool(name="survey", description=SURVEY, inputSchema={
            "type": "object",
            "properties": {
                "probe": {"type": "string", "description": "A saved probe, by name: this estate's probes/<name>.star, else beat's default pack's (`beat probes`): "
                          "the same question as `beat run <name>`, so surveys of it show drift. Or give `source`."},
                "source": {"type": "string", "description": "A Starlark probe: constants, functions and main()."},
                "name": {"type": "string", "description": "File name, e.g. nginx.star: the same name and source "
                         "make it the same question, so later surveys show drift against earlier ones."},
                "hosts": {"type": "array", "items": {"type": "string"},
                          "description": "Only these hosts (default: every live sensor)." + (
                              f" Live now: {', '.join(hosts)}." if hosts else "")},
                "timeout": {"type": "integer", "description": "Seconds per host (default 120, max 300)."},
                "history": {"type": "integer", "description": "Earlier surveys of this question to learn from and "
                            "compare with (default 3)."},
                "records": {"type": "boolean", "description": "Also return each answer's raw records (default false)."},
            }}),
        types.Tool(name="run", description=RUN_PREFIX + (guide or NO_GUIDE), inputSchema={
            "type": "object", "required": ["host", "source"],
            "properties": {
                "host": host,
                "source": {"type": "string", "description": "A Starlark probe: constants, functions and main()."},
                "name": {"type": "string", "description": "File name for spans and errors, e.g. nginx.star."},
                "timeout": {"type": "integer", "description": "Seconds (default 120, max 300)."},
            }}),
        types.Tool(name="query", description=QUERY, inputSchema={
            "type": "object", "required": ["sql"],
            "properties": {
                "sql": {"type": "string", "description": "One SELECT (or WITH ... SELECT)."},
                "limit": {"type": "integer", "description": "Most rows to return (default 200, max 2000)."},
            }}),
        types.Tool(name="inventory", description="The live sensors (they heartbeat to the beat service): name, "
                   "build, labels, since when; and whether this estate repository has the host (hosts/<host>/).",
                   inputSchema={"type": "object", "properties": {}}),
        types.Tool(name="logs", description=(
            "Compare a log across the hosts of an earlier survey, by its id (`survey` already returns this for a new "
            "question whose probe emits log summaries). Log summaries in a survey's answers (records from emit_log_summary), across its hosts: per log, each "
            "host's span (lines read, first and last time) and per template each host's line count, parameter "
            "values and examples; plus `proposed`, a curated template set (key=value tokens and versions made <*>, "
            "duplicates merged). The loop: `run` a probe with log_summary + emit_log_summary (explore), call `logs` "
            "with its survey id, edit `proposed`, then `run` again with log_summary(templates = [...]) so every host "
            "reports the same templates (lines outside them come back new); log_extract for the lines behind one."),
            inputSchema={"type": "object", "required": ["survey"], "properties": {
                "survey": {"type": "string", "description": "Survey id (from `run`'s reply) or a unique prefix."},
                "log": {"type": "string", "description": "Only this log: the name given to emit_log_summary."},
                "min_lines": {"type": "integer", "description": "Leave templates with fewer lines out of "
                              "`proposed` (default 1)."},
            }}),
        types.Tool(name="analyze", description=(
            "Compare the hosts of an earlier survey again, by its id, e.g. with more history (`survey` already returns "
            "this for a new question). A survey's answers analysed across its hosts: what kind each (subject, key) slot is (semantic, "
            "identity, time, metric; declared by emit(kind=) or inferred), exact groups of hosts with the same "
            "configuration, the independent differences that explain them (dimensions, each with its values and "
            "host counts; rare values marked with their hosts), inconsistencies (two facts that agree on every host "
            "but a few: the strongest findings), and drift since the same question's previous survey. Earlier "
            "surveys of the question teach it what changes (measurements) and what does not (configuration)."),
            inputSchema={"type": "object", "required": ["survey"], "properties": {
                "survey": {"type": "string", "description": "Survey id (from `run`'s reply) or a unique prefix."},
                "history": {"type": "integer", "description": "Earlier surveys of the question to use (default 3)."},
            }}),
        types.Tool(name="catalog", description="The osquery tables on a host (for osq()).",
                   inputSchema={"type": "object", "required": ["host"], "properties": {"host": host}}),
        types.Tool(name="describe_osquery_table", description="Columns and types of one osquery table on a host.",
                   inputSchema={"type": "object", "required": ["host", "table"],
                                "properties": {"host": host, "table": {"type": "string"}}}),
    ]


# Claude Code refuses an MCP tool's output past 25000 tokens by default (MAX_MCP_OUTPUT_TOKENS). Answers of 59-73 KB hit
# it (first discovery, 2026-11-01). JSON of records runs about 3 characters a token, so this leaves room for the rest of
# the turn: a judgement, not a measurement of any one client.
RUN_MAX_BYTES = 40_000


async def _ask_one(host: str, name: str, source: str, timeout: int = 120) -> dict:
    s = await ask.ask(name, source, [host], timeout, via="beat-mcp")
    a = s["answers"].get(host)
    if a is None:
        why = ask.why_not(s, host)
        return {"ok": False, "survey": s["survey"], "error": f"{host}: {why}"}
    return {"ok": True, "survey": s["survey"], "answer_hash": a["answer_hash"], **a["answer"]}


def _cap_log_summaries(out: dict, budget: int | None = None) -> dict:
    """A `run` answer the agent's client can take: over RUN_MAX_BYTES, its log summaries are cut, first the per-minute
    records, then the templates with the fewest lines (those outside curated templates kept first, as they are what
    is new), and `cut` says so and where the rest is. The answer is whole in the survey; anything else in it stays."""
    budget = RUN_MAX_BYTES if budget is None else budget
    records = out.get("records")
    if not records or _size(out) <= budget:
        return out
    logs: dict[str, dict[str, list]] = {}
    for r in records:
        log, _, template = str(r.get("subject", "")).partition("#")
        if log.startswith("log:") and template:
            logs.setdefault(log, {}).setdefault(template, []).append(r)
    if not logs:
        return out

    def minute(r: dict) -> bool:
        return "@" in str(r.get("key", "")) and "#" in str(r.get("subject", ""))

    def lines(rows: list) -> tuple:
        by_key = {r.get("key"): r.get("value") for r in rows}
        try:
            n = float(by_key.get("lines_count") or 0)
        except (TypeError, ValueError):
            n = 0
        return (by_key.get("new") != "yes", -n)

    ranked = {log: sorted(ts, key=lambda t: lines(ts[t])) for log, ts in logs.items()}
    no_minutes = [r for r in records if not minute(r)]
    dropped_minutes = len(records) - len(no_minutes)

    def keeping(top: int | None) -> list:
        gone = {f"{log}#{t}" for log, ts in ranked.items() for t in (ts[top:] if top is not None else [])}
        return [r for r in no_minutes if r.get("subject") not in gone]

    kept, top = keeping(None), None
    if _size({**out, "records": kept}) > budget:
        top = max(len(ts) for ts in ranked.values())
        while top > 1:
            top //= 2
            kept = keeping(top)
            if _size({**out, "records": kept}) <= budget:
                break
    cut = {"why": f"this answer was over {budget} bytes, too large for a tool's output: it is cut here, whole in the "
                  f"survey", "per_minute_records_omitted": dropped_minutes}
    if top is not None:
        cut["templates_kept_per_log"] = {log: f"{min(top, len(ts))} of {len(ts)}" for log, ts in ranked.items()}
    survey = out.get("survey")
    cut["the_rest"] = (f"`logs` with survey {survey!r} for every template; `query` for the records and per-minute "
                       f"counts (`observations` where survey_id = {survey!r}, `log_minutes`, `log_values`); or ask again "
                       f"with log_summary(top=...) or a narrower time window")
    return {**out, "records": kept, "cut": cut}


def _size(v: dict) -> int:
    return len(json.dumps(v, default=str))


async def _inventory() -> dict:
    live = await ask.sensors()
    try:
        repo = estate.root()
    except estate.EstateError:
        repo = None
    rows = []
    for name, e in sorted(live.items()):
        row = {"host": name, "sensor": e.get("sensor"), "labels": e.get("labels", {}), "since": e.get("started"),
               "sandbox": e.get("sandbox", "full")}
        if repo:
            row["in_estate_repo"] = {"facts": (repo / "hosts" / name / "facts").is_dir(),
                                     "model": (repo / "hosts" / name / "model.md").exists()}
        rows.append(row)
    return {"ok": True, "hosts": rows, "estate_repo": str(repo) if repo else None}


async def _query(sql: str, limit: int) -> dict:
    """SQL on the collector's store (ask.sql): columns and at most `limit` rows."""
    if not sql.strip():
        return {"ok": False, "error": "give `sql`"}
    try:
        r = await ask.sql(sql, timeout=30)
    except Exception as e:  # the service is not answering
        return {"ok": False, "error": f"the service did not answer: {type(e).__name__}: {e}"}
    if "error" in r:
        return {"ok": False, "error": r["error"]}
    rows = r["rows"]
    out = {"ok": True, "columns": r["columns"], "rows": rows[:limit], "row_count": len(rows)}
    if len(rows) > limit:
        out["cut"] = f"{len(rows)} rows, {limit} shown: aggregate, filter, or raise `limit`"
    return out


async def _call(name: str, args: dict) -> dict:
    host = args.get("host", "")
    if name == "inventory":
        return await _inventory()
    if name == "survey":
        hosts = [h for h in (args.get("hosts") or []) if h] or None
        qname, source = args.get("name") or "probe.star", args.get("source", "")
        if args.get("probe"):
            try:
                path = estate.probe_path(estate.root(), args["probe"])
            except estate.EstateError as e:
                return {"ok": False, "error": str(e)}
            qname, source = path.name, path.read_text()
        if not source:
            return {"ok": False, "error": "give `probe` (a saved probe's name) or `source`"}
        return {"ok": True, **await ask.report(qname, source, hosts,
                                               min(int(args.get("timeout") or 120), 300),
                                               int(args.get("history") or 3), bool(args.get("records")),
                                               via="beat-mcp")}
    if name == "run":
        return _cap_log_summaries(await _ask_one(host, args.get("name") or "probe.star", args.get("source", ""),
                                                 int(args.get("timeout") or 120)))
    if name == "analyze":
        params = {k: args[k] for k in ("survey", "history") if args.get(k) is not None}
        try:
            return {"ok": True, **await ask.api("analysis.get", params)}
        except RuntimeError as e:
            return {"ok": False, "error": str(e)}
    if name == "logs":
        params = {k: args[k] for k in ("survey", "log", "min_lines") if args.get(k) is not None}
        try:
            return {"ok": True, **await ask.api("logs.get", params)}
        except RuntimeError as e:  # an error reply (no such survey or log) or no collector
            return {"ok": False, "error": str(e)}
    if name == "query":
        return await _query(args.get("sql", ""), min(int(args.get("limit") or 200), 2000))
    if name == "catalog":
        r = await _ask_one(host, "catalog.star", CATALOG, 60)
        return {"ok": True, "osquery_tables": [x["value"] for x in r["records"]]} if r.get("ok") and not r.get(
            "error") else r
    if name == "describe_osquery_table":
        table = args.get("table", "")
        if not re.fullmatch(r"[A-Za-z0-9_]{1,64}", table):
            return {"ok": False, "error": f"bad osquery table name {table!r}"}
        r = await _ask_one(host, "describe.star", f"TABLE = {json.dumps(table)}\n" + DESCRIBE, 60)
        if not r.get("ok") or r.get("error"):
            return r
        if not r["records"]:
            return {"ok": False, "error": f"no osquery table {table!r} on {host}"}
        return {"ok": True, "columns": [{"name": x["key"], "type": x["value"]} for x in r["records"]]}
    return {"ok": False, "error": f"unknown tool {name!r}"}


async def _serve() -> None:
    try:
        hosts = sorted(await ask.sensors())
        guide = await ask.guide()
    except Exception:  # the service is not answering: start anyway, so the session can say so
        hosts, guide = [], None
    tools = tool_defs(guide, hosts)
    server = Server("beat", instructions=INSTRUCTIONS)

    @server.list_tools()
    async def list_tools() -> list[types.Tool]:
        return tools

    @server.call_tool()
    async def call_tool(name: str, arguments: dict) -> list[types.TextContent]:
        try:
            out = await _call(name, dict(arguments or {}))
        except Exception as e:  # the service unreachable, no directory, ...
            out = {"ok": False, "error": f"{type(e).__name__}: {e}"}
        return [types.TextContent(type="text", text=json.dumps(out, default=str))]

    async with stdio_server() as (read, write):
        await server.run(read, write, server.create_initialization_options())


def main() -> None:
    asyncio.run(_serve())
