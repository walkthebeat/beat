"""Log built-ins over the `drain` WASM tool (docs/probes.md §4.3, docs/security.md C21).

Defined only on sensors whose tools include drain.wasm. Input is a file (`path`, read through the tools: large
files stream; `tail` keeps the last N lines) or lines the probe already has (`lines`, e.g. journal messages).
Masks and the curated templates follow the tool (wasm/drain/src/main.rs): `self_names` are the host's own names
(hostname, addresses), shown as <SELF>; `header` is the number of header tokens every line has (syslog: 3).
"""

def _input(path: str | None, lines: list[str] | None, tail: int) -> tuple:
    """The pipe stages and stdin that feed drain."""
    if (path == None) == (lines == None):
        fail("give exactly one of path and lines")
    if lines != None:
        return [], "\n".join(lines)
    if tail > 0:
        return [["tail", "-n", str(tail), path]], ""
    return [["cat", path]], ""

def _options(self_names: list[str], header: int, masks: dict[str, str], templates: list[str] | None) -> list[str]:
    args = ["--header", str(header)]
    for n in self_names:
        args += ["--self", n]
    for name, regex in masks.items():
        args += ["--mask", name + "=" + regex]
    if templates != None:
        args += ["--templates", json.encode(templates)]
    return args

def log_summary(
        path: str | None = None,
        lines: list[str] | None = None,
        tail: int = 0,
        self_names: list[str] = [],
        header: int = 0,
        templates: list[str] | None = None,
        masks: dict[str, str] = {},
        sim: float = 0.4,
        depth: int = 4,
        top: int = 200,
        cap: int = 8,
        examples: int = 3,
        minutes: int = 60,
        levels: int = 12) -> dict[str, typing.Any]:
    """Templates of the lines: {"span", "lines", "skipped", "omitted", "settings", "templates": [{"id", "template", "count",
    "params": [{"distinct", "values": [[value, count]], "min"?, "max"?, "categorical"?, "minutes"?}], "examples", "new"?,
    "minutes"}]}.
    "minutes": [[minute, lines]] for the last `minutes` minutes of the input (a line's minute is its time, cut after
    the minutes: `2026-10-11T13:49`, or `13:49` when the line has only a clock time).
    A parameter with 2 to `levels` distinct values (a status, a method) is categorical: all its values, and its
    "minutes": [[minute, [[value, lines]]]] (503s per minute).
    With `templates`, those are matched exactly and reported even when nothing matched; other lines are mined and
    come back with "new": True."""
    stages, stdin = _input(path, lines, tail)
    drain = ["drain", "--sim", str(sim), "--depth", str(depth), "--top", str(top), "--cap", str(cap),
             "--examples", str(examples), "--minutes", str(minutes), "--levels", str(levels)] + _options(self_names, header, masks, templates)
    return json.decode(pipe(stdin = stdin, *(stages + [drain])).stdout)

def log_extract(
        path: str | None = None,
        lines: list[str] | None = None,
        tail: int = 0,
        templates: list[str] | None = None,
        grep: str | None = None,
        limit: int = 20,
        first: bool = False,
        self_names: list[str] = [],
        header: int = 0,
        masks: dict[str, str] = {}) -> dict[str, typing.Any]:
    """The lines themselves (unmasked) that match any of `templates` (as log_summary reports them) and the regex
    `grep`: {"matched": N, "lines": [...], "span"}, the last `limit` of them (the first with `first`).
    "span" ({"lines_read", "first_time", "last_time"}) is what the call covered, as in log_summary: two calls over
    one file cover different stretches unless they are given the same `tail` (and a live file can grow between
    them)."""
    stages, stdin = _input(path, lines, tail)
    drain = ["drain", "--extract", "--limit", str(limit)] + _options(self_names, header, masks, templates)
    if grep != None:
        drain += ["--grep", grep]
    if first:
        drain.append("--first")
    return json.decode(pipe(stdin = stdin, *(stages + [drain])).stdout)

def _number(x: typing.Any) -> str:
    """[R5]: plain digits for whole numbers (2048, not 2048.0)."""
    if type(x) == "float" and x == int(x):
        return str(int(x))
    return str(x)

def emit_log_summary(name: str, summary: dict[str, typing.Any], source: str = "drain") -> None:
    """Records for a summary, in one shape for every probe (docs/probes.md §4.4.1):
      log:<name>               lines_count, too_long_count, omitted_templates_count; what it covered:
                               lines_read_count, first_time, last_time (as written in the log; absent if none)
      log:<name>#<template id> template; lines_count; new (yes, for lines outside curated templates);
                               p<i> (one record per value), p<i>_distinct_count, p<i>_min, p<i>_max; example;
                               lines_count@<minute>: its lines in that minute (the summary's `minutes`);
                               for a categorical parameter: p<i>=<value>, how many lines had that value, and
                               p<i>@<minute>: "<value>=<lines> ..." in that minute (one record per minute: the index
                               expands it to p<i>=<value> per minute; answers stay small)
    The template id depends on the template's text only, so subjects compare across hosts. Counts are declared
    metrics, times times; parameter values are left to the analysis, which sees all hosts. The per-minute and
    per-value counts are for the record index (series), not the survey's comparison."""
    log = "log:" + name
    emit(log, "lines_count", _number(summary["lines"]), source, kind = "metric")
    emit(log, "too_long_count", _number(summary["skipped"]["too_long"]), source, kind = "metric")
    emit(log, "omitted_templates_count", _number(summary["omitted"]["templates"]), source, kind = "metric")
    span = summary["span"]
    emit(log, "lines_read_count", _number(span["lines_read"]), source, kind = "metric")
    for k in ("first_time", "last_time"):
        if span[k] != None:
            emit(log, k, span[k], source, kind = "time")
    for t in summary["templates"]:
        subj = log + "#" + t["id"]
        emit(subj, "template", t["template"], source, kind = "semantic")
        emit(subj, "lines_count", _number(t["count"]), source, kind = "metric")
        if t.get("new"):
            emit(subj, "new", "yes", source, kind = "semantic")
        for m in t.get("minutes", []):
            emit(subj, "lines_count@" + m[0], _number(m[1]), source, kind = "metric")
        for i, p in enumerate(t["params"]):
            k = "p%d" % i
            emit(subj, k + "_distinct_count", _number(p["distinct"]), source, kind = "metric")
            for v in p["values"]:
                emit(subj, k, v[0], source)  # what a parameter is, the analysis infers across hosts
                if p.get("categorical"):
                    emit(subj, k + "=" + v[0], _number(v[1]), source, kind = "metric")
            for m in p.get("minutes", []):
                emit(subj, k + "@" + m[0], " ".join([v[0] + "=" + _number(v[1]) for v in m[1]]), source)
            if "min" in p:
                emit(subj, k + "_min", _number(p["min"]), source, kind = "metric")
                emit(subj, k + "_max", _number(p["max"]), source, kind = "metric")
        for e in t["examples"]:
            emit(subj, "example", e, source)
