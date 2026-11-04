"""ask.report (MCP `survey`, `beat ask --analyze`): the comparison comes back instead of the raw records; and
`beat run` asks all its hosts in one survey, so the collector can compare them."""
import asyncio

from beat import ask, estate


def _survey(hosts):
    rec = {"subject": "conf", "key": "pool_max", "value": "5", "source": "file:/etc/x"}
    return {"survey": "S1", "question": "q", "expected": hosts, "down": [], "no_answer": [], "running": [],
            "not_live": [], "live": hosts,
            "answers": {h: {"answer_hash": "h1", "outcome": "ok",
                            "answer": {"records": [rec], "failures": [], "notes": [], "outcome": "ok"}}
                        for h in hosts}}


def test_report_returns_the_comparison_not_the_records(monkeypatch):
    calls = []

    async def fake_ask(name, source, hosts=None, timeout=120, via=""):
        return _survey(hosts or ["a", "b"])

    async def fake_api(method, params=None, timeout=10):
        calls.append(method)
        if method == "analysis.get":
            return {"survey": "S1", "history_surveys": ["S0"], "analysis": {"targets": 2, "groups": []},
                    "drift": {"changes": []}}
        return {"survey": "S1", "logs": {}}

    monkeypatch.setattr(ask, "ask", fake_ask)
    monkeypatch.setattr(ask, "api", fake_api)
    r = asyncio.run(ask.report("p.star", "src"))
    assert r["answers"] == [{"hosts": ["a", "b"], "outcome": "ok", "records": 1}]  # counts, no records
    assert r["analysis"]["targets"] == 2 and r["drift"] == {"changes": []} and "logs" not in r
    assert calls == ["analysis.get", "logs.get"]
    assert "answer" in asyncio.run(ask.report("p.star", "src", records=True))["answers"][0]


def test_beat_run_asks_all_hosts_in_one_survey(tmp_path, monkeypatch):
    repo = tmp_path / "est"
    (repo / "probes").mkdir(parents=True)
    (repo / "probes" / "p.star").write_text("def main():\n    pass\n")
    monkeypatch.setattr(estate, "root", lambda: repo)
    asked = []

    async def fake_ask(name, source, hosts=None, timeout=120, via=""):
        asked.append(list(hosts))
        s = _survey([h for h in hosts if h != "gone"])
        s["expected"], s["not_live"] = hosts, [h for h in hosts if h == "gone"]
        return s

    monkeypatch.setattr(ask, "ask", fake_ask)
    survey, answers = estate.ask_star("p", ["a", "b", "gone"])
    assert asked == [["a", "b", "gone"]] and survey == "S1"
    assert answers["a"]["records"] and isinstance(answers["gone"], estate.EstateError)


def test_mcp_survey_by_saved_probe_is_the_same_question_as_beat_run(tmp_path, monkeypatch):
    from beat import mcp
    repo = tmp_path / "est"
    (repo / "probes").mkdir(parents=True)
    (repo / "probes" / "nginx.star").write_text("def main():\n    pass\n")
    monkeypatch.setattr(estate, "root", lambda: repo)
    seen = {}

    async def fake_report(name, source, hosts=None, timeout=120, history=3, records=False, via=""):
        seen.update(name=name, source=source, hosts=hosts)
        return {"survey": "S1"}

    monkeypatch.setattr(ask, "report", fake_report)
    r = asyncio.run(mcp._call("survey", {"probe": "nginx", "hosts": ["lb-1"]}))
    assert r["ok"] and seen == {"name": "nginx.star", "source": "def main():\n    pass\n", "hosts": ["lb-1"]}
    assert not asyncio.run(mcp._call("survey", {"probe": "nope"}))["ok"]
    assert "probe" in asyncio.run(mcp._call("survey", {}))["error"]


def _summary_records(log: str, templates: int, minutes: int = 0) -> list[dict]:
    """What emit_log_summary emits: the log's totals, and per template its text, lines and per-minute counts. The
    first template has the most lines; the last is outside the curated set (`new`), with one line."""
    rows = [{"subject": f"log:{log}", "key": "lines_count", "value": "999", "kind": "metric", "source": "drain"}]
    for t in range(templates):
        s = f"log:{log}#{t:016x}"
        rows += [{"subject": s, "key": "template", "value": f"template {t} " + "x" * 200, "source": "drain"},
                 {"subject": s, "key": "lines_count", "value": str(1 if t == templates - 1 else 1000 - t),
                  "kind": "metric", "source": "drain"}]
        rows += [{"subject": s, "key": f"lines_count@2026-11-01T00:{m:02d}", "value": "1", "kind": "metric",
                  "source": "drain"} for m in range(minutes)]
    rows.append({"subject": f"log:{log}#{templates - 1:016x}", "key": "new", "value": "yes", "source": "drain"})
    return rows


def test_a_run_answer_that_fits_is_left_alone():
    from beat import mcp
    out = {"ok": True, "survey": "s1", "records": _summary_records("app", 3, 2)}
    assert mcp._cap_log_summaries(out) is out


def test_a_large_run_answer_loses_its_per_minute_records_first_and_says_so():
    from beat import mcp
    records = _summary_records("app", 5, 40)
    out = {"ok": True, "survey": "s1", "records": records}
    budget = mcp._size(out) // 2
    r = mcp._cap_log_summaries(out, budget)
    assert mcp._size(r) <= budget
    assert not any("@" in x["key"] for x in r["records"])
    assert {x["subject"] for x in r["records"]} == {x["subject"] for x in records}  # every template still there
    assert r["cut"]["per_minute_records_omitted"] == 200 and "templates_kept_per_log" not in r["cut"]
    assert "s1" in r["cut"]["the_rest"] and "`logs`" in r["cut"]["the_rest"]


def test_a_larger_one_keeps_its_top_templates_and_the_new_ones_and_other_records():
    from beat import mcp
    other = {"subject": "nginx", "key": "version", "value": "1.24", "source": "osq"}
    records = [other] + _summary_records("app", 64, 2)
    out = {"ok": True, "survey": "s1", "answer_hash": "h", "records": records}
    r = mcp._cap_log_summaries(out, 8000)
    assert mcp._size({**r, "cut": None}) <= 8000
    subjects = {x["subject"] for x in r["records"]}
    assert other in r["records"] and "log:app" in subjects  # what is not a template stays, the log's totals too
    assert f"log:app#{0:016x}" in subjects and f"log:app#{63:016x}" in subjects  # the most lines; the new one
    assert f"log:app#{40:016x}" not in subjects
    kept, _, total = r["cut"]["templates_kept_per_log"]["log:app"].partition(" of ")
    assert total == "64" and int(kept) < 64 and r["answer_hash"] == "h"


def test_a_large_answer_with_no_log_summary_is_not_cut():
    from beat import mcp
    out = {"ok": True, "survey": "s1", "records": [{"subject": "x", "key": "k", "value": "v" * 100}] * 100}
    assert mcp._cap_log_summaries(out, 1000) is out


def test_mcp_run_caps_but_catalog_does_not(monkeypatch):
    from beat import mcp
    big = _summary_records("app", 400, 30)

    async def ask_one(host, name, source, timeout=120):
        return {"ok": True, "survey": "s1", "records": big}
    monkeypatch.setattr(mcp, "_ask_one", ask_one)
    r = asyncio.run(mcp._call("run", {"host": "a", "source": "x"}))
    assert "cut" in r and mcp._size({**r, "cut": None}) <= mcp.RUN_MAX_BYTES
    c = asyncio.run(mcp._call("catalog", {"host": "a"}))  # needs every record: a table list is not a log summary
    assert "cut" not in c and len(c["osquery_tables"]) == len(big)


def test_a_loss_at_the_service_does_not_send_the_agent_to_the_host():
    loss = {"messages_dropped": 3, "hosts": 1, "note": "..."}
    say = " ".join(ask.standing({"ok": 9, "no_answer": 1}, True, 0, loss))
    assert "points at beat" in say and "look at those sensors" not in say
    assert "look at those sensors" in " ".join(ask.standing({"ok": 9, "no_answer": 1}, True))  # no loss: as before
    survey = {"no_answer": ["a", "b"], "maybe_lost": ["a"]}
    assert "points at beat" in ask.why_not(survey, "a")
    assert "look at the sensor" in ask.why_not(survey, "b")


def test_a_secret_walk_is_mentioned_only_when_something_was_not_looked_at():
    assert ask.secret_walk_note(None) == ""
    assert ask.secret_walk_note({"at": "t", "secrets": 3, "skipped": [], "cut": None, "error": None, "uncovered": []}) == ""
    note = ask.secret_walk_note({"at": "t", "skipped": [["/var/lib/docker", "container storage"]], "uncovered": ["/a b"]})
    assert "/var/lib/docker (container storage)" in note and "/a b" in note
    assert "not finished" in ask.secret_walk_note({"at": None})
