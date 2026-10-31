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
