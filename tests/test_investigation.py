"""Investigations from the client (investigation.py): the CLI's current one per directory as a stack, and the MCP
passing an investigation and a why with each survey."""
import asyncio

from beat import ask, investigation as inv, mcp


def test_the_current_investigation_is_a_stack_per_directory(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    monkeypatch.delenv(inv.ENV, raising=False)
    a, b = tmp_path / "a", tmp_path / "b"
    a.mkdir(), b.mkdir()
    assert inv.current(a) is None
    inv.push("i-1", a), inv.push("i-2", a)
    assert (inv.current(a), inv.current(b)) == ("i-2", None)
    assert inv.pop("i-2", a) == "i-1" and inv.pop("i-1", a) is None and inv.stack(a) == []
    monkeypatch.setenv(inv.ENV, "i-9")
    assert inv.current(b) == "i-9" and inv.intent() == {"investigation": "i-9", "why": None}
    monkeypatch.setenv(inv.ENV, "none")
    assert inv.intent() is None


def test_survey_and_run_ask_for_the_investigation_with_their_why(monkeypatch):
    seen = []

    async def fake_ask(name, source, hosts=None, timeout=120, via="", profile=False, **kw):
        seen.append(kw.get("intent"))
        return {"survey": "S1", "question": "q", "expected": hosts or ["a"], "down": [], "no_answer": [],
                "running": [], "not_live": [], "live": ["a"],
                "answers": {"a": {"answer_hash": "h", "outcome": "ok", "answer": {"records": [], "outcome": "ok"}}}}

    async def fake_api(method, params=None, timeout=10):
        seen.append((method, {k: v for k, v in (params or {}).items() if k not in ("user", "via", "cwd")}))
        if method == "analysis.get":
            return {"survey": "S1", "history_surveys": [], "analysis": {"targets": 1, "groups": []}}
        return {"investigation": "i-1"} if method == "investigation.open" else {"survey": "S1", "logs": {}}

    monkeypatch.setattr(ask, "ask", fake_ask)
    monkeypatch.setattr(ask, "api", fake_api)
    r = asyncio.run(mcp._call("investigate", {"action": "open", "text": "why slow?", "kind": "incident"}))
    assert r == {"ok": True, "investigation": "i-1"}
    asyncio.run(mcp._call("run", {"host": "a", "source": "def main():\n    pass\n", "investigation": "i-1",
                                  "why": "is it the db?"}))
    asyncio.run(mcp._call("survey", {"source": "def main():\n    pass\n", "investigation": "i-1"}))
    asyncio.run(mcp._call("investigations", {"text": "slow"}))
    assert seen[0] == ("investigation.open", {"text": "why slow?", "kind": "incident", "parents": []})
    assert seen[1] == {"investigation": "i-1", "why": "is it the db?"} and seen[2] == {"investigation": "i-1"}
    assert ("investigation.search", {"text": "slow"}) in seen
    assert asyncio.run(mcp._call("investigate", {"action": "edit"}))["ok"] is False
