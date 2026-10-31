"""Estate repository: init from the template, run probes into facts/; the MCP tools on offer."""
import json
import subprocess

import pytest

from beat import estate


@pytest.fixture
def repo(tmp_path, monkeypatch):
    estate.init(tmp_path / "estate")
    monkeypatch.chdir(tmp_path / "estate")
    return tmp_path / "estate"


def test_init(repo):
    assert (repo / "CLAUDE.md").exists() and (repo / "hosts").is_dir()
    assert "@BEAT@" not in (repo / "CLAUDE.md").read_text()
    mcp = json.loads((repo / ".mcp.json").read_text())
    assert mcp["mcpServers"]["beat"]["command"].endswith("beat-mcp")
    (repo / "hosts" / "web-1").mkdir()
    import os
    os.chdir(repo / "hosts" / "web-1")
    assert estate.root() == repo  # found from the working directory


def test_run_starlark_probe(repo, monkeypatch):
    """`beat run` on a .star probe: the answer (over NATS) becomes facts/<probe>.jsonl and run.json."""
    (repo / "probes" / "web.star").write_text('def main() -> None:\n    emit("a", "b", "c", "d")\n')
    seen = {}

    async def fake_ask(name, source, hosts=None, timeout=120, via=""):
        seen.update(host=hosts[0], name=name, source=source)
        return {"survey": "s", "question": "q", "expected": hosts, "down": [], "answers": {hosts[0]: {
            "answer_hash": "h", "outcome": "partial", "answer": {
            "v": 1, "outcome": "partial", "diag": "", "notes": ["n1"], "error": None,
            "records": [{"subject": "unit:x", "key": "k", "value": "2", "source": "s", "span": "web.star:2:5"},
                        {"subject": "unit:a", "key": "k", "value": "1", "source": "s", "span": "web.star:2:5"}],
            "failures": [{"kind": "assertion", "message": "expected one", "span": "web.star:3:1", "stack": ""}]}}}}
    from beat import ask
    monkeypatch.setattr(ask, "ask", fake_ask)
    r = estate.run_probe("web", "web-1")
    assert seen["name"] == "web.star" and seen["source"].startswith("def main")
    recs = [json.loads(l) for l in (repo / "hosts/web-1/facts/web.jsonl").read_text().splitlines()]
    assert [x["subject"] for x in recs] == ["unit:a", "unit:x"]  # sorted, spans dropped
    assert "span" not in recs[0]
    assert r["exit"] == 1 and r["assertions_failed"] == ["assertion: expected one (web.star:3:1)"] and r["commit"]


def test_mcp_offers_starlark_run_without_query():
    from beat import mcp
    tools = {t.name: t for t in mcp.tool_defs("starlark guide", ["web-1"])}
    assert set(tools) == {"survey", "run", "query", "inventory", "analyze", "logs", "catalog", "describe_osquery_table"}
    assert tools["run"].description == mcp.RUN_PREFIX + "starlark guide"
    assert "source" in tools["run"].inputSchema["required"] and "probe" in tools["survey"].inputSchema["properties"]
    # Each description starts with when to use the tool; the fleet tool is named where the agent would go instead.
    assert "use `survey`" in tools["run"].description and "`survey` already returns" in tools["analyze"].description


def test_run_on_a_host_with_no_live_sensor_says_so(repo, monkeypatch):
    """A mistyped or absent host fails at once with a reason and close live names, not after the deadline."""
    (repo / "probes" / "web.star").write_text('def main() -> None:\n    emit("a", "b", "c", "d")\n')

    async def fake_ask(name, source, hosts=None, timeout=120, via=""):
        return {"survey": "s", "question": "q", "expected": hosts, "answers": {}, "down": hosts,
                "not_live": hosts, "live": ["beat-dev", "legacy-web-1"]}
    from beat import ask
    monkeypatch.setattr(ask, "ask", fake_ask)
    with pytest.raises(estate.EstateError, match="no live sensor named 'beat-devg' \\(did you mean beat-dev\\?\\)"):
        estate.run_probe("web", "beat-devg")
    assert "did you mean" not in ask.not_live_reason("zzz", ["beat-dev"])
