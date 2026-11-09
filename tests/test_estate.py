"""Estate repository: init from the template, run probes into facts/; the MCP tools on offer."""
import json
import subprocess
import sys
from pathlib import Path

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

    async def fake_ask(name, source, hosts=None, timeout=120, via="", profile=False):
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

    async def fake_ask(name, source, hosts=None, timeout=120, via="", profile=False):
        return {"survey": "s", "question": "q", "expected": hosts, "answers": {}, "down": hosts,
                "not_live": hosts, "live": ["beat-dev", "legacy-web-1"]}
    from beat import ask
    monkeypatch.setattr(ask, "ask", fake_ask)
    with pytest.raises(estate.EstateError, match="no live sensor named 'beat-devg' \\(did you mean beat-dev\\?\\)"):
        estate.run_probe("web", "beat-devg")
    assert "did you mean" not in ask.not_live_reason("zzz", ["beat-dev"])


def test_the_default_pack_is_found_after_the_estates_probes(repo):
    assert estate.probe_path(repo, "hello") == estate.PACK / "hello.star"
    assert estate.origin(repo, estate.probe_path(repo, "hello")) == "pack:hello.star"
    (repo / "probes" / "hello.star").write_text('"""Ours."""\ndef main() -> None:\n    pass\n')
    assert estate.probe_path(repo, "hello") == repo / "probes" / "hello.star"  # the estate's wins
    assert estate.origin(repo, estate.probe_path(repo, "hello")) == "probes/hello.star"
    with pytest.raises(estate.EstateError, match="no probe 'nosuch'"):
        estate.probe_path(repo, "nosuch")


def test_probes_lists_both_with_where_each_comes_from(repo):
    (repo / "probes" / "nginx.star").write_text('"""nginx: its config."""\ndef main() -> None:\n    pass\n')
    (repo / "probes" / "hello.star").write_text('"""Ours."""\ndef main() -> None:\n    pass\n')
    estate.fork(repo, "journal")
    got = {p["name"]: p for p in estate.probes(repo)}
    assert got["nginx"]["origin"] == "estate" and got["nginx"]["summary"] == "nginx: its config."
    assert got["host-base"]["origin"] == "pack"
    assert got["hello"]["origin"] == "estate, over the pack's"
    assert got["journal"]["origin"] == "estate, forked from the pack"
    assert {"hello", "host-base", "systemd-units", "listeners", "sysctl-persist", "journal", "beat-sensor"} <= set(got)


def test_fork_makes_the_packs_probe_the_estates(repo):
    p = estate.fork(repo, "host-base")
    text = p.read_text()
    assert p == repo / "probes" / "host-base.star" and text.startswith(estate.FORKED)
    assert text.endswith((estate.PACK / "host-base.star").read_text())  # the pack's, below one marker line
    assert estate.probe_path(repo, "host-base") == p
    with pytest.raises(estate.EstateError, match="exists already"):
        estate.fork(repo, "host-base")
    with pytest.raises(estate.EstateError, match="no nosuch.star"):
        estate.fork(repo, "nosuch")


def test_run_every_asks_every_probe_and_writes_each_hosts_facts(repo, monkeypatch):
    asked = []

    async def fake_ask(name, source, hosts=None, timeout=120, via="", profile=False):
        asked.append(name)
        return {"survey": f"s-{name}", "question": "q", "expected": hosts, "down": [], "answers": {h: {
            "answer_hash": "h", "outcome": "ok", "answer": {"v": 1, "outcome": "ok", "diag": "", "notes": [],
            "error": None, "failures": [],
            "records": [{"subject": "host", "key": "probe", "value": name, "source": "s", "span": "x"}]}}
            for h in hosts}}

    async def fake_whoami():
        return {}
    from beat import ask
    monkeypatch.setattr(ask, "ask", fake_ask)
    monkeypatch.setattr(ask, "whoami", fake_whoami)
    from beat import seal
    monkeypatch.setattr(seal, "member", lambda: ("key", "cred"))
    out = estate.run_every(["web-1", "web-2"])
    names = [p["name"] for p in estate.probes(repo)]
    assert sorted(asked) == sorted(f"{n}.star" for n in names) and [n for n, _, _ in out] == names
    for name, survey, results in out:
        assert survey == f"s-{name}.star" and set(results) == {"web-1", "web-2"}
        assert results["web-1"]["probe"] == f"pack:{name}.star" and results["web-1"]["commit"]
    assert (repo / "hosts/web-2/facts/hello.jsonl").exists()


def test_init_and_commit_without_a_git_identity(tmp_path, monkeypatch):
    # A fresh laptop: git knows no name or email, and git itself would refuse to commit.
    for k in ("GIT_AUTHOR_NAME", "GIT_AUTHOR_EMAIL", "GIT_COMMITTER_NAME", "GIT_COMMITTER_EMAIL", "EMAIL"):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", str(tmp_path / "none"))
    monkeypatch.setenv("GIT_CONFIG_NOSYSTEM", "1")
    e = tmp_path / "estate"
    estate.init(e)
    log = subprocess.run(["git", "-C", str(e), "log", "--format=%an <%ae>"], capture_output=True, text=True).stdout
    assert log.strip() == "beat <beat@localhost>"
    # Nothing written to the repository's configuration: the person's identity, once set, is used.
    assert "user." not in (e / ".git" / "config").read_text()
    subprocess.run(["git", "-C", str(e), "config", "user.name", "Someone"], check=True)
    subprocess.run(["git", "-C", str(e), "config", "user.email", "someone@example.com"], check=True)
    (e / "notes.md").write_text("x\n")
    estate._git(e, "add", "notes.md")
    estate._git(e, "commit", "-q", "-m", "notes")
    log = subprocess.run(["git", "-C", str(e), "log", "-1", "--format=%an"], capture_output=True, text=True).stdout
    assert log.strip() == "Someone"


def test_init_names_commands_so_the_estate_works_on_another_machine(tmp_path, monkeypatch):
    # PATH finds this installation's beat: the files say `beat`, so settings.json's deny rule matches on every machine.
    bindir = Path(sys.executable).parent
    monkeypatch.setattr(estate.shutil, "which", lambda name: str(bindir / name))
    e = tmp_path / "estate"
    estate.init(e)
    assert json.loads((e / ".mcp.json").read_text())["mcpServers"]["beat"]["command"] == "beat-mcp"
    settings = (e / ".claude" / "settings.json").read_text()
    assert '"Bash(beat survey delete:*)"' in settings and str(bindir) not in settings
    assert str(bindir) not in (e / "CLAUDE.md").read_text()


def test_init_keeps_the_path_when_path_finds_another_beat(tmp_path, monkeypatch):
    monkeypatch.setattr(estate.shutil, "which", lambda name: "/elsewhere/bin/" + name)
    e = tmp_path / "estate"
    estate.init(e)
    bindir = Path(sys.executable).parent
    assert json.loads((e / ".mcp.json").read_text())["mcpServers"]["beat"]["command"] == str(bindir / "beat-mcp")
    assert f'"Bash({bindir / "beat"} survey delete:*)"' in (e / ".claude" / "settings.json").read_text()
