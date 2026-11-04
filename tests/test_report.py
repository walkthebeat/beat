"""`beat report`: the draft sends nothing, sending needs a person at a terminal, a transcript is masked first."""
import gzip
import http.server
import json
import os
import pty
import select
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

from beat import estate, report

AWS = "AKIA" + "IOSFODNN7EXAMPLF"
PEM = ("-----BEGIN RSA PRIVATE KEY-----\n" + "MIIEpAIBAAKCAQEA7bq3bPq8dKz3vJmL0xWn2Y5hR1sTf6uGc9oZiVtN4aXyE\n" * 4
       + "-----END RSA PRIVATE KEY-----")


@pytest.fixture
def env(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "cache"))
    monkeypatch.setattr(report, "_sensor_info", lambda: ({"web-secret-1"}, {"0.3.2"}))
    return tmp_path


def transcript(tmp_path) -> Path:
    t = tmp_path / "session.jsonl"
    t.write_text(json.dumps({"message": {"content": [{"text": f"key {AWS} here"}, {"text": PEM}]}}) + "\n"
                 + "not json, with " + AWS + "\n" + json.dumps({"plain": "nothing to see on this line"}) + "\n")
    return t


class Fake:
    """Stands in for the two ways out: fails the test if either is used."""

    def __init__(self, monkeypatch):
        self.sent = []
        monkeypatch.setattr(report, "upload", lambda d, v: self.sent.append("upload") or "r-20261104-aaaaaaaaaaaa")
        monkeypatch.setattr(report, "post_issue", lambda *a: self.sent.append(("issue", a[1])) or "Posted: url")


class Answers:
    def __init__(self, monkeypatch, *answers):
        self.questions, it = [], iter(answers)
        tty = self

        class T:
            f = sys.stderr

            def __enter__(s):
                return s

            def __exit__(s, *_):
                pass

            def confirm(s, q):
                tty.questions.append(q)
                return next(it)
        monkeypatch.setattr(report, "Tty", T)


def test_draft_writes_and_sends_nothing(env, monkeypatch):
    fake = Fake(monkeypatch)
    d = report.draft("it broke", None, ["20261104T100000Z-aaaaaa"], transcript(env), "beat 0.4.0")
    assert fake.sent == [] and d.stat().st_mode & 0o777 == 0o700
    assert (d / "transcript.masked.jsonl").stat().st_mode & 0o777 == 0o600
    text = report.body(d, None)
    assert "it broke" in text and "beat 0.4.0; sensors: 0.3.2" in text and "20261104T100000Z-aaaaaa" in text
    assert "web-secret-1" not in text  # names of hosts are never added by beat


def test_masks_a_transcript_as_decoded_json_and_as_text(env):
    hits = report.mask_transcript(transcript(env), env / "m.jsonl")
    out = (env / "m.jsonl").read_text()
    assert AWS not in out and "MIIEpAIBAAK" not in out and "[masked:" in out and sum(hits.values()) >= 3
    assert "nothing to see on this line" in out
    lines = out.splitlines()
    assert json.loads(lines[0])["message"]["content"][0]["text"].startswith("key [masked:")  # still JSON


def test_rules_in_gos_syntax_are_used():
    assert report._rules()[3] == 0
    tok = "SG." + "aB3dE5gH7j" * 6 + "aB3dE5"
    assert tok not in report.mask(f"sendgrid token {tok} here")


def test_a_secret_in_the_summary_is_masked(env):
    d = report.draft(f"failed with {AWS}", None, [], None, "beat x")
    assert AWS not in report.body(d, None) and json.loads((d / "draft.json").read_text())["summary_masked"] == 1


def test_no_rules_no_transcript(env, monkeypatch):
    report._rules.cache_clear()
    monkeypatch.setattr(report, "rules_dir", lambda: None)
    try:
        with pytest.raises(RuntimeError, match="cannot be masked"):
            report.draft("x", None, [], transcript(env), "beat x")
    finally:
        report._rules.cache_clear()


def test_each_part_has_its_own_yes(env, monkeypatch):
    fake = Fake(monkeypatch)
    d = report.draft("it broke", None, [], transcript(env), "beat x")
    Answers(monkeypatch, False, False)
    report.send(d.name, "beat x")
    assert fake.sent == []
    Answers(monkeypatch, False, True)
    report.send(d.name, "beat x")
    assert fake.sent == [("issue", report.body(d, None))] and "Not sent." in fake.sent[0][1]


def test_the_public_issue_names_only_the_report_id(env, monkeypatch):
    fake = Fake(monkeypatch)
    d = report.draft("it broke", None, [], transcript(env), "beat x")
    a = Answers(monkeypatch, True, True)
    report.send(d.name, "beat x")
    assert fake.sent[0] == "upload" and "r-20261104-aaaaaaaaaaaa" in fake.sent[1][1]
    assert "walkthebeat's staff will read it" in a.questions[0] and "PUBLIC" in a.questions[1]
    assert str(d) not in fake.sent[1][1] and "session.jsonl" not in fake.sent[1][1] and AWS not in fake.sent[1][1]
    Answers(monkeypatch)  # sent already: no question and nothing again
    report.send(d.name, "beat x")
    assert len(fake.sent) == 2


def test_warns_when_the_summary_names_a_sensor(env, monkeypatch):
    Fake(monkeypatch)
    d = report.draft("web-secret-1 is down", None, [], None, "beat x")
    a = Answers(monkeypatch, False)
    report.send(d.name, "beat x")
    assert "names your hosts: web-secret-1" in a.questions[0]


CMD = [sys.executable, "-c", "from beat.cli import main; main()"]


def run_cli(env, *args, **kw):
    return subprocess.run([*CMD, *args], env={**os.environ, "XDG_CACHE_HOME": str(env / "cache"),
                                              "BEAT_API": "http://127.0.0.1:9", "BEAT_TOKEN": "t"},
                          capture_output=True, text=True, start_new_session=True, timeout=120, **kw)


def test_no_terminal_no_send_and_a_pipe_does_not_answer(env, tmp_path):
    """As an agent runs it: no controlling terminal; piping yes in reaches nothing."""
    assert run_cli(env, "report", "draft", "--summary", "it broke").returncode == 0
    r = run_cli(env, "report", "send", input="yes\nyes\nyes\n")
    assert r.returncode != 0 and "nothing was sent" in r.stderr
    assert not list((env / "cache" / "beat" / "reports").glob("*/sent.json"))


def test_no_flag_says_yes(env):
    r = run_cli(env, "report", "send", "--yes")
    assert r.returncode != 0 and "unrecognized arguments" in r.stderr


def in_terminal(env, answer: str, *args, extra=None) -> str:
    """The command on a real terminal, answered there, as a person does."""
    pid, fd = pty.fork()
    if pid == 0:
        os.environ.update({"XDG_CACHE_HOME": str(env / "cache"), "BEAT_API": "http://127.0.0.1:9", "BEAT_TOKEN": "t",
                           **(extra or {})})
        os.execv(CMD[0], [*CMD, *args])
    out, until = b"", time.time() + 60
    while time.time() < until:
        r, _, _ = select.select([fd], [], [], 1)
        if r:
            try:
                data = os.read(fd, 65536)
            except OSError:
                break
            if not data:
                break
            out += data
            if out.rstrip().endswith(b"anything else not to:"):
                os.write(fd, answer.encode() + b"\n")
                out += b"<answered>"
    os.waitpid(pid, 0)
    return out.decode(errors="replace")


def test_at_a_real_terminal_no_is_no(env):
    assert run_cli(env, "report", "draft", "--summary", "it broke").returncode == 0
    out = in_terminal(env, "no", "report", "send")
    assert "PUBLIC" in out and "Summary not posted." in out and "Posted" not in out


def test_at_a_real_terminal_yes_with_no_gh_gives_a_link(env, tmp_path):
    assert run_cli(env, "report", "draft", "--summary", "it broke").returncode == 0
    empty = tmp_path / "bin"
    empty.mkdir()
    out = in_terminal(env, "yes", "report", "send", extra={"PATH": str(empty)}).replace("\r\n", "")
    assert "github.com/walkthebeat/feedback/issues/new?template=problem.yml" in out
    assert "what=it+broke" in out and "versions=beat" in out  # the form's own fields, not its headings


def test_gh_posts_with_the_users_own_login(env, tmp_path, monkeypatch):
    calls = tmp_path / "calls"
    gh = tmp_path / "gh"
    gh.write_text(f'#!/bin/sh\necho "$@" >> {calls}\ncase "$1" in issue) echo https://github.com/x/1;; esac\n')
    gh.chmod(0o755)
    monkeypatch.setenv("PATH", f"{tmp_path}:{os.environ['PATH']}")
    f = tmp_path / "b.md"
    f.write_text("x")
    assert report.post_issue("t", "x", f) == "Posted: https://github.com/x/1"
    assert f"issue create -R walkthebeat/feedback --title t --body-file {f}" in calls.read_text()


def test_upload_gzips_the_masked_copy_only_and_says_a_refusal(env, monkeypatch):
    got = {}

    class H(http.server.BaseHTTPRequestHandler):
        def do_POST(self):
            got["body"] = self.rfile.read(int(self.headers["Content-Length"]))
            got["auth"], got["client"] = self.headers["Authorization"], self.headers["Beat-Client"]
            code = 413 if got.get("refuse") else 200
            self.send_response(code)
            self.end_headers()
            self.wfile.write(json.dumps({"error": "over the limit"} if code == 413 else {"id": "r-1"}).encode())

        def log_message(self, *_):
            pass
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    monkeypatch.setenv("BEAT_API", f"http://127.0.0.1:{srv.server_address[1]}")
    monkeypatch.setenv("BEAT_TOKEN", "tok")
    d = report.draft("x", None, [], transcript(env), "beat x")
    assert report.upload(d, "beat 9") == "r-1"
    text = gzip.decompress(got["body"]).decode()
    assert AWS not in text and "[masked:" in text and got["auth"] == "Bearer tok" and got["client"] == "beat 9"
    got["refuse"] = True
    with pytest.raises(RuntimeError, match="over the limit"):
        report.upload(d, "beat 9")
    srv.shutdown()


def test_a_service_from_before_reports_is_said_plainly(env, monkeypatch, capsys):
    """Against an older service: GET /v1/reports is 405 with no JSON; POST reaches `unknown method`."""
    from argparse import Namespace

    from beat import ask
    monkeypatch.setattr(ask, "_http", lambda *a, **k: (405, b"Method Not Allowed"))
    with pytest.raises(RuntimeError, match="may not take reports yet"):
        report.main(Namespace(report_cmd="list"), "beat x")


def test_finds_this_directorys_newest_session(tmp_path, monkeypatch):
    monkeypatch.setenv("CLAUDE_CONFIG_DIR", str(tmp_path / "c"))
    monkeypatch.chdir(tmp_path)
    with pytest.raises(RuntimeError, match="--transcript"):
        report.session_transcript()
    d = tmp_path / "c" / "projects" / __import__("re").sub(r"[^A-Za-z0-9]", "-", str(Path.cwd()))
    d.mkdir(parents=True)
    (d / "old.jsonl").write_text("x")
    os.utime(d / "old.jsonl", (1, 1))
    (d / "new.jsonl").write_text("x")
    assert report.session_transcript().name == "new.jsonl"


def test_an_estate_denies_agents_the_send_and_gets_the_skill(tmp_path):
    estate.init(tmp_path / "e")
    s = json.loads((tmp_path / "e" / ".claude" / "settings.json").read_text())["permissions"]
    assert any(d.endswith("beat report send:*)") for d in s["deny"]) and any(d.endswith("beat report delete:*)") for d in s["deny"])
    assert any(x.endswith("beat report draft:*)") for x in s["allow"])
    skill = (tmp_path / "e" / ".claude" / "skills" / "report" / "SKILL.md").read_text()
    assert "@BEAT@" not in skill and "report draft" in skill
