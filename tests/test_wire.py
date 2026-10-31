"""The wire format's canonical JSON matches the sensor's (sensor/src/wire.rs checks the same vectors)."""
import json
from pathlib import Path

from beat import wire

VECTORS = json.loads((Path(__file__).parent / "wire_vectors.json").read_text())


def test_canonical_vectors():
    for case in VECTORS:
        c = wire.canonical(case["value"])
        assert c.decode() == case["canonical"]
        assert wire.sha256_hex(c) == case["sha256"]


def test_question_hash_covers_params():
    a = wire.question("a.star", "def main(): pass")
    b = wire.question("a.star", "def main(): pass", params={"port": "443"})
    assert wire.sha256_hex(a) != wire.sha256_hex(b)
    assert a == wire.question("a.star", "def main(): pass")


def test_survey_id_is_a_subject_token():
    s = wire.new_survey_id()
    assert "." not in s and " " not in s and len(s) == 23


def test_too_large_says_where_the_bytes_are():
    """The same message as sensor/src/wire.rs answer_too_large (its test uses the same answer)."""
    recs = [{"subject": f"job:{i}", "key": "state", "value": "FAILED"} for i in range(50)] + \
        [{"subject": "host", "key": "os", "value": "x"}]
    a = {"v": 1, "outcome": "ok", "records": recs, "failures": [], "error": None, "diag": "", "notes": ["n"]}
    t = wire.too_large(a, 2_000_000, 1_048_576)
    assert t["outcome"] == "error" and t["error"]["kind"] == "too_large" and t["records"] == [] and t["notes"] == ["n"]
    m = t["error"]["message"]
    assert m.startswith("answer too large: 2000000 bytes, 51 records, over the 1048576-byte message limit")
    assert "job: 50 records" in m and m.index("job:") < m.index("host:")


def test_the_service_url(tmp_path, monkeypatch):
    """BEAT_API, else what `beat login URL` kept, else this machine."""
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    monkeypatch.delenv("BEAT_API", raising=False)
    assert wire.api_source() == (wire.DEFAULT_API, "the default")
    wire.remember_api("https://beat.example.com/")
    assert wire.api_source() == ("https://beat.example.com", str(tmp_path / "beat" / "service"))
    monkeypatch.setenv("BEAT_API", "http://10.0.0.5:8480")
    assert wire.api_source() == ("http://10.0.0.5:8480", "BEAT_API")
