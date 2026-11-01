"""Signed questions and sealed answers (seal.py): the vectors the sensor checks too (sensor/src/seal.rs)."""
import json
from datetime import datetime
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric import x25519

from beat import seal

V = json.loads((Path(__file__).parent / "seal_vectors.json").read_text())


def test_vectors_verify_and_open():
    key = seal.signing_key(seal.unb64(V["seed"]))
    assert seal.b64(seal.public_raw(key)) == V["public"]
    for case in V["signed"]:
        payload = case["payload"].encode()
        assert seal.signed_bytes(case["kind"], case["headers"], payload).decode() == case["signed_bytes"]
        seal.verify(key.public_key(), case["kind"], case["headers"], payload, "vector")
    s = V["sealed"]
    sk = x25519.X25519PrivateKey.from_private_bytes(seal.unb64(s["private"]))
    assert seal.open_sealed(sk, s["survey"], s["target"], seal.unb64(s["sealed"])).decode() == s["plaintext"]


def test_what_is_refused():
    key = seal.signing_key(seal.unb64(V["seed"]))
    case = V["signed"][0]
    h, payload = case["headers"], case["payload"].encode()
    for kind, headers, data in [
        ("ask", {k: v for k, v in h.items() if k != "Beat-Signature"}, payload),   # unsigned
        ("ask", {**h, "Beat-Targets": "everyone"}, payload),                        # a header changed
        ("ask", {k: v for k, v in h.items() if k != "Beat-Targets"}, payload),      # a header removed
        ("ask", h, payload + b" "),                                                  # another payload
        ("ack", h, payload),                                                         # another kind
    ]:
        with pytest.raises(seal.Refused):
            seal.verify(key.public_key(), kind, headers, data, "q")
    other = seal.signing_key(bytes(32))
    with pytest.raises(seal.Refused):
        seal.verify(other.public_key(), "ask", h, payload, "q")
    s = V["sealed"]
    sk = x25519.X25519PrivateKey.from_private_bytes(seal.unb64(s["private"]))
    with pytest.raises(seal.Refused):  # sealed for target a, opened as b
        seal.open_sealed(sk, s["survey"], "b", seal.unb64(s["sealed"]))
    with pytest.raises(seal.Refused):  # another survey's key
        seal.open_sealed(seal.survey_key(), s["survey"], s["target"], seal.unb64(s["sealed"]))


def kept_root(path, name="r1"):
    """An org root kept on a machine (`beat org init --keep`)."""
    ring = seal.org_keys(path)
    ring.keep(name, seal.ed25519.Ed25519PrivateKey.generate())
    return ring


def test_keys_on_disk(tmp_path):
    client, service = tmp_path / "client", tmp_path / "service"
    org = kept_root(client)
    k = org.key()
    assert org.key().public_key().public_bytes(*seal.RAW) == seal.public_raw(k)
    name = org.current()
    assert (client / "org" / f"{name}.key").stat().st_mode & 0o777 == 0o600
    assert org.public() == {name: seal.b64(seal.public_raw(k))}
    own = seal.collector_keys(service)  # the service's own keys: other keys, in the service's directory
    assert (service / "collector" / f"{own.current()}.key").stat().st_mode & 0o777 == 0o600
    assert seal.public_raw(own.key()) != seal.public_raw(k)
    sensor = seal.signing_key(bytes(range(32)))
    seal.enroll("a", seal.b64(seal.public_raw(sensor)), service)
    enrolled = seal.Enrolled(service)
    assert enrolled.get("a").public_bytes(*seal.RAW) == seal.public_raw(sensor)
    assert enrolled.get("b") is None and enrolled.get("../a") is None
    with pytest.raises(ValueError):
        seal.enroll("a.b", seal.b64(seal.public_raw(sensor)), service)


def test_rotation(tmp_path):
    for ring in (kept_root(tmp_path), seal.collector_keys(tmp_path)):  # the same rotation for both
        first = ring.current()
        old = ring.key()
        pub = ring.new("next")
        assert ring.public() == {first: seal.b64(seal.public_raw(old)), "next": pub}
        assert seal.public_raw(ring.key()) == seal.public_raw(old)  # not in use yet
        for bad in ("next", "a.b", "current", "retired"):
            with pytest.raises(ValueError):
                ring.new(bad)
        with pytest.raises(ValueError):
            ring.retire(first)  # in use
        ring.use("next")
        assert seal.b64(seal.public_raw(ring.key())) == pub
        ring.retire(first)
        assert ring.public() == {"next": pub}
        assert first in ring.public(retired=True)
        assert not (ring.dir / f"{first}.key").exists()  # destroyed
        with pytest.raises(ValueError):
            ring.use(first)


def test_countersigned_vector():
    """Both signatures over the same bytes, each checked in its own header: one cannot stand in for the other."""
    c = V["countersigned"]
    h, payload = c["headers"], c["payload"].encode()
    org, collector = seal.signing_key(bytes([9] * 32)), seal.signing_key(seal.unb64(V["seed"]))
    assert seal.signed_bytes("ask", h, payload).decode() == c["signed_bytes"]
    seal.verify(org.public_key(), "ask", h, payload, "q")
    seal.verify(collector.public_key(), "ask", h, payload, "q", seal.COUNTERSIGNATURE)
    with pytest.raises(seal.Refused):
        seal.verify(collector.public_key(), "ask", h, payload, "q")
    with pytest.raises(seal.Refused, match="not countersigned"):
        seal.verify(collector.public_key(), "ask", V["signed"][0]["headers"], payload, "q", seal.COUNTERSIGNATURE)


def test_unenroll(tmp_path):
    seal.enroll("a", seal.b64(seal.public_raw(seal.signing_key(bytes(32)))), tmp_path)
    seal.unenroll("a", tmp_path)
    assert seal.Enrolled(tmp_path).get("a") is None
    with pytest.raises(ValueError):
        seal.unenroll("a", tmp_path)


def test_heartbeats():
    key = seal.signing_key(seal.unb64(V["seed"]))
    entry = V["heartbeat"]

    class One:
        def get(self, name):
            return key.public_key() if name == "legacy-web-1" else None
    at = datetime.fromisoformat("2026-10-15T10:00:10+00:00").timestamp()
    assert seal.check_heartbeat(entry, One(), now=at + 5) is None
    assert "old" in seal.check_heartbeat(entry, One(), now=at + 60)                     # replayed later
    assert "bad signature" in seal.check_heartbeat({**entry, "sandbox": "none"}, One(), now=at)
    assert "not signed" in seal.check_heartbeat({k: v for k, v in entry.items() if k != "signature"}, One(), now=at)
    assert seal.check_heartbeat({**entry, "name": "other"}, One(), now=at) == "not enrolled"


def test_credential_vector():
    c = V["credential"]
    root = seal.signing_key(seal.unb64(V["seed"]))
    m = seal.check_credential(c["credential"], {"r1": root.public_key()}, now=c["now"] + 10)
    assert (m["name"], m["root"], seal.b64(seal.public_raw_of(m["public"]))) == ("alice", "r1", c["member_public"])
    assert seal.credential(root, "r1", "alice", seal.unb64(c["member_public"]), now=c["now"]) == c["credential"]


def test_credentials_that_are_refused():
    root, other = seal.signing_key(bytes(range(32))), seal.signing_key(bytes(32))
    roots = {"r1": root.public_key()}
    member = seal.public_raw(seal.signing_key(bytes(range(3, 35))))
    good = seal.credential(root, "r1", "alice", member, now=1000)
    seal.check_credential(good, roots, now=1000 + 86400)
    fields = seal.read_credential(good)
    forged = seal.b64(seal.wire.canonical({**fields, "name": "root"}))  # a name changed under the root's signature
    for text, now, says in [
        (good, 1000 + seal.MEMBER_LIFE_S + seal.SKEW_S + 1, "expired"),
        (good, 1000 - seal.SKEW_S - 1, "not valid yet"),
        (seal.credential(other, "r1", "alice", member, now=1000), 1000, "not signed by a root"),
        (forged, 1000, "not signed by a root"),
        ("not base64!", 1000, "not base64"),
    ]:
        with pytest.raises(seal.Refused, match=says):
            seal.check_credential(text, roots, now=now)


def test_member_is_made_and_renewed_from_the_root_here(tmp_path, monkeypatch):
    monkeypatch.setattr(seal, "member_name", lambda: "alice")
    kept_root(tmp_path)                                # one person: the org's root kept on this machine
    cc = tmp_path / "cc"
    key, cred = seal.member(tmp_path, cc, now=1000)
    roots = {n: seal.public_key(k) for n, k in seal.org_keys(tmp_path).public().items()}
    m = seal.check_credential(cred, roots, now=1000)
    assert m["name"] == "alice" and seal.public_raw_of(m["public"]) == seal.public_raw(key)
    k, c = seal.member(tmp_path, cc, now=1000 + 86400)   # kept while fresh
    assert c == cred and seal.public_raw(k) == seal.public_raw(key)
    later = 1000 + seal.MEMBER_LIFE_S - seal.RENEW_BEFORE_S + 1
    key2, cred2 = seal.member(tmp_path, cc, now=later)   # due: a fresh key and credential
    assert cred2 != cred and seal.public_raw(key2) != seal.public_raw(key)
    monkeypatch.setattr(seal, "member_name", lambda: "bob")   # someone else signed in: their own credential
    _, cred_bob = seal.member(tmp_path, cc, now=later)
    assert seal.read_credential(cred_bob)["name"] == "bob"
    seal.org_keys(tmp_path).new("r2")
    seal.org_keys(tmp_path).use("r2")                # another root certifies from now on
    _, cred3 = seal.member(tmp_path, cc, now=later)
    assert seal.read_credential(cred3)["issuer"].startswith("r2:")
    assert (cc / "key").stat().st_mode & 0o777 == 0o600 and cc.stat().st_mode & 0o777 == 0o700
    assert seal.destroy_member(cc) and not (cc / "key").exists() and not seal.destroy_member(cc)


def test_creds_new_signs_from_a_root_file_like_kinit(tmp_path, monkeypatch):
    monkeypatch.setattr(seal, "member_name", lambda: "bob")
    admin, laptop = tmp_path / "admin", tmp_path / "laptop"
    ring = kept_root(admin)                             # the org's root, on the admin's machine
    root_file = ring.dir / f"{ring.current()}.key"
    with pytest.raises(seal.Refused, match="no member credential"):
        seal.member(laptop, laptop / "cc", now=1000)    # nothing here yet
    assert not (laptop / "org").exists()                # and no root made on the way
    root, name = seal.read_root(root_file)
    key, cred = seal.new_member(root, name, life=7 * 86400, cache=laptop / "cc", now=1000)
    roots = {n: seal.public_key(k) for n, k in ring.public().items()}
    assert seal.check_credential(cred, roots, now=1000)["name"] == "bob"
    k, c = seal.member(laptop, laptop / "cc", now=1000 + 6 * 86400)   # used as it is: no root here to renew it from
    assert c == cred and seal.public_raw(k) == seal.public_raw(key)
    with pytest.raises(seal.Refused, match="expired"):
        seal.member(laptop, laptop / "cc", now=1000 + 7 * 86400)
    with pytest.raises(ValueError, match="at most 90 days"):
        seal.new_member(root, name, life=91 * 86400, cache=laptop / "cc")
    with pytest.raises(seal.Refused, match="No such file"):
        seal.read_root(tmp_path / "nope.key")
    assert seal.member_roots(laptop / "cc") == ring.public()  # what `beat sensors add` gives hosts, root not here


def test_deny_list():
    root, other = seal.signing_key(seal.unb64(V["seed"])), seal.signing_key(bytes(32))
    roots = {"r1": root.public_key()}
    d = seal.check_deny(V["deny"]["list"].encode(), roots)
    assert d["seq"] == 7 and [e["name"] for e in d["entries"]] == ["alice"]
    old = seal.read_credential(V["credential"]["credential"])     # alice's, issued at 1800000000: before
    assert "deny list" in seal.denied(old, d)
    assert seal.denied({**old, "not_before": 1800000100}, d) is None   # a new one, issued at the denial or after
    assert seal.denied({**old, "name": "bob"}, d) is None
    with pytest.raises(seal.Refused, match="not signed by a root"):
        seal.check_deny(seal.deny_list(other, "x", [], 8), roots)
    forged = json.loads(V["deny"]["list"])
    forged["entries"] = []                                       # alice taken off under the root's signature
    with pytest.raises(seal.Refused, match="not signed by a root"):
        seal.check_deny(seal.wire.canonical(forged), roots)
    gone = seal.deny_list(root, "r1", [{"name": "alice", "before": 1, "until": 2}], 9, now=3)
    assert seal.check_deny(gone, roots)["entries"] == []          # past `until`: dropped


def test_no_org_root_is_ever_made_by_reading_it(tmp_path):
    ring = seal.org_keys(tmp_path)
    for read in (ring.current, ring.key, ring.public):
        with pytest.raises(seal.Refused, match="no org root on this machine"):
            read()
    assert not ring.exists() and not (tmp_path / "org").exists()
    assert seal.collector_keys(tmp_path).current()      # the service's own first key is still made on first use


def test_the_root_line_goes_through_a_password_manager_and_back(tmp_path, monkeypatch):
    key = seal.ed25519.Ed25519PrivateKey.generate()
    line = seal.root_line("20261102", key)
    assert line.startswith("beat-org-root:20261102:") and "\n" not in line
    back, name = seal.parse_root(f"  {line}\n")          # pasted with whitespace around it
    assert name == "20261102" and seal.public_raw(back) == seal.public_raw(key)
    (tmp_path / "root.txt").write_text(line + "\n")
    assert seal.read_root(tmp_path / "root.txt")[1] == "20261102"
    import io
    monkeypatch.setattr("sys.stdin", io.StringIO(line))   # `op read ... | beat creds init --root -`
    assert seal.read_root("-")[1] == "20261102"
    for bad in ("", "hello", "beat-org-root:20261102", "beat-org-root:a/b:" + seal.b64(bytes(32)),
                "beat-org-root:x:not base64!", "other:x:" + seal.b64(bytes(32))):
        with pytest.raises(seal.Refused, match="not an org root"):
            seal.parse_root(bad)
