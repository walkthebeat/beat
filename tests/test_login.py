"""login.py: the saved login, kept per service, renewed, and forgotten when the issuer refuses it."""
import json
import time

import pytest

from beat import login


@pytest.fixture
def saved(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    monkeypatch.setenv("BEAT_API", "http://svc:8480")
    monkeypatch.delenv("BEAT_TOKEN", raising=False)
    f = login.logins_file()
    f.parent.mkdir(parents=True)
    f.write_text(json.dumps({"http://svc:8480": {
        "issuer": "http://iss", "client_id": "beat-cli", "token_endpoint": "http://iss/oauth/token",
        "access_token": "old", "expires_at": int(time.time()) - 1, "refresh_token": "r1"}}))
    return f


def test_a_renewal_replaces_the_tokens(saved, monkeypatch):
    monkeypatch.setattr(login, "_form", lambda url, form: (200, {"access_token": "new", "expires_in": 900,
                                                                 "refresh_token": "r2"}))
    assert login.access_token() == "new"
    assert json.loads(saved.read_text())["http://svc:8480"]["refresh_token"] == "r2"


def test_a_refused_renewal_forgets_the_login(saved, monkeypatch):
    monkeypatch.setattr(login, "_form", lambda url, form: (400, {"error": "invalid_grant",
                                                                 "error_description": "the login was revoked"}))
    with pytest.raises(login.NotSignedIn, match="the login was revoked"):
        login.access_token()
    assert json.loads(saved.read_text()) == {}  # the next command says "not signed in", without asking the issuer
    with pytest.raises(login.NotSignedIn, match="not signed in"):
        login.access_token()
