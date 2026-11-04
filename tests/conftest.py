"""No test reads this machine's own logins, or the org this shell may be in."""
import pytest


@pytest.fixture(autouse=True)
def own_logins(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "xdg-config"))
    monkeypatch.delenv("BEAT_ORG", raising=False)
