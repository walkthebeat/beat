"""Signing in to the beat service: `beat login`, `beat whoami`, `beat logout`.

A generic OIDC device-flow client (RFC 8628): it asks the service which issuer it trusts (GET /v1/auth), reads the
issuer's discovery document, and signs in there: walkthebeat's portal for the hosted service, a
company's own identity provider for a service of its own. The person approves in a browser, which may be on another machine; this machine only
polls. `beat login URL` also records the service as this machine's (wire.api_source: BEAT_API still wins), so
shells and beat-mcp need no BEAT_API. What it gets: a short access token (a JWT the service checks offline) and a refresh token, kept per service in
$XDG_CONFIG_HOME/beat/logins.json (mode 0600). `access_token()` renews the access token when it is about to expire,
under a file lock: every beat-mcp of every Claude session shares the login, and an issuer may revoke a login whose
refresh token is used twice. BEAT_TOKEN, when set, is used as the access token as it is (tests, unattended
runs). The OS keychain is for later.
"""
from __future__ import annotations

import base64
import fcntl
import getpass
import json
import os
import socket
import time
import urllib.error
import urllib.parse
import urllib.request
from contextlib import contextmanager
from pathlib import Path

from . import wire

DEVICE_GRANT = "urn:ietf:params:oauth:grant-type:device_code"
RENEW_BEFORE_S = 60  # renew an access token this long before it expires


class NotSignedIn(RuntimeError):
    pass


def logins_file() -> Path:
    return Path(os.environ.get("XDG_CONFIG_HOME") or Path.home() / ".config") / "beat" / "logins.json"


@contextmanager
def _locked():
    """The logins file, read under an exclusive lock, and the dict to write back (or not: None)."""
    f = logins_file()
    f.parent.mkdir(parents=True, exist_ok=True)
    with open(f.with_suffix(".lock"), "w") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        try:
            logins = json.loads(f.read_text())
        except (OSError, ValueError):
            logins = {}
        box = {"logins": logins, "write": False}
        try:
            yield box
        finally:  # also when the block raises: a refused renewal forgets the login, then says so
            if box["write"]:
                tmp = f.with_suffix(".tmp")
                fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
                with os.fdopen(fd, "w") as out:
                    json.dump(box["logins"], out, indent=1)
                tmp.replace(f)


def _get(url: str) -> dict:
    try:
        with urllib.request.urlopen(url, timeout=15) as r:
            return json.loads(r.read())
    except urllib.error.HTTPError as e:
        raise RuntimeError(f"{url}: {e.code} {e.read()[:200]!r}") from None
    except OSError as e:
        raise RuntimeError(f"{url} is not answering: {getattr(e, 'reason', e)}") from None


def _form(url: str, fields: dict) -> tuple[int, dict]:
    """An OAuth endpoint: a form in, JSON out; (status, body) for an error status too."""
    req = urllib.request.Request(url, data=urllib.parse.urlencode(fields).encode(), method="POST",
                                 headers={"Content-Type": "application/x-www-form-urlencoded"})
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read())
        except ValueError:
            return e.code, {"error": f"HTTP {e.code}"}
    except OSError as e:
        raise RuntimeError(f"{url} is not answering: {getattr(e, 'reason', e)}") from None


def claims(token: str) -> dict:
    """A JWT's claims, unchecked: for display only (the service checks them)."""
    try:
        part = token.split(".")[1]
        return json.loads(base64.urlsafe_b64decode(part + "=" * (-len(part) % 4)))
    except (IndexError, ValueError):
        return {}


def device_name() -> str:
    return f"beat on {getpass.getuser()}@{socket.gethostname()}"


def login(url: str | None = None, say=lambda line: print(line, flush=True)) -> dict:
    """The device flow, start to end, with the service at `url` (else BEAT_API's); saves the login and returns it.
    Given a URL, it becomes this machine's service once signed in (wire.api_source). `say` gets each line for the
    person."""
    if url and not url.startswith(("http://", "https://")):
        raise RuntimeError(f"not a service URL: {url} (http://HOST:8480 or https://HOST)")
    api = url.rstrip("/") if url else wire.api_url()
    cfg = _get(api + "/v1/auth")
    if not cfg.get("issuer"):
        raise RuntimeError(f"the beat service at {api} has no sign-in (started with --no-auth)")
    issuer, client_id = cfg["issuer"], cfg["client_id"]
    meta = _get(issuer.rstrip("/") + "/.well-known/openid-configuration")
    say(f"Signing in to the beat service at {api}")
    say(f"  through {issuer}")
    status, d = _form(meta["device_authorization_endpoint"], {"client_id": client_id, "device_name": device_name()})
    if status != 200:
        raise RuntimeError(f"the issuer refused to start a sign-in: {d.get('error_description') or d.get('error')}")
    say("")
    say(f"Open      {d['verification_uri']}")
    say(f"and enter {d['user_code']}")
    if d.get("verification_uri_complete"):
        say(f"(or open {d['verification_uri_complete']})")
    say("")
    say(f"Waiting for you to approve it (the code expires in {int(d['expires_in']) // 60} min; Ctrl-C stops)...")
    interval, until = int(d.get("interval", 5)), time.time() + int(d["expires_in"])
    while time.time() < until:
        time.sleep(interval)
        status, t = _form(meta["token_endpoint"], {"grant_type": DEVICE_GRANT, "device_code": d["device_code"],
                                                    "client_id": client_id})
        if status == 200:
            break
        err = t.get("error")
        if err == "authorization_pending":
            continue
        if err == "slow_down":
            interval += 5
            continue
        if err == "access_denied":
            raise RuntimeError("the sign-in was denied")
        if err == "expired_token":
            break
        raise RuntimeError(f"the sign-in failed: {t.get('error_description') or err}")
    else:
        t = None
    if status != 200 or t is None:
        raise RuntimeError("the code expired before it was approved: `beat login` again")
    entry = _entry(issuer, client_id, meta, t)
    with _locked() as box:
        box["logins"][api] = entry
        box["write"] = True
    if url:
        wire.remember_api(api)
    return entry


def _entry(issuer: str, client_id: str, meta: dict, t: dict) -> dict:
    return {"issuer": issuer, "client_id": client_id, "token_endpoint": meta["token_endpoint"],
            "revocation_endpoint": meta.get("revocation_endpoint"), "access_token": t["access_token"],
            "expires_at": int(time.time()) + int(t.get("expires_in", 300)), "refresh_token": t.get("refresh_token")}


def access_token() -> str:
    """The access token for this machine's service (wire.api_url), renewed first if it is about to expire."""
    if os.environ.get("BEAT_TOKEN"):
        return os.environ["BEAT_TOKEN"]
    api = wire.api_url()
    with _locked() as box:  # under the lock: another process may have just renewed it
        e = box["logins"].get(api)
        if e is None:
            raise NotSignedIn(f"not signed in to the beat service at {api}: `beat login`")
        if e["expires_at"] - RENEW_BEFORE_S > time.time():
            return e["access_token"]
        if not e.get("refresh_token"):
            raise NotSignedIn("the login has expired: `beat login`")
        status, t = _form(e["token_endpoint"], {"grant_type": "refresh_token", "refresh_token": e["refresh_token"],
                                                 "client_id": e["client_id"]})
        if status != 200:
            del box["logins"][api]
            box["write"] = True
            raise NotSignedIn(f"the login could not be renewed ({t.get('error_description') or t.get('error')}): "
                              "`beat login`")
        t.setdefault("refresh_token", e["refresh_token"])
        box["logins"][api] = _entry(e["issuer"], e["client_id"], {"token_endpoint": e["token_endpoint"],
                                    "revocation_endpoint": e.get("revocation_endpoint")}, t)
        box["write"] = True
        return t["access_token"]


def current() -> dict | None:
    """The saved login for this machine's service, as it is (no renewal)."""
    with _locked() as box:
        return box["logins"].get(wire.api_url())


def logout() -> dict | None:
    """Forgets the login to this machine's service (it stays the service), and revokes its refresh token at the issuer when it can."""
    api = wire.api_url()
    with _locked() as box:
        e = box["logins"].pop(api, None)
        box["write"] = e is not None
    if e and e.get("revocation_endpoint") and e.get("refresh_token"):
        try:
            _form(e["revocation_endpoint"], {"token": e["refresh_token"], "client_id": e["client_id"]})
        except RuntimeError:
            pass  # the login is forgotten here either way
    return e
