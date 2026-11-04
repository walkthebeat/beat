"""Signing in to the beat service: `beat login`, `beat whoami`, `beat logout`.

A generic OIDC device-flow client (RFC 8628): it asks the service which issuer it trusts (GET /v1/auth), reads the
issuer's discovery document, and signs in there: walkthebeat's portal for the hosted service, a
company's own identity provider for a service of its own. The person approves in a browser, which may be on another machine; this machine only
polls. `beat login URL` also records the service as this machine's (wire.api_source: BEAT_API still wins), so
shells and beat-mcp need no BEAT_API. What it gets: a short access token (a JWT the service checks offline) and a refresh token, kept in
$XDG_CONFIG_HOME/beat/logins.json (mode 0600). `access_token()` renews the access token when it is about to expire,
under a file lock: every beat-mcp of every Claude session shares the login, and an issuer may revoke a login whose
refresh token is used twice. BEAT_TOKEN, when set, is used as the access token as it is (tests, unattended
runs). The OS keychain is for later.

**A login is in one org, and a machine may hold several** (docs/hosted.md H21): "<service>" is the first, as older
clients read it, and "<service>#<org>" each other; they ignore those and keep them. The org of a login is its token's
claim, read here only to choose among them: the service checks it. Which org a command is in (`resolve`), first
that applies: `--org` or BEAT_ORG, which the estate's pin must not contradict; the pin, beat.json in this directory or
above; the one login there is. Several logins and none of those is refused, and there is no machine-wide current org:
what a command asks is decided by the directory it runs in or a word typed for it, so `run` in the wrong shell cannot
reach the wrong fleet. The same for the keys (seal.keys_dir, seal.ccache_dir).
"""
from __future__ import annotations

import base64
import fcntl
import getpass
import json
import os
import re
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


ORG = re.compile(r"^[a-z0-9][a-z0-9-]{0,62}$")  # as the service's cell.ORG; it also names a directory here (org_home)
PIN = "beat.json"


class NotSignedIn(RuntimeError):
    pass


class OrgRefused(RuntimeError):
    """Which org this is not settled, or a token is of another org than it must be: nothing was asked of anyone."""


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


def _read() -> dict:
    """The logins, without the lock: writes replace the file whole, so a reader sees one state or the other."""
    try:
        return json.loads(logins_file().read_text())
    except (OSError, ValueError):
        return {}


def read_pin() -> dict | None:
    """The estate's pin (estate.py): {service, org, path} from beat.json in this directory or the nearest above."""
    here = Path.cwd().resolve()
    for d in (here, *here.parents):
        f = d / PIN
        if f.is_file():
            try:
                pin = json.loads(f.read_text())
                service, org = pin["service"].rstrip("/"), pin["org"]
            except (OSError, ValueError, KeyError, TypeError, AttributeError):
                raise OrgRefused(f"{f} is not a pin ({{\"service\": ..., \"org\": ...}}): fix it, or `beat org pin ID`") from None
            if not isinstance(org, str) or not ORG.match(org):
                raise OrgRefused(f"{f} names {org!r}, which is not an org id")
            return {"service": service, "org": org, "path": f}
    return None


def org_of(entry: dict) -> str | None:
    org = claims(entry.get("access_token") or "").get("org")
    return org if isinstance(org, str) and ORG.match(org) else None


def of_service(logins: dict, api: str) -> dict:
    """org -> its key in the logins, of one service. An entry whose token says no org (None) counts as one login."""
    found = {org_of(e): k for k, e in logins.items() if k.startswith(api + "#")}
    if api in logins:  # last: an older client's newer login to the same org
        found[org_of(logins[api])] = api
    return found


def wanted(api: str) -> tuple[str | None, str | None]:
    """(the org this command must be in, why), from what was said: --org or BEAT_ORG, and the pin. Refused when they
    disagree, or the pin belongs to another service (org ids are only unique per issuer)."""
    said = os.environ.get("BEAT_ORG", "").strip() or None
    if said and not ORG.match(said):
        raise OrgRefused(f"{said!r} is not an org id")
    pin = read_pin()
    if not pin:
        return said, "--org or BEAT_ORG" if said else None
    if pin["service"] != api.rstrip("/"):
        raise OrgRefused(f"{pin['path']} belongs to the service {pin['service']}, and this command would go to {api} "
                         f"({wire.api_source()[1]}). Nothing was asked.")
    if said and said != pin["org"]:
        raise OrgRefused(f"you said org {said}, and this estate is org {pin['org']} ({pin['path']}): an estate holds "
                         "one org's facts. Run it from elsewhere, or change the pin with `beat org pin`.")
    return pin["org"], f"pinned by {pin['path']}"


def _name_of(logins: dict, key: str) -> str:
    c = claims(logins[key].get("access_token") or "")
    return f"{c.get('org_name')} ({c.get('org')})" if c.get("org_name") else str(c.get("org"))


def _choose(logins: dict, api: str) -> tuple[str | None, str | None, str | None]:
    """(org, the login's key, why): module docstring. No org when nothing says one and nothing is signed in; no key
    when the org wanted has no login here."""
    org, why = wanted(api)
    have = of_service(logins, api)
    if org:
        return org, have.get(org), why
    if len(have) > 1:
        names = ", ".join(sorted(_name_of(logins, k) for k in have.values()))
        raise OrgRefused(f"signed in to several orgs here ({names}), and nothing says which: run this from an estate "
                         "repository of that org, or `beat --org ID ...`. Nothing was asked.")
    for only, key in have.items():
        return only, key, "the only login here"
    return None, None, None


def _token_org(api: str) -> str | None:
    """BEAT_TOKEN's org, refused when it is not the org wanted. A token with no readable org is not checked here: it
    may be for a service with no sign-in, and a service that has one refuses it."""
    want, why = wanted(api)
    got = claims(os.environ["BEAT_TOKEN"]).get("org")
    if want and got and got != want:
        raise OrgRefused(f"BEAT_TOKEN is for org {got}, and this must be org {want} ({why}). Nothing was asked.")
    return got if isinstance(got, str) and ORG.match(got) else want


def resolve() -> tuple[str | None, str | None]:
    """(the org this command is in, why), or (None, None) when no org is known. No network, no lock. Refuses what
    `_choose` refuses."""
    api = wire.api_url()
    if os.environ.get("BEAT_TOKEN"):
        return _token_org(api), "BEAT_TOKEN"
    return _choose(_read(), api)[::2]


def org_home(base: Path) -> Path:
    """Where this org's keys are under `base` (docs/hosted.md H21): base/orgs/<org> once it exists or this org is not
    the machine's one login; else base itself, as every older client left it, so one org means no migration."""
    org, _ = resolve()
    if not org:
        return base
    d = base / "orgs" / org
    have = set(of_service(_read(), wire.api_url()))
    return d if d.is_dir() or (have and have != {org}) else base


def org_name(org: str | None) -> str | None:
    """The org's name, from its login's token (a tier 3 token may have none). For people; ids decide."""
    logins = _read()
    key = of_service(logins, wire.api_url()).get(org)
    return claims(logins[key].get("access_token") or "").get("org_name") if key else None


def org_for_new_estate() -> str | None:
    """The org a new estate starts in: what was said, else the one login. Any pin above is another estate's, not
    this one's. Several logins with nothing said is refused."""
    said = os.environ.get("BEAT_ORG", "").strip() or None
    if said:
        if not ORG.match(said):
            raise OrgRefused(f"{said!r} is not an org id")
        return said
    if os.environ.get("BEAT_TOKEN"):
        return org_of({"access_token": os.environ["BEAT_TOKEN"]})
    have = of_service(_read(), wire.api_url())
    if len(have) > 1:
        raise OrgRefused("signed in to several orgs here, and an estate holds one org's facts: say which, `--org ID`")
    return next(iter(have), None)


def logins_here() -> list[dict]:
    """This machine's logins to this machine's service, for `beat org list`. No network."""
    logins = _read()
    out = []
    for org, key in sorted(of_service(logins, wire.api_url()).items(), key=lambda x: str(x[0])):
        c = claims(logins[key].get("access_token") or "")
        out.append({"org": org, "org_name": c.get("org_name"), "sub": c.get("sub")})
    return out


def _revoke(e: dict, refresh_token: str | None) -> None:
    if e.get("revocation_endpoint") and refresh_token:
        try:
            _form(e["revocation_endpoint"], {"token": refresh_token, "client_id": e["client_id"]})
        except RuntimeError:
            pass  # the login is forgotten here either way


def _left_service(org: str | None, logins: dict, api: str) -> None:
    """The machine's last login to the service is gone: the files beside it are that org's, not the next login's."""
    if org and not of_service(logins, api):
        from . import seal
        seal.adopt_flat(org)


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
    Given a URL, it becomes this machine's service once signed in (wire.api_source). The org wanted (--org, BEAT_ORG,
    the pin) is asked for with scope=org:<id>, and what the issuer signs in to must be that org; with none wanted, the
    person chooses at approval. `say` gets each line for the person."""
    if url and not url.startswith(("http://", "https://")):
        raise RuntimeError(f"not a service URL: {url} (http://HOST:8480 or https://HOST)")
    api = url.rstrip("/") if url else wire.api_url()
    want, why = wanted(api)
    cfg = _get(api + "/v1/auth")
    if not cfg.get("issuer"):
        raise RuntimeError(f"the beat service at {api} has no sign-in (started with --no-auth)")
    issuer, client_id = cfg["issuer"], cfg["client_id"]
    meta = _get(issuer.rstrip("/") + "/.well-known/openid-configuration")
    say(f"Signing in to the beat service at {api}")
    say(f"  through {issuer}")
    start = {"client_id": client_id, "device_name": device_name()}
    status, d = _form(meta["device_authorization_endpoint"], {**start, "scope": f"org:{want}"} if want else start)
    if status != 200 and d.get("error") == "invalid_scope":  # an issuer with no such scope: what it signs in to is checked below
        status, d = _form(meta["device_authorization_endpoint"], start)
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
    got = org_of(entry)
    if want and got != want:
        _revoke(entry, entry.get("refresh_token"))
        raise OrgRefused(f"org {want} was asked for ({why}), and {issuer} signed in to {got or 'no org it names'}: the "
                         "login is revoked and not kept.")
    with _locked() as box:
        have = of_service(box["logins"], api)
        if got not in have and len(have) == 1:  # a second org: the files beside the first login are the first org's
            first = next(iter(have))
            if first:
                from . import seal
                moved = seal.adopt_flat(first)
                if moved:
                    say(f"This machine's keys of org {first} are now in {moved}.")
        key = have.get(got) or (api if api not in box["logins"] or not got else f"{api}#{got}")
        box["logins"][key] = entry
        box["write"] = True
    if url:
        wire.remember_api(api)
    return entry


def _entry(issuer: str, client_id: str, meta: dict, t: dict) -> dict:
    return {"issuer": issuer, "client_id": client_id, "token_endpoint": meta["token_endpoint"],
            "revocation_endpoint": meta.get("revocation_endpoint"), "access_token": t["access_token"],
            "expires_at": int(time.time()) + int(t.get("expires_in", 300)), "refresh_token": t.get("refresh_token")}


def access_token() -> str:
    """The access token for this machine's service (wire.api_url) in the org this command is in (`_choose`), renewed
    first if it is about to expire; a renewal must stay in the login's org."""
    api = wire.api_url()
    if os.environ.get("BEAT_TOKEN"):
        _token_org(api)
        return os.environ["BEAT_TOKEN"]
    with _locked() as box:  # under the lock: another process may have just renewed it
        org, key, why = _choose(box["logins"], api)
        if key is None:
            raise NotSignedIn(f"not signed in to org {org} at {api} ({why}): `beat login --org {org}`" if org
                              else f"not signed in to the beat service at {api}: `beat login`")
        e = box["logins"][key]
        if e["expires_at"] - RENEW_BEFORE_S > time.time():
            return e["access_token"]
        if not e.get("refresh_token"):
            raise NotSignedIn(f"the login has expired: `beat login{f' --org {org}' if org else ''}`")
        status, t = _form(e["token_endpoint"], {"grant_type": "refresh_token", "refresh_token": e["refresh_token"],
                                                 "client_id": e["client_id"]})
        if status != 200:
            del box["logins"][key]
            box["write"] = True
            _left_service(org, box["logins"], api)
            raise NotSignedIn(f"the login could not be renewed ({t.get('error_description') or t.get('error')}): "
                              f"`beat login{f' --org {org}' if org else ''}`")
        t.setdefault("refresh_token", e["refresh_token"])
        new = _entry(e["issuer"], e["client_id"], {"token_endpoint": e["token_endpoint"],
                     "revocation_endpoint": e.get("revocation_endpoint")}, t)
        before = org_of(e)
        if before and org_of(new) != before:
            del box["logins"][key]
            box["write"] = True
            _revoke(new, new.get("refresh_token"))
            _left_service(before, box["logins"], api)
            raise OrgRefused(f"this login was in org {before}, and its renewal is for {org_of(new) or 'no org it names'}: "
                             f"it is revoked and forgotten. `beat login --org {before}`")
        box["logins"][key] = new
        box["write"] = True
        return t["access_token"]


def current() -> dict | None:
    """The saved login for this machine's service and the org this command is in, as it is (no renewal)."""
    logins = _read()
    _, key, _ = _choose(logins, wire.api_url())
    return logins.get(key) if key else None


def logout(everyone: bool = False) -> list[dict]:
    """Forgets this machine's login to its service (it stays the service) in the org this command is in, or all of
    them, and revokes their refresh tokens at the issuer when it can. Returns what was forgotten."""
    api = wire.api_url()
    with _locked() as box:
        have = of_service(box["logins"], api)
        if everyone:
            keys = list(have.items())
        else:
            org, key, _ = _choose(box["logins"], api)
            keys = [(org, key)] if key else []
        gone = [box["logins"].pop(k) for _, k in keys]
        box["write"] = bool(gone)
        for org, _ in keys:
            _left_service(org, box["logins"], api)
    for e in gone:
        _revoke(e, e.get("refresh_token"))
    return gone
