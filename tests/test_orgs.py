"""Several orgs on one machine (docs/hosted.md H21): which org a command is in, every way that is refused, the files of
each org apart, and a machine that was on one org before this existed."""
import base64
import json
import os
import subprocess
import sys
import time

import pytest

from beat import ask, estate, login, seal

API = "http://svc:8480"


def token(org=None, name=None, sub="github:1") -> str:
    def part(d):
        return base64.urlsafe_b64encode(json.dumps(d).encode()).decode().rstrip("=")
    claims = {"sub": sub, **({"org": org} if org else {}), **({"org_name": name} if name else {})}
    return f"{part({'alg': 'none'})}.{part(claims)}.sig"


def entry(org, name=None, expires=None, refresh="r") -> dict:
    return {"issuer": "http://iss", "client_id": "beat-cli", "token_endpoint": "http://iss/oauth/token",
            "revocation_endpoint": "http://iss/oauth/revoke", "access_token": token(org, name),
            "expires_at": expires or int(time.time()) + 900, "refresh_token": f"{refresh}-{org}"}


@pytest.fixture
def machine(tmp_path, monkeypatch):
    """A machine with its own logins and keys, working in an empty directory, its service API."""
    monkeypatch.setenv("BEAT_API", API)
    monkeypatch.setenv("BEAT_KEYS", str(tmp_path / "keys"))
    monkeypatch.setenv("BEAT_CCACHE", str(tmp_path / "ccache"))
    monkeypatch.delenv("BEAT_TOKEN", raising=False)
    (tmp_path / "work").mkdir()
    monkeypatch.chdir(tmp_path / "work")
    return tmp_path


def save(logins: dict) -> None:
    f = login.logins_file()
    f.parent.mkdir(parents=True, exist_ok=True)
    f.write_text(json.dumps(logins))


def two() -> None:
    save({API: entry("orga", "Acme"), f"{API}#orgb": entry("orgb", "Own")})


class Issuer:
    """The issuer's side of the device flow: approves at once, signing in to `org`; records what was asked."""

    def __init__(self, monkeypatch, org, refuse_scope=False):
        self.org, self.refuse_scope, self.started, self.revoked = org, refuse_scope, [], []
        monkeypatch.setattr(login, "_get", self.get)
        monkeypatch.setattr(login, "_form", self.form)
        monkeypatch.setattr(login.time, "sleep", lambda s: None)
        monkeypatch.setattr(login.wire, "remember_api", lambda api: None)

    def get(self, url):
        if url.endswith("/v1/auth"):
            return {"issuer": "http://iss", "client_id": "beat-cli"}
        return {"device_authorization_endpoint": "http://iss/device", "token_endpoint": "http://iss/token",
                "revocation_endpoint": "http://iss/revoke"}

    def form(self, url, fields):
        if url.endswith("/device"):
            self.started.append(fields)
            if self.refuse_scope and "scope" in fields:
                return 400, {"error": "invalid_scope"}
            return 200, {"device_code": "d", "user_code": "U", "verification_uri": "v", "expires_in": 600, "interval": 0}
        if url.endswith("/revoke"):
            self.revoked.append(fields["token"])
            return 200, {}
        return 200, {"access_token": token(self.org, f"name of {self.org}"), "expires_in": 900,
                     "refresh_token": f"new-{self.org}"}


quiet = {"say": lambda line: None}


# --- which org: the chain, and each refusal ---------------------------------------------------------------------
def test_one_login_needs_nothing_said(machine):
    save({API: entry("orga")})
    assert login.resolve() == ("orga", "the only login here")
    assert login.access_token() == entry("orga")["access_token"]


def test_several_logins_outside_an_estate_are_refused_and_name_them(machine):
    two()
    for call in (login.access_token, login.resolve, login.current, seal.ccache_dir, seal.keys_dir):
        with pytest.raises(login.OrgRefused, match=r"several orgs.*Acme \(orga\).*Own \(orgb\)"):
            call()


def test_said_chooses_among_several(machine, monkeypatch):
    two()
    monkeypatch.setenv("BEAT_ORG", "orgb")
    assert login.claims(login.access_token())["org"] == "orgb"


def test_the_pin_chooses_and_a_subdirectory_finds_it(machine):
    two()
    (machine / "work" / "beat.json").write_text(json.dumps({"service": API, "org": "orgb"}))
    (machine / "work" / "hosts").mkdir()
    os.chdir(machine / "work" / "hosts")
    org, why = login.resolve()
    assert org == "orgb" and "pinned by" in why and login.claims(login.access_token())["org"] == "orgb"


def test_said_against_the_pin_is_refused(machine, monkeypatch):
    two()
    (machine / "work" / "beat.json").write_text(json.dumps({"service": API, "org": "orgb"}))
    monkeypatch.setenv("BEAT_ORG", "orga")
    with pytest.raises(login.OrgRefused, match="you said org orga, and this estate is org orgb"):
        login.access_token()


def test_a_pin_of_another_service_is_refused(machine):
    save({API: entry("orga")})
    (machine / "work" / "beat.json").write_text(json.dumps({"service": "https://other", "org": "orga"}))
    with pytest.raises(login.OrgRefused, match="belongs to the service https://other"):
        login.access_token()


def test_a_pin_with_no_login_says_how_to_get_it_and_never_uses_another_org(machine):
    save({API: entry("orga")})
    (machine / "work" / "beat.json").write_text(json.dumps({"service": API, "org": "orgb"}))
    with pytest.raises(login.NotSignedIn, match="beat login --org orgb"):
        login.access_token()


@pytest.mark.parametrize("text", ["not json", "{}", '{"service": "x"}', '{"service": 1, "org": "a"}',
                                  '{"service": "http://svc:8480", "org": "../../etc"}'])
def test_a_broken_pin_is_refused_not_ignored(machine, text):
    save({API: entry("orga")})
    (machine / "work" / "beat.json").write_text(text)
    with pytest.raises(login.OrgRefused):
        login.access_token()


@pytest.mark.parametrize("bad", ["../x", "A", "a/b", ".."])
def test_a_said_org_is_an_id_it_also_names_a_directory(machine, monkeypatch, bad):
    monkeypatch.setenv("BEAT_ORG", bad)
    with pytest.raises(login.OrgRefused, match="not an org id"):
        seal.keys_dir()


def test_beat_token_of_another_org_than_the_pin_is_refused(machine, monkeypatch):
    (machine / "work" / "beat.json").write_text(json.dumps({"service": API, "org": "orgb"}))
    monkeypatch.setenv("BEAT_TOKEN", token("orga"))
    with pytest.raises(login.OrgRefused, match="BEAT_TOKEN is for org orga"):
        login.access_token()
    monkeypatch.setenv("BEAT_TOKEN", token("orgb"))
    assert login.access_token() == token("orgb")


def test_beat_token_with_no_org_claim_is_left_to_the_service(machine, monkeypatch):
    monkeypatch.setenv("BEAT_TOKEN", "opaque")
    assert login.access_token() == "opaque" and login.resolve()[0] is None


# --- login: what is asked, and what comes back --------------------------------------------------------------------
def test_login_without_an_org_sends_todays_request(machine, monkeypatch):
    i = Issuer(monkeypatch, "orga")
    login.login(**quiet)
    assert "scope" not in i.started[0]
    assert list(json.loads(login.logins_file().read_text())) == [API]  # where an older client reads it


def test_login_asks_for_the_org_said(machine, monkeypatch):
    i = Issuer(monkeypatch, "orgb")
    monkeypatch.setenv("BEAT_ORG", "orgb")
    login.login(**quiet)
    assert i.started[0]["scope"] == "org:orgb"


def test_login_in_an_estate_asks_for_its_org(machine, monkeypatch):
    i = Issuer(monkeypatch, "orgb")
    (machine / "work" / "beat.json").write_text(json.dumps({"service": API, "org": "orgb"}))
    login.login(**quiet)
    assert i.started[0]["scope"] == "org:orgb"


def test_login_to_another_org_than_asked_is_revoked_and_not_kept(machine, monkeypatch):
    """An issuer that ignores the scope (an old portal, a customer's IdP) and signs in to something else."""
    i = Issuer(monkeypatch, "orga")
    monkeypatch.setenv("BEAT_ORG", "orgb")
    with pytest.raises(login.OrgRefused, match="org orgb was asked for.*signed in to orga.*revoked"):
        login.login(**quiet)
    assert i.revoked == ["new-orga"] and not login.logins_file().exists()


def test_an_issuer_refusing_the_scope_is_asked_without_and_still_checked(machine, monkeypatch):
    i = Issuer(monkeypatch, "orgb", refuse_scope=True)
    monkeypatch.setenv("BEAT_ORG", "orgb")
    login.login(**quiet)
    assert ["scope" in s for s in i.started] == [True, False] and login.resolve()[0] == "orgb"
    j = Issuer(monkeypatch, "orga", refuse_scope=True)
    with pytest.raises(login.OrgRefused):
        login.login(**quiet)
    assert j.revoked == ["new-orga"]


def test_each_org_gets_its_login_and_one_org_again_replaces_its_own(machine, monkeypatch):
    save({API: entry("orga")})
    Issuer(monkeypatch, "orgb")
    login.login(**quiet)
    saved = json.loads(login.logins_file().read_text())
    assert set(saved) == {API, f"{API}#orgb"}
    Issuer(monkeypatch, "orgb")
    login.login(**quiet)
    assert set(json.loads(login.logins_file().read_text())) == {API, f"{API}#orgb"}
    Issuer(monkeypatch, "orga")
    login.login(**quiet)
    saved = json.loads(login.logins_file().read_text())
    assert saved[API]["refresh_token"] == "new-orga"


def test_two_services_do_not_mix(machine, monkeypatch):
    save({"http://other": entry("orgz"), API: entry("orga"), "http://other#orgy": entry("orgy")})
    assert login.resolve()[0] == "orga"
    monkeypatch.setenv("BEAT_API", "http://other")
    with pytest.raises(login.OrgRefused):
        login.resolve()


# --- renewal ------------------------------------------------------------------------------------------------------
def test_a_renewal_into_another_org_is_refused_revoked_and_forgotten(machine, monkeypatch):
    save({API: entry("orga", expires=1), f"{API}#orgb": entry("orgb")})
    monkeypatch.setenv("BEAT_ORG", "orga")
    i = Issuer(monkeypatch, "orgb")
    with pytest.raises(login.OrgRefused, match="was in org orga.*renewal is for orgb"):
        login.access_token()
    assert set(json.loads(login.logins_file().read_text())) == {f"{API}#orgb"} and i.revoked == ["new-orgb"]


def test_a_renewal_in_the_same_org_goes_on_and_keeps_the_other_login(machine, monkeypatch):
    save({API: entry("orga", expires=1), f"{API}#orgb": entry("orgb")})
    monkeypatch.setenv("BEAT_ORG", "orga")
    Issuer(monkeypatch, "orga")
    assert login.claims(login.access_token())["org"] == "orga"
    saved = json.loads(login.logins_file().read_text())
    assert saved[API]["refresh_token"] == "new-orga" and saved[f"{API}#orgb"]["refresh_token"] == "r-orgb"


def test_a_refused_renewal_forgets_only_that_login(machine, monkeypatch):
    save({API: entry("orga", expires=1), f"{API}#orgb": entry("orgb")})
    monkeypatch.setenv("BEAT_ORG", "orga")
    monkeypatch.setattr(login, "_form", lambda url, form: (400, {"error": "invalid_grant", "error_description": "gone"}))
    with pytest.raises(login.NotSignedIn, match="gone.*--org orga"):
        login.access_token()
    assert set(json.loads(login.logins_file().read_text())) == {f"{API}#orgb"}


# --- logout -------------------------------------------------------------------------------------------------------
def test_logout_needs_an_org_when_there_are_several(machine, monkeypatch):
    two()
    with pytest.raises(login.OrgRefused):
        login.logout()
    i = Issuer(monkeypatch, "x")
    monkeypatch.setenv("BEAT_ORG", "orgb")
    assert [login.org_of(e) for e in login.logout()] == ["orgb"] and i.revoked == ["r-orgb"]
    assert set(json.loads(login.logins_file().read_text())) == {API}


def test_logout_all(machine, monkeypatch):
    two()
    i = Issuer(monkeypatch, "x")
    assert len(login.logout(everyone=True)) == 2 and sorted(i.revoked) == ["r-orga", "r-orgb"]
    assert json.loads(login.logins_file().read_text()) == {}


# --- each org's keys ------------------------------------------------------------------------------------------------
def certify(root_name="root"):
    key = seal.ed25519.Ed25519PrivateKey.generate()
    return key, seal.new_member(key, root_name, "me")[1]


def test_one_org_stays_where_an_older_client_left_its_files(machine):
    save({API: entry("orga")})
    assert seal.keys_dir() == machine / "keys" and seal.ccache_dir() == machine / "ccache"
    _, cred = certify()
    assert (machine / "ccache" / "credential").read_text().strip() == cred
    assert seal.current_member()[1] == cred


def test_a_second_org_cannot_overwrite_the_first_orgs_credential(machine, monkeypatch):
    """An older client with one org, then a second: the bug this exists for, `beat org init` replacing the only pair."""
    save({API: entry("orga")})
    _, cred_a = certify("root-a")
    seal.org_keys().keep("root-a", seal.ed25519.Ed25519PrivateKey.generate())

    Issuer(monkeypatch, "orgb")
    said = []
    login.login(say=said.append)
    assert any("orgs/orga" in s for s in said)
    assert not (machine / "ccache" / "credential").exists() and not (machine / "keys" / "org").exists()

    monkeypatch.setenv("BEAT_ORG", "orgb")
    assert seal.ccache_dir() == machine / "ccache" / "orgs" / "orgb"
    with pytest.raises(seal.Refused, match="no member credential"):  # not the first org's, by accident
        seal.member()
    assert not seal.org_keys().exists()
    _, cred_b = certify("root-b")
    assert seal.member_roots().keys() == {"root-b"}

    monkeypatch.setenv("BEAT_ORG", "orga")
    assert seal.current_member()[1] == cred_a and cred_a != cred_b
    assert seal.member_roots().keys() == {"root-a"} and seal.org_keys().current() == "root-a"


def test_files_stay_with_their_org_when_it_logs_out(machine, monkeypatch):
    """Signed out of a, into b: b must not pick up a's root, and put it on the lines for b's hosts."""
    save({API: entry("orga")})
    _, cred_a = certify("root-a")
    seal.org_keys().keep("root-a", seal.ed25519.Ed25519PrivateKey.generate())
    Issuer(monkeypatch, "orgb")
    login.logout()
    login.login(**quiet)
    assert seal.member_roots() == {} and not seal.org_keys().exists()
    login.logout()
    Issuer(monkeypatch, "orga")
    login.login(**quiet)
    assert seal.current_member()[1] == cred_a  # and back


def test_an_org_said_without_a_login_never_gets_the_flat_files(machine, monkeypatch):
    save({API: entry("orga")})
    certify("root-a")
    monkeypatch.setenv("BEAT_ORG", "orgb")
    assert seal.ccache_dir() == machine / "ccache" / "orgs" / "orgb"
    assert seal.member_roots() == {}


def test_a_wrong_credential_is_refused_by_the_roots_a_sensor_pins(machine):
    """The other half of the hazard, which fails closed by itself: org a's credential against org b's pinned root."""
    save({API: entry("orga")})
    _, cred_a = certify("root-a")
    root_b = seal.ed25519.Ed25519PrivateKey.generate()
    with pytest.raises(seal.Refused, match="not signed by a root"):
        seal.check_credential(cred_a, {"root-b": root_b.public_key()})


def test_no_login_at_all_is_the_flat_layout(machine):
    assert seal.keys_dir() == machine / "keys"


def test_an_org_with_a_tricky_name_cannot_collide_with_the_flat_files(machine, monkeypatch):
    save({API: entry("orga"), f"{API}#credential": entry("credential")})
    monkeypatch.setenv("BEAT_ORG", "credential")
    assert seal.ccache_dir() == machine / "ccache" / "orgs" / "credential"


# --- the estate's pin -----------------------------------------------------------------------------------------------
def pin_of(repo):
    return json.loads((repo / "beat.json").read_text())


def test_init_pins_to_the_one_login(machine):
    save({API: entry("orga")})
    estate.init(machine / "e")
    assert pin_of(machine / "e") == {"service": API, "org": "orga"}
    assert "beat.json" in subprocess.run(["git", "-C", str(machine / "e"), "ls-files"], capture_output=True, text=True).stdout


def test_init_with_several_logins_needs_an_org_and_makes_nothing(machine, monkeypatch):
    two()
    with pytest.raises(login.OrgRefused, match="--org"):
        estate.init(machine / "e")
    assert not (machine / "e").exists()
    monkeypatch.setenv("BEAT_ORG", "orgb")
    estate.init(machine / "e")
    assert pin_of(machine / "e")["org"] == "orgb"


def test_init_inside_another_estate_does_not_inherit_its_pin(machine):
    save({API: entry("orga"), })
    (machine / "work" / "beat.json").write_text(json.dumps({"service": API, "org": "orgz"}))
    estate.init(machine / "work" / "new")
    assert pin_of(machine / "work" / "new")["org"] == "orga"


def test_init_with_no_login_leaves_it_for_the_first_question(machine):
    estate.init(machine / "e")
    assert not (machine / "e" / "beat.json").exists()


def existing_estate(machine) -> "object":
    """An estate from before pins: nothing says which org it is."""
    estate.init(machine / "old")
    os.chdir(machine / "old")
    assert not (machine / "old" / "beat.json").exists()
    return machine / "old"


def test_an_existing_estate_pins_itself_on_its_first_question_and_commits_only_that(machine, capsys):
    repo = existing_estate(machine)
    save({API: entry("orga")})
    (repo / "probes" / "dirty.star").write_text("# uncommitted work\n")
    estate.pin_on_first_use()
    assert pin_of(repo) == {"service": API, "org": "orga"}
    git = lambda *a: subprocess.run(["git", "-C", str(repo), *a], capture_output=True, text=True).stdout  # noqa: E731
    assert git("show", "--stat", "--format=%s", "HEAD").split()[:6] == ["This", "estate", "is", "org", "orga", "beat.json"]
    assert "?? probes/dirty.star" in git("status", "--short")  # the person's work was not swept in
    assert "pinned" in capsys.readouterr().err  # stderr: stdout is the MCP protocol
    estate.pin_on_first_use()
    assert git("rev-list", "--count", "HEAD").strip() == "2"  # once


def test_after_the_pin_a_second_login_changes_nothing_in_that_estate(machine):
    repo = existing_estate(machine)
    save({API: entry("orga")})
    estate.pin_on_first_use()
    two()
    assert login.resolve()[0] == "orga"
    os.chdir(machine / "work")
    with pytest.raises(login.OrgRefused):
        login.resolve()
    assert repo


def test_an_unpinned_estate_with_several_logins_refuses_rather_than_guess(machine):
    repo = existing_estate(machine)
    two()
    with pytest.raises(login.OrgRefused, match="several orgs"):
        estate.pin_on_first_use()
    assert not (repo / "beat.json").exists()


def test_an_estate_in_a_directory_git_cannot_commit_still_gets_the_pin(machine):
    repo = existing_estate(machine)
    save({API: entry("orga")})
    subprocess.run(["rm", "-rf", str(repo / ".git")])
    estate.pin_on_first_use()
    assert pin_of(repo)["org"] == "orga"


def test_ask_pins_before_it_asks(machine, monkeypatch):
    """The path every question takes: refused before anything reaches the service."""
    import asyncio
    repo = existing_estate(machine)
    two()
    called = []

    async def api(*a, **k):
        called.append(a)
    monkeypatch.setattr(ask, "api", api)
    with pytest.raises(login.OrgRefused):
        asyncio.run(ask.ask("q", "src", ["h"]))
    assert not called and not (repo / "beat.json").exists()


# --- the CLI --------------------------------------------------------------------------------------------------------
def beat(*args, cwd=None, env=None):
    return subprocess.run([sys.executable, "-c", "from beat.cli import main; main()", *args], capture_output=True,
                          text=True, cwd=cwd, env={**os.environ, **(env or {})})


def test_cli_refuses_in_one_line_and_lists(machine):
    two()
    r = beat("sensors", cwd=machine / "work")
    assert r.returncode != 0 and r.stderr.startswith("error: signed in to several orgs") and "Traceback" not in r.stderr
    r = beat("org", "list", cwd=machine / "work")
    assert r.returncode == 0 and "Acme (orga)" in r.stdout and "Own (orgb)" in r.stdout and "*" not in r.stdout


def test_cli_global_flag_and_a_subcommand_flag_cannot_disagree(machine):
    two()
    assert "two orgs given" in beat("--org", "orga", "logout", "--org", "orgb", cwd=machine / "work").stderr


def test_cli_org_flag_reaches_the_keys(machine):
    two()
    r = beat("--org", "orgb", "creds", cwd=machine / "work")
    assert "no member credential" in r.stderr or "no member credential" in r.stdout


def test_cli_org_pin(machine):
    repo = machine / "e"
    estate.init(repo)
    two()
    r = beat("org", "pin", "orgb", cwd=repo)
    assert r.returncode == 0 and pin_of(repo)["org"] == "orgb"
    assert beat("org", "pin", "../x", cwd=repo).returncode != 0
    assert "takes add or remove" in beat("org", "trust", "bogus", cwd=repo).stderr


def test_cli_init_org(machine):
    two()
    r = beat("init", str(machine / "e"), "--org", "orga", cwd=machine / "work")
    assert r.returncode == 0 and pin_of(machine / "e")["org"] == "orga"
