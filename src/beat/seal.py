"""Signed questions and sealed answers (docs/protocol.md, docs/protocol.md C14, C16). Sensor side:
sensor/src/seal.rs; tests/seal_vectors.json keeps both sides in step.

- **One rule for every signature** (Ed25519, header Beat-Signature): it covers the message's kind (ask, survey, ack,
  answer), all its other Beat-* headers and its payload's hash (`signed_bytes`). A question carries two signatures
  over the same bytes: the org's (Beat-Signature) and the collector's (Beat-Countersignature).
- **A member of the org signs what it asks** (docs/security.md H16): the collector prepares a
  question's envelope (survey.prepare), the client (ask.py: `beat ask`, `beat run`, beat-mcp) signs it with its member
  key, its credential in the envelope (Beat-Cred: the member's name and key, signed by the org's root), and the
  collector relays it (survey.start) after checking both against the roots the sensors pin; it can neither ask on its
  own nor change what it relays. It countersigns what it relays with its own key: the survey key in the envelope is
  the collector's, so a member cannot put one of their own in it and receive answers past gate 2.
  A question's headers are its envelope: Beat-Survey, Beat-Question (the payload's hash), Beat-Key (the survey's
  public key), Beat-Targets (absent: every sensor), Beat-Timeout, Beat-Issued, Beat-Deadline, Beat-Cred. A sensor
  answers only a question signed by a member key that a root it pins certified, and countersigned by a collector key,
  before its deadline, once. The survey's
  announcement on the stream is signed by the collector's key too, so the collector records only its own surveys.
- **The sensor seals what it answers** to the survey's key (HPKE, RFC 9180 base mode: X25519, HKDF-SHA256,
  ChaCha20-Poly1305; the payload is the encapsulated key followed by the ciphertext; info binds survey and target)
  and signs the message with its own key, acks too. The answer's hash (Beat-Answer) is not on the bus: equal answers
  would show as equal there; the collector hashes what it opened.
- **Survey keys** live in the collector's memory and are forgotten at the survey's deadline: a later answer cannot be
  opened, and its target ends no_answer. A collector restarted mid-survey loses the keys of the surveys in
  flight the same way (accepted for now).

- **Heartbeats are signed** (kind heartbeat, over the entry without its signature, which carries its time): a reader
  trusts an entry only from an enrolled sensor, and only while fresh (`check_heartbeat`).

- **Member credentials** (H16; docs/protocol.md): {kind: member, name, key, not_before,
  not_after, issuer}, signed by a root over canonical JSON (`credential_bytes`), carried base64 in Beat-Cred. With the
  org's root on this machine (one person), the client makes a fresh member key and credential when its own has less
  than RENEW_BEFORE_S left or another root made it, as `kinit -kt` gets a ticket from a keytab (`member`); without
  the root here, `beat creds init --root FILE` signs one from the root's key file (`new_member`).

Keys on disk, raw 32-byte keys in base64, one per file, split by owner. The client's (BEAT_KEYS, default
~/.local/share/beat/keys):
  org/<name>.key, .pub           the org's root keys (a Keyring): `org/current` names the one that certifies members
                                 (made on first use); every .pub here is pinned by the sensors
                                 (/etc/beat-sensor/roots/<name>.pub, `beat-sensor configure --org-root`)
  org/retired/<name>.pub         roots no longer deployed
The member's, apart (the ccache to the root's keytab: disposable, days), in BEAT_CCACHE, default
$XDG_RUNTIME_DIR/beat (tmpfs, the user's own, cleared at logout), else ~/.cache/beat/creds; 0700:
  key, credential                this machine's member key (0600) and its credential: what signs questions
The service's ($BEAT_SERVICES/keys, default /var/tmp/beat/keys):
  collector/<name>.key, .pub     the collector's own keys (a Keyring, the same layout), deployed to the sensors
                                 (/etc/beat-sensor/collectors/<name>.pub): they countersign questions and sign the
                                 stream's announcements
  sensors/<name>.pub             enrolled sensors (written at enrolment)
Rotation, either keyring (`--collector` for the collector's): `beat keys new NAME`, deploy,
`beat keys use NAME` (refused while a live sensor does not trust it), `beat keys retire OLD`, deploy. The service
learns the roots from the sensors' heartbeats (collector.py `Trust.obeyed`), never from anyone else.
"""
from __future__ import annotations

import base64
import getpass
import json
import os
import socket
import time
from datetime import datetime
from pathlib import Path

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hpke, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519

from . import wire

DEFAULT_KEYS = Path.home() / ".local/share/beat/keys"
SUITE = hpke.Suite(hpke.KEM.X25519, hpke.KDF.HKDF_SHA256, hpke.AEAD.CHACHA20_POLY1305)
RAW = serialization.Encoding.Raw, serialization.PublicFormat.Raw


class Refused(ValueError):
    """A message that is not signed by whom it must be, or cannot be opened."""


def keys_dir() -> Path:
    """The client's keys: the org's root keys."""
    return Path(os.environ.get("BEAT_KEYS") or DEFAULT_KEYS)


def ccache_dir() -> Path:
    """The member key and credential (as Kerberos's ccache, KRB5CCNAME): BEAT_CCACHE, else $XDG_RUNTIME_DIR/beat, else
    ~/.cache/beat/creds. Never /tmp: shared, so a predictable name there can be made by someone else first."""
    if os.environ.get("BEAT_CCACHE"):
        return Path(os.environ["BEAT_CCACHE"])
    run = os.environ.get("XDG_RUNTIME_DIR")
    return Path(run) / "beat" if run else Path.home() / ".cache/beat/creds"


def _cache(cache: Path | None) -> Path:
    d = cache or ccache_dir()
    d.mkdir(mode=0o700, parents=True, exist_ok=True)
    d.chmod(0o700)
    return d


def service_keys_dir() -> Path:
    """The service's keys: its own, enrolled sensors'."""
    return wire.services_dir() / "keys"


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


def unb64(text: str) -> bytes:
    try:
        return base64.b64decode(text.strip(), validate=True)
    except (ValueError, TypeError) as e:
        raise Refused(f"not base64: {e}") from None


def public_raw(key) -> bytes:
    return key.public_key().public_bytes(*RAW)


def public_raw_of(public: ed25519.Ed25519PublicKey) -> bytes:
    return public.public_bytes(*RAW)


def public_key(text: str) -> ed25519.Ed25519PublicKey:
    return ed25519.Ed25519PublicKey.from_public_bytes(unb64(text))


def signing_key(seed: bytes) -> ed25519.Ed25519PrivateKey:
    return ed25519.Ed25519PrivateKey.from_private_bytes(seed)


def seed_of(key: ed25519.Ed25519PrivateKey) -> bytes:
    return key.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
                             serialization.NoEncryption())


def fingerprint(public: bytes) -> str:
    """What heartbeats and listings show of a key: the first 12 hex digits of its SHA-256."""
    return wire.sha256_hex(public)[:12]


def _valid_name(name: str) -> bool:
    return bool(name) and not any(c in name for c in "./ *>") and name not in ("current", "retired")


def _write_secret(path: Path, text: str) -> None:
    tmp = path.with_suffix(".tmp")
    tmp.unlink(missing_ok=True)
    tmp.touch(mode=0o600)
    tmp.write_text(text)
    tmp.rename(path)


class Keyring:
    """Signing keys of one owner in a directory, one in use: <name>.key and .pub, `current` naming the one in use (a
    first key is made on first use), retired/<name>.pub for keys no longer deployed (their private halves destroyed).
    The org's (`org_keys`) and the collector's own (`collector_keys`) work alike, rotation included."""

    def __init__(self, d: Path, what: str):
        self.dir, self.what = d, what

    def _ready(self) -> Path:
        d = self.dir
        if not (d / "current").exists():
            d.mkdir(parents=True, exist_ok=True)
            name = time.strftime("%Y%m%d", time.gmtime())
            key = ed25519.Ed25519PrivateKey.generate()
            _write_secret(d / f"{name}.key", b64(seed_of(key)) + "\n")
            (d / f"{name}.pub").write_text(b64(public_raw(key)) + "\n")
            (d / "current").write_text(name + "\n")
        return d

    def current(self) -> str:
        return (self._ready() / "current").read_text().strip()

    def key(self) -> ed25519.Ed25519PrivateKey:
        """The key in use (0600)."""
        return signing_key(unb64((self._ready() / f"{self.current()}.key").read_text()))

    def public(self, retired: bool = False) -> dict[str, str]:
        """name -> public key (base64): the keys sensors are given (deploy-sensor), with the retired ones if asked."""
        d = self._ready()
        out = {p.stem: p.read_text().strip() for p in sorted(d.glob("*.pub"))}
        if retired:
            out.update({p.stem: p.read_text().strip() for p in sorted((d / "retired").glob("*.pub"))})
        return out

    def new(self, name: str) -> str:
        """A new key, not in use: deploy it to the sensors before `use`. Returns its public key."""
        d = self._ready()
        if not _valid_name(name):
            raise ValueError(f"key name {name!r}: letters, digits, - and _ only")
        if (d / f"{name}.key").exists() or (d / "retired" / f"{name}.pub").exists():
            raise ValueError(f"a {self.what} key named {name} exists")
        key = ed25519.Ed25519PrivateKey.generate()
        _write_secret(d / f"{name}.key", b64(seed_of(key)) + "\n")
        (d / f"{name}.pub").write_text(b64(public_raw(key)) + "\n")
        return b64(public_raw(key))

    def use(self, name: str) -> None:
        """Signs with `name` from the next question on."""
        if not (self._ready() / f"{name}.key").exists():
            raise ValueError(f"no {self.what} key named {name} (see `beat keys`)")
        (self.dir / "current").write_text(name + "\n")

    def retire(self, name: str) -> None:
        """Destroys the private key and stops deploying the public one (kept in retired/)."""
        d = self._ready()
        if name == self.current():
            raise ValueError(f"{name} is the {self.what} key in use: `beat keys use` another first")
        if not (d / f"{name}.pub").exists():
            raise ValueError(f"no {self.what} key named {name} (see `beat keys`)")
        (d / "retired").mkdir(exist_ok=True)
        (d / f"{name}.pub").rename(d / "retired" / f"{name}.pub")
        (d / f"{name}.key").unlink(missing_ok=True)


def org_keys(root: Path | None = None) -> Keyring:
    """The client's: the org's root keys, which certify members (H16); sensors pin their public halves."""
    return Keyring((root or keys_dir()) / "org", "org root")


# --- member credentials (docs/security.md H16) -----------------------------------------------------------------------
MEMBER_LIFE_S = 30 * 86400    # one person's credential (H16: to tune); renewal is silent
MAX_MEMBER_LIFE_S = 90 * 86400  # `beat creds init --days`: longer, and the credential is a long-lived secret
RENEW_BEFORE_S = 10 * 86400   # renewed when less than this is left
SKEW_S = 300                  # clocks: a credential counts this much before not_before and after not_after


def credential_bytes(fields: dict) -> bytes:
    """What a root signs: the credential without its signature, canonical (sensor/src/seal.rs check_credential)."""
    return wire.canonical({"v": 1, "kind": "credential", "credential": fields})


def credential(root_key: ed25519.Ed25519PrivateKey, root_name: str, name: str, member_public: bytes,
               now: float | None = None, life: int = MEMBER_LIFE_S) -> str:
    """A member credential (base64 of canonical JSON, as Beat-Cred carries it): `name` signs with `member_public`."""
    now = int(time.time() if now is None else now)
    fields = {"kind": "member", "name": name, "key": b64(member_public), "not_before": now, "not_after": now + life,
              "issuer": f"{root_name}:{fingerprint(public_raw(root_key))}"}
    return b64(wire.canonical({**fields, "signature": b64(root_key.sign(credential_bytes(fields)))}))


def read_credential(text: str) -> dict:
    """The credential's fields, unchecked (for showing it, and for deciding to renew)."""
    try:
        c = json.loads(unb64(text))
    except ValueError:
        raise Refused("the credential is not base64 JSON") from None
    if not isinstance(c, dict):
        raise Refused("the credential is not a JSON object")
    return c


def check_credential(text: str, roots: dict, now: float | None = None) -> dict:
    """The credential's fields, with "public" (the member's key) and "root" (the root's name, of `roots`: name ->
    public key), when one of `roots` signed it, it is a member's and valid now; else Refused."""
    c = read_credential(text or "")
    fields = {k: v for k, v in c.items() if k != "signature"}
    for name, public in roots.items():
        try:
            public.verify(unb64(str(c.get("signature") or "")), credential_bytes(fields))
            break
        except InvalidSignature:
            continue
    else:
        raise Refused(f"credential of {fields.get('name')!r} (issuer {fields.get('issuer')}): not signed by a root "
                      f"the sensors pin ({', '.join(roots) or 'none'})")
    if fields.get("kind") != "member":
        raise Refused(f"credential of kind {fields.get('kind')!r}, not member")
    now = time.time() if now is None else now
    nb, na = fields.get("not_before"), fields.get("not_after")
    if not isinstance(nb, int) or not isinstance(na, int):
        raise Refused("credential without not_before and not_after")
    if now < nb - SKEW_S:
        raise Refused(f"credential of {fields.get('name')!r} is not valid yet")
    if now > na + SKEW_S:
        raise Refused(f"credential of {fields.get('name')!r} expired at {wire.iso(na)}")
    try:
        key = public_key(str(fields.get("key")))
    except ValueError:
        raise Refused("credential's key is not an Ed25519 public key") from None
    return {**fields, "public": key, "root": name}


def member_name() -> str:
    """Who this machine's member is: the login's subject when signed in, else user@host."""
    try:
        from . import login
        return str(login.claims(login.access_token()).get("sub") or "")
    except Exception:  # not signed in, or no service: the name is a label, the root's signature is the proof
        return f"{getpass.getuser()}@{socket.gethostname()}"


def read_root(path: str | Path) -> tuple:
    """(the root's key, its name) from a root key file (one line, the seed in base64; BEAT_KEYS/org/<name>.key)."""
    p = Path(path)
    try:
        return signing_key(unb64(p.read_text())), p.stem
    except (OSError, ValueError) as e:
        raise Refused(f"{p}: not a root key file ({e})") from None


def new_member(root_key: ed25519.Ed25519PrivateKey, root_name: str, name: str | None = None,
               life: int = MEMBER_LIFE_S, cache: Path | None = None, now: float | None = None) -> tuple:
    """`beat creds init`, as `kinit -kt` gets a ticket from a keytab: a fresh member key, and its credential signed by
    the root, kept in the ccache (the old pair replaced). Returns (key, credential)."""
    if not 0 < life <= MAX_MEMBER_LIFE_S:
        raise ValueError(f"a credential lasts at most {MAX_MEMBER_LIFE_S // 86400} days")
    d = _cache(cache)
    key = ed25519.Ed25519PrivateKey.generate()
    cred = credential(root_key, root_name, name or member_name(), public_raw(key), now, life)
    _write_secret(d / "key", b64(seed_of(key)) + "\n")
    (d / "credential").write_text(cred + "\n")
    return key, cred


def current_member(cache: Path | None = None) -> tuple:
    """(key, credential, its fields) kept in the ccache, as they are; Refused when there are none."""
    d = cache or ccache_dir()
    try:
        cred = (d / "credential").read_text().strip()
        key = signing_key(unb64((d / "key").read_text()))
    except OSError:
        raise Refused(f"no member credential in {d}: `beat creds init --root FILE` (the org root's key file); on "
                      "the org's first machine, `beat keys` makes the root") from None
    fields = read_credential(cred)
    if fields.get("key") != b64(public_raw(key)):
        raise Refused("the member credential is not for the member key here: `beat creds init`")
    return key, cred, fields


def member(keys: Path | None = None, cache: Path | None = None, now: float | None = None) -> tuple:
    """(member key, credential) to sign questions with. With the org's root on this machine (one person,
    BEAT_KEYS/org), renewed silently when it has less than RENEW_BEFORE_S left, another root made it, or it names
    someone else than who is signed in now. Without, used until it expires, then refused: `beat creds init --root
    FILE`, as an expired ticket sends you to kinit. A machine without a root never makes one here (`beat keys`)."""
    now = time.time() if now is None else now
    ring = org_keys(keys)
    if not (ring.dir / "current").exists():
        key, cred, fields = current_member(cache)
        if fields.get("not_after", 0) <= now:
            raise Refused(f"the member credential expired at {wire.iso(fields.get('not_after', 0))}: "
                          "`beat creds init --root FILE`")
        return key, cred
    name = member_name()
    try:
        key, cred, fields = current_member(cache)
        if (fields.get("not_after", 0) - now > RENEW_BEFORE_S and fields.get("name") == name
                and str(fields.get("issuer", "")).split(":")[0] == ring.current()):
            return key, cred
    except Refused:
        pass
    return new_member(ring.key(), ring.current(), name, cache=cache, now=now)


# --- the deny list (docs/security.md H16) ------------------------------------------------------------------------
def deny_bytes(fields: dict) -> bytes:
    """What a root signs: the list without its signature, canonical (sensor/src/seal.rs check_deny)."""
    return wire.canonical({"v": 1, "kind": "deny", "deny": fields})


def deny_list(root_key: ed25519.Ed25519PrivateKey, root_name: str, entries: list[dict], seq: int,
              now: float | None = None) -> bytes:
    """The org's deny list, signed: credentials named entries[].name with not_before earlier than entries[].before are
    refused; an entry is kept until `until` (when every such credential has expired), then dropped. Sequence numbers
    rise: sensors take only a higher one, so an older copy cannot undo a denial."""
    now = int(time.time() if now is None else now)
    fields = {"seq": seq, "issued": now, "issuer": f"{root_name}:{fingerprint(public_raw(root_key))}",
              "entries": sorted((e for e in entries if e["until"] > now), key=lambda e: e["name"])}
    return wire.canonical({**fields, "signature": b64(root_key.sign(deny_bytes(fields)))})


def check_deny(data: bytes, roots: dict) -> dict:
    """The list's fields when one of `roots` signed it; else Refused."""
    try:
        d = json.loads(data)
    except ValueError:
        raise Refused("the deny list is not JSON") from None
    if not isinstance(d, dict):
        raise Refused("the deny list is not a JSON object")
    fields = {k: v for k, v in d.items() if k != "signature"}
    for public in roots.values():
        try:
            public.verify(unb64(str(d.get("signature") or "")), deny_bytes(fields))
            break
        except InvalidSignature:
            continue
    else:
        raise Refused(f"deny list {fields.get('seq')} (issuer {fields.get('issuer')}): not signed by a root the "
                      "sensors pin")
    if not isinstance(fields.get("seq"), int) or not isinstance(fields.get("entries"), list):
        raise Refused("deny list without seq and entries")
    return fields


def denied(cred: dict, deny: dict | None) -> str | None:
    """Why the deny list refuses this credential (its fields), or None."""
    for e in (deny or {}).get("entries", []):
        if e.get("name") == cred.get("name") and cred.get("not_before", 0) < e.get("before", 0):
            return (f"{cred.get('name')!r} is on the org's deny list (credentials issued before "
                    f"{wire.iso(e['before'])}; list {deny['seq']})")
    return None


def destroy_member(cache: Path | None = None) -> bool:
    """`beat creds destroy` (kdestroy): removes the member key and credential; True when there were any."""
    d = cache or ccache_dir()
    gone = False
    for f in ("key", "credential"):
        try:
            (d / f).unlink()
            gone = True
        except FileNotFoundError:
            pass
    return gone


def collector_keys(root: Path | None = None) -> Keyring:
    """The service's: the collector's own keys, which countersign every question it relays (Beat-Countersignature:
    the survey key in it is the collector's) and sign its announcements on the stream."""
    return Keyring((root or service_keys_dir()) / "collector", "collector")


def enroll(name: str, public: str, root: Path | None = None) -> Path:
    """Records a sensor's public key: from now on its acks, answers and heartbeats are accepted."""
    if not name or any(c in name for c in "./ *>"):
        raise ValueError(f"sensor name {name!r} cannot be a subject token")
    if len(unb64(public)) != 32:
        raise ValueError("an Ed25519 public key is 32 bytes")
    d = (root or service_keys_dir()) / "sensors"
    d.mkdir(parents=True, exist_ok=True)
    (d / f"{name}.pub").write_text(public.strip() + "\n")
    return d / f"{name}.pub"


def unenroll(name: str, root: Path | None = None) -> None:
    """From now on the sensor's acks, answers and heartbeats are refused (it shows as untrusted in `beat sensors`)."""
    p = (root or service_keys_dir()) / "sensors" / f"{name}.pub"
    if not name or any(c in name for c in "./ *>") or not p.exists():
        raise ValueError(f"no enrolled sensor named {name!r}")
    p.unlink()


class Enrolled:
    """The enrolled sensors' public keys, read from sensors/<name>.pub when first needed and again when changed."""

    def __init__(self, root: Path | None = None):
        self.dir = (root or service_keys_dir()) / "sensors"
        self.cache: dict[str, tuple[float, ed25519.Ed25519PublicKey]] = {}

    def get(self, name: str) -> ed25519.Ed25519PublicKey | None:
        if not name or any(c in name for c in "./ *>"):
            return None
        p = self.dir / f"{name}.pub"
        try:
            mtime = p.stat().st_mtime
        except FileNotFoundError:
            return None
        hit = self.cache.get(name)
        if hit and hit[0] == mtime:
            return hit[1]
        key = public_key(p.read_text())
        self.cache[name] = (mtime, key)
        return key


# --- what is signed ---------------------------------------------------------------------------------------------
COUNTERSIGNATURE = "Beat-Countersignature"
SIGNATURES = ("Beat-Signature", COUNTERSIGNATURE)  # what signed_bytes leaves out: both sign the same bytes
KINDS = {"beat.ask.": "ask", "beat.survey.": "survey", "beat.ack.": "ack", "beat.answer.": "answer"}
HEARTBEAT_FRESH_S = 35   # the directory's TTL: an entry older than that is a replay or a stalled sensor


def kind_of(subject: str) -> str:
    for prefix, kind in KINDS.items():
        if subject.startswith(prefix):
            return kind
    raise Refused(f"{subject}: not a signed subject")


def signed_bytes(kind: str, headers: dict, payload: bytes) -> bytes:
    """What a signature covers: the message's kind, its Beat-* headers but the signature (a header added, removed or
    changed in transit breaks it) and its payload's hash, as canonical JSON, so the verifier rebuilds the bytes from
    the message it got."""
    h = {k: v for k, v in (headers or {}).items() if k.startswith("Beat-") and k not in SIGNATURES}
    return wire.canonical({"v": 1, "kind": kind, "headers": h, "payload": wire.sha256_hex(payload)})


def sign(key: ed25519.Ed25519PrivateKey, kind: str, headers: dict, payload: bytes,
         header: str = "Beat-Signature") -> dict:
    """The headers with Beat-Signature (or the countersignature) added."""
    return {**headers, header: b64(key.sign(signed_bytes(kind, headers, payload)))}


def verify(public: ed25519.Ed25519PublicKey, kind: str, headers: dict, payload: bytes, what: str,
           header: str = "Beat-Signature") -> None:
    signature = (headers or {}).get(header)
    if not signature:
        raise Refused(f"{what} is not {'countersigned' if header == COUNTERSIGNATURE else 'signed'}")
    try:
        public.verify(unb64(signature), signed_bytes(kind, headers, payload))
    except InvalidSignature:
        raise Refused(f"{what}: bad signature") from None


def heartbeat_payload(entry: dict) -> bytes:
    """What a heartbeat's signature covers: the entry without its signature, canonical (sensor/src/main.rs)."""
    return wire.canonical({k: v for k, v in entry.items() if k != "signature"})


def check_heartbeat(entry: dict, enrolled: "Enrolled", now: float | None = None) -> str | None:
    """None when the entry is signed by its sensor's enrolled key and fresh; else why it is not trusted."""
    name = entry.get("name")
    public = enrolled.get(name) if isinstance(name, str) else None
    if public is None:
        return "not enrolled"
    try:
        verify(public, "heartbeat", {"Beat-Signature": entry.get("signature") or ""}, heartbeat_payload(entry),
               "heartbeat")
    except Refused as e:
        return str(e)
    try:
        at = datetime.fromisoformat(str(entry.get("at")).replace("Z", "+00:00")).timestamp()
    except ValueError:
        return "heartbeat has no time"
    age = (now or time.time()) - at
    if age > HEARTBEAT_FRESH_S:
        return f"heartbeat {age:.0f} s old (a replay, or the sensor stalled)"
    return None


# --- sealing -------------------------------------------------------------------------------------------------------
def info(survey: str, target: str) -> bytes:
    """HPKE's info: an answer sealed for one survey and target opens for no other."""
    return b"beat-answer/v1\0" + survey.encode() + b"\0" + target.encode()


def survey_key() -> x25519.X25519PrivateKey:
    return x25519.X25519PrivateKey.generate()


def seal(public: bytes, survey: str, target: str, plaintext: bytes) -> bytes:
    """encapsulated key (32 bytes) + ciphertext: what the sensor publishes (and the scale simulator)."""
    return SUITE.encrypt(plaintext, x25519.X25519PublicKey.from_public_bytes(public), info=info(survey, target))


def open_sealed(private: x25519.X25519PrivateKey, survey: str, target: str, sealed: bytes) -> bytes:
    try:
        return SUITE.decrypt(sealed, private, info=info(survey, target))
    except (InvalidTag, ValueError) as e:
        raise Refused(f"cannot open the answer: {type(e).__name__}") from None
