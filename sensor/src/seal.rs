//! Signed questions and sealed answers (docs/protocol.md, docs/protocol.md C14, C16). Python side and the
//! rules in full: src/beat/seal.py; tests/seal_vectors.json keeps both sides in step.
//!
//! Every signature (Ed25519, header Beat-Signature) covers the message's kind (ask, ack, answer), its other Beat-*
//! headers and its payload's hash, as canonical JSON. The sensor answers only questions signed by a member key
//! (Beat-Signature) whose credential (Beat-Cred: name and key, signed by an org root this sensor pins;
//! docs/security.md H16, `check_credential`) is valid now, and countersigned by a collector key over the same bytes (Beat-Countersignature:
//! the survey key in it is the collector's), and seals each answer to the survey's key (Beat-Key) with HPKE (RFC 9180
//! base mode: X25519, HKDF-SHA256, ChaCha20-Poly1305): the payload is the encapsulated key followed by the
//! ciphertext, info binds survey and target.
//!
//! Keys are files of one line, the raw 32 bytes in base64: the sensor's signing key (`beat-sensor keygen FILE`
//! creates it, 0600, and prints the public key to enroll) and the org roots' and the collector's public keys, one file
//! each (`<name>.pub`, a directory for each): any key in a directory counts (rotation: a new key is deployed before
//! it is used, the old one removed after).

use std::io::Write;
use std::path::Path;

use base64::{engine::general_purpose::STANDARD, Engine};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use hpke::{aead::ChaCha20Poly1305, kdf::HkdfSha256, kem::X25519HkdfSha256, Deserializable, Kem, OpModeS, Serializable};
use rand_core::{OsRng, RngCore};
use serde_json::{json, Map, Value};

use crate::wire::{canonical, sha256_hex};

/// A message's headers as name and value; a header given twice is refused (which value would be signed?).
pub type Headers = Vec<(String, String)>;

pub fn headers_of(msg: &async_nats::Message) -> Result<Headers, String> {
    let mut out = Headers::new();
    for (k, vs) in msg.headers.iter().flat_map(|h| h.iter()) {
        if vs.len() != 1 {
            return Err(format!("header {k} given {} times", vs.len()));
        }
        out.push((k.to_string(), vs[0].as_str().to_string()));
    }
    Ok(out)
}

pub fn get<'a>(h: &'a Headers, key: &str) -> Option<&'a str> {
    h.iter().find(|(k, _)| k == key).map(|(_, v)| v.as_str())
}

/// The headers signed_bytes leaves out: the signature and the countersignature, over the same bytes.
pub const SIGNATURE: &str = "Beat-Signature";
pub const COUNTERSIGNATURE: &str = "Beat-Countersignature";

/// What a signature covers (seal.py `signed_bytes`).
pub fn signed_bytes(kind: &str, headers: &Headers, payload: &[u8]) -> Vec<u8> {
    let mut h = Map::new();
    for (k, v) in headers {
        if k.starts_with("Beat-") && k != SIGNATURE && k != COUNTERSIGNATURE {
            h.insert(k.clone(), Value::String(v.clone()));
        }
    }
    canonical(&json!({"v": 1, "kind": kind, "headers": h, "payload": sha256_hex(payload)}))
}

/// The headers with Beat-Signature added.
pub fn sign(key: &SigningKey, kind: &str, mut headers: Headers, payload: &[u8]) -> Headers {
    let sig = key.sign(&signed_bytes(kind, &headers, payload));
    headers.push(("Beat-Signature".into(), STANDARD.encode(sig.to_bytes())));
    headers
}

/// `verify_header` for Beat-Signature (the tests' shorthand).
#[cfg(test)]
pub fn verify(key: &VerifyingKey, kind: &str, headers: &Headers, payload: &[u8]) -> Result<(), String> {
    verify_header(key, SIGNATURE, kind, headers, payload)
}

/// `verify` for the signature in `header` (Beat-Signature or Beat-Countersignature).
pub fn verify_header(key: &VerifyingKey, header: &str, kind: &str, headers: &Headers, payload: &[u8])
                     -> Result<(), String> {
    let sig = get(headers, header).ok_or("not signed")?;
    let sig = STANDARD.decode(sig).map_err(|e| format!("signature is not base64: {e}"))?;
    let sig = Signature::from_slice(&sig).map_err(|e| format!("not a signature: {e}"))?;
    key.verify(&signed_bytes(kind, headers, payload), &sig).map_err(|_| "bad signature".to_string())
}

/// What sealing adds to an answer: the encapsulated key (32 bytes) and the AEAD tag (16).
pub const OVERHEAD: usize = 48;

pub fn info(survey: &str, target: &str) -> Vec<u8> {
    [b"beat-answer/v1\0".as_slice(), survey.as_bytes(), b"\0", target.as_bytes()].concat()
}

/// Seals an answer to the survey's public key (Beat-Key, base64): encapsulated key + ciphertext.
pub fn seal(public_b64: &str, survey: &str, target: &str, plaintext: &[u8]) -> Result<Vec<u8>, String> {
    let raw = STANDARD.decode(public_b64.trim()).map_err(|e| format!("Beat-Key is not base64: {e}"))?;
    let pk = <X25519HkdfSha256 as Kem>::PublicKey::from_bytes(&raw).map_err(|e| format!("Beat-Key: {e}"))?;
    let (enc, ct) = hpke::single_shot_seal::<ChaCha20Poly1305, HkdfSha256, X25519HkdfSha256, _>(
        &OpModeS::Base, &pk, &info(survey, target), plaintext, b"", &mut OsRng)
        .map_err(|e| format!("sealing: {e}"))?;
    Ok([enc.to_bytes().as_slice(), &ct].concat())
}

fn read_raw(path: &Path) -> anyhow::Result<[u8; 32]> {
    let text = std::fs::read_to_string(path)?;
    let raw = STANDARD.decode(text.trim())?;
    raw.try_into().map_err(|_| anyhow::anyhow!("{}: not a 32-byte key", path.display()))
}

pub fn read_signing(path: &Path) -> anyhow::Result<SigningKey> {
    Ok(SigningKey::from_bytes(&read_raw(path)?))
}

pub fn read_verifying(path: &Path) -> anyhow::Result<VerifyingKey> {
    Ok(VerifyingKey::from_bytes(&read_raw(path)?)?)
}

/// What heartbeats and `beat keys` show of a key: the first 12 hex digits of its SHA-256 (seal.py `fingerprint`).
pub fn fingerprint(key: &VerifyingKey) -> String {
    sha256_hex(key.as_bytes())[..12].to_string()
}

/// One key the sensor trusts: `<name>.pub` in the org's or the collector's keys' directory.
pub struct Trusted {
    pub name: String,
    pub key: VerifyingKey,
}

/// The keys in `dir` (`*.pub`), read each time they are needed: a key deployed or removed counts at once.
pub fn read_keys(dir: &Path) -> anyhow::Result<Vec<Trusted>> {
    let mut out = Vec::new();
    for e in std::fs::read_dir(dir).map_err(|e| anyhow::anyhow!("{}: {e}", dir.display()))? {
        let p = e?.path();
        if p.extension().is_some_and(|x| x == "pub") {
            let name = p.file_stem().unwrap_or_default().to_string_lossy().to_string();
            out.push(Trusted { key: read_verifying(&p).map_err(|e| anyhow::anyhow!("{}: {e}", p.display()))?, name });
        }
    }
    out.sort_by(|a, b| a.name.cmp(&b.name));
    if out.is_empty() {
        anyhow::bail!("no key (*.pub) in {}", dir.display());
    }
    Ok(out)
}

/// Verifies the signature in `header` with each key until one holds; returns its name. `whose`: org or collector.
pub fn verify_any<'a>(keys: &'a [Trusted], whose: &str, header: &str, kind: &str, headers: &Headers, payload: &[u8])
                      -> Result<&'a str, String> {
    let what = if header == COUNTERSIGNATURE { "countersigned" } else { "signed" };
    get(headers, header).ok_or(format!("not {what}"))?;
    for c in keys {
        if verify_header(&c.key, header, kind, headers, payload).is_ok() {
            return Ok(&c.name);
        }
    }
    Err(format!("bad {} (none of the {} {whose} keys)", if what == "signed" { "signature" } else { "countersignature" },
                keys.len()))
}

/// A heartbeat entry with its signature (kind heartbeat, over the entry without it; seal.py `check_heartbeat`).
pub fn sign_entry(key: &SigningKey, mut entry: Map<String, Value>) -> Map<String, Value> {
    entry.remove("signature");
    let sig = key.sign(&signed_bytes("heartbeat", &Headers::new(), &canonical(&Value::Object(entry.clone()))));
    entry.insert("signature".into(), Value::String(STANDARD.encode(sig.to_bytes())));
    entry
}

/// Clocks: a credential counts this much before its not_before and after its not_after (seal.py SKEW_S).
pub const CRED_SKEW_S: i64 = 300;

/// A member of the org, as its credential says: who, the key that signs their questions, and the root that said so.
#[derive(Debug)]
pub struct Member {
    pub name: String,
    pub key: VerifyingKey,
    pub root: String,
    pub not_before: i64,
}

/// The member a credential names (Beat-Cred: base64 of canonical JSON {kind, name, key, not_before, not_after, issuer,
/// signature}), when one of `roots` signed it (over {"v": 1, "kind": "credential", "credential": the rest}, seal.py
/// `credential_bytes`), it is a member's and valid at `now`.
pub fn check_credential(text: &str, roots: &[Trusted], now: i64) -> Result<Member, String> {
    let raw = STANDARD.decode(text.trim()).map_err(|_| "Beat-Cred is not base64".to_string())?;
    let mut fields: Map<String, Value> = serde_json::from_slice(&raw).map_err(|_| "Beat-Cred is not a JSON object")?;
    let sig = fields.remove("signature").and_then(|s| s.as_str().map(String::from)).ok_or("credential not signed")?;
    let sig = STANDARD.decode(sig).ok().and_then(|s| Signature::from_slice(&s).ok()).ok_or("credential: not a signature")?;
    let name = fields.get("name").and_then(Value::as_str).unwrap_or("?").to_string();
    let signed = canonical(&json!({"v": 1, "kind": "credential", "credential": Value::Object(fields.clone())}));
    let root = roots.iter().find(|r| r.key.verify(&signed, &sig).is_ok())
        .ok_or(format!("credential of {name:?}: not signed by a root this sensor pins"))?;
    if fields.get("kind").and_then(Value::as_str) != Some("member") {
        return Err(format!("credential of {name:?}: not a member's"));
    }
    let (nb, na) = (fields.get("not_before").and_then(Value::as_i64), fields.get("not_after").and_then(Value::as_i64));
    let (Some(nb), Some(na)) = (nb, na) else { return Err(format!("credential of {name:?}: no validity")) };
    if now < nb - CRED_SKEW_S {
        return Err(format!("credential of {name:?}: not valid yet"));
    }
    if now > na + CRED_SKEW_S {
        return Err(format!("credential of {name:?}: expired"));
    }
    let key = fields.get("key").and_then(Value::as_str).and_then(|k| STANDARD.decode(k).ok())
        .and_then(|k| <[u8; 32]>::try_from(k).ok()).and_then(|k| VerifyingKey::from_bytes(&k).ok())
        .ok_or(format!("credential of {name:?}: no Ed25519 key"))?;
    Ok(Member { name, key, root: root.name.clone(), not_before: nb })
}

/// The org root's deny list (docs/security.md H16; seal.py `deny_list`): credentials of a name issued before a time are
/// refused. Taken only when a pinned root signed it, and only a higher seq than the one held.
#[derive(Debug, Default)]
pub struct Deny {
    pub seq: i64,
    pub entries: Vec<(String, i64)>,
}

impl Deny {
    /// Why this member is refused, or None.
    pub fn denies(&self, m: &Member) -> Option<String> {
        self.entries.iter().find(|(name, before)| *name == m.name && m.not_before < *before)
            .map(|(name, _)| format!("{name:?} is on the org's deny list ({})", self.seq))
    }
}

/// A deny list (canonical JSON {seq, issued, issuer, entries: [{name, before, until}], signature}) when one of
/// `roots` signed it (over {"v": 1, "kind": "deny", "deny": the rest}).
pub fn check_deny(data: &[u8], roots: &[Trusted]) -> Result<Deny, String> {
    let mut fields: Map<String, Value> = serde_json::from_slice(data).map_err(|_| "deny list: not a JSON object")?;
    let sig = fields.remove("signature").and_then(|s| s.as_str().map(String::from)).ok_or("deny list not signed")?;
    let sig = STANDARD.decode(sig).ok().and_then(|s| Signature::from_slice(&s).ok()).ok_or("deny list: not a signature")?;
    let signed = canonical(&json!({"v": 1, "kind": "deny", "deny": Value::Object(fields.clone())}));
    if !roots.iter().any(|r| r.key.verify(&signed, &sig).is_ok()) {
        return Err("deny list not signed by a root this sensor pins".into());
    }
    let seq = fields.get("seq").and_then(Value::as_i64).ok_or("deny list without seq")?;
    let entries = fields.get("entries").and_then(Value::as_array).ok_or("deny list without entries")?.iter()
        .filter_map(|e| Some((e.get("name")?.as_str()?.to_string(), e.get("before")?.as_i64()?)))
        .collect();
    Ok(Deny { seq, entries })
}

/// `beat-sensor keygen FILE`: the sensor's signing key, created when missing (0600); returns the public key.
pub fn keygen(path: &Path) -> anyhow::Result<String> {
    if !path.exists() {
        let mut seed = [0u8; 32];
        OsRng.fill_bytes(&mut seed);
        let tmp = path.with_extension("tmp");
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(&tmp)?;
        writeln!(f, "{}", STANDARD.encode(seed))?;
        std::fs::rename(&tmp, path)?;
    }
    Ok(STANDARD.encode(read_signing(path)?.verifying_key().to_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use hpke::OpModeR;

    fn vectors() -> Value {
        let text = std::fs::read_to_string(crate::test_vectors("seal_vectors.json")).unwrap();
        serde_json::from_str(&text).unwrap()
    }

    fn headers(v: &Value) -> Headers {
        v.as_object().unwrap().iter().map(|(k, v)| (k.clone(), v.as_str().unwrap().to_string())).collect()
    }

    /// A credential Python's root signed: Rust accepts it while valid, from that root only (docs/security.md H16).
    #[test]
    fn credentials_match_python() {
        let v = vectors();
        let c = &v["credential"];
        let root = SigningKey::from_bytes(&STANDARD.decode(v["seed"].as_str().unwrap()).unwrap().try_into().unwrap());
        let roots = [Trusted { name: "r1".into(), key: root.verifying_key() }];
        let (text, now) = (c["credential"].as_str().unwrap(), c["now"].as_i64().unwrap());
        let m = check_credential(text, &roots, now + 10).unwrap();
        assert_eq!((m.name.as_str(), m.root.as_str()), ("alice", "r1"));
        assert_eq!(STANDARD.encode(m.key.as_bytes()), c["member_public"].as_str().unwrap());
        assert!(check_credential(text, &roots, now + 31 * 86400).unwrap_err().contains("expired"));
        assert!(check_credential(text, &roots, now - 3600).unwrap_err().contains("not valid yet"));
        let other = [Trusted { name: "r1".into(), key: SigningKey::from_bytes(&[9; 32]).verifying_key() }];
        assert!(check_credential(text, &other, now).unwrap_err().contains("not signed by a root"));
        let mut forged: Value = serde_json::from_slice(&STANDARD.decode(text).unwrap()).unwrap();
        forged["name"] = "root".into();
        let forged = STANDARD.encode(forged.to_string());
        assert!(check_credential(&forged, &roots, now).unwrap_err().contains("not signed by a root"));
    }

    /// A deny list Python's root signed: Rust takes it, and refuses alice's credentials issued before the denial.
    #[test]
    fn deny_lists_match_python() {
        let v = vectors();
        let root = SigningKey::from_bytes(&STANDARD.decode(v["seed"].as_str().unwrap()).unwrap().try_into().unwrap());
        let roots = [Trusted { name: "r1".into(), key: root.verifying_key() }];
        let list = v["deny"]["list"].as_str().unwrap().as_bytes();
        let d = check_deny(list, &roots).unwrap();
        assert_eq!(d.seq, 7);
        let c = &v["credential"];
        let m = check_credential(c["credential"].as_str().unwrap(), &roots, c["now"].as_i64().unwrap()).unwrap();
        assert!(d.denies(&m).unwrap().contains("deny list (7)"));
        assert!(d.denies(&Member { not_before: 1_800_000_100, ..m }).is_none());
        let other = [Trusted { name: "r1".into(), key: SigningKey::from_bytes(&[9; 32]).verifying_key() }];
        assert!(check_deny(list, &other).is_err());
        let mut forged: Value = serde_json::from_slice(list).unwrap();
        forged["entries"] = json!([]);
        assert!(check_deny(forged.to_string().as_bytes(), &roots).is_err());
    }

    /// Python signs, Rust verifies and signs the same bytes (Ed25519 is deterministic).
    #[test]
    fn signatures_match_python() {
        let v = vectors();
        let key = SigningKey::from_bytes(&STANDARD.decode(v["seed"].as_str().unwrap()).unwrap().try_into().unwrap());
        for case in v["signed"].as_array().unwrap() {
            let (kind, payload) = (case["kind"].as_str().unwrap(), case["payload"].as_str().unwrap().as_bytes());
            let h = headers(&case["headers"]);
            assert_eq!(String::from_utf8(signed_bytes(kind, &h, payload)).unwrap(), case["signed_bytes"].as_str().unwrap());
            verify(&key.verifying_key(), kind, &h, payload).unwrap();
            let unsigned: Headers = h.iter().filter(|(k, _)| k != "Beat-Signature").cloned().collect();
            assert_eq!(get(&sign(&key, kind, unsigned, payload), "Beat-Signature"), get(&h, "Beat-Signature"));
            let mut changed = h.clone();
            changed.push(("Beat-Targets".into(), "elsewhere".into()));
            assert!(verify(&key.verifying_key(), kind, &changed, payload).is_err());
            assert!(verify(&key.verifying_key(), kind, &h, b"other").is_err());
            let other = if kind == "ask" { "ack" } else { "ask" };
            assert!(verify(&key.verifying_key(), other, &h, payload).is_err());
        }
    }

    /// Python seals, Rust opens; Rust seals, and opens with the key Python would hold.
    #[test]
    fn sealing_matches_python() {
        let v = vectors();
        let s = &v["sealed"];
        let sk = <X25519HkdfSha256 as Kem>::PrivateKey::from_bytes(&STANDARD.decode(s["private"].as_str().unwrap()).unwrap())
            .unwrap();
        let (survey, target) = (s["survey"].as_str().unwrap(), s["target"].as_str().unwrap());
        let open = |sealed: &[u8], target: &str| {
            let enc = <X25519HkdfSha256 as Kem>::EncappedKey::from_bytes(&sealed[..32]).unwrap();
            hpke::single_shot_open::<ChaCha20Poly1305, HkdfSha256, X25519HkdfSha256>(
                &OpModeR::Base, &sk, &enc, &info(survey, target), &sealed[32..], b"")
        };
        let from_python = STANDARD.decode(s["sealed"].as_str().unwrap()).unwrap();
        assert_eq!(open(&from_python, target).unwrap(), s["plaintext"].as_str().unwrap().as_bytes());
        assert!(open(&from_python, "another-host").is_err());
        let ours = seal(s["public"].as_str().unwrap(), survey, target, b"an answer").unwrap();
        assert_eq!(open(&ours, target).unwrap(), b"an answer");
    }

    /// The heartbeat Python checks: same entry, same signature (Ed25519 is deterministic).
    #[test]
    fn heartbeat_matches_python() {
        let v = vectors();
        let key = SigningKey::from_bytes(&STANDARD.decode(v["seed"].as_str().unwrap()).unwrap().try_into().unwrap());
        let signed = v["heartbeat"].as_object().unwrap().clone();
        assert_eq!(sign_entry(&key, signed.clone()), signed);
    }

    #[test]
    fn any_key() {
        let v = vectors();
        let key = SigningKey::from_bytes(&STANDARD.decode(v["seed"].as_str().unwrap()).unwrap().try_into().unwrap());
        let other = || Trusted { name: "old".into(), key: SigningKey::from_bytes(&[7; 32]).verifying_key() };
        let ours = Trusted { name: "new".into(), key: key.verifying_key() };
        let case = &v["signed"][0];
        let (h, payload) = (headers(&case["headers"]), case["payload"].as_str().unwrap().as_bytes());
        assert_eq!(verify_any(&[other(), ours], "org", SIGNATURE, "ask", &h, payload), Ok("new"));
        assert!(verify_any(&[other()], "org", SIGNATURE, "ask", &h, payload).unwrap_err().starts_with("bad signature"));
        assert_eq!(verify_any(&[other()], "collector", COUNTERSIGNATURE, "ask", &h, payload).unwrap_err(),
                   "not countersigned");
    }

    /// The countersigned vector (Python's): both signatures over the same bytes; each is checked against its own
    /// header, so one cannot stand in for the other.
    #[test]
    fn countersigned() {
        let v = vectors();
        let key = SigningKey::from_bytes(&STANDARD.decode(v["seed"].as_str().unwrap()).unwrap().try_into().unwrap());
        let c = &v["countersigned"];
        let (h, payload) = (headers(&c["headers"]), c["payload"].as_str().unwrap().as_bytes());
        assert_eq!(String::from_utf8(signed_bytes("ask", &h, payload)).unwrap(), c["signed_bytes"].as_str().unwrap());
        let org = [Trusted { name: "org".into(), key: SigningKey::from_bytes(&[9; 32]).verifying_key() }];
        let collector = [Trusted { name: "c".into(), key: key.verifying_key() }];
        assert_eq!(verify_any(&org, "org", SIGNATURE, "ask", &h, payload), Ok("org"));
        assert_eq!(verify_any(&collector, "collector", COUNTERSIGNATURE, "ask", &h, payload), Ok("c"));
        assert!(verify_any(&collector, "org", SIGNATURE, "ask", &h, payload).is_err());
        let mut swapped = h.clone();
        swapped.retain(|(k, _)| k != "Beat-Key");
        swapped.push(("Beat-Key".into(), "BBBB".into()));
        assert!(verify_any(&collector, "collector", COUNTERSIGNATURE, "ask", &swapped, payload).is_err());
    }

    #[test]
    fn keygen_keeps_the_key() {
        let d = std::env::temp_dir().join(format!("beat-keygen-{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        let p = d.join("sensor.key");
        let a = keygen(&p).unwrap();
        assert_eq!(keygen(&p).unwrap(), a);
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(std::fs::metadata(&p).unwrap().permissions().mode() & 0o777, 0o600);
        std::fs::remove_dir_all(&d).unwrap();
    }
}
