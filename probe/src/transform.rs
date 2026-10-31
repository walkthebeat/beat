//! Transformers (C23, docs/security.md): files of known meaning read for what they mean, never their bytes.
//!
//! Pure functions from a file's bytes to JSON. The builtins `keytab()`, `certificate()` and `private_key()` call them
//! through the host (`Host::transformed`), and `beat-probe secrets` runs them outside the sensor's sandbox for the
//! secret files the sandbox covers. No subprocess: the formats are parsed here, so every host answers the same
//! whatever krb5 or OpenSSL it has. Key material never appears in the output: only names, types, sizes, dates and
//! fingerprints of public parts.

use serde_json::{json, Value as Json};
use sha2::{Digest, Sha256};

use crate::builtins::iso_utc;

/// The kinds a probe can ask for, and that `detect` recognizes.
pub const KINDS: [&str; 3] = ["keytab", "certificate", "private_key"];

pub fn transform(kind: &str, bytes: &[u8]) -> Result<Json, String> {
    match kind {
        "keytab" => keytab(bytes),
        "certificate" => certificate(bytes),
        "private_key" => private_key(bytes),
        _ => Err(format!("unknown kind {kind}")),
    }
}

/// The kind of a file, from its first bytes (for `beat-probe secrets`, which has no probe to say what it expects).
pub fn detect(bytes: &[u8]) -> Option<&'static str> {
    if bytes.len() >= 2 && bytes[0] == 5 && (bytes[1] == 1 || bytes[1] == 2) {
        return Some("keytab");
    }
    let head = String::from_utf8_lossy(&bytes[..bytes.len().min(64 << 10)]);
    if head.contains("PRIVATE KEY-----") {
        return Some("private_key");
    }
    if head.contains("-----BEGIN CERTIFICATE-----") || x509_parser::parse_x509_certificate(bytes).is_ok() {
        return Some("certificate");
    }
    None
}

fn sha256_hex(b: &[u8]) -> String {
    Sha256::digest(b).iter().map(|x| format!("{x:02x}")).collect()
}

// --- keytab (MIT krb5 "keytab file format", versions 0x0501 and 0x0502) ------------------------------------------

struct Reader<'a> {
    b: &'a [u8],
    at: usize,
    big: bool,
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], String> {
        let s = self.b.get(self.at..self.at + n).ok_or("keytab: truncated")?;
        self.at += n;
        Ok(s)
    }
    fn u8(&mut self) -> Result<u8, String> {
        Ok(self.take(1)?[0])
    }
    fn u16(&mut self) -> Result<u16, String> {
        let s: [u8; 2] = self.take(2)?.try_into().unwrap();
        Ok(if self.big { u16::from_be_bytes(s) } else { u16::from_le_bytes(s) })
    }
    fn u32(&mut self) -> Result<u32, String> {
        let s: [u8; 4] = self.take(4)?.try_into().unwrap();
        Ok(if self.big { u32::from_be_bytes(s) } else { u32::from_le_bytes(s) })
    }
    fn counted(&mut self) -> Result<&'a [u8], String> {
        let n = self.u16()? as usize;
        self.take(n)
    }
}

/// Encryption type numbers (RFC 3961 and successors) as klist names them.
fn enctype(n: u16) -> String {
    match n {
        1 => "des-cbc-crc",
        3 => "des-cbc-md5",
        16 => "des3-cbc-sha1",
        17 => "aes128-cts-hmac-sha1-96",
        18 => "aes256-cts-hmac-sha1-96",
        19 => "aes128-cts-hmac-sha256-128",
        20 => "aes256-cts-hmac-sha384-192",
        23 => "arcfour-hmac",
        25 => "camellia128-cts-cmac",
        26 => "camellia256-cts-cmac",
        _ => return format!("enctype-{n}"),
    }
    .to_string()
}

/// `klist -k -t -e`: one entry per key, principal, kvno, enctype and timestamp. The key itself is only measured.
pub fn keytab(b: &[u8]) -> Result<Json, String> {
    if b.len() < 2 || b[0] != 5 || !(b[1] == 1 || b[1] == 2) {
        return Err("not a keytab (no 0x0501/0x0502 header)".into());
    }
    let v1 = b[1] == 1;
    let mut r = Reader { b, at: 2, big: !v1 || cfg!(target_endian = "big") };
    let mut entries = Vec::new();
    while r.at + 4 <= b.len() {
        let size = r.u32()? as i32;
        if size == 0 {
            break;
        }
        if size < 0 {
            r.take(size.unsigned_abs() as usize)?; // a hole left by a deleted entry
            continue;
        }
        let end = r.at + size as usize;
        let mut e = Reader { b: r.take(size as usize)?, at: 0, big: r.big };
        let mut n = e.u16()? as usize;
        if v1 {
            n = n.saturating_sub(1); // version 1 counts the realm as a component
        }
        let realm = String::from_utf8_lossy(e.counted()?).into_owned();
        let comps: Vec<String> = (0..n).map(|_| e.counted().map(|c| String::from_utf8_lossy(c).into_owned())).collect::<Result<_, _>>()?;
        let name_type = if v1 { None } else { Some(e.u32()?) };
        let timestamp = e.u32()? as i64;
        let vno8 = e.u8()? as u32;
        let enc = e.u16()?;
        let key_len = e.counted()?.len();
        let vno = if e.b.len() - e.at >= 4 { Some(e.u32()?).filter(|v| *v != 0).unwrap_or(vno8) } else { vno8 };
        entries.push(json!({
            "principal": format!("{}@{realm}", comps.join("/")), "kvno": vno, "enctype": enctype(enc),
            "timestamp": iso_utc(timestamp), "name_type": name_type, "key_bytes": key_len,
        }));
        debug_assert_eq!(r.at, end);
    }
    Ok(json!({"format": format!("keytab 0x050{}", b[1]), "entries": entries}))
}

// --- certificates ---------------------------------------------------------------------------------------------

fn oid_name(oid: &str) -> Option<&'static str> {
    Some(match oid {
        "1.2.840.113549.1.1.1" => "rsa",
        "1.2.840.10045.2.1" => "ec",
        "1.3.101.112" => "ed25519",
        "1.3.101.113" => "ed448",
        "1.2.840.113549.1.1.5" => "sha1-rsa",
        "1.2.840.113549.1.1.11" => "sha256-rsa",
        "1.2.840.113549.1.1.12" => "sha384-rsa",
        "1.2.840.113549.1.1.13" => "sha512-rsa",
        "1.2.840.113549.1.1.10" => "rsa-pss",
        "1.2.840.10045.4.3.2" => "ecdsa-sha256",
        "1.2.840.10045.4.3.3" => "ecdsa-sha384",
        "1.2.840.10045.4.3.4" => "ecdsa-sha512",
        _ => return None,
    })
}

fn one_certificate(der: &[u8]) -> Result<Json, String> {
    use x509_parser::extensions::GeneralName;
    use x509_parser::public_key::PublicKey;
    let (_, c) = x509_parser::parse_x509_certificate(der).map_err(|e| format!("not a certificate: {e}"))?;
    let sans: Vec<String> = match c.subject_alternative_name() {
        Ok(Some(ext)) => ext
            .value
            .general_names
            .iter()
            .map(|g| match g {
                GeneralName::DNSName(s) => format!("DNS:{s}"),
                GeneralName::RFC822Name(s) => format!("email:{s}"),
                GeneralName::URI(s) => format!("URI:{s}"),
                GeneralName::IPAddress(b) if b.len() == 4 => format!("IP:{}.{}.{}.{}", b[0], b[1], b[2], b[3]),
                GeneralName::IPAddress(b) if b.len() == 16 => {
                    let a: [u8; 16] = (*b).try_into().unwrap();
                    format!("IP:{}", std::net::Ipv6Addr::from(a))
                }
                other => format!("{other:?}"),
            })
            .collect(),
        _ => Vec::new(),
    };
    let spki = c.public_key();
    let key_oid = spki.algorithm.algorithm.to_id_string();
    let key_bits = match spki.parsed() {
        Ok(PublicKey::RSA(k)) => Some(k.key_size()),
        Ok(PublicKey::EC(k)) => Some(k.key_size()),
        _ => None,
    };
    let sig_oid = c.signature_algorithm.algorithm.to_id_string();
    let v = c.validity();
    Ok(json!({
        "subject": c.subject().to_string(), "issuer": c.issuer().to_string(),
        "serial": c.raw_serial_as_string(), "not_before": iso_utc(v.not_before.timestamp()),
        "not_after": iso_utc(v.not_after.timestamp()), "sans": sans, "is_ca": c.is_ca(),
        "self_signed": c.subject() == c.issuer(),
        "key": oid_name(&key_oid).unwrap_or(&key_oid), "key_bits": key_bits,
        "signature": oid_name(&sig_oid).unwrap_or(&sig_oid),
        "fingerprint_sha256": sha256_hex(der), "public_key_sha256": sha256_hex(spki.raw),
    }))
}

/// Every certificate in a PEM file (a chain, in order) or a DER one. Other PEM blocks are named, not shown.
pub fn certificate(b: &[u8]) -> Result<Json, String> {
    if !b.windows(11).any(|w| w == b"-----BEGIN ") {
        return Ok(json!({"format": "der", "certificates": [one_certificate(b)?], "other_blocks": []}));
    }
    let (mut certs, mut other) = (Vec::new(), Vec::new());
    for pem in x509_parser::pem::Pem::iter_from_buffer(b) {
        let pem = pem.map_err(|e| format!("bad PEM block: {e}"))?;
        if pem.label == "CERTIFICATE" || pem.label == "TRUSTED CERTIFICATE" {
            certs.push(one_certificate(&pem.contents)?);
        } else {
            other.push(pem.label.clone());
        }
    }
    if certs.is_empty() {
        return Err(format!("no certificate in the file (PEM blocks: {other:?})"));
    }
    Ok(json!({"format": "pem", "certificates": certs, "other_blocks": other}))
}

// --- private keys ---------------------------------------------------------------------------------------------

const OIDS: [(&[u8], &str); 8] = [
    (&[0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01], "rsa"),
    (&[0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01], "ec"),
    (&[0x06, 0x03, 0x2b, 0x65, 0x70], "ed25519"),
    (&[0x06, 0x03, 0x2b, 0x65, 0x71], "ed448"),
    (&[0x06, 0x03, 0x2b, 0x65, 0x6e], "x25519"),
    (&[0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07], "p256"),
    (&[0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22], "p384"),
    (&[0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x23], "p521"),
];

/// Algorithm and curve OIDs near the start of a DER key: enough to name it without parsing the key.
fn der_algorithms(der: &[u8]) -> Vec<&'static str> {
    let head = &der[..der.len().min(48)];
    OIDS.iter().filter(|(o, _)| head.windows(o.len()).any(|w| w == *o)).map(|(_, n)| *n).collect()
}

fn ssh_string<'a>(b: &'a [u8], at: &mut usize) -> Option<&'a [u8]> {
    let n = u32::from_be_bytes(b.get(*at..*at + 4)?.try_into().ok()?) as usize;
    let s = b.get(*at + 4..*at + 4 + n)?;
    *at += 4 + n;
    Some(s)
}

/// An OpenSSH key: cipher (none = no passphrase) and the public key, which is stored unencrypted.
fn openssh(der: &[u8]) -> Result<Json, String> {
    use base64::Engine;
    let magic = b"openssh-key-v1\0";
    let rest = der.strip_prefix(magic).ok_or("not an OpenSSH key")?;
    let mut at = 0;
    let bad = || "truncated OpenSSH key".to_string();
    let cipher = String::from_utf8_lossy(ssh_string(rest, &mut at).ok_or_else(bad)?).into_owned();
    let kdf = String::from_utf8_lossy(ssh_string(rest, &mut at).ok_or_else(bad)?).into_owned();
    ssh_string(rest, &mut at).ok_or_else(bad)?; // kdf options
    let n = u32::from_be_bytes(rest.get(at..at + 4).ok_or_else(bad)?.try_into().unwrap());
    at += 4;
    let public = ssh_string(rest, &mut at).ok_or_else(bad)?;
    let mut p = 0;
    let key_type = String::from_utf8_lossy(ssh_string(public, &mut p).unwrap_or_default()).into_owned();
    let fp = base64::engine::general_purpose::STANDARD_NO_PAD.encode(Sha256::digest(public));
    Ok(json!({"format": "openssh", "label": "OPENSSH PRIVATE KEY", "algorithm": key_type, "encrypted": cipher != "none",
              "der_bytes": der.len(), "cipher": cipher, "kdf": kdf, "keys": n,
              "public_fingerprint": format!("SHA256:{fp}")}))
}

/// What a private key is: format, algorithm (and curve), whether a passphrase protects it, its size. For OpenSSH
/// keys also the public key's fingerprint, as `ssh-keygen -l` shows it.
pub fn private_key(b: &[u8]) -> Result<Json, String> {
    use base64::Engine;
    let text = String::from_utf8_lossy(b);
    let begin = text.find("-----BEGIN ").ok_or("not a PEM private key")?;
    let label_end = text[begin + 11..].find("-----").ok_or("bad PEM header")? + begin + 11;
    let label = text[begin + 11..label_end].to_string();
    if !label.ends_with("PRIVATE KEY") {
        return Err(format!("not a private key (PEM block {label})"));
    }
    let end_marker = format!("-----END {label}-----");
    let body_end = text[label_end..].find(&end_marker).ok_or("PEM block not closed")? + label_end;
    let body = &text[label_end + 5..body_end];
    let legacy_encrypted = body.contains("Proc-Type: 4,ENCRYPTED");
    let b64: String = body.lines().filter(|l| !l.contains(':')).flat_map(|l| l.trim().chars()).collect();
    let der = base64::engine::general_purpose::STANDARD.decode(b64.as_bytes()).map_err(|e| format!("bad base64: {e}"))?;
    if label == "OPENSSH PRIVATE KEY" {
        return openssh(&der);
    }
    let (format, algorithm, encrypted) = match label.as_str() {
        "PRIVATE KEY" => ("pkcs8", der_algorithms(&der).join("/"), false),
        "ENCRYPTED PRIVATE KEY" => ("pkcs8", String::new(), true),
        "RSA PRIVATE KEY" => ("pkcs1", "rsa".to_string(), legacy_encrypted),
        "EC PRIVATE KEY" => ("sec1", ["ec"].into_iter().chain(der_algorithms(&der)).collect::<Vec<_>>().join("/"), legacy_encrypted),
        "DSA PRIVATE KEY" => ("openssl", "dsa".to_string(), legacy_encrypted),
        _ => ("pem", String::new(), legacy_encrypted),
    };
    Ok(json!({"format": format, "label": label, "algorithm": algorithm, "encrypted": encrypted, "der_bytes": der.len()}))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn counted(b: &[u8]) -> Vec<u8> {
        let mut v = (b.len() as u16).to_be_bytes().to_vec();
        v.extend_from_slice(b);
        v
    }

    fn keytab_bytes(key: &[u8]) -> Vec<u8> {
        let mut e = 2u16.to_be_bytes().to_vec();
        e.extend(counted(b"LAB.INTERNAL"));
        e.extend(counted(b"HTTP"));
        e.extend(counted(b"api-1.lab.internal"));
        e.extend(1u32.to_be_bytes());
        e.extend(1_760_000_000u32.to_be_bytes());
        e.push(3);
        e.extend(18u16.to_be_bytes());
        e.extend(counted(key));
        e.extend(3u32.to_be_bytes());
        let mut b = vec![5, 2];
        b.extend((e.len() as i32).to_be_bytes());
        b.extend(e);
        b
    }

    #[test]
    fn keytab_lists_principals_not_keys() {
        let key = [0xabu8; 32];
        let out = keytab(&keytab_bytes(&key)).unwrap();
        let e = &out["entries"][0];
        assert_eq!(e["principal"], "HTTP/api-1.lab.internal@LAB.INTERNAL");
        assert_eq!(e["kvno"], 3);
        assert_eq!(e["enctype"], "aes256-cts-hmac-sha1-96");
        assert_eq!(e["key_bytes"], 32);
        assert!(!out.to_string().contains("abab"), "{out}");
        assert_eq!(detect(&keytab_bytes(&key)), Some("keytab"));
        assert!(keytab(b"hello").is_err());
    }

    #[test]
    fn pkcs8_and_openssh_keys_are_named() {
        use base64::Engine;
        let e = base64::engine::general_purpose::STANDARD;
        let mut der = vec![0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20];
        der.extend([7u8; 32]);
        let pem = format!("-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----\n", e.encode(&der));
        let out = private_key(pem.as_bytes()).unwrap();
        assert_eq!(out["algorithm"], "ed25519");
        assert_eq!(out["encrypted"], false);
        assert_eq!(detect(pem.as_bytes()), Some("private_key"));

        let mut pubkey = Vec::new();
        for s in [&b"ssh-ed25519"[..], &[9u8; 32][..]] {
            pubkey.extend((s.len() as u32).to_be_bytes());
            pubkey.extend_from_slice(s);
        }
        let mut blob = b"openssh-key-v1\0".to_vec();
        for s in [&b"none"[..], b"none", b""] {
            blob.extend((s.len() as u32).to_be_bytes());
            blob.extend_from_slice(s);
        }
        blob.extend(1u32.to_be_bytes());
        blob.extend((pubkey.len() as u32).to_be_bytes());
        blob.extend(&pubkey);
        let pem = format!("-----BEGIN OPENSSH PRIVATE KEY-----\n{}\n-----END OPENSSH PRIVATE KEY-----\n", e.encode(&blob));
        let out = private_key(pem.as_bytes()).unwrap();
        assert_eq!(out["algorithm"], "ssh-ed25519");
        assert_eq!(out["encrypted"], false);
        assert!(out["public_fingerprint"].as_str().unwrap().starts_with("SHA256:"));
        for f in ["format", "label", "algorithm", "encrypted", "der_bytes"] {
            assert!(out.get(f).is_some(), "the guide promises .{f} for every key");
        }
    }

    #[test]
    fn certificate_metadata() {
        let pem = std::fs::read(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/root/etc/ssl/certs/orders.pem")).unwrap();
        let out = certificate(&pem).unwrap();
        let c = &out["certificates"][0];
        assert_eq!(c["subject"], "CN=orders.lab.internal");
        assert!(c["sans"].as_array().unwrap().iter().any(|s| s == "DNS:orders.lab.internal"), "{c}");
        assert_eq!(c["key"], "ec");
        assert_eq!(c["self_signed"], true);
        assert_eq!(detect(&pem), Some("certificate"));
        assert!(certificate(b"plain text").is_err());
    }
}
