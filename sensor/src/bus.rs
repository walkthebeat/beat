//! The sensor's login to the bus (docs/security.md, "The bus"; docs/protocol.md, "Logins"). NATS runs in operator
//! mode: a client connects with a user JWT and signs the server's nonce with the key the JWT names. The sensor's JWT
//! names its own signing key, the one it enrolled; the service mints it for a request signed with that key
//! (POST <api>/v1/bus-credential, kind "bus") and it allows the sensor's own subjects only, for an hour. The sensor
//! renews it at half life; async-nats asks for it (the auth callback) on every connection, and the server drops a
//! connection whose JWT expired, so the client reconnects with the newest at once. A removed sensor gets no new one.
//!
//! The nonce is signed with the key that signs answers and heartbeats, and the server chooses it. Every beat signature
//! covers canonical JSON (`{"v":1,"kind":...`, seal.rs `signed_bytes`), so the sensor signs a nonce only if it looks
//! like what nats-server sends (8-64 of `[A-Za-z0-9_-]`): no byte string can be both, and a bus cannot get a beat
//! message signed by passing it off as a nonce.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::Context;
use base64::{engine::general_purpose::STANDARD, Engine};
use ed25519_dalek::{Signer, SigningKey};
use serde_json::{json, Value};

use crate::{enroll, seal};

/// The current login: its JWT and when it expires (unix seconds).
#[derive(Clone, Default)]
pub struct Login {
    pub jwt: String,
    pub expires: i64,
}

pub type Slot = Arc<Mutex<Login>>;

/// The signed request for a login: name, key and time, signed over its own bytes (kind "bus").
pub fn request(key: &SigningKey, name: &str, iat: i64) -> Value {
    let req = json!({"name": name, "iat": iat, "key": STANDARD.encode(key.verifying_key().to_bytes())}).to_string();
    let sig = key.sign(&seal::signed_bytes("bus", &seal::Headers::new(), req.as_bytes()));
    json!({"request": req, "signature": STANDARD.encode(sig.to_bytes())})
}

/// A login from the service (blocking HTTP).
pub fn fetch(api: &str, key: &SigningKey, name: &str, now: i64) -> anyhow::Result<Login> {
    let v = enroll::post(api, "/v1/bus-credential", &request(key, name, now))?;
    Ok(Login {
        jwt: v["jwt"].as_str().context("the service's answer has no jwt")?.to_string(),
        expires: v["expires"].as_i64().context("the service's answer has no expiry")?,
    })
}

/// What nats-server sends as a nonce, and never the start of a beat message (module comment).
pub fn nonce_ok(nonce: &[u8]) -> bool {
    (8..=64).contains(&nonce.len()) && nonce.iter().all(|b| b.is_ascii_alphanumeric() || *b == b'-' || *b == b'_')
}

/// The auth callback's answer: the current JWT and the nonce signed, or a refusal.
pub fn auth(key: &SigningKey, slot: &Slot, nonce: &[u8]) -> Result<async_nats::Auth, async_nats::AuthError> {
    if !nonce_ok(nonce) {
        return Err(async_nats::AuthError::new(format!("refusing to sign a nonce of {} bytes that is not one", nonce.len())));
    }
    let mut a = async_nats::Auth::new();
    a.jwt = Some(slot.lock().unwrap().jwt.clone());
    a.signature = Some(key.sign(nonce).to_bytes().to_vec());
    Ok(a)
}

/// A first login, asking again until the service gives one (it may be starting, or the sensor not enrolled yet).
pub async fn first(api: String, key: SigningKey, name: String) -> Login {
    let mut wait = Duration::from_secs(5);
    loop {
        let (a, k, n) = (api.clone(), key.clone(), name.clone());
        match tokio::task::spawn_blocking(move || fetch(&a, &k, &n, crate::unix_now())).await {
            Ok(Ok(l)) => return l,
            Ok(Err(e)) => eprintln!("bus login: {e:#}; asking again in {} s", wait.as_secs()),
            Err(e) => eprintln!("bus login: {e}"),
        }
        tokio::time::sleep(wait).await;
        wait = (wait * 2).min(Duration::from_secs(60));
    }
}

/// Renews the login at half its life; on failure, every minute until it works.
pub async fn keep(api: String, key: SigningKey, name: String, slot: Slot) {
    loop {
        let left = slot.lock().unwrap().expires - crate::unix_now();
        tokio::time::sleep(Duration::from_secs((left / 2).max(60) as u64)).await;
        let (a, k, n) = (api.clone(), key.clone(), name.clone());
        match tokio::task::spawn_blocking(move || fetch(&a, &k, &n, crate::unix_now())).await {
            Ok(Ok(l)) => *slot.lock().unwrap() = l,
            Ok(Err(e)) => eprintln!("bus login renewal: {e:#}"),
            Err(e) => eprintln!("bus login renewal: {e}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_nonce_shaped_input_is_signed() {
        assert!(nonce_ok(b"pRzFj1Hc6r7Lrnw"));  // what nats-server sends: 11 random bytes, base64url
        assert!(!nonce_ok(b"short"));
        assert!(!nonce_ok(&[b'a'; 65]));
        assert!(!nonce_ok(br#"{"v":1,"kind":"heartbeat"}"#));  // a beat message can never pass
        assert!(!nonce_ok(b"abcdefgh\n"));
        let key = SigningKey::from_bytes(&[7; 32]);
        let slot: Slot = Arc::new(Mutex::new(Login { jwt: "j".into(), expires: 0 }));
        assert!(auth(&key, &slot, br#"{"v":1,"kind":"answer","headers":{}}"#).is_err());
        let a = auth(&key, &slot, b"pRzFj1Hc6r7Lrnw").unwrap();
        assert_eq!(a.jwt.as_deref(), Some("j"));
        assert_eq!(a.signature.unwrap(), key.sign(b"pRzFj1Hc6r7Lrnw").to_bytes().to_vec());
    }

    #[test]
    fn the_request_is_signed_over_its_own_bytes() {
        let key = SigningKey::from_bytes(&[9; 32]);
        let r = request(&key, "api-1", 1_760_000_000);
        let req = r["request"].as_str().unwrap();
        let sig = ed25519_dalek::Signature::from_slice(&STANDARD.decode(r["signature"].as_str().unwrap()).unwrap()).unwrap();
        key.verifying_key().verify_strict(&seal::signed_bytes("bus", &seal::Headers::new(), req.as_bytes()), &sig).unwrap();
        // not an enrolment request's signature: the kind is covered
        assert!(key.verifying_key()
            .verify_strict(&seal::signed_bytes("enroll", &seal::Headers::new(), req.as_bytes()), &sig).is_err());
    }
}
