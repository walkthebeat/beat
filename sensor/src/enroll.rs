//! `beat-sensor enroll`: asks the beat service to admit this sensor, and waits until a member of the org approves
//! (docs/security.md H14; the service's side is beat_service/enroll.py); with a rollout token (H5,
//! `--token-file`), the service enrols it at once or says why not.
//!
//! The request is this sensor's name, public key, host name and the time, as JSON, signed with its key (kind
//! "enroll", seal.rs `signed_bytes`): POST {request, signature} to <api>/v1/enroll. The service answers with a
//! code until someone runs `beat sensors approve <code>` on a signed-in machine, and then "enrolled". Asking again
//! (every few seconds here, or by running this again) keeps the same code while it lasts. No secret is sent or
//! kept: what proves the host is the member comparing its name and the key's fingerprint with what this printed.
//! A token goes inside the signed request (bound to this key), and is not kept either. So does an identity the
//! host's platform gave it (`--attest oidc:FILE`, H4: a Kubernetes projected service-account token; `--attest aws`:
//! one the sensor asks AWS STS for, aws.rs): one of the org's trust policies accepts it and the service names the sensor from it
//! (docs/security.md H13); the service's name is the one the sensor runs under.

use std::path::Path;
use std::time::{Duration, Instant};

use anyhow::{bail, Context};
use base64::{engine::general_purpose::STANDARD, Engine};
use ed25519_dalek::Signer;
use serde_json::{json, Value};

use crate::seal;

pub const DEFAULT_KEY: &str = "/var/lib/beat-sensor/keys/sensor.key";
const ENV_FILE: &str = "/etc/beat-sensor.env";
const GIVE_UP: Duration = Duration::from_secs(3600);

/// The signed request for `name` (seal.py `signed_bytes` over the request's own bytes).
pub fn request(key: &ed25519_dalek::SigningKey, name: &str, host: &str, iat: i64, version: &str,
               proof: &Proof) -> Value {
    let mut req = json!({"name": name, "host": host, "iat": iat, "version": version,
                         "key": STANDARD.encode(key.verifying_key().to_bytes())});
    match proof {
        Proof::Token(t) => req["token"] = Value::String(t.clone()),
        Proof::Oidc(jwt) => req["attest"] = json!({"kind": "oidc", "token": jwt}),
        Proof::Approval => {}
    }
    let req = req.to_string();
    let sig = key.sign(&seal::signed_bytes("enroll", &seal::Headers::new(), req.as_bytes()));
    json!({"request": req, "signature": STANDARD.encode(sig.to_bytes())})
}

/// A setting from the sensor's configuration (/etc/beat-sensor.env: BEAT_SENSOR_NAME, BEAT_API), when there is one.
pub fn configured(var: &str) -> Option<String> {
    let text = std::fs::read_to_string(ENV_FILE).ok()?;
    let prefix = format!("{var}=");
    text.lines().find_map(|l| l.strip_prefix(prefix.as_str())).map(|v| v.trim().to_string()).filter(|v| !v.is_empty())
}

pub fn host_name() -> anyhow::Result<String> {
    Ok(std::fs::read_to_string("/proc/sys/kernel/hostname").context("host name")?.trim().to_string())
}

pub fn post(api: &str, path: &str, body: &Value) -> anyhow::Result<Value> {
    let url = format!("{}{path}", api.trim_end_matches('/'));
    match ureq::post(&url).timeout(Duration::from_secs(15)).send_json(body.clone()) {
        Ok(r) => Ok(r.into_json()?),
        Err(ureq::Error::Status(code, r)) => {
            let v: Value = r.into_json().unwrap_or_default();
            bail!("the service refused ({code}): {}", v["error"].as_str().unwrap_or("no reason given"))
        }
        Err(e) => bail!("{url} is not answering: {e}"),
    }
}

/// What proves the sensor may join: nothing (a member approves its code), a rollout token, or an identity token.
pub enum Proof {
    Approval,
    Token(String),
    Oidc(String),
}

/// The proof from `--token`, `--token-file` (a root-only file that configuration management placed) or `--attest`:
/// `oidc:FILE` (the file the platform keeps the identity token in) or `aws[:AUDIENCE]` (fetched from STS now,
/// aws.rs); read once, here.
pub fn proof(given: Option<String>, file: Option<String>, attest: Option<String>) -> anyhow::Result<Proof> {
    let read = |f: &str| -> anyhow::Result<String> {
        Ok(std::fs::read_to_string(f).with_context(|| f.to_string())?.trim().to_string())
    };
    match (given, file, attest) {
        (None, None, None) => Ok(Proof::Approval),
        (Some(t), None, None) => Ok(Proof::Token(t.trim().to_string())),
        (None, Some(f), None) => Ok(Proof::Token(read(&f)?)),
        (None, None, Some(a)) => match a.split_once(':') {
            Some(("oidc", f)) if !f.is_empty() => Ok(Proof::Oidc(read(f)?)),
            Some(("aws", aud)) if !aud.is_empty() => Ok(Proof::Oidc(crate::aws::identity_token(aud)?)),
            None if a == "aws" => Ok(Proof::Oidc(crate::aws::identity_token("beat-enroll")?)),
            _ => bail!("--attest {a}: oidc:FILE (the identity token's file) or aws[:AUDIENCE] (x509 later)"),
        },
        _ => bail!("one proof: --token, --token-file or --attest"),
    }
}

pub fn run(argv: &[String], version: &str) -> anyhow::Result<()> {
    let (mut api, mut name, mut key) = (std::env::var("BEAT_API").ok(), None, DEFAULT_KEY.to_string());
    let (mut tok, mut tok_file, mut attest) = (None, None, None);
    let mut it = argv.iter();
    while let Some(x) = it.next() {
        let mut val = || it.next().cloned().with_context(|| format!("{x} needs a value"));
        match x.as_str() {
            "--api" => api = Some(val()?),
            "--name" => name = Some(val()?),
            "--key" => key = val()?,
            "--token" => tok = Some(val()?),
            "--token-file" => tok_file = Some(val()?),
            "--attest" => attest = Some(val()?),
            other => bail!("unknown argument {other}\nusage: beat-sensor enroll --api URL [--name NAME] [--key FILE] \
                            [--token-file FILE | --token TOKEN | --attest oidc:FILE|aws]"),
        }
    }
    let api = api.or_else(|| configured("BEAT_API"))
        .context("--api URL (or BEAT_API): the beat service, e.g. https://api.walkthebeat.ai")?;
    let name = match name.or_else(|| configured("BEAT_SENSOR_NAME")) {
        Some(n) => n,
        None => host_name()?,
    };
    let enrolled = wait(&api, &name, Path::new(&key), version, &proof(tok, tok_file, attest)?)?;
    // the running sensor's own key only: a key given with --key is some other sensor's (a test's), not this one's
    if enrolled != name && key == DEFAULT_KEY && configured("BEAT_SENSOR_NAME").is_some() {
        rename(&enrolled)?;
    }
    Ok(())
}

/// The service named this sensor otherwise (attestation): BEAT_SENSOR_NAME in /etc/beat-sensor.env becomes that
/// name, and the sensor restarts on it.
pub fn rename(name: &str) -> anyhow::Result<()> {
    let text = std::fs::read_to_string(ENV_FILE)?;
    let text: String = text.lines()
        .map(|l| if l.starts_with("BEAT_SENSOR_NAME=") { format!("BEAT_SENSOR_NAME={name}\n") } else { format!("{l}\n") })
        .collect();
    let tmp = format!("{ENV_FILE}.new");
    std::fs::write(&tmp, text)?;
    std::fs::rename(&tmp, ENV_FILE)?;
    let ok = std::process::Command::new("systemctl").args(["restart", "beat-sensor"]).status().map(|s| s.success());
    println!("  runs as {name} from now on (BEAT_SENSOR_NAME){}",
             if ok.unwrap_or(false) { "; beat-sensor restarted" } else { "; restart beat-sensor" });
    Ok(())
}

/// Asks until the service says enrolled (a member approved the code, the token was good, a policy accepted the
/// identity), printing the code once; returns the name it is enrolled under.
pub fn wait(api: &str, name: &str, path: &Path, version: &str, proof: &Proof) -> anyhow::Result<String> {
    let host = host_name()?;
    let key = path.display().to_string();
    seal::keygen(path).with_context(|| format!("the sensor's key {key} (run as root)"))?;
    let key = seal::read_signing(path)?;
    let fingerprint = seal::fingerprint(&key.verifying_key());

    println!("Enrolling sensor {name:?} (host {host}) with the beat service at {api}");
    println!("  key fingerprint {fingerprint}");
    let started = Instant::now();
    let mut shown = false;
    loop {
        let r = post(api, "/v1/enroll", &request(&key, name, &host, crate::unix_now(), version, proof))?;
        let enrolled = r["name"].as_str().unwrap_or(name).to_string();
        match r["state"].as_str() {
            Some("enrolled") if r["policy"].is_string() => {
                println!("Enrolled by trust policy {}: {enrolled} is enrolled. The service accepts its answers from \
                          now on.", r["policy"].as_str().unwrap_or("?"));
                return Ok(enrolled);
            }
            Some("enrolled") if r["token"].is_string() => {
                println!("Enrolled with rollout token {}: {name} is enrolled. The service accepts its answers from now \
                          on.", r["token"].as_str().unwrap_or("?"));
                return Ok(enrolled);
            }
            Some("enrolled") => {
                println!("Approved: {name} is enrolled. The service accepts its answers from now on.");
                return Ok(enrolled);
            }
            Some("pending") if !shown => {
                let code = r["code"].as_str().unwrap_or("?");
                println!();
                println!("On a machine signed in to the service, run");
                println!("    beat sensors approve {code}");
                println!("and check that it shows host {host} and key {fingerprint}.");
                println!();
                println!("Waiting for approval (the code lasts {} min; Ctrl-C stops, running this again resumes)...",
                         r["expires_in"].as_u64().unwrap_or(0) / 60);
                shown = true;
            }
            Some("pending") => {}
            _ => bail!("unexpected reply from the service: {r}"),
        }
        if started.elapsed() > GIVE_UP {
            bail!("not approved within {} min: run beat-sensor enroll again", GIVE_UP.as_secs() / 60);
        }
        std::thread::sleep(Duration::from_secs(r["interval"].as_u64().unwrap_or(5).clamp(2, 60)));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::Verifier;

    #[test]
    fn the_request_is_signed_over_its_own_bytes() {
        let key = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
        let r = request(&key, "api-1", "ip-10-0-0-1", 1_800_000_000, "beat-sensor/0.1.0", &Proof::Token("brt.a.b".into()));
        let req = r["request"].as_str().unwrap();
        let sig: [u8; 64] = STANDARD.decode(r["signature"].as_str().unwrap()).unwrap().try_into().unwrap();
        let signed = seal::signed_bytes("enroll", &seal::Headers::new(), req.as_bytes());
        key.verifying_key().verify(&signed, &ed25519_dalek::Signature::from_bytes(&sig)).unwrap();
        let fields: Value = serde_json::from_str(req).unwrap();
        assert_eq!(fields["name"], "api-1");
        assert_eq!(fields["token"], "brt.a.b");
        assert_eq!(fields["key"], STANDARD.encode(key.verifying_key().to_bytes()));
    }
}
