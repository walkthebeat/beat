//! `beat-sensor configure`: points an installed sensor at a beat service and at the org it obeys, then enrols it
//! (docs/security.md H9, H14, H15, H16).
//!
//!   sudo beat-sensor configure --api URL --org-root NAME=KEY... [--name NAME] [--bus URL]
//!                              [--token-file FILE | --token TOKEN | --attest oidc:FILE|aws | --no-enroll]
//!
//! Two sources, on purpose. From the operator, on the command line: the org's root, pinned here, whose members'
//! questions this sensor runs (`beat sensors add` prints the line with it; more than one while a root rotates). From
//! the service (GET /v1/sensor-config): the bus to connect to and the collector's public keys, which must countersign
//! every question. The service never supplies a root: whoever runs it could then command the sensor (H15, H16).
//!
//! Writes /etc/beat-sensor.env (BEAT_NATS, BEAT_SENSOR_NAME, BEAT_API), /etc/beat-sensor/roots/ and
//! /etc/beat-sensor/collectors/ (each replaced whole, by one rename), makes the sensor's key if missing, restarts
//! the sensor, and then enrols it as `beat-sensor enroll` does (enroll.rs): with a rollout token at once, else by
//! approval. With `--attest`, it enrols first, since the service names the sensor (a trust policy, H13), and then
//! writes that name and starts it. Run again to change anything; a sensor already enrolled with this key goes
//! straight through.

use std::path::Path;
use std::time::Duration;

use anyhow::{bail, Context};
use base64::{engine::general_purpose::STANDARD, Engine};
use serde_json::Value;

use crate::enroll;

const ENV_FILE: &str = "/etc/beat-sensor.env";
const CONF_DIR: &str = "/etc/beat-sensor";
const USAGE: &str = "usage: beat-sensor configure --api URL --org-root NAME=KEY... [--name NAME] [--bus URL] \
                     [--token-file FILE | --token TOKEN | --attest oidc:FILE|aws | --no-enroll]";

/// NAME=KEY: a key name the sensor's heartbeats can carry, and a 32-byte Ed25519 public key in base64.
pub fn parse_key(arg: &str) -> anyhow::Result<(String, String)> {
    let (name, key) = arg.split_once('=').with_context(|| format!("{arg}: expected NAME=KEY"))?;
    if name.is_empty() || !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_') {
        bail!("key name {name:?}: letters, digits, - and _ only");
    }
    match STANDARD.decode(key.trim()) {
        Ok(raw) if raw.len() == 32 => Ok((name.to_string(), key.trim().to_string())),
        _ => bail!("{name}: not an Ed25519 public key (32 bytes, base64)"),
    }
}

fn sensor_config(api: &str) -> anyhow::Result<Value> {
    let url = format!("{}/v1/sensor-config", api.trim_end_matches('/'));
    match ureq::get(&url).timeout(Duration::from_secs(15)).call() {
        Ok(r) => Ok(r.into_json()?),
        Err(ureq::Error::Status(code, _)) => bail!("{url}: {code} (is this a beat service?)"),
        Err(e) => bail!("{url} is not answering: {e}"),
    }
}

/// Makes `dir` hold exactly these keys, one `<name>.pub` each, replacing it in one rename.
fn put_keys(dir: &Path, keys: &[(String, String)]) -> anyhow::Result<()> {
    let new = dir.with_extension("new");
    let old = dir.with_extension("old");
    let _ = std::fs::remove_dir_all(&new);
    std::fs::create_dir_all(&new)?;
    for (name, key) in keys {
        std::fs::write(new.join(format!("{name}.pub")), format!("{key}\n"))?;
    }
    let _ = std::fs::remove_dir_all(&old);
    if dir.exists() {
        std::fs::rename(dir, &old)?;
    }
    std::fs::rename(&new, dir)?;
    let _ = std::fs::remove_dir_all(&old);
    Ok(())
}

pub fn run(argv: &[String], version: &str) -> anyhow::Result<()> {
    let (mut api, mut name, mut bus, mut enrol) = (std::env::var("BEAT_API").ok(), None, None, true);
    let (mut org, mut tok, mut tok_file, mut attest) = (Vec::new(), None, None, None);
    let mut it = argv.iter();
    while let Some(x) = it.next() {
        let mut val = || it.next().cloned().with_context(|| format!("{x} needs a value"));
        match x.as_str() {
            "--api" => api = Some(val()?),
            "--org-root" => org.push(parse_key(&val()?)?),
            "--name" => name = Some(val()?),
            "--bus" => bus = Some(val()?),
            "--no-enroll" => enrol = false,
            "--token" => tok = Some(val()?),
            "--token-file" => tok_file = Some(val()?),
            "--attest" => attest = Some(val()?),
            other => bail!("unknown argument {other}\n{USAGE}"),
        }
    }
    let api = api.with_context(|| format!("--api URL: the beat service\n{USAGE}"))?;
    if org.is_empty() {
        bail!("--org-root NAME=KEY: the org root's public key, whose members' questions this sensor runs (on a \
               machine signed in to the service, `beat sensors add` prints this command with it)\n{USAGE}");
    }
    let proof = enroll::proof(tok, tok_file, attest)?;  // read before anything changes: a missing file stops here
    let mut name = match name {
        Some(n) => n,
        None => enroll::host_name()?,
    };
    let named_by_service = matches!(proof, enroll::Proof::Oidc(_));  // a trust policy names it
    if !named_by_service && (name.is_empty() || name.contains(['.', ' ', '*', '>']) || name.contains('\n')) {
        bail!("sensor name {name:?} cannot be a NATS subject token: give --name");
    }

    let cfg = sensor_config(&api)?;
    let bus = match bus.or_else(|| cfg["bus"].as_str().map(String::from)) {
        Some(b) => b,
        None => bail!("the service names no bus (BEAT_BUS at the service): give --bus nats://HOST:4222"),
    };
    let collectors: Vec<(String, String)> = cfg["collector_keys"].as_object().into_iter().flatten()
        .map(|(n, k)| parse_key(&format!("{n}={}", k.as_str().unwrap_or(""))))
        .collect::<anyhow::Result<_>>().context("the service's collector keys")?;
    if collectors.is_empty() {
        bail!("the service has no collector key to give (beat-service keys)");
    }

    std::fs::create_dir_all(CONF_DIR).context("/etc/beat-sensor (run as root)")?;
    let key = Path::new(enroll::DEFAULT_KEY);
    use std::os::unix::fs::DirBuilderExt;
    std::fs::DirBuilder::new().recursive(true).mode(0o700).create(key.parent().unwrap())?;  // hidden from questions
    crate::seal::keygen(key)?;
    if named_by_service && enrol {
        name = enroll::wait(&api, &name, key, version, &proof)?;
        println!();
    }
    put_keys(&Path::new(CONF_DIR).join("roots"), &org)?;
    let _ = std::fs::remove_dir_all(Path::new(CONF_DIR).join("org"));  // before roots (H16): signing keys, not roots
    put_keys(&Path::new(CONF_DIR).join("collectors"), &collectors)?;
    let env = format!("BEAT_NATS={bus}\nBEAT_SENSOR_NAME={name}\nBEAT_API={api}\n");
    let tmp = format!("{ENV_FILE}.new");
    std::fs::write(&tmp, env)?;
    std::fs::rename(&tmp, ENV_FILE)?;
    let names = |ks: &[(String, String)]| ks.iter().map(|(n, _)| n.as_str()).collect::<Vec<_>>().join(" ");
    println!("Configured sensor {name:?}: bus {bus}, service {api}");
    println!("  pins org root(s) {}; countersigned by collector key(s) {}", names(&org), names(&collectors));

    let restarted = std::process::Command::new("systemctl").args(["restart", "beat-sensor"]).status();
    match restarted {
        Ok(s) if s.success() => println!("  beat-sensor restarted"),
        _ => println!("  beat-sensor not restarted (no systemd unit? install it first): it reads this when it starts"),
    }
    if !enrol {
        println!("Next: beat-sensor enroll (the service accepts its answers once a member approves it)");
        return Ok(());
    }
    if named_by_service {
        return Ok(());
    }
    println!();
    enroll::wait(&api, &name, key, version, &proof).map(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keys_are_checked() {
        let k = STANDARD.encode([1u8; 32]);
        assert_eq!(parse_key(&format!("org-1={k}")).unwrap(), ("org-1".into(), k.clone()));
        assert!(parse_key(&format!("a.b={k}")).is_err());
        assert!(parse_key("org-1=AAAA").is_err());
        assert!(parse_key(&k).is_err());
    }

    #[test]
    fn put_keys_replaces_the_directory() {
        let d = std::env::temp_dir().join(format!("beat-configure-{}", std::process::id()));
        let dir = d.join("org");
        put_keys(&dir, &[("a".into(), "A".into()), ("b".into(), "B".into())]).unwrap();
        put_keys(&dir, &[("c".into(), "C".into())]).unwrap();
        let mut names: Vec<_> = std::fs::read_dir(&dir).unwrap().map(|e| e.unwrap().file_name()).collect();
        names.sort();
        assert_eq!(names, ["c.pub"]);
        std::fs::remove_dir_all(&d).unwrap();
    }
}
