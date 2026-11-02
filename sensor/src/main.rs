//! beat-sensor: answers questions published on NATS (docs/protocol.md; the protocol is in wire.rs).
//!
//!   beat-sensor --nats URL --probe PATH --tools DIR --cache DIR --key FILE --roots DIR --collector-keys DIR
//!               [--name NAME] [--deny FILE]
//!               [--label k=v]... [--osqueryi PATH] [--journalctl PATH] [--bpf-tools DIR] [--placeholders DIR | --no-sandbox]
//!               [--concurrency N] [--unit-property P]... [--systemd DIR]
//!   beat-sensor keygen FILE     creates the sensor's signing key when missing; prints its public key (to enroll)
//!   beat-sensor enroll --api URL [--name NAME] [--key FILE]
//!                               asks the service to admit this sensor; waits for a member's approval (enroll.rs)
//!   beat-sensor configure --api URL --org-root NAME=KEY... [--name NAME] [--bus URL] [--no-enroll]
//!                               points it at a service and the org it obeys, restarts it, enrols it (configure.rs)
//!
//! Connects *out* to NATS; nothing listens on the host. Subscribes to beat.ask.all and beat.ask.host.<name>, runs
//! each question a member of the org signed (its credential signed by a root this sensor pins, docs/security.md H16)
//! and a collector key countersigned with beat-probe (runner.rs), seals the answer to
//! the survey's key and signs it (seal.rs), publishes it to beat.answer.<survey> through JetStream, and heartbeats
//! into the beat-directory KV bucket so surveys know whom to expect; heartbeats are signed too, and list the org roots
//! and collector keys this sensor trusts (`DIR/<name>.pub`, read for each question: a key deployed or removed counts at
//! once). A question not signed and countersigned by them, issued before this sensor started (a replay across a restart), past its deadline or with a deadline
//! further than its time limit allows, or asked again, is dropped unanswered, with a line in the log.
//!
//! A question's time limit (Beat-Timeout) counts from when it arrives, queueing for a slot included: a sensor answers
//! by then, with an error (kind `busy`) if the wait used it up. When the answer is not out within ACK_AFTER, the
//! sensor acknowledges on beat.ack.<survey> with that time (Beat-Answer-By), so the collector can tell a sensor that
//! is working from one that never got the question (silent) or died on it (lost).
//! --name defaults to the host name. --no-sandbox runs beat-probe directly (development, no root).
//! --unit-property: a systemd property for every question's unit, as `systemd-run -p` takes it; installed from an
//! image, MountImages= gives the questions the image's /nix/store (docs/security.md M16).
//! --systemd: the directory of the host's systemd-run and systemctl, /usr/bin by default (NixOS: the systemd
//! package's bin; the NixOS module passes it).

mod aws;
mod bus;
mod configure;
mod enroll;
mod runner;
mod seal;
mod wire;

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{bail, Context};
use async_nats::jetstream;
use base64::{engine::general_purpose::STANDARD, Engine};
use futures::StreamExt;
use serde_json::json;

use runner::Runner;

const VERSION: &str = concat!("beat-sensor/", env!("CARGO_PKG_VERSION"));
const MAX_TIMEOUT_S: u64 = 300;
const HEARTBEAT: Duration = Duration::from_secs(10);
const ACK_AFTER: Duration = Duration::from_secs(1); // short questions answer before this: no ack
/// The collector's windows past a question's time limit (collector.py: ack window 10 s, runner slack 15 s, grace
/// 30 s): a deadline further than the limit plus this is refused, so no signed question stays live for long.
const DEADLINE_SLACK_S: i64 = 60;
/// Allowance for the collector's clock behind ours, when refusing questions issued before this sensor started.
const SKEW_S: i64 = 5;

struct Config {
    nats: String,
    /// The service's API (BEAT_API), where the sensor gets its bus login (bus.rs).
    api: String,
    name: String,
    labels: serde_json::Map<String, serde_json::Value>,
    concurrency: usize,
    version: String,
    runner: Runner,
    key: ed25519_dalek::SigningKey,
    roots: PathBuf,
    collectors: PathBuf,
    /// The org root's deny list (H16): read from the KV bucket beat-deny at each heartbeat, taken when a pinned root
    /// signed it and its seq is higher; kept in `deny_file` (--deny), so a restart cannot roll it back.
    deny: std::sync::Mutex<seal::Deny>,
    deny_file: Option<PathBuf>,
    /// Unix seconds this sensor started: a question issued before then may be a replay (`seen` was empty).
    started: i64,
}

fn parse(argv: &[String]) -> anyhow::Result<Config> {
    let (mut nats, mut api, mut name, mut probe, mut tools, mut cache) = (None, None, None, None, None, None);
    let (mut osqueryi, mut journalctl, mut placeholders, mut no_sandbox) = (None, None, None, false);
    let (mut bpf_tools, mut unit_props, mut systemd) = (None, vec![], PathBuf::from("/usr/bin"));
    let (mut key, mut roots, mut collector, mut deny_file) = (None, None, None, None);
    let mut labels = serde_json::Map::new();
    let mut concurrency = 2;
    let mut version = VERSION.to_string();
    let mut it = argv.iter();
    while let Some(x) = it.next() {
        let mut val = || it.next().cloned().with_context(|| format!("{x} needs a value"));
        match x.as_str() {
            "--nats" => nats = Some(val()?),
            "--api" => api = Some(val()?),
            "--name" => name = Some(val()?),
            "--probe" => probe = Some(PathBuf::from(val()?)),
            "--tools" => tools = Some(PathBuf::from(val()?)),
            "--cache" => cache = Some(PathBuf::from(val()?)),
            "--osqueryi" => osqueryi = Some(PathBuf::from(val()?)),
            "--journalctl" => journalctl = Some(PathBuf::from(val()?)),
            "--bpf-tools" => bpf_tools = Some(PathBuf::from(val()?)),
            "--placeholders" => placeholders = Some(PathBuf::from(val()?)),
            "--no-sandbox" => no_sandbox = true,
            "--key" => key = Some(PathBuf::from(val()?)),
            "--roots" => roots = Some(PathBuf::from(val()?)),
            "--deny" => deny_file = Some(PathBuf::from(val()?)),
            "--collector-keys" => collector = Some(PathBuf::from(val()?)),
            "--unit-property" => unit_props.push(val()?),
            "--systemd" => systemd = PathBuf::from(val()?),
            "--concurrency" => concurrency = val()?.parse().context("--concurrency")?,
            "--version" => version = val()?,
            "--label" => {
                let kv = val()?;
                let (k, v) = kv.split_once('=').with_context(|| format!("--label {kv}: expected k=v"))?;
                labels.insert(k.into(), v.into());
            }
            other => bail!("unknown argument {other}"),
        }
    }
    let name = match name {
        Some(n) => n,
        None => std::fs::read_to_string("/proc/sys/kernel/hostname").context("host name")?.trim().to_string(),
    };
    // A subject token: no dots, spaces or wildcards.
    if name.is_empty() || name.contains(['.', ' ', '*', '>']) {
        bail!("sensor name {name:?} cannot be a NATS subject token");
    }
    let sandbox = match (placeholders, no_sandbox) {
        (Some(p), false) => Some(p),
        (None, true) => None,
        _ => bail!("give exactly one of --placeholders DIR and --no-sandbox"),
    };
    let key = key.context("--key is required (beat-sensor keygen FILE creates one)")?;
    let roots = roots.context("--roots is required: the directory of the org roots' public keys")?;
    seal::read_keys(&roots).context("--roots")?;
    let collectors = collector.context("--collector-keys is required: the directory of the collector's public keys")?;
    seal::read_keys(&collectors).context("--collector-keys")?;
    let deny = deny_file.as_ref().and_then(|f| std::fs::read(f).ok())
        .and_then(|d| seal::check_deny(&d, &seal::read_keys(&roots).ok()?).map_err(|e| eprintln!("--deny: {e}")).ok())
        .unwrap_or_default();
    Ok(Config {
        key: seal::read_signing(&key).with_context(|| format!("--key {}", key.display()))?,
        deny: std::sync::Mutex::new(deny),
        deny_file,
        roots,
        collectors,
        started: unix_now(),
        nats: nats.context("--nats is required")?,
        api: api.context("--api is required: the service's API, where the sensor gets its bus login")?,
        name,
        labels,
        concurrency,
        version,
        runner: Runner {
            probe: probe.context("--probe is required")?,
            tools: tools.context("--tools is required")?,
            cache: cache.context("--cache is required")?,
            osqueryi,
            journalctl,
            bpf_tools,
            sandbox,
            secret_mounts_denied: Default::default(),
            hide: vec![key.clone()],
            unit_props,
            systemd,
        },
    })
}

/// A protocol test vector file (tests/, shared with the client's tests): BEAT_TEST_VECTORS names the directory when
/// the crate is built outside the repo (the Nix check), else it is next to the crate.
#[cfg(test)]
fn test_vectors(name: &str) -> std::path::PathBuf {
    std::env::var_os("BEAT_TEST_VECTORS")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../tests"))
        .join(name)
}

fn unix_now() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

fn iso_now() -> String {
    iso_at(unix_now())
}

fn iso_at(secs: i64) -> String {
    let (days, rem) = (secs.div_euclid(86400), secs.rem_euclid(86400));
    // Civil date from days since the epoch (Howard Hinnant's algorithm).
    let z = days + 719468;
    let era = z.div_euclid(146097);
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + if m <= 2 { 1 } else { 0 };
    format!("{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z", rem / 3600, rem % 3600 / 60, rem % 60)
}

/// Unix seconds of an ISO 8601 UTC time as the collector writes it (2026-10-15T10:00:00Z).
fn parse_iso(s: &str) -> Option<i64> {
    let b = s.as_bytes();
    if b.len() != 20 || b[4] != b'-' || b[7] != b'-' || b[10] != b'T' || b[13] != b':' || b[16] != b':' || b[19] != b'Z' {
        return None;
    }
    let n = |r: std::ops::Range<usize>| s.get(r)?.parse::<i64>().ok();
    let (y, m, d, hh, mm, ss) = (n(0..4)?, n(5..7)?, n(8..10)?, n(11..13)?, n(14..16)?, n(17..19)?);
    if !(1..=12).contains(&m) || !(1..=31).contains(&d) || hh > 23 || mm > 59 || ss > 60 {
        return None;
    }
    // Days since the epoch from a civil date (Howard Hinnant's algorithm; iso_at is its inverse).
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    Some((era * 146097 + doe - 719468) * 86400 + hh * 3600 + mm * 60 + ss)
}

/// Surveys this sensor has taken, until their deadline: a question signed once is answered once (a copy replayed on
/// the bus is dropped).
type Seen = Arc<std::sync::Mutex<HashMap<String, i64>>>;

/// What a signed question asks of this sensor (seal.rs; the headers are its envelope).
struct Ask {
    survey: String,
    question_hash: String,
    key: String,
    timeout: u64,
}

/// Checks a question before anything runs: signed by a member of the org (Beat-Cred, H16) and countersigned by a collector key, for this payload, for this sensor, issued since
/// this sensor started, with a deadline its time limit allows and not past, not seen before. Err(None): not for this
/// sensor (no log line); Err(Some(why)): refused.
fn admit(cfg: &Config, seen: &Seen, msg: &async_nats::Message) -> Result<Ask, Option<String>> {
    let h = seal::headers_of(msg).map_err(Some)?;
    let roots = seal::read_keys(&cfg.roots).map_err(|e| Some(format!("{e:#}")))?;
    let cred = seal::get(&h, "Beat-Cred").ok_or_else(|| Some("question without Beat-Cred (a member's credential)".into()))?;
    let member = seal::check_credential(cred, &roots, unix_now()).map_err(|e| Some(format!("question: {e}")))?;
    seal::verify_header(&member.key, seal::SIGNATURE, "ask", &h, &msg.payload)
        .map_err(|e| Some(format!("question from {} (root {}): {e}", member.name, member.root)))?;
    if let Some(why) = cfg.deny.lock().unwrap().denies(&member) {
        return Err(Some(format!("question: {why}")));
    }
    let collectors = seal::read_keys(&cfg.collectors).map_err(|e| Some(format!("{e:#}")))?;
    seal::verify_any(&collectors, "collector", seal::COUNTERSIGNATURE, "ask", &h, &msg.payload)
        .map_err(|e| Some(format!("question {e}")))?;
    let survey = seal::get(&h, "Beat-Survey").unwrap_or("").to_string();
    if survey.is_empty() || survey.contains(['.', ' ', '*', '>']) {
        return Err(Some(format!("survey id {survey:?} is not a subject token")));
    }
    if let Some(targets) = seal::get(&h, "Beat-Targets") {
        if !targets.split(',').any(|t| t.trim() == cfg.name) {
            return Err(None);
        }
    }
    let question_hash = wire::sha256_hex(&msg.payload);
    if seal::get(&h, "Beat-Question") != Some(question_hash.as_str()) {
        return Err(Some(format!("survey {survey}: Beat-Question does not match the payload")));
    }
    let key = seal::get(&h, "Beat-Key").ok_or_else(|| Some(format!("survey {survey}: no Beat-Key")))?.to_string();
    let deadline = seal::get(&h, "Beat-Deadline").and_then(parse_iso)
        .ok_or_else(|| Some(format!("survey {survey}: no Beat-Deadline")))?;
    let issued = seal::get(&h, "Beat-Issued").and_then(parse_iso)
        .ok_or_else(|| Some(format!("survey {survey}: no Beat-Issued")))?;
    let timeout: u64 = seal::get(&h, "Beat-Timeout").and_then(|t| t.parse().ok())
        .filter(|t| (1..=MAX_TIMEOUT_S).contains(t))
        .ok_or_else(|| Some(format!("survey {survey}: Beat-Timeout missing or not 1 to {MAX_TIMEOUT_S} s")))?;
    let now = unix_now();
    if issued < cfg.started - SKEW_S {
        return Err(Some(format!("survey {survey}: issued {} s before this sensor started (a replay?)",
                                cfg.started - issued)));
    }
    if deadline - issued > timeout as i64 + DEADLINE_SLACK_S {
        return Err(Some(format!("survey {survey}: deadline {} s after issue, more than the {timeout} s limit allows",
                                deadline - issued)));
    }
    if now > deadline {
        return Err(Some(format!("survey {survey}: past its deadline ({} s)", now - deadline)));
    }
    let mut seen = seen.lock().expect("not poisoned");
    seen.retain(|_, d| *d >= now);
    if seen.insert(survey.clone(), deadline).is_some() {
        return Err(Some(format!("survey {survey}: asked again (a replay)")));
    }
    Ok(Ask { survey, question_hash, key, timeout })
}

/// Handles one message on an ask subject: answer it, or drop it (admit). `slots` bounds how many questions run at
/// once; the time limit counts from arrival, waiting for a slot included.
async fn handle(cfg: Arc<Config>, client: async_nats::Client, js: jetstream::Context, slots: Arc<tokio::sync::Semaphore>,
                seen: Seen, msg: async_nats::Message) {
    let arrived = std::time::Instant::now();
    let Ask { survey, question_hash, key, timeout } = match admit(&cfg, &seen, &msg) {
        Ok(a) => a,
        Err(None) => return,
        Err(Some(why)) => {
            eprintln!("refused on {}: {why}", msg.subject);
            return;
        }
    };
    // The runner's own bound is the limit plus 15 s (runner.rs: waiting for systemd-run): the promise includes it.
    let answer_by = iso_at(unix_now() + timeout as i64 + 15);
    let started = iso_now();
    let work = async {
        let q = match wire::parse_question(&msg.payload) {
            Err(e) => return wire::answer_error("rejected", &e),
            Ok(q) => q,
        };
        let _permit = slots.acquire_owned().await.expect("the semaphore is never closed");
        let left = Duration::from_secs(timeout).saturating_sub(arrived.elapsed());
        if left < Duration::from_secs(1) {
            let waited = arrived.elapsed().as_secs();
            return wire::answer_error("busy", &format!("waited {waited} s for a free slot: the {timeout} s time limit \
                                                         was used up before the question could start"));
        }
        match cfg.runner.run(&q.name, &q.source, left.as_secs()).await {
            Ok(result) => wire::answer_from_result(&result),
            // The runner had what was left of the limit; the caller knows the limit they set.
            Err(e) if e.kind == "timeout" => wire::answer_error("timeout", &format!(
                "time limit ({timeout} s, counted from the question's arrival) reached: the question was stopped")),
            Err(e) => wire::answer_error(e.kind, &e.message),
        }
    };
    tokio::pin!(work);
    let answer = tokio::select! {
        a = &mut work => a,
        _ = tokio::time::sleep(ACK_AFTER) => {
            ack(&cfg, &js, &survey, &question_hash, &answer_by).await;
            work.await
        }
    };
    let finished = iso_now();
    let mut body = wire::canonical(&answer);
    // Over the server's message limit the publish fails and the sensor would be silent: say so instead.
    let limit = (client.server_info().max_payload).saturating_sub(wire::HEADROOM + seal::OVERHEAD);
    let answer = if body.len() > limit {
        let a = wire::answer_too_large(&answer, body.len(), limit);
        eprintln!("survey {survey}: answer too large ({} bytes, limit {limit})", body.len());
        body = wire::canonical(&a);
        a
    } else {
        answer
    };
    let answer_hash = wire::sha256_hex(&body);
    let outcome = answer["outcome"].as_str().unwrap_or("error").to_string();
    let size = body.len();
    // Sealed to the survey's key: the stream holds no readable answer. Its hash is not a header either (equal answers
    // would show as equal on the bus); the collector hashes what it opens.
    let body = match seal::seal(&key, &survey, &cfg.name, &body) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("survey {survey}: cannot seal the answer: {e}");
            return;
        }
    };
    let fields: seal::Headers = [("Beat-Survey", survey.as_str()), ("Beat-Question", &question_hash),
                                 ("Beat-Target", &cfg.name), ("Beat-Outcome", &outcome), ("Beat-Started", &started),
                                 ("Beat-Finished", &finished), ("Beat-Sensor", &cfg.version)]
        .iter().map(|(k, v)| (k.to_string(), v.to_string())).collect();
    let h = header_map(seal::sign(&cfg.key, "answer", fields, &body));
    let subject = wire::answer_subject(&survey);
    // JetStream acks once the answer is stored in the stream; retried a few times, since losing it makes us silent.
    for attempt in 1..=3 {
        match js.publish_with_headers(subject.clone(), h.clone(), body.clone().into()).await {
            Ok(ack) => match ack.await {
                Ok(_) => {
                    eprintln!("survey {survey}: answered {outcome} ({size} bytes, {})", &answer_hash[..12]);
                    return;
                }
                Err(e) => eprintln!("survey {survey}: answer not acknowledged (attempt {attempt}): {e}"),
            },
            Err(e) => eprintln!("survey {survey}: publish failed (attempt {attempt}): {e}"),
        }
        tokio::time::sleep(Duration::from_secs(attempt)).await;
    }
    eprintln!("survey {survey}: answer lost after 3 attempts");
}

/// Publishes the builtins guide by its hash (kept, no TTL: content-addressed, the same for every sensor of a build).
/// "Working on it, the answer comes by `answer_by`": one ack per question, through JetStream like answers, so the
/// collector reads acks and answers in order. A lost ack makes the target look silent until its answer arrives.
async fn ack(cfg: &Config, js: &jetstream::Context, survey: &str, question_hash: &str, answer_by: &str) {
    let fields: seal::Headers = [("Beat-Survey", survey), ("Beat-Question", question_hash),
                                 ("Beat-Target", cfg.name.as_str()), ("Beat-Answer-By", answer_by),
                                 ("Beat-Sensor", cfg.version.as_str())]
        .iter().map(|(k, v)| (k.to_string(), v.to_string())).collect();
    let h = header_map(seal::sign(&cfg.key, "ack", fields, b""));
    match js.publish_with_headers(wire::ack_subject(survey), h, Vec::new().into()).await {
        Ok(f) => {
            if let Err(e) = f.await {
                eprintln!("survey {survey}: ack not acknowledged: {e}");
            }
        }
        Err(e) => eprintln!("survey {survey}: ack failed: {e}"),
    }
}

fn header_map(h: seal::Headers) -> async_nats::HeaderMap {
    let mut m = async_nats::HeaderMap::new();
    for (k, v) in h {
        m.insert(k.as_str(), v.as_str());
    }
    m
}

/// Puts the builtins guide in the guides bucket by its hash. The collector makes the bucket: a sensor may not (H17).
async fn publish_guide(cfg: &Config, js: &jetstream::Context) -> Option<String> {
    let kv = js.get_key_value(wire::GUIDES).await.map_err(|e| eprintln!("guides bucket: {e}")).ok()?;
    let guide = cfg.runner.guide().await.map_err(|e| eprintln!("guide: {e}")).ok()?;
    let hash = wire::sha256_hex(guide.as_bytes());
    kv.put(&hash, guide.into_bytes().into()).await.map_err(|e| eprintln!("guide: {e}")).ok()?;
    Some(hash)
}

/// Takes the org root's deny list from the KV bucket when it is newer than the one held and a pinned root signed it.
async fn refresh_deny(cfg: &Config, js: &jetstream::Context) {
    let Ok(kv) = js.get_key_value(wire::DENY).await else { return };  // none published yet
    let Ok(Some(data)) = kv.get("list").await else { return };
    let roots = match seal::read_keys(&cfg.roots) {
        Ok(r) => r,
        Err(_) => return,
    };
    let d = match seal::check_deny(&data, &roots) {
        Ok(d) => d,
        Err(e) => return eprintln!("refused a deny list: {e}"),
    };
    let held = cfg.deny.lock().unwrap().seq;
    if d.seq <= held {
        return;
    }
    if let Some(f) = &cfg.deny_file {
        let tmp = f.with_extension("tmp");
        if let Err(e) = std::fs::write(&tmp, &data).and_then(|_| std::fs::rename(&tmp, f)) {
            eprintln!("deny list {}: not kept in {}: {e}", d.seq, f.display());
        }
    }
    eprintln!("deny list {} taken: {}", d.seq,
              if d.entries.is_empty() { "nobody".to_string() } else { d.entries.iter().map(|(n, _)| n.as_str()).collect::<Vec<_>>().join(", ") });
    *cfg.deny.lock().unwrap() = d;
}

async fn heartbeat(cfg: Arc<Config>, js: jetstream::Context) {
    let started = iso_now();
    let (mut guide, mut kv) = (None, None);
    loop {
        if guide.is_none() {
            guide = publish_guide(&cfg, &js).await;
        }
        // The keys trusted now, as name:fingerprint (`beat keys use` checks a new key is trusted).
        let trusted = |dir: &std::path::Path| -> Vec<String> {
            match seal::read_keys(dir) {
                Ok(keys) => keys.iter().map(|c| format!("{}:{}", c.name, seal::fingerprint(&c.key))).collect(),
                Err(e) => {
                    eprintln!("heartbeat: {e:#}");
                    Vec::new()
                }
            }
        };
        refresh_deny(&cfg, &js).await;
        let deny_seq = cfg.deny.lock().unwrap().seq;
        let (roots, collectors) = (trusted(&cfg.roots), trusted(&cfg.collectors));
        // The roots' public keys themselves: the service checks credentials against what enrolled sensors pin, so it
        // is never told a root (docs/security.md H15, H16; collector.py `Trust.obeyed`).
        let root_keys: serde_json::Map<String, serde_json::Value> = seal::read_keys(&cfg.roots).unwrap_or_default().iter()
            .map(|c| (c.name.clone(), STANDARD.encode(c.key.as_bytes()).into())).collect();
        let entry = json!({"name": cfg.name, "sensor": cfg.version, "labels": cfg.labels, "started": started,
                           "guide": guide, "sandbox": cfg.runner.sandbox_mode(), "at": iso_now(),
                           "roots": roots, "collectors": collectors, "root_keys": root_keys,
                           "deny": deny_seq});
        let entry = serde_json::Value::Object(seal::sign_entry(&cfg.key, entry.as_object().cloned().unwrap_or_default()));
        if kv.is_none() {  // the collector makes the bucket
            kv = js.get_key_value(wire::DIRECTORY).await.map_err(|e| eprintln!("directory bucket: {e}")).ok();
        }
        if let Some(k) = &kv {
            if let Err(e) = k.put(&cfg.name, wire::canonical(&entry).into()).await {
                eprintln!("heartbeat: {e}");
            }
        }
        tokio::time::sleep(HEARTBEAT).await;
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    if argv.first().map(String::as_str) == Some("keygen") {
        let path = argv.get(1).context("usage: beat-sensor keygen FILE")?;
        println!("{}", seal::keygen(std::path::Path::new(path))?);
        return Ok(());
    }
    if argv.first().map(String::as_str) == Some("enroll") {
        // blocking HTTP, before anything else runs on the runtime
        return tokio::task::block_in_place(|| enroll::run(&argv[1..], VERSION));
    }
    if argv.first().map(String::as_str) == Some("configure") {
        return tokio::task::block_in_place(|| configure::run(&argv[1..], VERSION));
    }
    let cfg = Arc::new(parse(&argv)?);
    // Its own login (bus.rs): a JWT for its key from the API, renewed at half life, handed over at every connection.
    let slot: bus::Slot = Arc::new(std::sync::Mutex::new(
        bus::first(cfg.api.clone(), cfg.key.clone(), cfg.name.clone()).await));
    tokio::spawn(bus::keep(cfg.api.clone(), cfg.key.clone(), cfg.name.clone(), slot.clone()));
    let (key, held) = (cfg.key.clone(), slot.clone());
    let client = async_nats::ConnectOptions::with_auth_callback(move |nonce| {
            std::future::ready(bus::auth(&key, &held, &nonce))
        })
        .name(format!("beat-sensor {}", cfg.name))
        .custom_inbox_prefix(format!("_INBOX_{}", cfg.name))  // its replies only: its login allows no other inbox
        .retry_on_initial_connect()
        .connect(&cfg.nats)
        .await
        .with_context(|| format!("connecting to {}", cfg.nats))?;
    let js = jetstream::new(client.clone());
    let all = client.subscribe(wire::ASK_ALL).await?;
    let mine = client.subscribe(wire::ask_host(&cfg.name)).await?;
    eprintln!("{} as {:?}: listening on {} and {} via {}", cfg.version, cfg.name, wire::ASK_ALL,
              wire::ask_host(&cfg.name), cfg.nats);
    tokio::spawn(heartbeat(cfg.clone(), js.clone()));

    let slots = Arc::new(tokio::sync::Semaphore::new(cfg.concurrency));
    let seen = Seen::default();
    let mut asks = futures::stream::select(all, mine);
    while let Some(msg) = asks.next().await {
        tokio::spawn(handle(cfg.clone(), client.clone(), js.clone(), slots.clone(), seen.clone(), msg));
    }
    bail!("NATS subscriptions closed")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn iso_round_trips() {
        for t in [0, 951782400, 1760522400, 1760522459 + 86400 * 400] {
            assert_eq!(parse_iso(&iso_at(t)), Some(t), "{}", iso_at(t));
        }
        assert_eq!(parse_iso("2026-10-15T10:00:00"), None);
        assert_eq!(parse_iso("2026-13-15T10:00:00Z"), None);
    }
}
