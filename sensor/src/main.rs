//! beat-sensor: answers questions published on NATS (docs/protocol.md; the protocol is in wire.rs).
//!
//!   beat-sensor --nats URL --probe PATH --tools DIR --cache DIR --key FILE --roots DIR --collector-keys DIR
//!               [--name NAME] [--deny FILE]
//!               [--label k=v]... [--osqueryi PATH] [--journalctl PATH] [--bpf-tools DIR] [--tcpdump PATH]
//!               [--placeholders DIR | --no-sandbox] [--question-user NAME]
//!               [--concurrency N] [--unit-property P]... [--systemd DIR]
//!               [--bwrap PATH --setpriv PATH --seccomp FILE --seccomp-capture FILE --host-root DIR --question-uid N]
//!               [--landlock --seccomp FILE]
//!   beat-sensor keygen FILE     creates the sensor's signing key when missing; prints its public key (to enroll)
//!   beat-sensor enroll --api URL [--name NAME] [--key FILE]
//!                               asks the service to admit this sensor; waits for a member's approval (enroll.rs)
//!   beat-sensor configure --api URL --org-root NAME=KEY... [--name NAME] [--bus URL] [--no-enroll]
//!                               points it at a service and the org it obeys, restarts it, enrols it (configure.rs)
//!
//! Connects *out* to NATS; nothing listens on the host. Subscribes to beat.ask.all and beat.ask.host.<name>, runs
//! each question a member of the org signed (its credential signed by a root this sensor pins, docs/security.md H16)
//! and a collector key countersigned with beat-probe (runner.rs), seals the answer to
//! the survey's key and signs it (seal.rs), sends it to the survey's collector (beat.answer.<survey>, a request)
//! until it says it is stored or the deadline passes (`deliver`), and heartbeats on beat.heartbeat.<name>
//! so surveys know whom to expect; heartbeats are signed too, and list the org roots
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
//! --tcpdump: capture() for questions (capture.rs): the sensor runs it in a unit of its own and passes the pcap back;
//! without it, or with --no-sandbox, questions have no capture().
//! --question-user: the user questions and the secret walk run as, with their capabilities ambient (runner.rs
//! `question_user`); the sensor's unit makes it. Without it, or when there is no such user, questions run as root (the heartbeat's
//! `question_user` says which).
//! --systemd: the directory of the host's systemd-run and systemctl, /usr/bin by default (NixOS: the systemd
//! package's bin; the NixOS module passes it).
//! --bwrap ...: questions and the walk sandboxed by bubblewrap in a cgroup of the sensor's own, not in systemd units:
//! a sensor in a Kubernetes pod (bwrap.rs, packaging/kubernetes). --host-root is the host's / in the pod; questions
//! run as --question-uid, capture()'s tcpdump as the next uid.
//! --landlock (instead of --placeholders or --no-sandbox): questions sandboxed with no privilege (landlock.rs), for a
//! sensor in a pod that is not privileged, the cluster sensor; --seccomp is then packaging/kubernetes/seccomp.c's
//! `cluster` filter (no socket). No secret walk, no capture(), no host tools: there is no host to read.

mod aws;
mod bwrap;
mod bus;
mod capture;
mod configure;
mod enroll;
mod landlock;
mod runner;
mod seal;
mod wire;

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{bail, Context};
use base64::{engine::general_purpose::STANDARD, Engine};
use futures::StreamExt;
use serde_json::json;

use runner::Runner;

/// The release (pyproject.toml's, which the flake passes in); a cargo build has only the crate's version.
static VERSION: std::sync::LazyLock<String> = std::sync::LazyLock::new(|| {
    format!("beat-sensor/{}", option_env!("BEAT_RELEASE").unwrap_or(env!("CARGO_PKG_VERSION")))
});
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
    /// The org root's deny list (H16): asked of a collector at each heartbeat (beat.deny.get), taken when a pinned root
    /// signed it and its seq is higher; kept in `deny_file` (--deny), so a restart cannot roll it back.
    deny: std::sync::Mutex<seal::Deny>,
    deny_file: Option<PathBuf>,
    /// Unix seconds this sensor started: a question issued before then may be a replay (`seen` was empty).
    started: i64,
    /// Counts the bus's (re)connections: an answer in flight when the connection dropped is sent again (`deliver`).
    connections: tokio::sync::watch::Sender<u64>,
}

fn parse(argv: &[String]) -> anyhow::Result<Config> {
    let (mut nats, mut api, mut name, mut probe, mut tools, mut cache) = (None, None, None, None, None, None);
    let (mut osqueryi, mut journalctl, mut placeholders, mut no_sandbox) = (None, None, None, false);
    let (mut bpf_tools, mut unit_props, mut systemd) = (None, vec![], PathBuf::from("/usr/bin"));
    let mut tcpdump: Option<PathBuf> = None;
    let mut question_user: Option<String> = None;
    // --bwrap (bwrap.rs): a sensor in a pod sandboxes questions itself.
    let (mut bwrap, mut setpriv, mut seccomp, mut host_root, mut question_uid) = (None, None, None, None, None);
    let mut landlock = false;
    let mut seccomp_capture = None;
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
            "--tcpdump" => tcpdump = Some(PathBuf::from(val()?)),
            "--question-user" => question_user = Some(val()?),
            "--bwrap" => bwrap = Some(PathBuf::from(val()?)),
            "--setpriv" => setpriv = Some(PathBuf::from(val()?)),
            "--seccomp" => seccomp = Some(PathBuf::from(val()?)),
            "--seccomp-capture" => seccomp_capture = Some(PathBuf::from(val()?)),
            "--host-root" => host_root = Some(PathBuf::from(val()?)),
            "--question-uid" => question_uid = Some(val()?.parse::<u32>().context("--question-uid")?),
            "--placeholders" => placeholders = Some(PathBuf::from(val()?)),
            "--no-sandbox" => no_sandbox = true,
            "--landlock" => landlock = true,
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
    let sandbox = match (placeholders, no_sandbox, landlock) {
        (Some(p), false, false) => Some(p),
        (None, true, false) | (None, false, true) => None,
        _ => bail!("give exactly one of --placeholders DIR, --landlock and --no-sandbox"),
    };
    let cache = cache.context("--cache is required")?;
    let tools = tools.context("--tools is required")?;
    let landlock = match landlock {
        true => {
            let seccomp = seccomp.clone().context("--landlock needs --seccomp FILE (seccomp.c's `cluster` filter)")?;
            let l = landlock::Landlock::new(&[PathBuf::from("/nix"), tools.clone(), cache.clone()], &seccomp)
                .map_err(|e| anyhow::anyhow!("--landlock: {e}"))?;
            eprintln!("questions sandboxed by Landlock (ABI {}) and seccomp, without privileges", l.abi);
            Some(std::sync::Arc::new(l))
        }
        false => None,
    };
    let bwrap = match bwrap {
        Some(b) if sandbox.is_some() => {
            let bw = bwrap::Bwrap {
                bwrap: b, setpriv: setpriv.context("--bwrap needs --setpriv")?, seccomp: seccomp.context("--bwrap needs --seccomp")?,
                seccomp_capture: seccomp_capture.context("--bwrap needs --seccomp-capture")?,
                host: host_root.context("--bwrap needs --host-root: the host's / in the pod")?, cgroup: PathBuf::from("/sys/fs/cgroup"),
            };
            bw.init().map_err(|e| anyhow::anyhow!("--bwrap: {e}"))?;
            Some(std::sync::Arc::new(bw))
        }
        _ => None,
    };
    // Under --bwrap the question's user is a number: the pod has no account for it, and the host's is not needed.
    let question_user = match (&bwrap, question_uid) {
        (Some(_), Some(uid)) => Some((question_user.clone().unwrap_or_else(|| "beat-question".into()), uid)),
        _ => question_user.filter(|_| sandbox.is_some()).and_then(|u| runner::question_user(&u)
            .map_err(|e| eprintln!("--question-user {u}: {e}; questions run as root")).ok()),
    };
    // capture()'s tcpdump under --bwrap: in a sandbox of its own, as the user after the questions' (a unit's
    // DynamicUser= on a host).
    let capture_as = bwrap.clone().zip(question_uid.map(|u| u + 1));
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
        connections: tokio::sync::watch::Sender::new(0),
        nats: nats.context("--nats is required")?,
        api: api.context("--api is required: the service's API, where the sensor gets its bus login")?,
        name,
        labels,
        concurrency,
        version,
        runner: Runner {
            probe: probe.context("--probe is required")?,
            tools,
            cache,
            landlock,
            osqueryi,
            journalctl,
            bpf_tools,
            // capture() needs the sandbox's units: without them (--no-sandbox) there is no broker.
            capture: tcpdump.filter(|_| sandbox.is_some()).map(|t| {
                let mut b = capture::Broker::new(t, systemd.clone(), unit_props.clone(), vec![key.clone()],
                                                 PathBuf::from(runner::RUN_DIR));
                b.bwrap = capture_as;
                std::sync::Arc::new(b)
            }),
            sandbox,
            secret_mounts_denied: Default::default(),
            hide: vec![key.clone()],
            unit_props,
            systemd,
            walk: tokio::sync::watch::Sender::new(None),
            walk_error: Default::default(),
            uncovered: Default::default(),
            question_user,
            bwrap,
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

/// Now to the millisecond, for Beat-Started and Beat-Finished: subtracted from the bus's own stamp (docs/hosted.md
/// H25), whole seconds would be a second of rounding.
fn iso_now_ms() -> String {
    let d = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default();
    let s = iso_at(d.as_secs() as i64);
    format!("{}.{:03}Z", s.trim_end_matches('Z'), d.subsec_millis())
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
    /// Beat-Deadline, unix seconds: past it the survey is sealed and an answer is refused.
    deadline: i64,
    /// Beat-Profile: 1, signed with the rest: each host call timed, the slowest reported as records (beat-probe --profile)
    profile: bool,
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
    if !wire::is_token(&survey) {
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
    let profile = seal::get(&h, "Beat-Profile") == Some("1");
    Ok(Ask { survey, question_hash, key, timeout, deadline, profile })
}

/// Handles one message on an ask subject: answer it, or drop it (admit). `slots` bounds how many questions run at
/// once; the time limit counts from arrival, waiting for a slot included.
async fn handle(cfg: Arc<Config>, client: async_nats::Client, slots: Arc<tokio::sync::Semaphore>, seen: Seen,
                msg: async_nats::Message) {
    let arrived = std::time::Instant::now();
    let Ask { survey, question_hash, key, timeout, deadline, profile } = match admit(&cfg, &seen, &msg) {
        Ok(a) => a,
        Err(None) => return,
        Err(Some(why)) => {
            eprintln!("refused on {}: {why}", msg.subject);
            return;
        }
    };
    // The runner's own bound is the limit plus 15 s (runner.rs: waiting for systemd-run): the promise includes it.
    let answer_by = iso_at(unix_now() + timeout as i64 + 15);
    let started = iso_now_ms();
    let phases = runner::Phases::default();
    let work = async {
        let q = match wire::parse_question(&msg.payload) {
            Err(e) => return wire::answer_error("rejected", &e),
            Ok(q) => q,
        };
        let _permit = slots.acquire_owned().await.expect("the semaphore is never closed");
        phases.queue_ms.store(arrived.elapsed().as_millis() as u64, std::sync::atomic::Ordering::Relaxed);
        let left = Duration::from_secs(timeout).saturating_sub(arrived.elapsed());
        if left < Duration::from_secs(1) {
            let waited = arrived.elapsed().as_secs();
            return wire::answer_error("busy", &format!("waited {waited} s for a free slot: the {timeout} s time limit \
                                                         was used up before the question could start"));
        }
        match cfg.runner.run(&q.name, &q.source, left.as_secs(), &phases, profile).await {
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
            ack(&cfg, &client, &survey, &question_hash, &answer_by).await;
            work.await
        }
    };
    let finished = iso_now_ms();
    let sealing = std::time::Instant::now();
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
    // Sealed to the survey's key: the bus carries no readable answer. Its hash is not a header either (equal answers
    // would show as equal on the bus); the collector hashes what it opens.
    let body = match seal::seal(&key, &survey, &cfg.name, &body) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("survey {survey}: cannot seal the answer: {e}");
            return;
        }
    };
    phases.seal_ms.store(sealing.elapsed().as_millis() as u64, std::sync::atomic::Ordering::Relaxed);
    // In a header, like the times above: in the answer they would make equal answers differ (their hash names them).
    let phase_text = phases.text();
    let fields: seal::Headers = [("Beat-Survey", survey.as_str()), ("Beat-Question", &question_hash),
                                 ("Beat-Target", &cfg.name), ("Beat-Outcome", &outcome), ("Beat-Started", &started),
                                 ("Beat-Finished", &finished), ("Beat-Phases", &phase_text), ("Beat-Sensor", &cfg.version)]
        .iter().map(|(k, v)| (k.to_string(), v.to_string())).collect();
    let h = header_map(seal::sign(&cfg.key, "answer", fields, &body));
    match deliver(&cfg.connections, &client, wire::answer_subject(&survey), h, body, deadline).await {
        Delivery::Stored => eprintln!("survey {survey}: answered {outcome} ({size} bytes, {}; ms: {phase_text})",
                                      &answer_hash[..12]),
        Delivery::Refused(why) => eprintln!("survey {survey}: answer refused by the collector: {why}"),
        Delivery::GaveUp(why) => eprintln!("survey {survey}: answer not confirmed: {why}"),
    }
}

enum Delivery {
    Stored,
    Refused(String),
    GaveUp(String),
}

/// First wait after a request no one took ("no responders"), doubled up to RETRY_MAX.
const RETRY_FIRST: Duration = Duration::from_secs(1);
const RETRY_MAX: Duration = Duration::from_secs(8);

/// Sends a sealed answer to the survey's collector and waits for its reply, sent once the answer is stored, until the
/// survey's deadline (docs/protocol.md, "Delivery"). The wait is not cut short: a collector that is behind replies
/// late, and sending again would only add to what it has to read. Sent again: a request no one took ("no responders":
/// the bus restarting, or the survey's collector gone, as a restarted one does not listen for surveys it no longer
/// holds the key of), after 1 s doubling to 8 s; one in flight when the connection dropped,
/// once it is back (the reply, or the request, may have gone with it). A copy that arrives twice is harmless: the
/// collector writes by hash. Past the deadline the survey is sealed, so the sensor gives up.
async fn deliver(connections: &tokio::sync::watch::Sender<u64>, client: &async_nats::Client, subject: String,
                 h: async_nats::HeaderMap, body: Vec<u8>, deadline: i64) -> Delivery {
    use async_nats::client::{Request, RequestErrorKind};
    let mut wait = RETRY_FIRST;
    let mut connections = connections.subscribe();
    loop {
        let left = deadline - unix_now();
        if left <= 0 {
            return Delivery::GaveUp("the survey's deadline passed before a collector took it: lost".into());
        }
        connections.mark_unchanged();
        let request = Request::new().headers(h.clone()).payload(body.clone().into())
            .timeout(Some(Duration::from_secs(left as u64)));
        tokio::select! {
            r = client.send_request(subject.clone(), request) => match r {
                Ok(reply) => return match serde_json::from_slice::<serde_json::Value>(&reply.payload) {
                    Ok(v) if v["stored"] == json!(true) => Delivery::Stored,
                    Ok(v) => Delivery::Refused(v["refused"].as_str().unwrap_or("no reason given").to_string()),
                    Err(e) => Delivery::Refused(format!("a reply that is not JSON: {e}")),
                },
                // A collector that is behind still records what reached it in time, and replies only then: this
                // answer may be among them.
                Err(e) if e.kind() == RequestErrorKind::TimedOut =>
                    return Delivery::GaveUp("no reply by the deadline (a collector that is behind still records \
                                             what reached it in time)".into()),
                Err(e) => eprintln!("{subject}: not taken ({e}); sending again in {} s", wait.as_secs()),
            },
            _ = connections.changed() => {
                eprintln!("{subject}: the bus reconnected while waiting; sending again");
                continue;
            }
        }
        tokio::time::sleep(wait.min(Duration::from_secs(left.max(0) as u64))).await;
        wait = (wait * 2).min(RETRY_MAX);
    }
}

/// "Working on it, the answer comes by `answer_by`": one ack per question, to the survey's collector. Information only
/// (C25): a lost one changes no outcome, so it is published once, not delivered.
async fn ack(cfg: &Config, client: &async_nats::Client, survey: &str, question_hash: &str, answer_by: &str) {
    let fields: seal::Headers = [("Beat-Survey", survey), ("Beat-Question", question_hash),
                                 ("Beat-Target", cfg.name.as_str()), ("Beat-Answer-By", answer_by),
                                 ("Beat-Sensor", cfg.version.as_str())]
        .iter().map(|(k, v)| (k.to_string(), v.to_string())).collect();
    let h = header_map(seal::sign(&cfg.key, "ack", fields, b""));
    if let Err(e) = client.publish_with_headers(wire::ack_subject(survey), h, Vec::new().into()).await {
        eprintln!("survey {survey}: ack failed: {e}");
    }
}

fn header_map(h: seal::Headers) -> async_nats::HeaderMap {
    let mut m = async_nats::HeaderMap::new();
    for (k, v) in h {
        m.insert(k.as_str(), v.as_str());
    }
    m
}

/// Hands the builtins guide to a collector, which keeps it by its hash; the heartbeat names the hash.
async fn publish_guide(cfg: &Config, client: &async_nats::Client) -> Option<String> {
    let guide = cfg.runner.guide().await.map_err(|e| eprintln!("guide: {e}")).ok()?;
    let hash = wire::sha256_hex(guide.as_bytes());
    let reply = client.request(wire::GUIDE_PUT, guide.into_bytes().into()).await
        .map_err(|e| eprintln!("guide: not taken ({e}); again at the next heartbeat")).ok()?;
    match serde_json::from_slice::<serde_json::Value>(&reply.payload) {
        Ok(v) if v["hash"].as_str() == Some(hash.as_str()) => Some(hash),
        _ => {
            eprintln!("guide: the collector's reply does not name it: {}", String::from_utf8_lossy(&reply.payload));
            None
        }
    }
}

/// Takes the org root's deny list from a collector when it is newer than the one held and a pinned root signed it.
async fn refresh_deny(cfg: &Config, client: &async_nats::Client) {
    let Ok(reply) = client.request(wire::DENY_GET, Vec::new().into()).await else { return };  // again next heartbeat
    let data = reply.payload;
    if data.is_empty() {
        return;  // none put yet
    }
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

async fn heartbeat(cfg: Arc<Config>, client: async_nats::Client) {
    let started = iso_now();
    let mut guide = None;
    loop {
        if guide.is_none() {
            guide = publish_guide(&cfg, &client).await;
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
        refresh_deny(&cfg, &client).await;
        let deny_seq = cfg.deny.lock().unwrap().seq;
        let (roots, collectors) = (trusted(&cfg.roots), trusted(&cfg.collectors));
        // The roots' public keys themselves: the service checks credentials against what enrolled sensors pin, so it
        // is never told a root (docs/security.md H15, H16; collector.py `Trust.obeyed`).
        let root_keys: serde_json::Map<String, serde_json::Value> = seal::read_keys(&cfg.roots).unwrap_or_default().iter()
            .map(|c| (c.name.clone(), STANDARD.encode(c.key.as_bytes()).into())).collect();
        let entry = json!({"name": cfg.name, "sensor": cfg.version, "labels": cfg.labels, "started": started,
                           "guide": guide, "sandbox": cfg.runner.sandbox_mode(),
                           "question_user": cfg.runner.question_user_name(), "secret_walk": cfg.runner.walk_state(),
                           "at": iso_now(),
                           "roots": roots, "collectors": collectors, "root_keys": root_keys,
                           "deny": deny_seq});
        let entry = serde_json::Value::Object(seal::sign_entry(&cfg.key, entry.as_object().cloned().unwrap_or_default()));
        if let Err(e) = client.publish(wire::heartbeat_subject(&cfg.name), wire::canonical(&entry).into()).await {
            eprintln!("heartbeat: {e}");
        }
        tokio::time::sleep(HEARTBEAT).await;
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    if argv == ["--version"] {
        // alone, the operator's question; with a value, the version the service reports (beat-sensor-run)
        println!("{}", *VERSION);
        return Ok(());
    }
    if argv.first().map(String::as_str) == Some("keygen") {
        let path = argv.get(1).context("usage: beat-sensor keygen FILE")?;
        println!("{}", seal::keygen(std::path::Path::new(path))?);
        return Ok(());
    }
    if argv.first().map(String::as_str) == Some("enroll") {
        // blocking HTTP, before anything else runs on the runtime
        return tokio::task::block_in_place(|| enroll::run(&argv[1..], &VERSION));
    }
    if argv.first().map(String::as_str) == Some("configure") {
        return tokio::task::block_in_place(|| configure::run(&argv[1..], &VERSION));
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
        .event_callback({
            let cfg = cfg.clone();
            move |event| {
                if let async_nats::Event::Connected = event {
                    cfg.connections.send_modify(|n| *n += 1);
                }
                async {}
            }
        })
        .retry_on_initial_connect()
        .connect(&cfg.nats)
        .await
        .with_context(|| format!("connecting to {}", cfg.nats))?;
    let all = client.subscribe(wire::ASK_ALL).await?;
    let mine = client.subscribe(wire::ask_host(&cfg.name)).await?;
    eprintln!("{} as {:?}: listening on {} and {} via {}", cfg.version, cfg.name, wire::ASK_ALL,
              wire::ask_host(&cfg.name), cfg.nats);
    tokio::spawn(heartbeat(cfg.clone(), client.clone()));
    if cfg.runner.sandbox.is_some() {
        let walking = cfg.clone();
        tokio::spawn(async move { walking.runner.walk_forever().await });
    }

    let slots = Arc::new(tokio::sync::Semaphore::new(cfg.concurrency));
    let seen = Seen::default();
    let mut asks = futures::stream::select(all, mine);
    while let Some(msg) = asks.next().await {
        tokio::spawn(handle(cfg.clone(), client.clone(), slots.clone(), seen.clone(), msg));
    }
    bail!("NATS subscriptions closed")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A nats-server of the test's own, on free ports (NATS, and WebSocket without TLS: the load balancer's side of
    /// it); None (the test is skipped) when there is none on PATH (`nix shell nixpkgs#nats-server` gives one).
    struct Server {
        port: u16,
        ws: u16,
        child: Option<std::process::Child>,
    }

    fn free_port() -> Option<u16> {
        std::net::TcpListener::bind("127.0.0.1:0").ok()?.local_addr().ok().map(|a| a.port())
    }

    impl Server {
        fn start() -> Option<Server> {
            let mut s = Server { port: free_port()?, ws: free_port()?, child: None };
            s.restart().then_some(s)
        }

        fn restart(&mut self) -> bool {
            self.stop();
            let conf = std::env::temp_dir().join(format!("beat-sensor-test-nats-{}.conf", self.port));
            std::fs::write(&conf, format!("listen: \"127.0.0.1:{}\"\nwebsocket {{ listen: \"127.0.0.1:{}\", no_tls: true }}\n",
                                          self.port, self.ws)).unwrap();
            let Ok(child) = std::process::Command::new("nats-server").arg("-c").arg(&conf)
                .stderr(std::process::Stdio::null()).spawn() else {
                eprintln!("no nats-server on PATH: skipped");
                return false;
            };
            self.child = Some(child);
            for _ in 0..100 {
                if [self.port, self.ws].iter().all(|p| std::net::TcpStream::connect(("127.0.0.1", *p)).is_ok()) {
                    return true;
                }
                std::thread::sleep(Duration::from_millis(50));
            }
            false
        }

        fn stop(&mut self) {
            if let Some(mut c) = self.child.take() {
                let _ = c.kill();
                let _ = c.wait();
            }
        }

        async fn client(&self, connections: Option<Arc<tokio::sync::watch::Sender<u64>>>) -> async_nats::Client {
            let mut o = async_nats::ConnectOptions::new().retry_on_initial_connect();
            if let Some(c) = connections {
                o = o.event_callback(move |event| {
                    if let async_nats::Event::Connected = event {
                        c.send_modify(|n| *n += 1);
                    }
                    async {}
                });
            }
            o.connect(format!("127.0.0.1:{}", self.port)).await.unwrap()
        }
    }

    impl Drop for Server {
        fn drop(&mut self) {
            self.stop();
        }
    }

    /// A collector stand-in: replies `reply` to each request on `subject`, and counts them.
    async fn collector(client: async_nats::Client, subject: &str, reply: &'static str) -> Arc<std::sync::atomic::AtomicU32> {
        let n = Arc::new(std::sync::atomic::AtomicU32::new(0));
        let mut sub = client.subscribe(subject.to_string()).await.unwrap();
        client.flush().await.unwrap();
        let seen = n.clone();
        tokio::spawn(async move {
            while let Some(m) = sub.next().await {
                seen.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                if let Some(r) = m.reply {
                    let _ = client.publish(r, reply.into()).await;
                }
            }
        });
        n
    }

    fn sender() -> Arc<tokio::sync::watch::Sender<u64>> {
        Arc::new(tokio::sync::watch::Sender::new(0))
    }

    /// Sensors reach the bus over WebSocket (`wss://` behind the load balancer; `ws://` here): async-nats's
    /// `websockets` feature, on by default, must stay on.
    #[tokio::test]
    async fn the_bus_over_websocket() {
        let Some(s) = Server::start() else { return };
        let sensor = async_nats::ConnectOptions::new().connect(format!("ws://127.0.0.1:{}", s.ws)).await.unwrap();
        let n = collector(s.client(None).await, "beat.answer.s1", r#"{"stored": true}"#).await;
        let d = deliver(&sender(), &sensor, "beat.answer.s1".into(), Default::default(), b"x".to_vec(), unix_now() + 10).await;
        assert!(matches!(d, Delivery::Stored));
        assert_eq!(n.load(std::sync::atomic::Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn an_answer_is_delivered_once_stored_and_a_refusal_is_final() {
        let Some(s) = Server::start() else { return };
        let (c, sensor) = (sender(), s.client(None).await);
        let n = collector(s.client(None).await, "beat.answer.s1", r#"{"stored": true}"#).await;
        let d = deliver(&c, &sensor, "beat.answer.s1".into(), Default::default(), b"x".to_vec(), unix_now() + 10).await;
        assert!(matches!(d, Delivery::Stored));
        let r = collector(s.client(None).await, "beat.answer.s2", r#"{"refused": "sealed"}"#).await;
        let d = deliver(&c, &sensor, "beat.answer.s2".into(), Default::default(), b"x".to_vec(), unix_now() + 10).await;
        assert!(matches!(d, Delivery::Refused(ref w) if w == "sealed"));
        assert_eq!((n.load(std::sync::atomic::Ordering::SeqCst), r.load(std::sync::atomic::Ordering::SeqCst)), (1, 1));
    }

    #[tokio::test]
    async fn no_responders_is_sent_again_until_someone_takes_it() {
        let Some(s) = Server::start() else { return };
        let (c, sensor) = (sender(), s.client(None).await);
        let late = s.client(None).await;
        let started = std::time::Instant::now();
        let n = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(2500)).await;  // after the tries at 0, 1 and 3 s: taken at 3 s
            collector(late, "beat.answer.s1", r#"{"stored": true}"#).await
        });
        let d = deliver(&c, &sensor, "beat.answer.s1".into(), Default::default(), b"x".to_vec(), unix_now() + 20).await;
        assert!(matches!(d, Delivery::Stored));
        assert!((2..6).contains(&started.elapsed().as_secs()), "{:?}", started.elapsed());
        assert_eq!(n.await.unwrap().load(std::sync::atomic::Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn past_the_deadline_it_gives_up() {
        let Some(s) = Server::start() else { return };
        let (c, sensor) = (sender(), s.client(None).await);
        let started = std::time::Instant::now();
        // no one subscribed: tried again until the deadline, 3 s away
        let d = deliver(&c, &sensor, "beat.answer.s1".into(), Default::default(), b"x".to_vec(), unix_now() + 3).await;
        assert!(matches!(d, Delivery::GaveUp(_)));
        assert!(started.elapsed() < Duration::from_secs(5), "{:?}", started.elapsed());
        // subscribed but never replying (a collector far behind, or gone with the request): waited on, to the deadline
        let mut silent = s.client(None).await.subscribe("beat.answer.s2").await.unwrap();
        tokio::spawn(async move { while silent.next().await.is_some() {} });
        let started = std::time::Instant::now();
        let d = deliver(&c, &sensor, "beat.answer.s2".into(), Default::default(), b"x".to_vec(), unix_now() + 3).await;
        assert!(matches!(d, Delivery::GaveUp(ref w) if w.contains("no reply")));
        assert!(started.elapsed() >= Duration::from_secs(2), "{:?}", started.elapsed());
    }

    #[tokio::test]
    async fn an_answer_in_flight_when_the_bus_restarts_is_sent_again() {
        let Some(mut s) = Server::start() else { return };
        let c = sender();
        let sensor = s.client(Some(c.clone())).await;
        // The first copy is taken and never answered (the collector's reply went with the old server); after the
        // restart the copy sent again is stored.
        let first = s.client(None).await;
        let mut sub = first.subscribe("beat.answer.s1").await.unwrap();
        first.flush().await.unwrap();
        let got_first = tokio::spawn(async move { sub.next().await.is_some() });
        let deliver = tokio::spawn({
            let (c, sensor) = (c.clone(), sensor.clone());
            async move {
                deliver(&c, &sensor, "beat.answer.s1".into(), Default::default(), b"x".to_vec(), unix_now() + 30).await
            }
        });
        assert!(got_first.await.unwrap());
        s.restart();
        let n = collector(s.client(None).await, "beat.answer.s1", r#"{"stored": true}"#).await;
        let d = tokio::time::timeout(Duration::from_secs(20), deliver).await.expect("sent again").unwrap();
        assert!(matches!(d, Delivery::Stored));
        assert!(n.load(std::sync::atomic::Ordering::SeqCst) >= 1);
    }

    #[test]
    fn iso_round_trips() {
        for t in [0, 951782400, 1760522400, 1760522459 + 86400 * 400] {
            assert_eq!(parse_iso(&iso_at(t)), Some(t), "{}", iso_at(t));
        }
        assert_eq!(parse_iso("2026-10-15T10:00:00"), None);
        assert_eq!(parse_iso("2026-13-15T10:00:00Z"), None);
    }
}
