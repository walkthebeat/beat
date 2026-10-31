//! The wire protocol between control plane and sensors (docs/protocol.md). Python side: src/beat/wire.py.
//!
//! A NATS message's **payload is a content-addressed blob**, byte for byte: a question or an answer. Its **headers are
//! the relations**: which survey, which target, when. The receiver hashes the payload it got (sha256 of the bytes), so
//! the two sides never have to agree on a canonical form; the writer of a blob writes canonical JSON (sorted keys, no
//! whitespace) once so that equal content gets equal bytes.
//!
//!   beat.ask.all, beat.ask.host.<name>   core NATS   payload: question   Beat-Survey, Beat-Question, Beat-Key,
//!                                                                         Beat-Timeout, Beat-Issued, Beat-Deadline,
//!                                                                         Beat-Targets (optional: only these answer)
//!   beat.answer.<survey>                 JetStream   payload: sealed     Beat-Survey, Beat-Question, Beat-Target,
//!                                                    answer              Beat-Outcome, Beat-Started, Beat-Finished,
//!                                                                         Beat-Sensor
//!   beat.ack.<survey>                    JetStream   no payload          Beat-Survey, Beat-Question, Beat-Target,
//!                                                                         Beat-Answer-By, Beat-Sensor (only when the
//!                                                                         answer is not out within a second)
//!   KV bucket beat-directory, key <name>             sensor heartbeats: {name, sensor, labels, started, guide, sandbox, at, collectors, signature}; signed (kind heartbeat, over the entry without its signature); readers trust enrolled and fresh (<35 s) entries only
//!
//! Questions, acks and answers carry Beat-Signature (seal.rs): questions the collector's, acks and answers ours.
//!   KV bucket beat-guides, key <sha256>              the builtins guide a sensor's beat-probe prints (`guide` above)

use serde_json::{json, Value};

pub const ASK_ALL: &str = "beat.ask.all";
pub const DIRECTORY: &str = "beat-directory";
pub const GUIDES: &str = "beat-guides";
/// The org root's deny list (docs/security.md H16), key "list"; the collector publishes it.
pub const DENY: &str = "beat-deny";

pub fn ask_host(name: &str) -> String {
    format!("beat.ask.host.{name}")
}

pub fn answer_subject(survey: &str) -> String {
    format!("beat.answer.{survey}")
}

pub fn ack_subject(survey: &str) -> String {
    format!("beat.ack.{survey}")
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::Digest;
    sha2::Sha256::digest(bytes).iter().map(|b| format!("{b:02x}")).collect()
}

/// Canonical JSON: serde_json's default map is ordered by key, and `to_vec` writes no whitespace.
pub fn canonical(v: &Value) -> Vec<u8> {
    serde_json::to_vec(v).expect("a JSON value serializes")
}

/// A question as the sensor reads it: `{v: 1, name, source, libraries: {}, params: {}}`.
pub struct Question {
    pub name: String,
    pub source: String,
}

pub fn parse_question(payload: &[u8]) -> Result<Question, String> {
    let v: Value = serde_json::from_slice(payload).map_err(|e| format!("question is not JSON: {e}"))?;
    if v["v"] != json!(1) {
        return Err(format!("unsupported question version {}", v["v"]));
    }
    let source = v["source"].as_str().ok_or("question has no source")?.to_string();
    let name = v["name"].as_str().unwrap_or("question.star").to_string();
    // Libraries (load(), docs/probes.md D5) and parameters are part of the question's hash already; beat-probe does
    // not take them yet, so a question that has them is refused rather than answered without them.
    for k in ["libraries", "params"] {
        if v[k].as_object().is_some_and(|m| !m.is_empty()) {
            return Err(format!("question {k} are not supported by this sensor yet"));
        }
    }
    Ok(Question { name, source })
}

/// The answer blob: what the sensor said, nothing about who or when (C17). From beat-probe's run result
/// (docs/probes.md §9), `probe`, `name`, `started`, `finished` and `usage` move to the headers or are dropped.
/// `secrets` (gate 1's masks and flags, docs/security.md) is kept when beat-probe found something, and absent
/// otherwise, so a clean answer keeps its hash.
pub fn answer_from_result(result: &Value) -> Value {
    let mut a = json!({
        "v": 1,
        "outcome": result["outcome"],
        "records": result["records"],
        "failures": result["failures"],
        "error": result["error"],
        "diag": result["diag"],
        "notes": result["notes"],
    });
    if let Some(s) = result.get("secrets").filter(|s| !s.is_null()) {
        a["secrets"] = s.clone();
    }
    a
}

/// An answer for a question the sensor could not run at all (bad question, beat-probe crashed, time limit).
pub fn answer_error(kind: &str, message: &str) -> Value {
    json!({
        "v": 1, "outcome": "error", "records": [], "failures": [],
        "error": {"kind": kind, "message": message, "span": ""}, "diag": "", "notes": [],
    })
}

/// Room left for the headers when an answer is checked against the server's message limit.
pub const HEADROOM: usize = 8 * 1024;

/// The answer that replaces one too large to publish (over the server's max_payload): without it the sensor would be
/// silent. It says how large the answer was and where the bytes are (records by subject type, the part before ':'),
/// so the probe's author knows what to aggregate. The same text as src/beat/wire.py `too_large`.
pub fn answer_too_large(answer: &Value, size: usize, limit: usize) -> Value {
    let records = answer["records"].as_array().map(Vec::as_slice).unwrap_or(&[]);
    let mut by_type: std::collections::BTreeMap<String, (usize, usize)> = Default::default();
    for r in records {
        let subject = r["subject"].as_str().unwrap_or("");
        let t = subject.split(':').next().unwrap_or("").to_string();
        let e = by_type.entry(t).or_default();
        e.0 += 1;
        e.1 += canonical(r).len() + 1;
    }
    let mut top: Vec<_> = by_type.into_iter().collect();
    top.sort_by(|a, b| b.1 .1.cmp(&a.1 .1).then(a.0.cmp(&b.0)));
    let parts: Vec<String> = top.iter().take(3)
        .map(|(t, (n, b))| format!("{t}: {n} records, {} KB", b / 1024)).collect();
    let message = format!(
        "answer too large: {size} bytes, {} records, over the {limit}-byte message limit; most bytes by subject type: {}; \
         aggregate in the probe (counts, quantiles, summaries) or emit fewer records",
        records.len(), parts.join("; "));
    let mut a = answer_error("too_large", &message);
    a["notes"] = answer["notes"].clone();
    a
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The same vectors are checked by tests/test_wire.py, so both sides write the same bytes for the same content.
    #[test]
    fn canonical_vectors() {
        let text = std::fs::read_to_string(crate::test_vectors("wire_vectors.json")).unwrap();
        let vectors: Value = serde_json::from_str(&text).unwrap();
        for case in vectors.as_array().unwrap() {
            let bytes = canonical(&case["value"]);
            assert_eq!(String::from_utf8(bytes.clone()).unwrap(), case["canonical"].as_str().unwrap());
            assert_eq!(sha256_hex(&bytes), case["sha256"].as_str().unwrap());
        }
    }

    #[test]
    fn question_with_params_is_refused() {
        let q = br#"{"v":1,"name":"a.star","source":"def main(): pass","libraries":{},"params":{"x":1}}"#;
        assert!(parse_question(q).is_err());
        let q = br#"{"v":1,"name":"a.star","source":"def main(): pass","libraries":{},"params":{}}"#;
        assert_eq!(parse_question(q).unwrap().name, "a.star");
    }

    #[test]
    fn answer_has_no_time() {
        let r = json!({"probe": "x", "name": "a", "started": "t0", "finished": "t1", "outcome": "ok", "records": [],
                       "failures": [], "error": null, "diag": "", "notes": [], "usage": {"wall_ms": 3}});
        let a = String::from_utf8(canonical(&answer_from_result(&r))).unwrap();
        assert!(!a.contains("t0") && !a.contains("wall_ms"));
    }

    #[test]
    fn secrets_section_is_kept_only_when_present() {
        let mut r = json!({"outcome": "ok", "records": [], "failures": [], "error": null, "diag": "", "notes": []});
        assert!(answer_from_result(&r).get("secrets").is_none());
        r["secrets"] = json!({"check": true, "masked": [{"at": "records[0].value", "rule": "github-pat"}], "flagged": []});
        assert_eq!(answer_from_result(&r)["secrets"]["masked"][0]["rule"], "github-pat");
    }

    #[test]
    fn too_large_says_where_the_bytes_are() {
        let recs: Vec<Value> = (0..50).map(|i| json!({"subject": format!("job:{i}"), "key": "state", "value": "FAILED"}))
            .chain([json!({"subject": "host", "key": "os", "value": "x"})]).collect();
        let a = json!({"v": 1, "outcome": "ok", "records": recs, "failures": [], "error": null, "diag": "", "notes": ["n"]});
        let t = answer_too_large(&a, 2_000_000, 1_048_576);
        assert_eq!(t["outcome"], "error");
        assert_eq!(t["error"]["kind"], "too_large");
        let m = t["error"]["message"].as_str().unwrap();
        assert!(m.starts_with("answer too large: 2000000 bytes, 51 records, over the 1048576-byte"), "{m}");
        assert!(m.contains("job: 50 records") && m.find("job:") < m.find("host:"), "{m}");
        assert_eq!(t["records"], json!([]));
        assert_eq!(t["notes"], json!(["n"]));
    }
}
