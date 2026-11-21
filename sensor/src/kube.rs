//! --kube DIR: the cluster sensor's view of the cluster's API (packaging/kubernetes/beat-cluster.yaml). It lists and watches the
//! kinds in RESOURCES with its service account's token (read-only RBAC, never Secrets or ConfigMaps) and keeps each
//! kind in DIR/<Kind>.json: a line of what the watch knows ({kind, synced, error, count}), then an object per line, as
//! the API gives them less managedFields and last-applied-configuration. Questions have no network: each gets these
//! files as open descriptors (runner.rs, BEAT_K8S), so Landlock never lets it open DIR, and beat-probe's k8s() reads
//! them. Env values stay in the files: k8s() gives them to the question as environ() does (a value only for names
//! known to be safe, otherwise a token), so a spec and a process's environment hash alike.
//!
//! Plain HTTPS (ureq, rustls with the cluster's CA): no Kubernetes client crate, whose dependencies would double the
//! sensor's build. One thread per kind: list in pages, then watch from the list's resourceVersion; a 410 (too old)
//! lists again; an error is kept in the kind's file and retried with backoff.

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde_json::{json, Value};
use ureq::rustls;

/// (Kind, the API path listing it across namespaces): what "why pending", rollouts and services are answered from.
pub const RESOURCES: &[(&str, &str)] = &[
    ("Pod", "/api/v1/pods"),
    ("Event", "/api/v1/events"),
    ("Node", "/api/v1/nodes"),
    ("Namespace", "/api/v1/namespaces"),
    ("Service", "/api/v1/services"),
    ("PersistentVolumeClaim", "/api/v1/persistentvolumeclaims"),
    ("PersistentVolume", "/api/v1/persistentvolumes"),
    ("ResourceQuota", "/api/v1/resourcequotas"),
    ("LimitRange", "/api/v1/limitranges"),
    ("Deployment", "/apis/apps/v1/deployments"),
    ("ReplicaSet", "/apis/apps/v1/replicasets"),
    ("StatefulSet", "/apis/apps/v1/statefulsets"),
    ("DaemonSet", "/apis/apps/v1/daemonsets"),
    ("Job", "/apis/batch/v1/jobs"),
    ("CronJob", "/apis/batch/v1/cronjobs"),
    ("EndpointSlice", "/apis/discovery.k8s.io/v1/endpointslices"),
    ("HorizontalPodAutoscaler", "/apis/autoscaling/v2/horizontalpodautoscalers"),
    ("PodDisruptionBudget", "/apis/policy/v1/poddisruptionbudgets"),
    ("StorageClass", "/apis/storage.k8s.io/v1/storageclasses"),
    ("PriorityClass", "/apis/scheduling.k8s.io/v1/priorityclasses"),
];

const SA: &str = "/var/run/secrets/kubernetes.io/serviceaccount";
/// The API server ends a watch after this; the read timeout is a little longer (bookmarks arrive meanwhile).
const WATCH_S: u64 = 290;
const WRITE_EVERY: Duration = Duration::from_secs(2);

pub struct Api {
    base: String,
    agent: ureq::Agent,
    token: PathBuf,
}

impl Api {
    /// From the pod's service account and the API's Service (KUBERNETES_SERVICE_HOST/PORT).
    pub fn in_cluster() -> Result<Api, String> {
        let host = std::env::var("KUBERNETES_SERVICE_HOST").map_err(|_| "KUBERNETES_SERVICE_HOST is not set: not in a pod?")?;
        let port = std::env::var("KUBERNETES_SERVICE_PORT").unwrap_or_else(|_| "443".into());
        let base = if host.contains(':') { format!("https://[{host}]:{port}") } else { format!("https://{host}:{port}") };
        let ca = Path::new(SA).join("ca.crt");
        let pem = std::fs::read(&ca).map_err(|e| format!("{}: {e}", ca.display()))?;
        let mut roots = rustls::RootCertStore::empty();
        use rustls::pki_types::{pem::PemObject, CertificateDer};
        for c in CertificateDer::pem_slice_iter(&pem) {
            roots.add(c.map_err(|e| format!("{}: {e:?}", ca.display()))?).map_err(|e| format!("{}: {e}", ca.display()))?;
        }
        let tls = rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions().map_err(|e| e.to_string())?
            .with_root_certificates(roots).with_no_client_auth();
        let agent = ureq::AgentBuilder::new().tls_config(Arc::new(tls)).timeout_connect(Duration::from_secs(10))
            .timeout_read(Duration::from_secs(WATCH_S + 30)).build();
        Ok(Api { base, agent, token: Path::new(SA).join("token") })
    }

    fn get(&self, path: &str) -> Result<ureq::Response, String> {
        // Read each time: the kubelet rotates the token.
        let token = std::fs::read_to_string(&self.token).map_err(|e| format!("{}: {e}", self.token.display()))?;
        self.agent.get(&format!("{}{path}", self.base)).set("Authorization", &format!("Bearer {}", token.trim()))
            .set("Accept", "application/json").call().map_err(|e| match e {
                ureq::Error::Status(code, r) => {
                    let body = r.into_string().unwrap_or_default();
                    let msg = serde_json::from_str::<Value>(&body).ok()
                        .and_then(|v| v["message"].as_str().map(String::from)).unwrap_or(body);
                    format!("{code}: {msg}")
                }
                e => e.to_string(),
            })
    }
}

#[derive(Default)]
struct Kind {
    items: HashMap<String, Value>,
    synced: Option<u64>,
    error: Option<String>,
    dirty: bool,
}

/// Every kind's objects, written to DIR when they change.
pub struct Store {
    dir: PathBuf,
    kinds: Mutex<HashMap<&'static str, Kind>>,
}

impl Store {
    pub fn new(dir: &Path) -> Result<Store, String> {
        std::fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
        let kinds = RESOURCES.iter().map(|(k, _)| (*k, Kind { dirty: true, ..Default::default() })).collect();
        Ok(Store { dir: dir.into(), kinds: Mutex::new(kinds) })
    }

    fn with<R>(&self, kind: &'static str, f: impl FnOnce(&mut Kind) -> R) -> R {
        let mut kinds = self.kinds.lock().unwrap();
        let k = kinds.get_mut(kind).expect("a kind of RESOURCES");
        k.dirty = true;
        f(k)
    }

    /// The kinds whose objects changed, each written whole to a new file renamed over the old: a question's
    /// descriptor keeps the version it opened.
    pub fn write_changed(&self) {
        let changed: Vec<(&str, Vec<u8>)> = {
            let mut kinds = self.kinds.lock().unwrap();
            kinds.iter_mut().filter(|(_, k)| k.dirty).map(|(name, k)| {
                k.dirty = false;
                (*name, file_text(name, k))
            }).collect()
        };
        for (name, text) in changed {
            let (tmp, path) = (self.dir.join(format!(".{name}.json")), self.dir.join(format!("{name}.json")));
            if let Err(e) = std::fs::File::create(&tmp).and_then(|mut f| f.write_all(&text)).and_then(|_| std::fs::rename(&tmp, &path)) {
                eprintln!("kube: cannot write {}: {e}", path.display());
            }
        }
    }
}

fn file_text(name: &str, k: &Kind) -> Vec<u8> {
    let mut out = serde_json::to_vec(&json!({"kind": name, "synced": k.synced, "error": k.error, "count": k.items.len()}))
        .expect("json");
    out.push(b'\n');
    let mut keys: Vec<&String> = k.items.keys().collect();
    keys.sort();
    for key in keys {
        serde_json::to_writer(&mut out, &k.items[key]).expect("json");
        out.push(b'\n');
    }
    out
}

/// What no question needs and the API repeats in every object.
fn trim(mut v: Value) -> Value {
    if let Some(m) = v.get_mut("metadata").and_then(Value::as_object_mut) {
        m.remove("managedFields");
        if let Some(a) = m.get_mut("annotations").and_then(Value::as_object_mut) {
            a.remove("kubectl.kubernetes.io/last-applied-configuration");
        }
    }
    v
}

fn uid(v: &Value) -> String {
    let m = &v["metadata"];
    m["uid"].as_str().map(String::from)
        .unwrap_or_else(|| format!("{}/{}", m["namespace"].as_str().unwrap_or(""), m["name"].as_str().unwrap_or("")))
}

fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// For a query parameter (continue tokens are base64).
fn escape(s: &str) -> String {
    s.bytes().map(|b| match b {
        b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => (b as char).to_string(),
        _ => format!("%{b:02X}"),
    }).collect()
}

enum Ended {
    /// The resourceVersion is too old (410): list again.
    Relist,
    Failed(String),
}

/// One kind, for ever: list, then watch until the version expires; errors kept in the file and retried.
fn keep(api: &Api, store: &Store, kind: &'static str, path: &str) -> ! {
    let mut backoff = 5;
    loop {
        let ended = list(api, store, kind, path).and_then(|rv| { backoff = 5; Ok(watch(api, store, kind, path, rv)) });
        match ended {
            Ok(Ended::Relist) => continue,
            Ok(Ended::Failed(e)) | Err(e) => {
                eprintln!("kube {kind}: {e}");
                store.with(kind, |k| k.error = Some(format!("{e} (at {})", now())));
                std::thread::sleep(Duration::from_secs(backoff));
                backoff = (backoff * 2).min(120);
            }
        }
    }
}

fn list(api: &Api, store: &Store, kind: &'static str, path: &str) -> Result<String, String> {
    let mut items = HashMap::new();
    let mut cont = String::new();
    loop {
        let q = format!("{path}?limit=500{}", if cont.is_empty() { String::new() } else { format!("&continue={}", escape(&cont)) });
        let page: Value = serde_json::from_reader(api.get(&q)?.into_reader()).map_err(|e| format!("{q}: {e}"))?;
        for it in page["items"].as_array().into_iter().flatten() {
            let it = trim(it.clone());
            items.insert(uid(&it), it);
        }
        cont = page["metadata"]["continue"].as_str().unwrap_or("").to_string();
        if cont.is_empty() {
            let rv = page["metadata"]["resourceVersion"].as_str().unwrap_or("").to_string();
            store.with(kind, |k| { k.items = items; k.synced = Some(now()); k.error = None; });
            return Ok(rv);
        }
    }
}

fn watch(api: &Api, store: &Store, kind: &'static str, path: &str, mut rv: String) -> Ended {
    loop {
        let q = format!("{path}?watch=1&allowWatchBookmarks=true&timeoutSeconds={WATCH_S}&resourceVersion={}", escape(&rv));
        let r = match api.get(&q) {
            Ok(r) => r,
            Err(e) if e.starts_with("410") => return Ended::Relist,
            Err(e) => return Ended::Failed(e),
        };
        for line in BufReader::new(r.into_reader()).lines() {
            let line = match line {
                Ok(l) => l,
                Err(e) => return Ended::Failed(format!("watch: {e}")),
            };
            let Ok(ev) = serde_json::from_str::<Value>(&line) else { return Ended::Failed(format!("watch: not JSON: {line:.200}")) };
            let obj = &ev["object"];
            match ev["type"].as_str().unwrap_or("") {
                "ERROR" if obj["code"] == 410 => return Ended::Relist,
                "ERROR" => return Ended::Failed(format!("watch: {}", obj["message"].as_str().unwrap_or(&line))),
                t => {
                    if let Some(v) = obj["metadata"]["resourceVersion"].as_str() {
                        rv = v.to_string();
                    }
                    match t {
                        "ADDED" | "MODIFIED" => { let o = trim(obj.clone()); store.with(kind, |k| k.items.insert(uid(&o), o)); }
                        "DELETED" => { store.with(kind, |k| k.items.remove(&uid(obj))); }
                        _ => {}  // BOOKMARK: only the version
                    }
                }
            }
        }
        // The server ended the watch (timeoutSeconds): again from the last version seen.
    }
}

/// A thread per kind and one writing the files; runs for the sensor's life.
pub fn start(dir: &Path) -> Result<(), String> {
    let api = Arc::new(Api::in_cluster()?);
    let store = Arc::new(Store::new(dir)?);
    store.write_changed();
    for (kind, path) in RESOURCES {
        let (api, store) = (api.clone(), store.clone());
        std::thread::Builder::new().name(format!("kube {kind}")).spawn(move || keep(&api, &store, kind, path))
            .map_err(|e| e.to_string())?;
    }
    std::thread::Builder::new().name("kube writer".into()).spawn(move || loop {
        std::thread::sleep(WRITE_EVERY);
        store.write_changed();
    }).map_err(|e| e.to_string())?;
    Ok(())
}

/// The snapshot's files, opened for one question: (Kind, file). Kinds not written yet are left out.
pub fn open(dir: &Path) -> Vec<(&'static str, std::fs::File)> {
    RESOURCES.iter().filter_map(|(k, _)| std::fs::File::open(dir.join(format!("{k}.json"))).ok().map(|f| (*k, f))).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn objects_lose_what_no_question_needs() {
        let o = trim(json!({"metadata": {"name": "a", "uid": "u1", "managedFields": [{}],
            "annotations": {"kubectl.kubernetes.io/last-applied-configuration": "{...}", "keep": "me"}}, "spec": {}}));
        assert_eq!(o, json!({"metadata": {"name": "a", "uid": "u1", "annotations": {"keep": "me"}}, "spec": {}}));
        assert_eq!(uid(&o), "u1");
        assert_eq!(uid(&json!({"metadata": {"name": "n", "namespace": "ns"}})), "ns/n");
    }

    #[test]
    fn files_are_a_status_line_then_objects() {
        let dir = std::env::temp_dir().join(format!("beat-kube-{}", std::process::id()));
        let store = Store::new(&dir).unwrap();
        store.with("Pod", |k| { k.items.insert("b".into(), json!({"n": 2})); k.items.insert("a".into(), json!({"n": 1})); k.synced = Some(7); });
        store.write_changed();
        let text = std::fs::read_to_string(dir.join("Pod.json")).unwrap();
        assert_eq!(text, "{\"count\":2,\"error\":null,\"kind\":\"Pod\",\"synced\":7}\n{\"n\":1}\n{\"n\":2}\n");
        let node = std::fs::read_to_string(dir.join("Node.json")).unwrap();
        assert!(node.starts_with("{\"count\":0,\"error\":null,\"kind\":\"Node\",\"synced\":null}"), "{node}");
        assert_eq!(open(&dir).len(), RESOURCES.len());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn continue_tokens_are_escaped() {
        assert_eq!(escape("eyJ2+/="), "eyJ2%2B%2F%3D");
    }
}
