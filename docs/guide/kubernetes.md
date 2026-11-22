# beat on Kubernetes (experimental)

On a cluster, beat is two kinds of sensor, both from one image, `ghcr.io/walkthebeat/beat-sensor`:

```
 your laptop: beat, your agent            the beat service            the cluster
 ─────────────────────────────            ────────────────            ───────────
 signs each question ──── HTTPS ────────►  countersigns, carries ◄──── every sensor connects out (wss, 443);
 reads the answers   ◄───────────────────  keeps the answers            nothing listens, nothing is exposed

                                                                       node 1          node 2          node N
                                                                      ┌───────────┐   ┌───────────┐   ┌───────────┐
                         node sensors (DaemonSet beat-sensor) ──────► │ beat-sensor│   │ beat-sensor│   │ beat-sensor│
                         <cluster>_<node>: the node and every         └───────────┘   └───────────┘   └───────────┘
                         container on it, as root sees them               │ one of the nodes
                                                                     ┌────▼──────────┐   watch, get, list   ┌──────────┐
                         the cluster sensor (Deployment beat-cluster)│ beat-cluster  │ ───────────────────► │ the API  │
                         <cluster>_api: what only the API knows      └───────────────┘   (read-only role)   └──────────┘
```

- **A node sensor** per node (DaemonSet `beat-sensor`) answers for that node and every container on it: processes and
  their cgroups, files (a container's through `/proc/<pid>/root`), logs under `/var/log/pods`, sockets, kernel state,
  eBPF traces (`trace()`), packet captures (`capture()`). It is privileged, which is root on the node, as the host
  install is, so it can sandbox each question itself; the question runs unprivileged, read-only, with no network.
- **The cluster sensor**, one per cluster (Deployment `beat-cluster`), answers what only the API knows: why a pod is
  Pending, Events, rollouts, quotas, Services and their endpoints. It is an ordinary pod (Pod Security "restricted": not
  root, no capabilities, no host access) that watches the API with a read-only ClusterRole, and questions read its
  snapshot with `k8s()`.

Both enrol with their pods' own service-account tokens, which the beat service checks against your cluster's issuer:
no secret to create or hand out. They run only questions signed by a member of your org. The full model, with each
claim's place in the code: [`docs/security.md`](https://github.com/walkthebeat/beat/blob/main/docs/security.md), "A
sensor in a Kubernetes pod" and "The cluster sensor".

Experimental: tried on k3s with Debian 12 and AlmaLinux 9 nodes (SELinux enforcing), and in our labs
([walkthebeat/labs](https://github.com/walkthebeat/labs), scenario `k8s`).

## What the cluster needs

- Kubernetes 1.30 or later: a pod's token then names its node, which names the node sensor.
- Linux nodes on x86_64 with cgroup v2 (every current distribution; not Windows nodes, not EKS Fargate).
- A namespace that allows privileged pods, for the node sensors: the manifest makes `beat`, labelled for Pod Security
  Admission.
- For the cluster sensor, a node kernel with Landlock (Linux 5.13 or later, enabled: the default on current
  distributions).
- Nodes that can pull from `ghcr.io`, or a registry of yours you copy the image to.
- Sandboxed runtimes (gVisor, Kata) hide their containers' processes from the node: a sensor cannot see inside them.

And on your laptop: beat 0.4 or later, signed in to your org (getting started, steps 1-4), and `kubectl` for the
cluster.

## Install

### 1. The manifests

Each release carries them with its image already named: `beat-sensor.yaml` (the namespace, the node sensors) and
`beat-cluster.yaml` (the cluster sensor and its read-only ClusterRole).

```
v=$(beat --version | awk '{print $2}')     # the manifests of your client's release
curl -fsSLO https://github.com/walkthebeat/beat/releases/download/v$v/beat-sensor.yaml
curl -fsSLO https://github.com/walkthebeat/beat/releases/download/v$v/beat-cluster.yaml
```

Read them before you apply them: each starts with what it is given, and why.

### 2. Trust the cluster

The service admits the cluster's sensors by their tokens, checked against the cluster's service-account issuer. Get
the issuer and its keys:

```
kubectl get --raw /.well-known/openid-configuration      # its "issuer"
kubectl get --raw /openid/v1/jwks > cluster-jwks.json
```

Then add two trust policies to your org, one for each kind of sensor, here for a cluster you call `my-cluster`:

```
beat org trust add my-cluster --issuer ISSUER --jwks cluster-jwks.json \
  --claim kubernetes.io/namespace=beat --claim kubernetes.io/serviceaccount/name=beat-sensor \
  --sensor-name '{policy}_{kubernetes.io/node/name}'
beat org trust add my-cluster-api --issuer ISSUER --jwks cluster-jwks.json \
  --claim kubernetes.io/namespace=beat --claim kubernetes.io/serviceaccount/name=beat-cluster \
  --sensor-name my-cluster_api
```

- The two claims say which workload may be a sensor: any pod can get a token for itself, and only the `beat-sensor` and
  `beat-cluster` service accounts in `beat` are sensors.
- Node sensors are named after the cluster and the node, `my-cluster_ip-10-0-1-17`: node names repeat across clusters,
  and never hold `_`. The cluster sensor is `my-cluster_api`.
- `--jwks` pins the keys, for an issuer the service cannot reach (most clusters). An issuer on the internet (EKS, GKE,
  AKS) can leave it out. When the cluster rotates its signing keys, run both commands again with the new keys.

### 3. Your org's values, then apply

`beat sensors add` prints the two values a sensor needs: `--api` and `--org-root`. Put them in `beat-sensor.yaml`'s
ConfigMap (`beat-cluster.yaml` uses the same one), with the cluster's name:

```yaml
data:
  BEAT_API: "https://api.walkthebeat.ai/o/..."   # --api
  BEAT_ORG_ROOT: "...=..."                         # --org-root
  BEAT_CLUSTER: "my-cluster"                       # a label on every sensor of this cluster
```

Then:

```
kubectl apply -f beat-sensor.yaml
kubectl apply -f beat-cluster.yaml                     # after beat-sensor.yaml: it uses its namespace and ConfigMap
kubectl -n beat logs ds/beat-sensor | grep -i enrolled  # "Enrolled by trust policy my-cluster: my-cluster_<node> ..."
beat sensors
```

`beat sensors` lists one sensor per node, labelled `cluster=my-cluster platform=kubernetes`, and `my-cluster_api`,
labelled `role=cluster` and shown as "the cluster's API".

## Asking

In an estate (getting started, step 8), your agent asks the cluster's sensors like any others, by name. Or from a
shell:

```
beat run k8s-pending my-cluster_api      # every Pending pod, and why; every workload short of pods
beat probes run                          # the pack: API probes go to cluster sensors, the others to the nodes
```

`k8s-pending`, in beat's pack, gives every Pending pod with the scheduler's own reason and the evidence it points to
(requests, node selectors and affinity, taints and tolerations, each node's free capacity, volume claims and
StorageClasses, quotas), and every workload whose pods are not being created at all (a quota, admission). It collects
the evidence; the agent reasons over it.

A question of your own for the cluster sensor, `web.star`, then `beat ask web.star --host my-cluster_api --show`:

```python
def main() -> None:
    for p in k8s("pod", namespace = "shop", selector = "app=web"):
        emit(p["metadata"]["name"], "phase", p["status"]["phase"], "k8s.pod")
```

The useful questions often take both kinds: the API says a pod restarts and on which node, the node sensor reads its
log and its sockets there. An agent does that on its own.

## What a question can and cannot see

| | Node sensor | Cluster sensor |
| --- | --- | --- |
| Reads | the node and its containers, as root reads them: processes, files, logs, sockets, cgroups, kernel state; eBPF tools and packet captures | a snapshot of 20 kinds from the API: pods, nodes, events, workloads, Services and endpoints, claims and StorageClasses, quotas, HPAs, PDBs, ... (`sensor/src/kube.rs`) |
| Never | the contents of secret files: pods' mounted Secrets and service-account tokens, the kubelet's and k3s's keys, `/etc/shadow`, ... (a question sees that they exist, and their metadata) | Secrets and ConfigMaps (not in its role); an env value other than a short list of safe names (a token, compared across pods as a keyed hash); `managedFields` |
| Writes | nothing: read-only file system, no network | nothing: no verb that writes, no socket |

## Known limits

- No way yet to ask "every sensor of this cluster" or "the nodes running app=web" in one flag: name the sensors, or
  let the agent pick them from `beat sensors` and `k8s("pod")`. Asking by label is next.
- `trace()` is refused on kernels with `kernel.perf_event_paranoid` 3 (Debian's default): the eBPF tools need
  `CAP_SYS_ADMIN` there, which questions do not get.
- On a node sensor, no pod-aware built-ins yet: a question finds a pod from its cgroup path or its log directory's
  name, and the cluster sensor's `k8s("pod")` gives a pod's node and container IDs.
- Who changed an object, and when, is not kept yet (the API's `managedFields` are dropped).
- `k8s-pending` covers Pending pods and missing ones, not pods that run and fail (a crash loop): an agent finds those
  with a question of its own.

## Remove

```
kubectl delete -f beat-cluster.yaml -f beat-sensor.yaml
beat sensors remove NAME                # each node's sensor, and my-cluster_api, at the service
beat org trust remove my-cluster; beat org trust remove my-cluster-api
```

Each node keeps `/var/lib/beat-sensor` (the sensor's key and state): remove it to forget the sensor there.
