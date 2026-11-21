# The sensor on Kubernetes (experimental)

On a Kubernetes cluster the sensor runs as a DaemonSet: one pod per node, which answers for that node and every
container on it. It enrols with its pod's own token, so there is no secret to hand out, and each sensor is named
after its node. What the pod is allowed and how questions stay read-only inside it: `docs/security.md`, "A sensor in
a Kubernetes pod".

Experimental: tried on k3s with Debian 12 and AlmaLinux 9 nodes (SELinux enforcing). The image is not published yet:
you build it.

## What the cluster needs

- Linux nodes on x86_64 with cgroup v2 (every current distribution; not Windows nodes, not EKS Fargate).
- A namespace that allows privileged pods (the manifest makes `beat`, labelled for Pod Security Admission).
- Kubernetes 1.30 or later: the pod's token then names its node, which names the sensor.
- Sandboxed runtimes (gVisor, Kata) hide their containers' processes from the node: a sensor cannot see inside them.

## 1. The image

```
nix build github:walkthebeat/beat#beat-sensor-oci
./result | docker load            # or: ./result | sudo k3s ctr images import -   (on each node)
```

Push it to a registry your nodes pull from, or import it on each node.

## 2. A trust policy for the cluster

The service admits the cluster's sensors by their tokens, checked against the cluster's service-account issuer. Its
issuer and keys:

```
kubectl get --raw /.well-known/openid-configuration      # "issuer"
kubectl get --raw /openid/v1/jwks > cluster-jwks.json
```

Then, signed in as a member of your org:

```
beat org trust add my-cluster --issuer ISSUER --jwks cluster-jwks.json \
  --claim kubernetes.io/namespace=beat --claim kubernetes.io/serviceaccount/name=beat-sensor \
  --sensor-name '{policy}_{kubernetes.io/node/name}'
```

`--jwks` pins the keys, for an issuer the service cannot reach (most clusters); an issuer on the internet (EKS, GKE,
AKS) can leave it out. The two claims say which workload may be a sensor: any pod can get a token for itself, and
only the `beat-sensor` service account in `beat` is one. Each sensor is named after its cluster and its node,
`my-cluster_ip-10-0-1-17`: node names repeat across clusters, and a node name never holds `_`. When the cluster rotates its signing keys, run the command
again with the new keys.

## 3. Apply

In `packaging/kubernetes/beat-sensor.yaml`, set the ConfigMap's `BEAT_API` and `BEAT_ORG_ROOT` to the two values
`beat sensors add` prints (`--api` and `--org-root`), `BEAT_CLUSTER` to a name for the cluster, and the image to
yours. Then:

```
kubectl apply -f beat-sensor.yaml
kubectl -n beat logs ds/beat-sensor     # "Enrolled by trust policy my-cluster: my-cluster_<node> is enrolled"
beat sensors                            # one per node, labelled cluster=my-cluster platform=kubernetes
```

Questions then see the node and its containers: their processes and cgroups, their files through `/proc/<pid>/root`,
their logs under `/var/log/pods`, their traffic with `capture()`. Pods' Secrets and service-account tokens are secret
files: a question sees that they exist, never their contents.

## The cluster sensor

The node sensors see the nodes. What only the API knows, such as why a pod is Pending, its Events, a rollout or a
quota, comes from one more sensor, `<cluster>_api`: an ordinary pod (not privileged) that watches the API with a
read-only ClusterRole and gives questions `k8s()` (`docs/probes.md` [B11c]). Its trust policy names it by its service
account:

```
beat org trust add my-cluster-api --issuer ISSUER [--jwks cluster-jwks.json] \
  --claim kubernetes.io/namespace=beat --claim kubernetes.io/serviceaccount/name=beat-cluster \
  --sensor-name my-cluster_api
kubectl apply -f beat-cluster.yaml      # after beat-sensor.yaml: it uses its namespace and ConfigMap
beat sensors                            # my-cluster_api, labelled role=cluster
```

A question for it, `web.star`, then `beat ask web.star --host my-cluster_api --show`:

```python
def main() -> None:
    for p in k8s("pod", namespace = "shop", selector = "app=web"):
        emit(p["metadata"]["name"], "phase", p["status"]["phase"], "k8s.pod")
```

Its node needs Landlock (Linux 5.13 or later, enabled: the default on current distributions).

## Known limits

- `trace()` is refused on kernels with `kernel.perf_event_paranoid` 3 (Debian's default): the eBPF tools need
  `CAP_SYS_ADMIN` there, which questions do not get.
- On a node sensor, no pod-aware built-ins yet: a question finds a pod from its cgroup path or its log directory's
  name, and the cluster sensor's `k8s("pod")` gives the pod's node and container IDs.

## Remove

```
kubectl delete -f beat-cluster.yaml -f beat-sensor.yaml
beat sensors remove NODE                # each node's sensor, and my-cluster_api, at the service
```

The node keeps `/var/lib/beat-sensor` (the sensor's key and state): remove it to forget the sensor there.
