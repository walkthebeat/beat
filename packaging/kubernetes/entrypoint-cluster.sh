#!@shell@
# The cluster sensor (beat-cluster.yaml): one per cluster, in a pod that is not privileged,
# no host to read. It enrols with its pod's projected token under a trust policy of its own (the cluster's name and
# `_api`, `beat org trust add --sensor-name`) and runs each question sandboxed by Landlock and seccomp
# (sensor/src/landlock.rs). /etc and /var/lib/beat-sensor are the pod's emptyDirs: it runs as no root, and a new pod
# is a new key under the same name (the policy's replacement rule). From the ConfigMap: BEAT_API, BEAT_ORG_ROOT,
# BEAT_CLUSTER.
set -eu
: "${BEAT_API:?BEAT_API: the beat service (the ConfigMap)}" "${BEAT_ORG_ROOT:?BEAT_ORG_ROOT: NAME=KEY (the ConfigMap)}"
export PATH=@path@ SSL_CERT_FILE=@cacert@
mkdir -p /var/lib/beat-sensor/wasm-cache /var/lib/beat-sensor/state
@probe@ tools --tools @tools@ --cache /var/lib/beat-sensor/wasm-cache >/dev/null
@sensor@/bin/beat-sensor configure --api "$BEAT_API" --org-root "$BEAT_ORG_ROOT" \
  --attest "oidc:${BEAT_TOKEN:-/var/run/secrets/beat/token}"
set -a; . /etc/beat-sensor.env; set +a
exec @sensor@/bin/beat-sensor --nats "$BEAT_NATS" --api "$BEAT_API" --name "$BEAT_SENSOR_NAME" \
  --version "@version@" --probe @probe@ --tools @tools@ --cache /var/lib/beat-sensor/wasm-cache \
  --landlock --seccomp @seccomp_cluster@ \
  --key /var/lib/beat-sensor/keys/sensor.key --roots /etc/beat-sensor/roots \
  --deny /var/lib/beat-sensor/state/deny.json --collector-keys /etc/beat-sensor/collectors \
  --label platform=kubernetes --label role=cluster ${BEAT_CLUSTER:+--label "cluster=$BEAT_CLUSTER"}
