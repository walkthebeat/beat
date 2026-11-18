#!@shell@
# beat-sensor in a pod (packaging/kubernetes): enrols with the pod's projected service-account token (a trust policy
# of the org names it after its node, docs/security.md H13), then runs with each question sandboxed by bubblewrap in a
# cgroup of the pod's own (sensor/src/bwrap.rs). From the ConfigMap: BEAT_API, BEAT_ORG_ROOT (NAME=KEY, the line
# `beat sensors add` prints). Paths the questions must see are hostPaths at the same path on the host and in the pod:
# /var/lib/beat-sensor (key, state, compiled tools) and /run/beat-sensor (each question's files).
set -eu
: "${BEAT_API:?BEAT_API: the beat service (the ConfigMap)}" "${BEAT_ORG_ROOT:?BEAT_ORG_ROOT: NAME=KEY (the ConfigMap)}"
export PATH=@path@ SSL_CERT_FILE=@cacert@
mkdir -p /var/lib/beat-sensor/wasm-cache /var/lib/beat-sensor/state /run/beat-sensor
chmod 700 /run/beat-sensor
@probe@ tools --tools @tools@ --cache /var/lib/beat-sensor/wasm-cache >/dev/null
@sensor@/bin/beat-sensor configure --api "$BEAT_API" --org-root "$BEAT_ORG_ROOT" \
  --attest "oidc:${BEAT_TOKEN:-/var/run/secrets/beat/token}"
set -a; . /etc/beat-sensor.env; set +a
exec @sensor@/bin/beat-sensor --nats "$BEAT_NATS" --api "$BEAT_API" --name "$BEAT_SENSOR_NAME" \
  --version "@version@" --probe @probe@ --tools @tools@ --cache /var/lib/beat-sensor/wasm-cache \
  --osqueryi @osqueryi@ --journalctl /usr/bin/journalctl --bpf-tools @bpftools@ \
  --placeholders @placeholders@ --key /var/lib/beat-sensor/keys/sensor.key --roots /etc/beat-sensor/roots \
  --deny /var/lib/beat-sensor/state/deny.json --collector-keys /etc/beat-sensor/collectors \
  --label platform=kubernetes ${BEAT_CLUSTER:+--label "cluster=$BEAT_CLUSTER"} \
  --tcpdump @tcpdump@ \
  --bwrap @bwrap@ --setpriv @setpriv@ --seccomp @seccomp@ --seccomp-capture @seccomp_capture@ --host-root /host --question-uid "${BEAT_QUESTION_UID:-64321}"
