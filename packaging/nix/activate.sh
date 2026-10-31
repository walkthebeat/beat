#!@shell@
# beat-sensor-activate --nats URL --name NAME --org-root NAME=KEY... --collector-key NAME=KEY...: make this build
# (@out@) the running sensor.
# Run as root on the target, after its closure has been copied into /nix/store (`nix copy`; a deployment tool does both).
# Idempotent; activating an older build is a rollback. Without arguments, keeps /etc/beat-sensor.env and the keys as
# they are. --org-root, once per root (`beat keys deployed`: name and base64 public key): the org roots whose
# members' questions it runs (docs/security.md H16), one file each in /etc/beat-sensor/roots/<name>.pub; --collector-key (`beat-service keys deployed`)
# likewise, the keys they must be countersigned with, in /etc/beat-sensor/collectors/. Given at all, a kind's keys
# replace its directory's contents (a key left out is removed: rotation). The sensor's own signing key is made here
# once (/var/lib/beat-sensor/keys/sensor.key, root only, hidden from questions); its public key is printed as
# "sensor-key NAME KEY" for the deployment tool to enroll. The sensor is restarted only when its build, settings or
# unit changed (or it is not running): it reads the keys for every question, so new keys need no restart
# (activate again with the new keys).
set -euo pipefail
export PATH=/usr/sbin:/usr/bin:/sbin:/bin # the host's own systemctl; not from the store
out=@out@

nats="" name="" orgs=() collectors=()
while [ $# -gt 0 ]; do
  case "$1" in
    --nats) nats="$2"; shift 2;;
    --name) name="$2"; shift 2;;
    --org-root) orgs+=("$2"); shift 2;;
    --collector-key) collectors+=("$2"); shift 2;;
    *) echo "unknown argument $1" >&2; exit 2;;
  esac
done
env_before="$(cat /etc/beat-sensor.env 2>/dev/null || true)"
if [ -n "$nats" ]; then
  printf 'BEAT_NATS=%s\nBEAT_SENSOR_NAME=%s\n' "$nats" "${name:-$(hostname)}" > /etc/beat-sensor.env
fi
[ -f /etc/beat-sensor.env ] || { echo "no /etc/beat-sensor.env: activate with --nats URL --name NAME" >&2; exit 1; }
mkdir -p /etc/beat-sensor
# put_keys DIR FLAG NAME=KEY...: DIR holds exactly these keys (replaced in one rename); none given: left as it is.
put_keys() {
  local keys="$1" flag="$2" new c n k; shift 2
  if [ $# -gt 0 ]; then
    new="$(mktemp -d -p /etc/beat-sensor)"
    for c in "$@"; do
      n="${c%%=*}" k="${c#*=}"
      case "$n" in ""|*[!A-Za-z0-9_-]*|"$c") echo "$flag $c: expected NAME=KEY" >&2; rm -rf "$new"; exit 2;; esac
      printf '%s\n' "$k" > "$new/$n.pub"
    done
    chmod 0755 "$new"
    rm -rf "$keys.old"; [ ! -d "$keys" ] || mv "$keys" "$keys.old"
    mv "$new" "$keys" && rm -rf "$keys.old"
  fi
  ls "$keys"/*.pub >/dev/null 2>&1 || { echo "no key in $keys: activate with $flag NAME=KEY" >&2; exit 1; }
}
put_keys /etc/beat-sensor/roots --org-root ${orgs[@]+"${orgs[@]}"}
rm -rf /etc/beat-sensor/org  # before roots (H16): signing keys
put_keys /etc/beat-sensor/collectors --collector-key ${collectors[@]+"${collectors[@]}"}
install -d -m 0700 /var/lib/beat-sensor/keys
echo "sensor-key $(. /etc/beat-sensor.env; echo "$BEAT_SENSOR_NAME") $(@sensor@ keygen /var/lib/beat-sensor/keys/sensor.key)"

mkdir -p /opt/beat-sensor
prev="$(readlink /opt/beat-sensor/current || true)"
ln -sfn "$out" /opt/beat-sensor/current.new && mv -T /opt/beat-sensor/current.new /opt/beat-sensor/current
[ "$prev" = "$out" ] || echo "$(date -u +%FT%TZ) $out" >> /opt/beat-sensor/history

# Compile the WASM tools behind pipe() once, here: question runs see this cache read-only.
mkdir -p /var/lib/beat-sensor/wasm-cache
@probe@ tools --tools @tools@ --cache /var/lib/beat-sensor/wasm-cache >/dev/null

# SELinux (RHEL family): store paths arrive labelled root_t, which systemd (init_t) may not execute (status 203/EXEC).
# Label the store like /usr/bin: persistently when semanage is installed, else with chcon (lost on a full relabel).
if command -v selinuxenabled >/dev/null && selinuxenabled; then
  if command -v semanage >/dev/null; then
    semanage fcontext -l | grep -q '^/nix/store(/\.\*)?' || semanage fcontext -a -t bin_t '/nix/store(/.*)?'
    restorecon -R /nix/store
  else
    chcon -R -t bin_t /nix/store
  fi
fi

# The HTTP sensor this one replaced (beat-sensor2: root on tcp/8480, no auth; removed 2026-10-14): stop and delete it
# where an older deployment left it.
if [ -e /etc/systemd/system/beat-sensor2.service ] || [ -e /opt/beat-sensor2 ]; then
  systemctl disable --now beat-sensor2 >/dev/null 2>&1 || true
  rm -rf /etc/systemd/system/beat-sensor2.service /opt/beat-sensor2 /usr/local/bin/beat-sensor2
  echo "removed beat-sensor2"
fi

unit=/etc/systemd/system/beat-sensor.service
if [ "$prev" = "$out" ] && [ "$env_before" = "$(cat /etc/beat-sensor.env)" ] &&
   cmp -s "$out/share/beat-sensor/beat-sensor.service" "$unit" && systemctl is-active --quiet beat-sensor; then
  trusted() { ls "$1" | sed 's/\.pub$//' | paste -sd' '; }
  echo "beat-sensor unchanged, not restarted: $(basename "$out") (roots $(trusted /etc/beat-sensor/roots);" \
    "collector $(trusted /etc/beat-sensor/collectors))"
  exit 0
fi
install -m 0644 "$out/share/beat-sensor/beat-sensor.service" "$unit"
systemctl daemon-reload
systemctl enable beat-sensor >/dev/null 2>&1
systemctl restart beat-sensor

for _ in $(seq 20); do
  if journalctl -u beat-sensor --since "-30s" --no-pager -o cat 2>/dev/null | grep -q "listening on"; then
    echo "beat-sensor active: $(basename "$out") (previous: ${prev:-none})"
    exit 0
  fi
  sleep 0.5
done
echo "beat-sensor did not come up as $(basename "$out")" >&2
systemctl status --no-pager beat-sensor >&2 || true
journalctl -u beat-sensor -n 20 --no-pager >&2 || true
exit 1
