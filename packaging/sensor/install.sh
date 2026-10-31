#!/bin/sh
# Installs the beat sensor @version@ (docs/security.md M16; docs/guide/getting-started.md):
#
#   curl -fsSL @base@/install.sh | sudo sh
#
# Checks the host, downloads the sensor's image and checks it against the hashes below, installs it in
# /opt/beat-sensor/@version@, and installs the systemd unit, closed: the sensor starts once
# `beat-sensor configure` has run. Run it again to repair or upgrade; the configuration and the sensor's key are kept,
# and a configured sensor is restarted on the new version. BEAT_SENSOR_BASE: download from there instead (a mirror).
set -eu
version='@version@'
base="${BEAT_SENSOR_BASE:-@base@}"
top=/opt/beat-sensor
dir="$top/$version"
fail() { echo "beat-sensor install: $*" >&2; exit 1; }

# The host. MountImages= (systemd 247) mounts the image; the kernel needs loop devices, squashfs (xz) and dm-verity.
[ "$(id -u)" = 0 ] || fail "run it as root: curl -fsSL $base/install.sh | sudo sh"
[ "$(uname -m)" = x86_64 ] || fail "x86_64 only for now; this host is $(uname -m)"
[ -d /run/systemd/system ] || fail "systemd is not running as init here"
sd="$(systemctl --version | sed -n '1s/^systemd \([0-9]*\).*/\1/p')"
[ "${sd:-0}" -ge 247 ] || fail "needs systemd 247 or later (MountImages=); this host has ${sd:-an unknown version}"
[ -x /usr/bin/systemd-run ] || fail "no /usr/bin/systemd-run"
command -v curl >/dev/null || fail "needs curl"
kmod() {  # NAME FILE: loaded, loadable or built in
  [ -d "/sys/module/$1" ] || modprobe -q "$1" 2>/dev/null || grep -q "/$2.ko" "/lib/modules/$(uname -r)/modules.builtin" 2>/dev/null
}
kmod loop loop || fail "the kernel has no loop devices (module loop)"
kmod squashfs squashfs || fail "the kernel has no squashfs (module squashfs)"
kmod dm_verity dm-verity || fail "the kernel has no dm-verity (module dm-verity)"

# The image, checked against the hashes this script was built with.
mkdir -p "$top"
tmp="$(mktemp -d "$top/.install.XXXXXX")"
trap 'rm -rf "$tmp"' EXIT
echo "Downloading beat-sensor $version from $base"
for f in beat-sensor.raw beat-sensor.verity beat-sensor.roothash beat-sensor.service beat-sensor; do
  curl -fsSL -o "$tmp/$f" "$base/$f" || fail "could not download $base/$f"
done
(cd "$tmp" && sha256sum -c --quiet) <<'EOF' || fail "a download does not match its hash: not installed"
@sums@
EOF

# SELinux (the RHEL family): systemd needs /dev/loop-control to mount an image. One rule, as a CIL module.
if command -v selinuxenabled >/dev/null && selinuxenabled; then
  echo '(allow init_t loop_control_device_t (chr_file (open read write ioctl lock)))' > "$tmp/beat_sensor.cil"
  if ! semodule -i "$tmp/beat_sensor.cil"; then
    [ "$(getenforce)" != Enforcing ] || fail "could not install the SELinux module beat_sensor (semodule -i)"
    echo "SELinux is not enforcing and the module beat_sensor did not install: the sensor runs while that lasts" >&2
  fi
fi

rm -rf "$dir"
mkdir -p "$dir/bin"
mv "$tmp"/beat-sensor.raw "$tmp"/beat-sensor.verity "$tmp"/beat-sensor.roothash "$tmp"/beat-sensor.service "$dir/"
install -m 0755 "$tmp/beat-sensor" "$dir/bin/beat-sensor"
chmod 0644 "$dir"/beat-sensor.*

# Does the image run here? A shell from it, in a unit that mounts it as the sensor's does: the loop device,
# squashfs, the hash tree, SELinux and exec, before anything points at it. Through /bin/sh: an older systemd-run
# (249) looks for the program on the host.
systemd-run --quiet --wait --collect --pipe -p "MountImages=$dir/beat-sensor.raw:/nix/store" \
  /bin/sh -c 'exec "$0" -c true' @shell@ </dev/null \
  || fail "the image does not run on this host; systemd's reason is in: journalctl -b -n 30"

prev="$(readlink "$top/current" 2>/dev/null || true)"
ln -sfn "$version" "$top/current.new" && mv -T "$top/current.new" "$top/current"
install -m 0644 "$dir/beat-sensor.service" /etc/systemd/system/beat-sensor.service
systemctl daemon-reload
systemctl enable --quiet beat-sensor.service
# Keeps this version and the one before it (a rollback: point current back, install its unit).
for d in "$top"/*; do
  v="${d##*/}"
  [ -L "$d" ] || [ "$v" = "$version" ] || [ "$v" = "$prev" ] || [ ! -f "$d/beat-sensor.raw" ] || rm -rf "$d"
done

if [ -f /etc/beat-sensor.env ]; then
  systemctl restart beat-sensor.service
  echo "beat-sensor $version is installed, and the sensor restarted on it."
else
  echo "beat-sensor $version is installed. It starts once configured: run \`beat sensors add\` on your machine,"
  echo "and here the sudo .../beat-sensor configure line it prints."
fi
