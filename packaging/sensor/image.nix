# The sensor for hosts without Nix (docs/security.md M16): what https://walkthebeat.ai/sensor/VERSION/ serves.
#   install.sh                        curl -fsSL BASE/install.sh | sudo sh: checks the host, installs, closed
#   beat-sensor.raw (+ .verity, .roothash)
#                                     the sensor's /nix/store closure as a squashfs; systemd mounts it at /nix/store in
#                                     the sensor's unit and in each question's (MountImages=), checking every block
#                                     against the hash tree next to it (dm-verity)
#   beat-sensor.service, beat-sensor  the unit, and the wrapper the operator runs (configure, enroll)
# On the host it all goes to /opt/beat-sensor/VERSION/; /opt/beat-sensor/current/bin/beat-sensor is the command
# `beat sensors add` prints, as on a host that has the sensor from Nix.
{ pkgs, sensor, sensorBin, probe, tools, base }:
let
  inherit (sensor) version;
  dir = "/opt/beat-sensor/${version}";
  subst = name: src: pkgs.runCommand name { } ''
    substitute ${src} $out --replace-quiet @out@ ${sensor} --replace-quiet @image@ ${dir}/beat-sensor.raw \
      --replace-quiet @sensor@ ${sensorBin}/bin/beat-sensor --replace-quiet @probe@ ${probe}/bin/beat-probe \
      --replace-quiet @tools@ ${tools}
    ! grep -q '@[a-z]*@' $out
  '';
  closure = pkgs.closureInfo { rootPaths = [ sensor sensorBin ]; };
in
pkgs.runCommand "beat-sensor-image-${version}" { nativeBuildInputs = [ pkgs.squashfsTools pkgs.cryptsetup ]; } ''
  mkdir $out
  # Labelled like /usr/bin for SELinux (RHEL family): unlabelled files on a squashfs are unlabeled_t, which systemd
  # (init_t) may not execute. Hosts without SELinux ignore the attribute.
  SOURCE_DATE_EPOCH=0 mksquashfs $(cat ${closure}/store-paths) $out/beat-sensor.raw \
    -quiet -noappend -exit-on-error -keep-as-directory -all-root -root-mode 755 -b 1M -comp xz \
    -xattrs-add security.selinux=system_u:object_r:bin_t:s0
  # The hash tree and its root hash, where systemd looks for them; fixed salt and uuid, so a build repeats exactly.
  veritysetup format $out/beat-sensor.raw $out/beat-sensor.verity \
    --salt=0000 --uuid=00000000-0000-0000-0000-000000000000 \
    | sed -n 's/^Root hash:[[:space:]]*//p' > $out/beat-sensor.roothash
  [ -s $out/beat-sensor.roothash ]
  cp ${subst "beat-sensor.service" ./beat-sensor.service} $out/beat-sensor.service
  cp ${subst "beat-sensor" ./beat-sensor.sh} $out/beat-sensor
  (cd $out && sha256sum beat-sensor.raw beat-sensor.verity beat-sensor.roothash beat-sensor.service beat-sensor) \
    > sums
  substitute ${./install.sh} $out/install.sh --replace-fail @version@ '${version}' \
    --replace-fail @base@ '${base}/${version}' --replace-fail @shell@ ${pkgs.runtimeShell} \
    --replace-fail @sums@ "$(cat sums)"
''
