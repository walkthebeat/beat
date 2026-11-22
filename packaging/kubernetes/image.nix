# The sensor as a container image for a Kubernetes DaemonSet (beat-sensor.yaml): the sensor's closure, bubblewrap,
# setpriv and the sandboxes' seccomp filters (seccomp.nix). `nix build .#beat-sensor-oci` gives a script that streams a docker
# archive (`./result | docker load`, or `| k3s ctr images import -`).
{ pkgs, sensor, sensorBin, probe, tools, libbpfTools }:
let
  inherit (sensor) version;
  seccomp = import ./seccomp.nix { inherit pkgs; };
  entrypoint = pkgs.runCommand "beat-sensor-entrypoint" { } ''
    substitute ${./entrypoint.sh} $out --replace-fail @shell@ ${pkgs.runtimeShell} \
      --replace-fail @path@ ${pkgs.lib.makeBinPath [ pkgs.coreutils ]} --replace-fail @cacert@ ${pkgs.cacert}/etc/ssl/certs/ca-bundle.crt \
      --replace-fail @probe@ ${probe}/bin/beat-probe --replace-fail @tools@ ${tools} \
      --replace-fail @sensor@ ${sensorBin} --replace-fail @version@ ${version} \
      --replace-fail @osqueryi@ ${pkgs.osquery}/bin/osqueryi --replace-fail @bpftools@ ${libbpfTools}/bin \
      --replace-fail @placeholders@ ${sensor}/share/beat-sensor/placeholders \
      --replace-fail @bwrap@ ${pkgs.bubblewrap}/bin/bwrap --replace-fail @setpriv@ ${pkgs.util-linux}/bin/setpriv \
      --replace-fail @seccomp@ ${seccomp}/question --replace-fail @seccomp_capture@ ${seccomp}/capture \
      --replace-fail @tcpdump@ ${pkgs.tcpdump}/bin/tcpdump
    chmod +x $out
  '';
  # The cluster sensor's (beat-cluster.yaml): the Deployment runs /bin/beat-cluster.
  clusterEntrypoint = pkgs.runCommand "beat-cluster-entrypoint" { } ''
    mkdir -p $out/bin
    substitute ${./entrypoint-cluster.sh} $out/bin/beat-cluster --replace-fail @shell@ ${pkgs.runtimeShell} \
      --replace-fail @path@ ${pkgs.lib.makeBinPath [ pkgs.coreutils ]} --replace-fail @cacert@ ${pkgs.cacert}/etc/ssl/certs/ca-bundle.crt \
      --replace-fail @probe@ ${probe}/bin/beat-probe --replace-fail @tools@ ${tools} \
      --replace-fail @sensor@ ${sensorBin} --replace-fail @version@ ${version} \
      --replace-fail @seccomp_cluster@ ${seccomp}/cluster
    chmod +x $out/bin/beat-cluster
  '';
in
pkgs.dockerTools.streamLayeredImage {
  name = "ghcr.io/walkthebeat/beat-sensor";
  tag = builtins.replaceStrings [ "+" ] [ "-" ] version;  # a tag cannot hold "+"
  contents = [ pkgs.cacert clusterEntrypoint ];
  # bwrap makes each question's root on a tmpfs at /tmp; configure writes /etc/beat-sensor.env and /etc/beat-sensor/.
  extraCommands = "mkdir -m 1777 tmp; mkdir -p etc run var/lib";
  config = {
    Entrypoint = [ "${entrypoint}" ];
    Env = [ "SSL_CERT_FILE=${pkgs.cacert}/etc/ssl/certs/ca-bundle.crt" ];
  };
}
