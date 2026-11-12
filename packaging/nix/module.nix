# The sensor on NixOS (flake output nixosModules.beat-sensor): this flake's build as a system service, for hosts
# whose /etc and units NixOS manages, where install.sh's image (packaging/sensor) and beat-sensor-activate's unit
# have no place.
#
#   imports = [ beat.nixosModules.beat-sensor ];
#   services.beat-sensor.enable = true;
#
# Installed closed, as from the image: nothing starts until `sudo beat-sensor configure ...` (the line
# `beat sensors add` prints) has written /etc/beat-sensor.env. The configuration stays out of the Nix config on
# purpose: it is the operator's, made once per host, and the store is world-readable. What configure writes
# (/etc/beat-sensor.env, /etc/beat-sensor/{roots,collectors}/, /var/lib/beat-sensor/keys/) is not NixOS-managed, so
# it survives a rebuild; a reinstalled host is configured again. Keep in step with packaging/sensor/beat-sensor.service.
{ sensor, probe, tools }:
{ config, lib, pkgs, ... }:
let
  cfg = config.services.beat-sensor;
in
{
  options.services.beat-sensor.enable = lib.mkEnableOption "the beat sensor (answers its org's signed questions)";

  config = lib.mkIf cfg.enable {
    # The operator's command (configure, enroll, keygen) alone: not beat-sensor-activate (hosts that are not NixOS).
    environment.systemPackages = [ (pkgs.linkFarm "beat-sensor-cli" [ { name = "bin/beat-sensor"; path = "${sensor}/bin/beat-sensor"; } ]) ];

    # The user questions run as (runner.rs `question_user`; beat-sensor-run passes --question-user beat-question).
    users.users.beat-question = { isSystemUser = true; group = "beat-question"; description = "beat sensor questions"; };
    users.groups.beat-question = { };

    systemd.services.beat-sensor = {
      description = "beat sensor: answers questions published on NATS";
      after = [ "network-online.target" ];
      wants = [ "network-online.target" ];
      wantedBy = [ "multi-user.target" ];
      unitConfig.ConditionPathExists = "/etc/beat-sensor.env";
      # NixOS has no /usr/bin/systemd-run: questions start through the system's own systemd.
      environment = { HOME = "/tmp"; BEAT_SYSTEMD = "${config.systemd.package}/bin"; };
      # Compile the WASM tools behind pipe() once: question runs see this cache read-only.
      preStart = "${probe}/bin/beat-probe tools --tools ${tools} --cache /var/lib/beat-sensor/wasm-cache >/dev/null";
      serviceConfig = {
        EnvironmentFile = "/etc/beat-sensor.env";
        WorkingDirectory = "/";
        ExecStart = "${sensor}/bin/beat-sensor-run";
        Restart = "always";
        RestartSec = 5;
        NoNewPrivileges = true;
        ProtectSystem = "strict";
        PrivateTmp = true;
        RuntimeDirectory = "beat-sensor";
        RuntimeDirectoryMode = "0700";
        StateDirectory = [ "beat-sensor/state" "beat-sensor/wasm-cache" ];
        StateDirectoryMode = "0700";
      };
    };
  };
}
