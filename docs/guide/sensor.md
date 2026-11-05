# The sensor

What you are putting on a host, in short. [`docs/security.md`](https://github.com/walkthebeat/beat/blob/main/docs/security.md)
has the full model, with each claim's place in the code.

- It runs as a systemd service, `beat-sensor`, as root, so its questions can read what an administrator can.
- It listens on no port. It connects out to your beat service: its message bus, and its API for the bus login and at
  `configure` and `enroll`. With `--attest aws`, also to the instance metadata service and AWS STS.
- It runs only questions signed by a member of your org, certified by your org root (pinned on the host at
  configure), and countersigned by your beat service. The service alone cannot ask anything.
- Questions are Starlark programs that read the host and return records. Each runs in its own short-lived systemd
  unit with a read-only file system, no network and limits on memory, tasks and time.
- Answers are encrypted to the survey that asked and go to your beat service, which keeps them for your org.

## Remove

```
sudo systemctl disable --now beat-sensor
sudo rm -rf /etc/systemd/system/beat-sensor.service /etc/beat-sensor.env /etc/beat-sensor /opt/beat-sensor /var/lib/beat-sensor
sudo systemctl daemon-reload
sudo semodule -r beat_sensor     # only where SELinux is on
sudo rmdir /nix/store /nix       # only on a host without Nix: the empty mount point systemd made
```

Then, on the laptop, `beat sensors remove NAME` unenrols it at the service.
