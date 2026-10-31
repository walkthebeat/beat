# Getting started

Draft, 2026-10-30. Steps marked **not yet** wait for packaging: until then they only work in our own lab. The rest
is what beat does today.

You need: a laptop (Linux or macOS) with [Claude Code](https://claude.com/claude-code), and one or more Linux hosts
(x86_64, systemd) you have root on.

```
 laptop (no root)                          walkthebeat                       your hosts (root)
 ────────────────                          ───────────                       ─────────────────
 2. install beat                           1. sign up: your org
 3. beat login ───── device code ────────► portal
 4. beat sensors add ── prints a line ──────────────────────────────────►    5. install the sensor
                                                                             6. run the line: enrol
 7. beat sensors ◄──── the beat service ◄── sensors connect out, answer ──
 8. Claude asks
```

## 1. Sign up

Open [walkthebeat.ai](https://walkthebeat.ai) and sign in with GitHub or Google. The first sign-in makes your account and an org of your
own. The account page shows the org's id; you will not need to type it.

## 2. Install beat on your laptop

**Not yet**: `uv tool install` from PyPI. It installs two commands, `beat` and `beat-mcp`, needs no root, and
configures nothing.

## 3. Sign in from the laptop

```
beat login https://<your service>
```

It prints a code and a link. Open the link, check the code matches, and approve. `beat whoami` shows who you are
and which service you use; this machine remembers the service, so later commands and Claude need no setting.

**Not yet**: the address of your service. For the first evaluators, each org gets its own.

## 4. Get the line for your hosts

```
beat sensors add
```

The first time, this makes your **org root**: a key on this laptop (`~/.local/share/beat/keys/org/`) that sensors
trust. Only questions signed by a member the root certified run on your hosts; neither walkthebeat nor the beat
service holds it. Keep a copy somewhere safe: losing it means configuring every host again.

`beat sensors add` prints a `sudo beat-sensor configure ...` line with your service and your root's public key. It
holds no secret. Copy it for step 6.

## 5. Install the sensor on a host

**Not yet** (built and tried, not published):

```
curl -fsSL https://walkthebeat.ai/sensor/install.sh | sudo sh
```

The host needs x86_64 and systemd 247 or later: Ubuntu 22.04 and newer, Debian 12, RHEL 9 and its rebuilds
(AlmaLinux, Rocky), Amazon Linux 2023. The installer checks that first and says what is missing. It puts the sensor
in `/opt/beat-sensor` as one image that systemd mounts for the sensor alone, adds one SELinux rule where SELinux is
on, and configures nothing: the sensor stays stopped until step 6 points it at a service and a root. Run it again
to upgrade.

## 6. Enrol the host

A sensor's answers count once the service has enrolled it. Pick one way.

### A. By approval: a few hosts, anywhere

On the host, run the line from step 4. It prints a code and waits:

```
sudo /opt/beat-sensor/current/bin/beat-sensor configure --api https://<your service> --org-root <name>=<key>
```

On the laptop:

```
beat sensors pending             # who is waiting: code, name, host, key fingerprint
beat sensors approve KXQT-7RMB   # shows the host and its key fingerprint: compare with the host's, then y
```

The host's command sees the approval and exits; the sensor is running. `beat sensors deny CODE` refuses one.

Many hosts at once: `beat sensors token --hosts 20 --expires 24h` prints a rollout token (once) and the configure
line with `--token-file`. Each host enrols at once, with no approval. `beat sensors tokens` shows who used it;
`beat sensors revoke-token ID` ends it.

### B. On EC2: by the instance's AWS identity

Each instance proves who it is with a token from AWS STS, so you approve nothing per host and no secret goes on it.
Once per AWS account:

1. Turn on outbound identity federation: `aws iam enable-outbound-web-identity-federation`.
   `aws iam get-outbound-web-identity-federation-info` prints the account's issuer URL.
2. Allow the instances' role to call `sts:GetWebIdentityToken`:
   `{"Effect": "Allow", "Action": "sts:GetWebIdentityToken", "Resource": "*"}`.
3. On the laptop, trust that role's instances (one line; `<account>` is the AWS account id, `<role>` the instance
   role's name):

```
A='https://sts.amazonaws.com/'
beat org trust add aws --issuer <issuer URL from 1> \
    --claim "$A/aws_account=<account>" --claim "$A/principal_id=arn:aws:iam::<account>:role/<role>" \
    --name-from "$A/ec2_source_instance_arn"
```

Name the role: the account's issuer signs for every principal in it, people's sessions too. Each sensor is named
by its instance id.

Then `beat sensors add --attest aws` prints the configure line, the same for every instance: run it on each (by
hand, user data, or your configuration management). Each enrols at once.

## 7. Check

```
beat sensors
```

Each host is listed with its name and when it was last heard from. A host listed as UNTRUSTED is not enrolled.

## 8. Ask with Claude

```
mkdir ~/estate && cd ~/estate && beat init
claude
```

`beat init` writes `.mcp.json`, so Claude starts beat's MCP server in this directory. Ask it about your hosts, for
example "which hosts have a failed systemd unit, and why?".

## 9. Remove

A host: see [the sensor](sensor.md), "Remove". `beat sensors remove NAME` unenrols it at the service.

Your account: write to us; it is done by hand for now.
