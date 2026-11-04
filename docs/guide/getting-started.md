# Getting started

You need: a laptop (Linux or macOS) with [Claude Code](https://claude.com/claude-code), and one or more Linux hosts
(x86_64, systemd) you have root on.

```
 laptop (no root)                          walkthebeat                       your hosts (root)
 ────────────────                          ───────────                       ─────────────────
 2. install beat                           1. sign up: your org
 3. beat login ───── device code ────────► portal
 4. beat org init, beat sensors add ────────────────────────────────────►    5. install the sensor
                                                                             6. run the line: enrol
 7. beat sensors ◄──── the beat service ◄── sensors connect out, answer ──
 8. Claude asks
```

## 1. Sign up

Open [walkthebeat.ai](https://walkthebeat.ai) and sign in with GitHub or Google. The first sign-in makes your account and an org of your
own. The account page shows the org's id (12 letters and digits, such as `k3x9p2m7q4ta`); you will not need to type
it.

Two addresses, two jobs: **walkthebeat.ai** is where you sign in (your account, these docs). **api.walkthebeat.ai**
is the beat service: your laptop and your sensors talk to it, and it keeps each org's data apart from every other's.

## 2. Install beat on your laptop

beat is installed with [uv](https://docs.astral.sh/uv/), a Python package manager; it brings its own Python, so
you need neither Python nor pip. If `uv --version` says it is not found, install it (no root):

```
curl -LsSf https://astral.sh/uv/install.sh | sh     # Linux or macOS
brew install uv                                     # or, on macOS with Homebrew
```

Open a new terminal so it is on your PATH. Then install beat from the repository (PyPI later), and let uv put its
commands on your PATH:

```
uv tool install git+https://github.com/walkthebeat/beat
uv tool update-shell
```

It installs two commands, `beat` and `beat-mcp` (in `~/.local/bin`), needs no root, and configures nothing. Open
a new terminal again and check that `beat --version` works.

It needs `git`: while the repository is private, git uses your GitHub login (`gh auth setup-git` once, if git does not already have it).

To upgrade later (`uv tool install` does not replace an installed beat): `uv tool upgrade walkthebeat` (the package's name; the commands are `beat` and `beat-mcp`).

## 3. Sign in from the laptop

```
beat login
```

It signs in to the beat service at `https://api.walkthebeat.ai` (the default; `beat login URL` is for a service of
your own). It prints a code and a link to walkthebeat.ai: open the link, check the code matches, and approve.

```
beat whoami
```

shows who you are, your org, and the address your org's sensors call: `https://api.walkthebeat.ai/o/<your org id>`.

## 4. Your org's root, and the line for your hosts

Your hosts run only questions signed by people your **org root** certified. The root is a key that you keep;
neither walkthebeat nor the beat service ever holds it. Make it once, on your first laptop:

```
beat org init
```

It shows the root once, as one line (`beat-org-root:...`). Save that line in your password manager: any will do
(Google Password Manager, 1Password, Bitwarden, KeePass, ...), as a password or a note. It asks you to paste it
back, to be sure it was saved, then certifies this laptop for 30 days. beat does not keep the root: that line is the
only copy. Lost, it cannot be recovered, and every host would have to be configured again with a new root.
(Set up before November 2026? Your root is still on that laptop: `beat keys export` prints its line for your
password manager; then delete it there as it says.)

On another laptop, or on this one when its 30 days are up (beat says so):

```
beat creds init
```

and paste the line when it asks (it is not shown). With a password manager that has a command line, you can pipe it
instead: `op read op://Private/beat-root/password | beat creds init --root -`. Each laptop gets its own key; if one
is lost, `beat keys deny` ends its access at once.

Then:

```
beat sensors add
```

prints a `sudo beat-sensor configure ...` line with your org's address
(`https://api.walkthebeat.ai/o/<your org id>`) and your root's public key. It holds no secret: the key is public,
and it is fine that it ends up in the host's logs (sudo records the command). Copy it for step 6.

## 5. Install the sensor on a host

```
curl -fsSL https://github.com/walkthebeat/beat/releases/latest/download/install.sh | sudo sh
```

**While the repository is private** (until its first public release), downloads need your GitHub login, so fetch
the release with the GitHub CLI and install from the files:

```
gh release download -R walkthebeat/beat -p '*' -D beat-sensor
sudo BEAT_SENSOR_BASE=file://$PWD/beat-sensor sh beat-sensor/install.sh
```

Each release lists its files and the image's root hash; `docs/security.md` says how to check it against the source.

The host needs x86_64 and systemd 247 or later: Ubuntu 22.04 and newer, Debian 12, RHEL 9 and its rebuilds
(AlmaLinux, Rocky), Amazon Linux 2023. The installer checks that first and says what is missing. It puts the sensor
in `/opt/beat-sensor` as one image that systemd mounts for the sensor alone, adds one SELinux rule where SELinux is
on, and configures nothing: the sensor stays stopped until step 6 points it at a service and a root. Run it again
to upgrade.

**On NixOS**, skip the installer and use the flake's module. In your flake's inputs add
`beat.url = "github:walkthebeat/beat/v<release>";`, then in the host's configuration:

```
imports = [ beat.nixosModules.beat-sensor ];
services.beat-sensor.enable = true;
```

It installs the sensor the same way: closed until step 6. There, run the configure line as
`sudo beat-sensor configure ...`, not under `/opt/beat-sensor`. Leave its configuration out of your Nix config: the
line writes `/etc/beat-sensor.env` and `/etc/beat-sensor/`, which NixOS does not manage and a rebuild keeps.

## 6. Enrol the host

A sensor's answers count once the service has enrolled it. Pick one way.

### A. By approval: a few hosts, anywhere

On the host, run the line from step 4. It looks like this (yours has your org id and your root's key), prints a
code and waits:

```
sudo /opt/beat-sensor/current/bin/beat-sensor configure --api https://api.walkthebeat.ai/o/k3x9p2m7q4ta \
    --org-root 20261031=UNhY4JhezH9gQYqvDMWrWH9CwlcKiECVqejMrND2VFw=
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
2. Allow each role whose instances should be sensors to call `sts:GetWebIdentityToken` for beat's audience:

```
{"Effect": "Allow", "Action": "sts:GetWebIdentityToken", "Resource": "*",
 "Condition": {"ForAllValues:StringEquals": {"sts:IdentityTokenAudience": ["beat-enroll"]},
               "NumericLessThanEquals": {"sts:DurationSeconds": 300}}}
```

3. On the laptop, trust the account's instances (one line; `<account>` is the AWS account id):

```
A='https://sts.amazonaws.com/'
beat org trust add aws --issuer <issuer URL from 1> \
    --claim "$A/aws_account=<account>" --name-from "$A/ec2_source_instance_arn"
```

This is per account, not per host or role: every instance whose role has the permission from 2 enrols, now and
later. That permission is what makes a role's instances sensors, so it is decided in IAM, with your other roles. Only
an instance's token names an instance (`ec2_source_instance_arn`): a person's session with the permission is refused.
Each sensor is named by its instance id.

Stricter, if not everyone who manages IAM in the account should decide what is a sensor: name the roles in the
trust instead, one policy per role, `--claim "$A/principal_id=arn:aws:iam::<account>:role/<role>"` added to the
line (a policy's claims must all match).

Then `beat sensors add --attest aws` prints the configure line, the same for every instance: run it on each (by
hand, user data, or your configuration management). Each enrols at once.

## 7. Check

```
beat sensors
```

Each host is listed with its name and when it was last heard from. A host listed as UNTRUSTED is not enrolled.

## 8. Ask with Claude

Claude reaches beat through beat's MCP server, `beat-mcp` (installed in step 2). Make a directory for your hosts'
notes and set it up:

```
beat init ~/estate
cd ~/estate
claude
```

`beat init` makes the directory a git repository that Claude works in, with:

- `.mcp.json`: Claude starts `beat-mcp` here, which talks to the service you signed in to in step 3.
- `.claude/settings.json`: Claude may use the beat server and the read-only `beat` commands without asking each
  time; deleting surveys stays denied.
- `CLAUDE.md` and two skills, `discover` (map what runs on hosts) and `investigate` (chase a problem across them):
  how to work with beat, and where the findings go (`hosts/`, `probes/`).

beat comes with a default set of probes for any Linux host (`beat probes` lists them): asked to discover your hosts,
Claude runs them all first, so the first answer takes a minute, then explores what they do not cover. They are a
starting point: where one does not fit a host, Claude adapts it for your estate.

In Claude, `/mcp` should list `beat` as connected. Then ask about your hosts, for example "which hosts have a
failed systemd unit, and why?", or `/discover` to have it map what runs where.

To use beat from Claude in any directory instead, add the server once for your user:
`claude mcp add -s user beat -- beat-mcp`.

## 9. Remove

A host: see [the sensor](sensor.md), "Remove". `beat sensors remove NAME` unenrols it at the service.

Your account: write to us; it is done by hand for now.

## Tell us what is wrong

We want to hear what broke, what confused you, and what your agent could not see. Open an issue at
[github.com/walkthebeat/feedback](https://github.com/walkthebeat/feedback), or ask Claude to use the `report` skill, or
run it yourself:

```
beat report draft --summary "what went wrong" --survey SURVEY_ID --session
beat report send
```

`draft` writes the report to `~/.cache/beat/reports/` and sends nothing, so you can read and edit it. `send` asks you
at your own terminal before each of two parts, and an agent cannot answer for you:

- **The summary** becomes a **public** GitHub issue, through your own `gh`, or a link you open if you have no `gh`.
  Keep hostnames and configuration out of it. `send` warns when it sees one of your sensors' names.
- **The transcript**, only if you offered one, goes privately to the beat service under your org's login, gzipped.
  **walkthebeat's staff read it, and it holds your hostnames and configuration, and possibly secrets.** It is masked
  first, on your machine, with the sensor's rules, and you can read the masked copy before you send it. Masking
  catches known kinds of secret, not every secret. The public issue names only the report's id.

The service keeps a transcript for 90 days. `beat report list` shows what your org has sent, and
`beat report delete ID` removes one at once (a backup of the service may hold it for up to 7 more days).
