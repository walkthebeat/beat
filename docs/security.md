# The sensor's security model

For someone deciding whether to run `beat-sensor` on their hosts. Each statement here names the code that enforces
it. Decisions keep their ids (H16, C14, …), which the code's comments cite. What is not built yet says so.

## In one paragraph

The sensor runs as root and listens on no port. It connects out to a message bus (NATS) and runs only questions
that carry two signatures: one by a member of your org, whose credential your org root signed (the root's public key
is pinned on the host when you configure it), and a countersignature by your beat service. Each question is a
Starlark program run in its own short-lived systemd unit: read-only file system, no network, no devices, limits on
memory, tasks and time, secret files replaced by placeholders. Its answer is masked for known secrets, sealed to a
key only the service holds for that survey, and signed by the sensor. Neither the service nor its operator can make
a sensor run anything on their own.

## The parts

```
 your machine                         beat service                          your host
 ────────────                         ────────────                          ─────────
 beat / beat-mcp                      collector, store, API                 beat-sensor (root, systemd service)
   org root (a key file)                                                       pins: your org root(s), the
   member key + credential              countersigns questions                 service's collector key(s)
   (short-lived, signed by the root)    from members of orgs whose             │
 signs each question ──── HTTPS ────►   live sensors pin that root ── NATS ──►  admits (H16, C14), runs beat-probe
                                        opens answers in memory,               in a transient unit, masks (gate 1),
                                        checks again (gate 2), stores  ◄─────  seals to the survey key, signs (C16)
```

## Whom the sensor obeys

- **H16. Sensors pin the org root; members sign with short-lived keys the root certified.**
  - The root is an Ed25519 key pair of your org. Its private half lives on a machine of yours (`beat keys`); it signs
    members' credentials and nothing else. Its public half reaches each host once, on the configure line
    (`beat-sensor configure --org-root NAME=KEY`), and is written to `/etc/beat-sensor/roots/NAME.pub`. It is never
    re-read from anywhere: a change to whatever carried it cannot re-root the fleet later.
  - A member's credential is signed JSON, `{kind: "member", name, key, not_before, not_after, issuer}`, valid for 30
    to 90 days. The member makes their own key pair; the root signs only the public half.
  - Per question, offline, the sensor checks (`sensor/src/main.rs` `admit`, `sensor/src/seal.rs`
    `check_credential`): the credential in `Beat-Cred` is signed by a pinned root, of kind `member`, valid now (5
    minutes of clock skew allowed); its member is not on the deny list; the question is signed by the credential's
    key (`Beat-Signature`); a collector key countersigned the same bytes (`Beat-Countersignature`).
  - **The deny list** ends a member's credentials before they expire (a stolen laptop, someone who left). The root
    signs it, with a sequence number. The service relays it over the bus; the sensor takes a list only when a pinned
    root signed it and its sequence is higher than the one it holds, and keeps it in
    `/var/lib/beat-sensor/state/deny.json`, so a restart cannot roll it back. A compromised service can withhold a new
    list (until the denied credentials expire) but cannot forge, shorten or roll one back.
  - **Where the root lives** (2026-11-01, with the user, after managing one org from two laptops: the second laptop
    silently made a second root, and the host enrolled from the first refused its questions). The root is made only
    on purpose, `beat org init`, once per org: it refuses when the org's sensors already pin a root (their
    heartbeats say which) and sends you to `beat creds init`; shows the root once, as one line
    (`beat-org-root:NAME:KEY`, NAME the date and the key's fingerprint, so two roots never share a name), to keep
    in a password manager; asks for it to be pasted back; certifies the laptop; and does not keep it (`--keep` does,
    the user's call: "if i am silly enough to store it on disk this is my problem"). Every laptop, the first included
    once its credential runs out, gets a credential with `beat creds init`, pasting the root (hidden) or reading
    it (`--root FILE`, `--root -` from a password manager's command line); `beat keys deny` takes it the same way.
    `beat sensors add` needs only the credential: the root's public half is kept next to it. A stolen laptop then
    exposes a credential that ends within 30 days and can be denied at once; a root on it would let the thief
    certify anyone, and the only remedy would be configuring every host again.
    - *Rejected: one password manager's integration* (1Password's `op`, Bitwarden's `bw`, `pass`): there is no
      common interface, Google Password Manager has no command line at all, and naming one imposes it. Copy and
      paste is the interface every manager has; `--root -` lets a command line feed it.
    - *Rejected: the OS keychain* (macOS Keychain, libsecret): the root stays on each laptop, so a second laptop is
      as hard as before and a stolen one as bad.
    - *Later: certify without the root reaching the laptop*, as a certificate request: the new laptop prints its
      public key, the root's holder signs it, the laptop takes the credential. Then the root can sit in a vault
      that signs without exporting it (Vault's transit engine does Ed25519): the enterprise form.
- **H15. Never a vendor CA, never the OS trust store.** Whoever runs a CA the sensors trust could issue a credential
  for anyone. The root is yours. Corporate PKI (an X.509 CA you pin, with the subjects it may certify) is planned as
  a second kind of root; the OS trust store is never one, since it holds every public CA.
- **C14. Authority is in the message, not the connection.** A question carries everything needed to judge it. Access
  to the bus lets you deliver a question, not have it run.
- **Replay.** A question carries its survey id, when it was issued, its deadline and its time limit, all covered by
  both signatures. The sensor refuses one issued before it started (5 s skew), one whose deadline is past or further
  than its time limit allows (at most 300 s, plus 60 s), and a survey id it has already seen (`admit`). `Beat-Targets`
  names the hosts a question is for; others drop it.

## What a question can do

A question is a Starlark program (`docs/probes.md`) run by `beat-probe` in a transient systemd unit
(`sensor/src/runner.rs`):

| Property | Value |
| --- | --- |
| File system | `ProtectSystem=strict`, `ProtectHome=read-only`, `PrivateTmp=yes`: everything read-only |
| Network | `PrivateNetwork=yes`: none |
| Devices, kernel | `PrivateDevices`, `ProtectKernelTunables`, `ProtectKernelModules`, `ProtectControlGroups` |
| Privileges | `NoNewPrivileges`, `RestrictSUIDSGID`, `LockPersonality`; capabilities limited to `CAP_DAC_READ_SEARCH` (read any file) and `CAP_SYS_PTRACE` (read other processes' `/proc`), plus `CAP_BPF` and `CAP_PERFMON` only for a question that uses a `trace()` entry of the built-in eBPF catalog |
| Limits | `MemoryMax=1G`, `TasksMax=64`, `CPUQuota=100%`, `RuntimeMaxSec` = the question's time limit |
| The sensor's key | `InaccessiblePaths`: no question sees it in any form |
| Secret files | replaced by placeholders (below) |

- Starlark has no I/O of its own. Everything a question reads goes through beat's built-ins: files, osquery
  (`osqueryi`), the journal, and WASM tools (coreutils, jq, awk, the log miner) run under wasmtime with only the
  directories they are given. `beat-probe check` refuses a program that is not shaped as a probe before it runs.
- One question per unit; at most two run at once by default. A question past its limits is killed by systemd, not
  by the sensor's goodwill.

## Secrets

- **Placeholders.** The unit binds a placeholder over each secret file (keys, keytabs, credential caches,
  `/etc/shadow`, …). A question sees that a file is a secret, and its metadata through `secrets()`, never its bytes.
  Placeholders need concrete paths before the unit starts, so the patterns are enumerated in two ways:
  - **Fixed paths and single-level globs** (`/etc/shadow`, `/etc/ssh/ssh_host_*_key`, `/home/*/.ssh`, …): checked live
    before each question (`beat-probe secrets --live`). They are never stale.
  - **Recursive patterns** (`/etc/**/*.key`, `/opt/**/*.key`, `/opt/**/*.keytab`, `/srv/**/*.key`,
    `/var/lib/**/*.keytab`): walked in the background at the sensor's start and five minutes after each walk ends, in a
    unit of its own (read-only, no network, a quarter of a CPU, 256 MiB, idle I/O priority), and questions use the latest
    result, with each path checked against the disk first. **So a new file under one of these patterns has no
    placeholder until the next walk ends:** `read()` refuses it at once, as beat-probe checks the patterns itself on
    every read, but a tool or `osqueryi` in a question could read it in that window.
  - A question never runs without this. Until the first walk ends (it waits up to half of its time limit), when the
    latest walk is over an hour old, or when the live check takes over 10 s, it is refused with an error of kind
    `secrets`.
  - **What the walk does not enter:** container storage, where it is configured (Docker's data root, containerd,
    Podman, kubelet's pods), and network, FUSE and layered mounts. A budget (300 s, 5 million entries) stops it on
    anything else that is large. The live check does not touch network mounts either, so `.ssh` in NFS homes has no
    placeholder. Files in those places stay readable to a tool or `osqueryi` in a question, and `read()` refuses only
    what the patterns name. The heartbeat (`secret_walk`) and the note of any run that calls `secrets()` say what was
    left out.
  - **Paths systemd cannot express** (a quote or a control character in the name) get no placeholder, and are reported
    the same way.
  - `/proc/*/environ` is not enumerated: `read()` refuses it, and so does each other way there (below).
- **Processes' environments.** A question gets them through `environ(pid)`: every variable's name; the value of a short
  list of names known not to be secrets (`PATH`, `PYTHONPATH`, `CLASSPATH`, `LD_LIBRARY_PATH`, `JAVA_HOME`, `LANG`,
  `LC_*`, `TZ`, `HOME`, `USER`, `PWD`, `SHELL`, and the JVM option variables `JAVA_OPTS`, `JAVA_TOOL_OPTIONS`,
  `_JAVA_OPTIONS`, `JDK_JAVA_OPTIONS`, `CATALINA_OPTS`); and for any other value, a token the question cannot read.
  - **Allowed values are masked first:** a URL's password or token in any of them, and in the JVM variables, the value of
    any option named like password, passwd, pwd, secret, token, credential or key. Gate 1 then scans what is emitted.
  - **Other values leave the host as an unkeyed SHA-256, sealed to the collector, which replaces it with an HMAC under
    the org's estate key before anything stores it.** A sensor has no key an org's hosts share, and a plain hash of a
    short value can be guessed, so the hash is keyed at the collector. So hosts compare equal when values are, the
    collector process briefly holds the digest, and running `beat-probe run` on its own (no collector) shows the digest.
    A service whose rules predate `beat-env-value` keeps the digest in the answer: the service's rules must be updated
    before a sensor with `environ()`.
  - `osq()` refuses `process_envs`, `docker_container_envs`, `process_events` and `docker_containers.env_variables`
    (name that table's columns: no `*`), reading the query as SQLite's tokenizer does, so case, quotes, comments,
    aliases and subqueries do not help, and refuses osqueryi's dot commands. A string equal to one of these table names
    is refused too, as SQLite takes a string as a table name in `FROM`.
  - `read()` and `sample()` refuse `/proc/<pid>/environ` and `mem`, in `task/<tid>/` too.
  - **Tools have no `/proc/<pid>`:** nothing under it is mapped into them, as a mapping cannot leave one file out and a
    tool can build any path. A pipe that names `/proc` gets a copy of its own small files (`meminfo`, `stat`, ...) and its
    directories (`/proc/sys`). For the rest, `stdin = read(path)`, which a tool's failure says.
- **`/proc` is how a question debugs, so a path through it is judged by what it leads to.** With `CAP_SYS_PTRACE`,
  `/proc/1/root/etc/shadow` is the real file, past every placeholder, and `/proc/1/root/tmp/x` is how a question reaches
  a file in the host's `/tmp`, its own being private.
  - `read()` and `sample()` resolve `/proc/<pid>/root/...` and `cwd/...` inside that process's root (symlinks followed
    there, `..` stopping at it) and apply the patterns to the result. So a container's `/etc/shadow` is refused and its
    other files are as readable as the host's. The check and the read are two steps: a process that swaps a symlink
    between them could win that race.
  - `/proc/<pid>/fd/N` and `map_files` are judged by the file the link names, a deleted one by its old name. A socket,
    pipe or memfd names no file and is refused; `readlink` and `list_dir` work on all of them.
  - A symlink on the host is judged by where it leads. The sensor's keys are refused by path, as `/proc/<pid>/root`
    would otherwise reach them past the mount that hides them.
  - **The patterns are what is refused, not secrets in general:** a key at a path no pattern names, or a hard link to one,
    is readable through these doors as it is directly.
  - **`osq()`, best effort:** for `hash`, `file`, `yara` and `augeas`, literal paths through a process's root, cwd or fd
    are refused, as written or as a pattern, and so is any query that builds strings (`||`, `printf()`, `replace()`...).
    This is not a boundary: a path taken from another table's column is not seen. `osqueryi` holds `CAP_SYS_PTRACE`.
  - On RHEL-family hosts SELinux may forbid systemd to mount over some of them. The sensor then runs questions
    without the placeholders and says so in its heartbeat (`sandbox: no-secret-mounts`). `beat-probe` still refuses
    to read those files, but a program it starts (`osqueryi`) could.
- **C23. Files of known meaning are read for what they mean** (`probe/src/transform.rs`): a keytab as `klist -k`
  would show it, a certificate as its subject, issuer and validity, a private key as its type and public
  fingerprint, `/etc/shadow` as each user's status and ages. Never the secret itself.
- **Gate 1** (`probe/src/secrets.rs`): everything a question emits is scanned before it leaves the host.
  - Tokens of known shape (the Betterleaks rule set, `probe/rules/`) are masked with a marker
    `«secret:<kind>:sha256:<prefix>»`, so equal values still compare across hosts. A mask on the sensor is final.
  - Suspicious values (high entropy, secret-like keys) are flagged, not masked: hashes and UUIDs score high too.
  - It runs in the runtime, on what the program emits; a program cannot turn it off.
- **Gate 2** runs at the service, on every answer, by a different method, before anything is stored. It is the
  service's, not the sensor's, and outside this repo.

## What leaves the host

- **Answers only, sealed and signed (C16).** Each answer is sealed to the survey's public key with HPKE (RFC 9180,
  base mode: X25519, HKDF-SHA256, ChaCha20-Poly1305), with the survey and the host bound into it, and signed with the
  sensor's own key. Only the service holds the survey's private key; whoever runs or breaks into the bus reads
  nothing.
- **Heartbeats**, every 10 s, signed: the sensor's name, version, labels and start time; the roots it pins (names
  and public keys) and its collector keys' names; the deny list's sequence; whether its sandbox is complete.
- **C21. Logs are not collected.** Questions can summarise logs on the host (templates, counts) and return extracts
  someone asked for; nothing is shipped continuously.
- Nothing else: the sensor opens no port and connects only to the bus; to the service's API for its bus login
  (every half hour) and when you run `configure` or `enroll`; and, with `--attest aws`, to the instance metadata service and AWS STS for its identity
  token (`sensor/src/aws.rs`).

## Enrolment: admitting a sensor to the service

Enrolment decides which sensors the service believes and lets on the bus. It does not decide whom a sensor obeys:
that is the root (H16).

- **H9. Install is separate from configuration.** Installing changes nothing about whom the sensor obeys and
  starts nothing: the unit runs only once `/etc/beat-sensor.env` exists. `beat-sensor configure` writes it later, with
  the root from your machine and the bus and collector keys from the service (`sensor/src/configure.rs`).
- **H4. Enrolment is an exchange:** the sensor's public key and one proof, signed by the sensor's key
  (`sensor/src/enroll.rs`). Three kinds of proof:
  - **H14. Approval:** the host prints a code and its key's fingerprint; a member compares them and approves
    (`beat sensors approve`). No secret on the host.
  - **H5. A rollout token:** made by a member for N hosts and a time, given to the host in a root-only file and read
    once. It is bound to the key it enrols.
  - **H13. Attestation:** an identity the host already has (an OIDC token from Kubernetes or a cloud, or AWS STS's
    signed identity token), checked against a trust policy your org sets: the issuer, the audience, the claims that
    must match, and which claim names the sensor.
- **What a stolen proof gets:** a fake sensor enrolled under that name. Its answers pollute your store; it commands
  nothing, and it sees only the questions it is asked.

## The bus: every sensor logs in with its own key (H17)

NATS runs in operator mode: nobody connects without a login, and each login allows only its own subjects. The code:
`sensor/src/bus.rs`; the subjects: `docs/protocol.md`, "Logins".

- **A sensor's login is a JWT for its own enrolled key,** minted by the service for a request signed with that key
  (`POST /v1/bus-credential`, kind `bus`) and valid an hour. The sensor renews it at half life and hands the newest
  to the NATS client at every connection; the server drops a connection whose login expired. No secret is stored
  for it: the key is the one the sensor already has, and the JWT names only its public half.
- **What it allows:** receiving questions sent to every sensor and to this one by name, publishing its own acks,
  answers and directory entry, its builtins guide, reading the deny list; replies on an inbox of its own. Not:
  another sensor's questions or directory entry, sending questions, creating or deleting streams and buckets.
  Signatures still decide what is believed; the login decides who is on the bus and what it can see.
- **A removed sensor** (`beat sensors remove`) gets no new login: it is off the bus within the hour.
- **The nonce is signed only if it looks like one.** NATS's server sends a nonce for the client to sign, with the
  same key that signs answers and heartbeats. Every beat signature covers canonical JSON (`{"v":1,"kind":...`), and
  the sensor signs a nonce only if it is 8-64 characters of `[A-Za-z0-9_-]`, which nats-server's nonces are and a
  JSON object never is: a bus (or something impersonating it) cannot get a beat message signed by sending it as a
  nonce.
- **TLS to the bus:** a `tls://` bus address, as the hosted service gives, uses TLS. A `nats://` address does not, so
  keep that to a network you trust; answers are sealed and signed either way, but who talks to whom is visible.
- **Not built yet:** an attested sensor attesting again for each login (today it renews with its key, as the others
  do).

## The binary you run

- **M16. One image, checked block by block.** The sensor ships as a squashfs image of its Nix closure with a
  dm-verity hash tree (`packaging/sensor/`). systemd mounts it at `/nix/store` in the sensor's unit and in each
  question's unit only; the kernel checks every block as it is read, so a modified image fails on read. The
  installer checks every file against SHA-256 hashes built into it.
- **Not yet reproducible bit for bit.** `nix build .#beat-sensor-image` at a release's tag is meant to give the
  release's `beat-sensor.roothash`, but a rebuild can differ in the type order of a few eBPF tools, so today equal
  hashes prove the image and different ones prove nothing: `docs/reproducibility.md`. Public releases carry a build
  attestation (`gh attestation verify FILE -R walkthebeat/beat`), which says which workflow built a file.
- On a host with Nix, the sensor can also run as a Nix closure (`packaging/nix/`).

## What a compromised beat service can do

| It can | It cannot |
| --- | --- |
| read the answers it opens (gate 2 masks known secrets before storing) | make a sensor run a question no member of your org signed |
| refuse to relay questions, or withhold a new deny list | forge a member credential, add or remove a deny-list entry, roll a sensor's deny list back |
| enrol fake sensors (they command nothing) | read a secret file's bytes, which no question can read |
| keep a removed sensor's login alive, or mint any login it likes | get a sensor to sign anything but a nonce-shaped string with its key |

## Reporting a vulnerability

`SECURITY.md`.
