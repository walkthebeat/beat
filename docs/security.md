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

- **Placeholders.** Before each question, `beat-probe secrets` finds secret files (keys, keytabs, credential caches,
  `/etc/shadow`, …) and the unit binds a placeholder over each. A question sees that a file is a secret, and its
  metadata through `secrets()`, never its bytes.
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
- Nothing else: the sensor opens no port and connects only to the bus; to the service's API when you run
  `configure` or `enroll`; and, with `--attest aws`, to the instance metadata service and AWS STS for its identity
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
- **Not built yet:** per-sensor NATS credentials (H4's credential bound to the sensor's key). Today the bus is open
  to whoever can reach it; that delivers questions but cannot make one run (C14).

## The binary you run

- **M16. One image, checked block by block.** The sensor ships as a squashfs image of its Nix closure with a
  dm-verity hash tree (`packaging/sensor/`). systemd mounts it at `/nix/store` in the sensor's unit and in each
  question's unit only; the kernel checks every block as it is read, so a modified image fails on read. The
  installer checks every file against SHA-256 hashes built into it, and the build is deterministic: `nix build
  .#beat-sensor-image` and compare your `beat-sensor.roothash` with the release's.
- On a host with Nix, the sensor can also run as a Nix closure (`packaging/nix/`).

## What a compromised beat service can do

| It can | It cannot |
| --- | --- |
| read the answers it opens (gate 2 masks known secrets before storing) | make a sensor run a question no member of your org signed |
| refuse to relay questions, or withhold a new deny list | forge a member credential, add or remove a deny-list entry, roll a sensor's deny list back |
| enrol fake sensors (they command nothing) | read a secret file's bytes, which no question can read |

## Reporting a vulnerability

`SECURITY.md`.
