# beat-sensor

The sensor: a root daemon on each host that answers signed questions published on a NATS bus. It listens on no
port. Why it can be trusted with root, and what stops it: `docs/security.md`. The messages: `docs/protocol.md`.
What a question may do: `docs/probes.md`.

```
 beat service                                               a host
 ┌──────────────────────────────────────────┐               ┌──────────────────────────────────────────┐
 │ NATS :4222                               │◄── outbound ──┤ beat-sensor (systemd service, root)      │
 │   stream "beat": surveys, acks, answers  │               │   sub beat.ask.all, beat.ask.host.<name> │
 │   KV "beat-directory": heartbeats        │               │   per question: a transient unit running │
 │   KV "beat-deny": the org's deny list    │               │     beat-probe run - (sandboxed)         │
 │ collector: countersigns, opens answers   │               │   pub beat.answer.<survey>, sealed       │
 └──────────────────────────────────────────┘               │   KV put every 10 s (heartbeat)          │
                                                            └──────────────────────────────────────────┘
```

## One question, in order

1. A member asks (`beat ask q.star`). The service prepares a survey: its id, its key pair (the private key stays
   in the service), the targets, the time limit and deadline. The member's client signs this envelope with the
   member's key and attaches the member's credential (signed by the org root). The service checks both,
   countersigns with its collector key, announces the survey on the stream, and publishes the question to
   `beat.ask.all` or `beat.ask.host.<name>`.
2. Each sensor (`src/main.rs` `admit`, `handle`) checks: the credential against the roots it pins
   (`/etc/beat-sensor/roots/`) and the deny list; the member's signature (`Beat-Signature`); the collector's
   countersignature over the same bytes (`Beat-Countersignature`, a key in `/etc/beat-sensor/collectors/`); the
   question's hash; the targets; that it was issued since the sensor started, its deadline is within its time
   limit's reach and not past, and the survey is new. Anything else is dropped with a "refused" log line.
3. It runs the question in a transient systemd unit (`src/runner.rs`), acks on `beat.ack.<survey>` if it has not
   answered within a second, seals the answer to the survey's key and signs it (`src/seal.rs`), and publishes it
   through JetStream.
4. The service takes acks and answers of enrolled sensors only, opens each answer in memory, checks it again, and
   stores it.

## Install, configure, enrol

- On a host without Nix: the image and its installer (`packaging/sensor/`); `docs/guide/getting-started.md`.
- On a host with Nix: the closure, `nix build .#beat-sensor`, activated by `bin/beat-sensor-activate`
  (`packaging/nix/`).
- Then `beat-sensor configure` (`src/configure.rs`) points it at a service and pins the org root, and enrols it:
  by approval, a rollout token, or the host's identity (`--attest oidc:FILE|aws`).

## Development

A sensor without root or sandbox, against a service of your own (it answers only questions a member of an org
whose root it pins signed, and a collector key countersigned):
```
cargo build --release
K=~/.local/share/beat/keys
./target/release/beat-sensor --nats nats://127.0.0.1:4222 --api http://127.0.0.1:8480 --name dev --no-sandbox \
  --probe ../probe/target/release/beat-probe --tools $(nix build ..#wasm-tools --no-link --print-out-paths) \
  --cache ~/.cache/beat-probe --journalctl /usr/bin/journalctl --key $K/dev-sensor.key --roots $K/org \
  --collector-keys DIR
./target/release/beat-sensor enroll --api http://127.0.0.1:8480 --name dev --key $K/dev-sensor.key
```

## Build and test
```
nix develop -c bash -c 'cd sensor && cargo test -j2'   # includes the protocol's vectors, shared with Python
nix build .#checks.x86_64-linux.beat-sensor-test       # the same, as CI runs it
nix build .#beat-sensor
```

## Not yet
- The bus has no per-sensor credentials: anyone who reaches it can publish, but sensors answer only questions
  signed and countersigned as above, and the service takes only enrolled sensors' messages.
- Questions with parameters or libraries are refused (beat-probe does not take them yet).
- Answers over NATS's 1 MB message limit fail.
