# The protocol between the service and sensors

What travels on the bus and how it is signed and sealed. The normative text is in the two implementations' module
docs, kept in step by shared test vectors:

| | Python (the client and the service) | Rust (the sensor) | Vectors |
| --- | --- | --- | --- |
| Messages and blobs | `src/beat/wire.py` | `sensor/src/wire.rs` | `tests/wire_vectors.json` |
| Signatures, sealing, credentials, deny list | `src/beat/seal.py` | `sensor/src/seal.rs` | `tests/seal_vectors.json` |

The security reasoning behind it: `docs/security.md`.

## Messages

NATS subjects, with JetStream where a message must be kept. The payload is a content-addressed blob; the headers are
the relations (survey, target, times).

| Subject | Transport | Payload | From | Headers |
| --- | --- | --- | --- | --- |
| `beat.survey.<survey>` | JetStream | question | collector | Beat-Survey, Beat-Question, Beat-Selector, Beat-Expected, Beat-Asked-By, Beat-Asked-At, Beat-Deadline, Beat-Ack-Until |
| `beat.ask.all`, `beat.ask.host.<name>` | core NATS | question | member, countersigned by the collector | Beat-Survey, Beat-Question, Beat-Key, Beat-Timeout, Beat-Issued, Beat-Deadline, Beat-Cred, Beat-Targets (optional) |
| `beat.ack.<survey>` | JetStream | none | sensor | Beat-Survey, Beat-Question, Beat-Target, Beat-Answer-By, Beat-Sensor |
| `beat.answer.<survey>` | JetStream | sealed answer | sensor | Beat-Survey, Beat-Question, Beat-Target, Beat-Outcome, Beat-Started, Beat-Finished, Beat-Phases, Beat-Sensor |
| KV `beat-directory`, key `<name>` | KV | heartbeat | sensor | (the entry is signed JSON) |
| KV `beat-deny`, key `list` | KV | the org root's deny list | root, relayed by the service | (signed JSON) |

`Beat-Phases` says where an answer's time went, in milliseconds: `queue=N,secrets=N,run=N` (waiting for a slot, finding
secret files, the question's unit). It is a header like the times beside it, not part of the answer: the answer's hash
names it, and equal answers must stay equal. A heartbeat's `secret_walk` says when secret files were last walked for
and what was left out (`docs/security.md`).

- A sensor acks only when its answer is not out within a second, with the time it will answer by.
- The stream `beat` keeps `beat.survey.>`, `beat.ack.>` and `beat.answer.>` in order, so a survey is announced
  before its acks and answers.

## Blobs

- **Canonical JSON:** sorted keys, no whitespace, UTF-8. Writers write it; receivers hash the bytes they got
  (SHA-256, hex). Blobs written by both sides avoid floats, which Python and Rust format differently.
- **C17. A question's hash covers exactly what it asks:** `{v: 1, name, source, libraries, params}`. An answer's hash
  covers only what the sensor said: its records or its error, and gate 1's report when it found something. Who
  answered, when, and with which version are headers, so identical answers from many hosts are one blob.

## Signatures

- **One rule:** an Ed25519 signature covers the message's kind (`ask`, `survey`, `ack`, `answer`, `heartbeat`,
  `enroll`), all its other `Beat-*` headers, and the payload's hash, as canonical JSON (`signed_bytes`). A header given
  twice is refused.
- **C14. A question carries two signatures over the same bytes:** the member's (`Beat-Signature`) and the
  collector's (`Beat-Countersignature`). `Beat-Key`, the survey's public key, is the collector's, so a member cannot
  put in one of their own and receive answers that skip the service's checks.
- **C16. Answers and acks are signed by the sensor,** so they keep their origin through the bus and the store.
- **Member credentials** (H16): `{kind: "member", name, key, not_before, not_after, issuer}`, signed by an org root
  over canonical JSON, carried base64 in `Beat-Cred`.
- **The deny list** (H16): `{v: 1, kind: "deny", deny: {seq, issued, issuer, entries: [{name, before, until}]}}`,
  signed by a root. A credential named in an entry and issued before `before` is refused; the entry can go after
  `until`.

## Sealing

Each answer is sealed to its survey's key with HPKE (RFC 9180), base mode: X25519, HKDF-SHA256, ChaCha20-Poly1305.
The payload is the encapsulated key followed by the ciphertext; the `info` binds the survey and the target. The
answer's hash is not on the bus (equal answers would show as equal there); the collector hashes what it opened.

## Keys on a host

Raw 32-byte keys in base64, one per file.

| Path | What |
| --- | --- |
| `/var/lib/beat-sensor/keys/sensor.key` | the sensor's signing key, root only (`beat-sensor keygen`); hidden from questions |
| `/etc/beat-sensor/roots/<name>.pub` | the org roots it obeys (`configure --org-root`) |
| `/etc/beat-sensor/collectors/<name>.pub` | the collector keys that must countersign (from the service, at `configure`) |
| `/var/lib/beat-sensor/state/deny.json` | the newest deny list it has taken |

Any key in a directory counts, so a key is rotated by adding the new one, switching, then removing the old.

## Enrolment (HTTPS)

`<api>` is the sensor's `--api`: the org's address on the service. A service that serves many orgs puts each under
`/o/<org>` (`https://api.walkthebeat.ai/o/<org>`), and `beat sensors add` prints it. The org id in it is not a secret:
it only finds the org, and what the sensor gets there still needs that org's approval, token or trust policy.

- `GET <api>/v1/sensor-config`, open: the bus to connect to and the collector's public keys.
- `POST <api>/v1/enroll`, open: `{request, signature}`, the request being the sensor's name, public key, host name
  and time, plus a rollout token or an identity token when it has one, signed with the sensor's key (kind `enroll`).
  The answer is a code to approve, or `enrolled` (`sensor/src/enroll.rs`).
- `POST <api>/v1/bus-credential`, open: `{request, signature}`, the request being the sensor's name, public key and
  time (`iat`, within 5 minutes of the service's clock), signed with the sensor's key (kind `bus`). The answer is
  `{jwt, expires, inbox}` when the key is enrolled under that name, else 403 (`sensor/src/bus.rs`).

## Logins (NATS operator mode)

The service's operator key signs one account per org; the org's account key signs every login (a NATS user JWT,
`alg: ed25519-nkey`). A client sends the JWT and signs the server's nonce with the key the JWT names (`sub`).
Accounts share nothing: every subject, stream and bucket below exists once per org, so two orgs' sensors never hear
each other's questions, and two orgs may each have a sensor of the same name.

| Login | Key | Life | Subscribe | Publish |
| --- | --- | --- | --- | --- |
| sensor `<name>` | its enrolled key | an hour | `beat.ask.all`, `beat.ask.host.<name>`, `_INBOX_<name>.>` | `beat.ack.*`, `beat.answer.*`, `$KV.beat-directory.<name>`, `$KV.beat-guides.*`, `$JS.API.STREAM.INFO.KV_<bucket>` for those and `beat-deny`, the deny list's `list` by direct or message get |
| collector | the service's | a day | everything in the account | everything in the account |
| API | the service's | a day | `_INBOX_serve.>` | `beat.api.>`, `beat.cp.>` |

The collector makes the stream and the buckets; a sensor uses them.

## Survey outcomes

**C25. An up sensor answers; one that does not is a finding.** Each target ends **answered** (ok, partial or error,
including the sensor's own `busy` and `too_large`) or **not answered**: **down** (no fresh heartbeat: one every 10 s,
stale after 35 s) or **up, no answer**. The deadline is the only clock, judged by when a message reached the stream,
not when it was processed. There is no threshold: every up sensor that did not answer is reported.
