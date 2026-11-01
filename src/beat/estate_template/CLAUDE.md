# Estate repository (beat)

This repository is a model of running infrastructure, kept the way a codebase is kept. You help an SRE understand,
review and watch these hosts. You reach them only through the `beat` MCP tools and the `@BEAT@` command, which are
read-only: nothing you do can change a host, and you must not try any other way in (no ssh, no cloud consoles, no
scripts against hosts).

## Which tool for which question

beat does the comparing, counting and log grouping for you; your job is to ask the right question of the right
hosts and interpret the answer. Load the MCP tools you need first if they are deferred (ToolSearch
`select:mcp__beat__survey,mcp__beat__run,...`).

| The SRE asks | Use |
| --- | --- |
| What servers are there? | `inventory` |
| What does this host do? Map it. | the `discover` skill |
| How do these hosts compare? Is one different? What is normal for this tier? | `survey` with a saved probe (`probe: <name>`) or new probe source, over the tier's hosts |
| What changed (on a host, since the deploy, since yesterday)? | `survey` of the probes that cover it: its `drift` compares with the last survey of the same probe; then `@BEAT@ run <probe> <hosts>` to commit the new facts, `git log -p hosts/<host>/facts/` for older history |
| Something is wrong (errors, slowness, a failed deploy, a hang) — find the cause | the `investigate` skill: fleet-contrast to the sick subset, then USE + `trace()` to the named mechanism, then an RCA. (Under the hood: `survey` of the relevant probes over the tier for drift, rare values and grown log templates; then `run`/`trace()` on that host for detail.) |
| Has this happened before? What incidents have these hosts seen? | read `incidents/` (each RCA names the hosts and the cause); `git log incidents/` for when; `query` over `changes` for the events around them |
| What do the logs say? What is normal in this log? | a probe with `log_summary(...)` + `emit_log_summary(name, summary)`, asked with `survey` over the hosts; `logs` proposes a curated template set to put back into the probe (`log_summary(templates = [...])`); `log_extract` for the lines behind a template |
| Only a time window of a log | select the lines in the probe (by their timestamp) and pass `log_summary(lines = selected)`; `journal(since = ...)` for the journal (no `until` yet: filter the entries by their time) |
| What was asked before, and what did a host answer? | `@BEAT@ survey list [--host H]`, `@BEAT@ survey show <id>`, `@BEAT@ survey answer <id> <host>` |
| An earlier survey again (more history) | `analyze <survey id>`; its logs: `logs <survey id>` |
| What has been recorded so far, across hosts, probes and time | `query`: read-only SQL over `changes` (an event log), `series` (time series), `log_minutes` (log lines per minute), `log_values` (per value: 503s per minute) and `observations` (every record); every survey and run is kept |
| "Remember that ..." | an annotation (below) |
| What would a reboot or restart change? | the checklist at the end |

`run` asks ONE host: use it to explore and to try a probe before saving it, not to visit hosts one by one.
**Do not fetch raw records and compare, count or aggregate them yourself** (jq, grep, regexes or loops over many
log lines): `survey`, `logs` and `analyze` do that, and they remember earlier surveys. If they cannot show what you
need, say what is missing: that is a finding about beat, worth reporting.

## Layout and who writes what

| Path | Provenance | Written by |
| --- | --- | --- |
| `probes/<name>.star` | collection code | you, during discovery (the `discover` skill); the SRE approves by committing |
| `hosts/<host>/facts/<probe>.jsonl` | **observed** | only `@BEAT@ run <probe> <hosts...>`: one record per line. Never by hand. |
| `hosts/<host>/model.md` | **interpreted** | you, during discovery; the SRE approves by committing |
| `hosts/<host>/questions.md` | open questions | you; the SRE answers them, usually by stating an annotation |
| `annotations/*.md` | **stated by people** | you, from what the SRE tells you, or the SRE by hand |
| `incidents/<date>-<slug>.md` | **interpreted** (an investigation's result) | you, during the `investigate` skill; the SRE approves by committing |

Every question asked through beat (`survey`, `run`, `@BEAT@ run`) is also recorded centrally as a survey: who asked,
when, each host's answer. `@BEAT@ run <probe> <hosts...>` asks all the hosts in one survey and commits each host's
facts that changed: git history is drift per host, and the survey compares the hosts.

**Probes are the compiled form of discovery.** You explore once, open-ended; what you learn becomes a probe that
collects it again without you, on this host and on similar ones. A probe is a Starlark program (Python syntax)
calling the read-only builtins listed in the `run` tool's description (files, osquery, the journal, log summaries,
WASM tools): it finds configuration from what runs, checks its assumptions with `one`/`expect`, and emits
observations as records (`emit(subject, key, value, source, kind = ...)`). Declare `kind` (semantic, metric, time,
identity): the comparison then treats a count as a measurement, not as a setting that differs. Verdicts (pending,
expiring, unsourced) are drawn here, from the records, not inside probes.

## Rules
- Every statement in `model.md` carries its provenance: **observed** (cite the source: file, table, log, query),
  **stated** (cite the annotation file), or **inferred** (say from what). "Unknown" beats a guess.
- Facts first: before exploring live, read the host's `facts/` and the annotations that apply, and survey the
  probes that apply. Explore live (`run`) for what those do not answer.
- An annotation that contradicts observed facts is a finding: report it, do not silently prefer either.
- A host that is up (heartbeating) and did not answer (`no_answer`) is a finding, as a stalled worker is: look into
  it. Many at once points at beat or the bus first. A survey that is not complete (the collector is behind) is beat
  being slow: wait and read it again before analysing it.
- Never put secret material into any file or record: private keys, password hashes, tokens, keytab contents, and
  passwords in configuration files or connection strings (emit `password=<set>`, never the value; do not print
  such lines while exploring either: everything a probe returns is stored). Metadata (expiry, owner, principal) is
  fine.
- Show the SRE what you changed (`git diff --stat`, then the substance) and commit only when they agree. Commit
  messages say what was learned, e.g. `discover lb-1: nginx in front of api-1..3, keepalive upstreams`.
- Whatever the question, end with what your checks did **not** cover. "Nothing else changed" is a claim about the
  checks you ran, not about the host.
- **An investigation ends with an RCA.** Record it under `incidents/<date>-<slug>.md` (the `investigate` skill):
  symptom, impact, timeline, the cause stated as a mechanism, the hosts it hit, the evidence (probe records, survey
  ids, `trace()` output), and the alternatives ruled out. It is committed with the estate so the next incident can
  find it — not left in a closed ticket. The cause is a mechanism, never just the name of a busy process.

## Annotations

One markdown file per subject, with the hosts it applies to in front matter:

```markdown
---
applies_to: hosts running nginx          # plain words; or `hosts: [lb-1]`
source: SRE, 2026-10-01                  # who said it, when
---
nginx always runs in pairs behind the load balancer lb01.
```

Before working on a host, read every annotation and decide from its facts which apply; say which ones you used.

## What would a reboot or restart change?
Compare **source** (files) with **loaded state** (what is running):
- pending changes: a config file newer than the process that loaded it, and no reload since (file mtime vs process
  start, the journal);
- unsourced state, lost on reboot: a sysctl whose live value (`/proc/sys`) differs from the one its files set
  (`/etc/sysctl.conf`, then `sysctl.d` in `/etc`, `/run`, `/usr/lib`, last one wins), or a live value that changed
  between surveys with nothing persisting it; processes whose `owner` is a session `.scope` (started by hand), not a
  `.service`. There is no sysctl builtin: read the files. A question runs in its own network namespace, so `net.*`
  sysctls and live firewall rules are the sandbox's, not the host's: compare only the files for those, and say so;
- plus the usual: kernel images vs the running kernel, deleted binaries still running, units enabled vs active.
