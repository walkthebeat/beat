---
name: investigate
description: Investigate an incident across the estate — from a symptom to the named root-cause mechanism, isolating which hosts and when it started, and record an RCA. Use when the SRE reports something wrong (slow, errors, a failed deploy, a hang, a host behaving oddly) and wants the cause, not just the symptom.
---

# Investigate an incident: from the symptom to the named cause

Your output is a root-cause analysis: the symptom and its impact, a timeline, the **cause stated as a mechanism**,
the evidence, the alternatives ruled out — recorded against the estate so it can be queried later. "metricsd seems
to be slowing things down" is a symptom, not a cause; the cause is *what it does and why that hurts* ("metricsd
forks ~300 children/s with no exec, saturating the run queue on nodes 03 and 05, so rank 2 there stalls and the
lockstep job waits for it"). You reach hosts only through the read-only beat tools; delegate deep single-host
exploration to the `beat-investigator` subagent while you keep the fleet view and the RCA.

## The bar you are held to — read before you start

You are not done when you can name a busy process. You are done only when all of these hold:

- **The cause is a mechanism, not a component.** Keep asking "why" until the next answer is a kernel/OS fact nothing
  beat can see goes behind, or it points off this host. A named process is a waypoint, not the terminus.
- **You isolated which hosts, and why those and not the others.** In a coupled/lockstep workload every node *looks*
  busy because it waits for the slowest — only the cross-fleet compare finds the few that are the cause.
- **You placed it in time, allowing for a gap.** When it started, and what changed then. An effect can lag its cause
  by hours or days, so "nothing changed just now" does not clear a change made earlier.
- **A fleet-wide change is a red herring until you tie it to the sick subset.** Same version everywhere but only some
  hosts sick ⇒ the cause is the change *and* the condition that fires on those hosts, together — not the change alone.
- **You separated look-alikes and the expected.** Different faults have different signatures; subtract what is
  expected (scaling to more nodes, a scheduled batch) before blaming the fault.
- **Off-host / no-local-cause is a valid terminus**, stated as such with the evidence that points outward — not a
  dead end you stop short of. So is *below* the host: a device or the hypervisor that stops answering.
- **You claim only what you observed.** A mechanism inside code you cannot see into (a closed binary, a remote
  service) is a hypothesis, never the cause. A timing coincidence ("it began N minutes after start") is a lead to
  test, not a mechanism. That includes your own records: when you say what a probe run or a survey shows, read the
  values that bear on the question in *that* answer, not its diff stat, the lines it removed, or what an earlier
  run said. A state you saw end can come back between two runs.
- **Your evidence covers the moment it matters.** A check taken after the onset cannot clear what happened at the
  onset: "no inbound connections" from a trace twelve minutes later says nothing about the minute it began.

## Steps

1. **Frame and get normal.** Restate the symptom as something measurable ("order batches: none completed since
   14:00"). Read the tier's `model.md` (its expectations: cadence, log pairs, what normal looks like) and the
   annotations that apply — that is your baseline. Never judge "slow" without "slow versus what".
2. **Fleet first: isolate the subset.** `survey` the relevant probes over the whole tier, not one host; its grouping
   shows drift, rare values and inconsistencies — the few hosts that differ. Record which hosts, and the metric that
   separates them. Do not visit hosts one by one and compare yourself.
3. **To the mechanism: USE, then `trace()`.** On a sick host, go resource by resource — utilization, saturation,
   errors — for CPU, memory, disk, network (the checklist in `CLAUDE.md`). Where a snapshot cannot explain it because
   the cause is in what a process *does* (same unit, binary and command line, no drift, yet it misbehaves), use
   `trace()`: `runqlat` (run-queue latency), `cpudist` (on-CPU time), `execsnoop` (new processes — forks without
   exec show here and nowhere else), `biolatency` (block I/O latency), `opensnoop` (opens), `tcpconnect`/`tcplife`
   (connections). Scope it (`pid`/`cgroup`) so the answer stays small.
4. **What changed — and when.** `survey`'s drift and `query` over `changes` and `series` say what moved and when;
   correlate with the symptom's onset (a job's submit time, a deploy, a version bump). Hold the two possibilities
   open: a local, recent trigger, or a change made earlier whose effect lagged or fires only on a subset. A
   fleet-wide change does not become the cause until you explain why only the sick hosts react.
   **Ask who touched the estate at the onset.** Operators and automation leave traces where they come from, not only
   where they land: logins, sudo, ssh and configuration-management runs in the journals of the hosts that
   administer the fleet (a bastion, a deploy or management host), around the onset, before and after. Ask beneath the
   OS too: device errors, hung tasks, I/O that stops with nothing queued behind it locally, CPU steal.
5. **Separate look-alikes and the expected.** Several faults in one survey read as one: separate them by signature
   (fork noise vs disk contention are different mechanisms, often on different hosts). Then subtract the expected — a
   job spread over more nodes is slower by the scaling, a nightly job loads the disk on schedule — and say which
   effect you attributed to what.
6. **Confirm, and rule out.** Confirm the mechanism against a second source where you can (the operator's own output
   reached through the sensor; a second `trace()`; a correlated log). Name the alternatives you considered and the
   evidence that ruled each out.
7. **Write the RCA.** `incidents/<date>-<slug>.md`: symptom and impact; a timeline (onset, the change, detection,
   resolution); the root cause as a named mechanism with the hosts it hit; the evidence (probe records, survey ids,
   `trace()` output — cite them); alternatives ruled out; and what would catch it next time (a probe or a beat
   check). Tag every line observed / stated / inferred. It belongs with the estate — committed and queryable later
   ("has this happened on these hosts before?").
8. **Show and ask.** Lead with the cause and its evidence, then the RCA and `git status`. Commit only when the SRE
   agrees. End with what your checks did **not** cover: "nothing else" is a claim about the checks you ran.

## When the cause is off-host

No local drift and no local mechanism explains it is a *finding*, not a failure: an external trigger — another host,
a central rollout, a client, an operator, the network path, the storage or hypervisor beneath — is the terminus.
Point at it with the evidence you have (an inbound connection, a remote time that lines up, an opcode on a port, a
session on an admin host, a device that stopped answering) and say what off-host access would confirm it. Do not
invent a local cause to avoid stopping there.

You reach this terminus when the sick and the healthy hosts are identical in everything you can compare (binary,
config, unit, start time, environment) and the difference is only in behaviour. Then the RCA says, in these terms:
**the mechanism** (what the process or device does now and why that hurts — observed), **the trigger: external,
not identified** (or the off-host source, if you found it), **what would identify it** (the logs, hosts or access
that would), and the hypotheses you could not test, labelled as such. Your advice follows from that: a restart that
clears the state, and watching for recurrence. Do not schedule around a trigger you invented ("expect it again N
minutes after the restart").
