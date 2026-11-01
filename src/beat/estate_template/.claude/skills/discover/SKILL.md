---
name: discover
description: Discover a host, or a tier of similar hosts, in this estate repository and compile what you learn into probes (probes/*.star, Starlark) that re-collect it without you, plus hosts/<host>/model.md and questions.md. Use when the SRE asks to inspect, discover, understand or map hosts.
---

# Discover a host, and compile it into probes

Discovery is open-ended; its result must not be. You explore the host with the `run` tool (small Starlark probes
over the read-only beat builtins), and you leave behind **probes** that collect what you found, deterministically,
on this host and on similar ones, with no model in the loop. An SRE reads them like any other code.

Outputs:
- `probes/<name>.star`: one per piece of software or concern (`nginx.star`, `sched-agent.star`, `host-base.star`).
  Extend an existing probe rather than writing a near-duplicate. The default pack's are read-only: to change one,
  `@BEAT@ probes fork <name>` (it becomes the estate's), or write a probe for what the pack does not cover.
- `hosts/<host>/facts/<name>.jsonl`: written only by `@BEAT@ run <name> <hosts...>` (never by hand).
- `hosts/<host>/model.md`: what it all means, every observed statement citing probe records.
- `hosts/<host>/questions.md`: what could not be determined.

## Steps

1. **Context, at once.** Run every probe there is, on every host, in one go: `@BEAT@ probes run <hosts...>` (no
   hosts: every trusted live sensor). That is the estate's `probes/` and beat's default pack (`@BEAT@ probes` lists
   them), all in flight together, in about a minute, and their facts committed. **Tell the SRE what they show
   before exploring further**: what each host is, what runs, what stands out. Then read `annotations/`, the probes'
   headers (what each covers, where it applies, what it cannot see) and `hosts/<host>/`. A failed assertion is
   information: that probe's assumptions do not hold here, which is what discovery should fix. The default pack is
   a reference and a quick start, written for common hosts: expect some of it not to fit, and where it does not,
   fork it and adjust it, or discover more. It is never the end of discovery. Hosts that answer
   alike are one tier: discover the tier once, not each host.
2. **Explore.** Delegate to the `beat-investigator` subagent, one per host or tier: the hosts, the applicable
   annotations verbatim, what the
   existing probes already cover (so it does not redo it), and what to find out: what each workload is, how it
   starts, its configuration, what it depends on (files, certificates, credentials, other hosts), what normal looks
   like in its logs, and risks. Ask it to return, with each finding, the probe code that established it.
3. **Write the probes.** Rules, in order of importance:
   - **Find, do not hardcode.** Locate configuration from what runs: the unit's ExecStart, a `-c` flag in a
     command line, an `include`; fall back to the package default and say so in a comment.
   - **Check assumptions.** `one(osq(...), "expected one nginx master")`; `expect(s != None and s.readable, "no "
     + conf)`. On a host that differs, the probe must fail loudly at the assumption, never emit nothing. Where one
     bad item must not hide the others (each certificate, each unit file), loop with `each(items, fn)`: a failure
     then ends that item only.
   - **Emit observations, not verdicts.** Emit both sides and let the comparison happen centrally: a config value
     and the file's mtime *and* the process start time, never "pending"; a certificate's not-after date, never
     "expires soon"; a live sysctl *and* the value the files set.
   - **Records:** `emit(subject, key, value, source, kind = ...)`, values as strings; declare `kind` ("semantic" for
     settings, "metric" for counts and sizes, "time" for times, "identity" for names and addresses). SUBJECT is `kind:stable-id`
     (`unit:nginx.service`, `file:/etc/nginx/nginx.conf`, `cert:/etc/x.crt`, `endpoint:sched01:7520`), never a PID
     or the run's time. KEY says what (`listen`, `ssl_protocols`, `mtime`, `user`). SOURCE is `file:line`, an
     osquery table or `journal`. Relations are records too:
     `emit("unit:nginx.service", "loads", "file:/etc/nginx/nginx.conf", source)`.
   - **Readable.** A docstring header: what it covers, where it applies, its assumptions, what it cannot see, who
     wrote it and when. Code in `main()` and small named functions, one per concern, with a comment each; constants
     at the top. No cleverness an SRE has to decode.
   - **Logs through the log builtins.** `log_summary` + `emit_log_summary` for what normal looks like in a log
     (curate the templates with `logs` and pass them back as `log_summary(templates = [...])`); not regexes and
     counters over lines. A structured log you need numbers from (an access log's status codes, response times)
     may be aggregated with the `awk` tool.
   - **Builtins only, no secrets.** The `run` tool's description lists them. Certificate and key metadata through
     `osq` (osquery `certificates`) and `secrets()`, never their contents; passwords in config files as
     `password=<set>`, never the value.
4. **Run and check.** `@BEAT@ run <name> <hosts...>` for each probe, on every host it applies to (one survey; it
   prints the survey id), then `survey` or `analyze <id>` to see how the hosts compare. Exit 0, no failed assertions, and every observed
   statement you intend to make is supported by a record. Fix and re-run until it is. Read the records back from
   `hosts/<host>/facts/<name>.jsonl`. Before saving a probe, run its exact text with the `run` tool: the sensor
   checks names, types and structure before anything runs, and reports problems with file:line.
5. **Write `model.md`**: one paragraph on what the host is for (inferred, say from what); workloads; listeners;
   relations (`A -> B (kind)`); expectations (what normal progress looks like); risks with dates. Tag every line
   observed (cite `probe:<name> <subject> <key>`) / stated (annotation) / inferred.
6. **Write `questions.md`**: what no probe could determine, why, and what would answer it; one sentence each.
7. **Show and ask.** The probes are the main artifact: show them first, then a few lines on the host (purpose, top
   risks, open questions) and `git status`. Commit probes, model and questions only when the SRE agrees.
