Run one probe on the host: a Starlark program (Python syntax, Bazel's configuration language). It can only call the
builtins below; they only read. There is no shell: no processes, no network, no writes.

Shape of a probe:
    """<what it covers>.

    Applies to: <which hosts>.  Assumes: <what must hold>.  Cannot see: <blind spots>.
    """
    UNIT = "nginx.service"                     # top level: constants and functions only

    def main() -> None:                        # the sensor calls main()
        u = one(osq("select active_state from systemd_units where id = ?", UNIT), "expected one %s" % UNIT)
        emit("unit:" + UNIT, "active_state", u["active_state"], "osq.systemd_units")

Records and checks:
  emit(subject, key, value, source, kind="")   one observation; all four are strings (str(n) for numbers);
                                      kind declares what the value is: "metric" (a measurement: counts, sizes,
                                      ages), "time", "identity" (unique per host), "semantic" (configuration).
                                      Declare measurements: one host's 0-3 restarts look like a setting.
  one(list, message)                  the only element, else a failure "message, got N"
  expect(condition, message)          a failure if the condition is False
  fail(message)                       always a failure
  each(items, fn)                     fn(item) for each item; a failure ends that item only, not the probe
  print(...)                          debugging text for you, not a record
A failure means the host differs from what the probe assumes; outside each() it ends the probe.

Records are compared across many hosts, so:
  - one fact per record: "app_version" "1.5.0" and "batch_interval" "10", not one line holding both; several
    values of a key are several records
  - what the config says and what the running process shows are separate records of the same fact
    ("server" from the file, "connected_server" from the process or its log)
  - no PID, port number of a connection, timestamp or generated id in a subject or key; those are values
  - declare measurements (kind="metric") and name them as such (_count, _pct, _bytes, _age_s): a count that
    takes few values is not configuration
  - one form per kind of value: plain digits, times as epoch seconds or iso_utc, yes/no
  - absence that matters is a record: emit("file:/etc/x", "present", "no", "stat")

Files (read-only; paths absolute):
  read(path) -> str                   a secret path is a failure "denied"; a missing one, "missing"
  stat(path) -> struct | None         .kind ("file" "dir" "link" "other") .size .mode ("644") .uid .gid .user
                                      .group .mtime (epoch s) .readable .secret; None if missing
  glob(pattern) -> list[str]          sorted; * ? [..] and **; no match gives []
  list_dir(path) -> list[str]         names, sorted
  readlink(path) -> str | None
  keytab(path) -> dict                what klist -k shows: .format .entries [{principal kvno enctype timestamp
                                      name_type key_bytes}]; never the keys. Not a keytab: a failure "format"
  certificate(path) -> dict           a PEM chain or DER file: .certificates [{subject issuer serial not_before
                                      not_after sans is_ca self_signed key key_bits signature fingerprint_sha256
                                      public_key_sha256}] .other_blocks
  private_key(path) -> dict           what the key is, never the key: .format .label .algorithm .encrypted
                                      .der_bytes; OpenSSH keys also .cipher .public_fingerprint (as ssh-keygen -l)
                                      These three read secret files too: take the path from the config or the
                                      environment that names it (ssl_certificate, KRB5_KTNAME, default_keytab_name).
  environ(pid) -> list[struct]        a process's environment: .name of every variable, .value of names known to be
                                      safe (PATH, CLASSPATH, JAVA_OPTS, ...; passwords in them masked), else None, and
                                      .hash for the others: emit it as a value and the answer holds a keyed hash there,
                                      equal across hosts for equal values. osq()'s process_envs is refused for this
  secrets() -> list[struct]           secret files (shadow, keys, keytabs): .path .kind .mode .uid .gid .size
                                      .mtime; their content is never readable. A run note says
                                      what was not checked (container storage, network mounts)

Live state (the probe itself runs as a transient unit beat-question-<pid>-<n>.service, child processes of
beat-sensor: leave them out of unit and process lists, or every run looks like a change):
  osq(sql, *params) -> list[dict]     osquery SQL (SQLite dialect, joins); ? take the params; typed values
                                      (int, float, str, None). One call costs ~0.6 s: prefer one query with a
                                      join or an IN list over a query per item.
  journal(unit=, since=, grep=, limit=1000) -> list[dict]   .ts .unit .pid .priority .message, oldest first;
                                      since as journalctl takes it ("-30d", "2026-10-01"); grep: a regex
                                      kernel=True: the kernel's messages, this boot (what dmesg shows)
  sample(patterns, seconds=1) -> struct   the files matching the globs read, then read again `seconds` later
                                      (at most 60): .seconds (measured) .before .after ({path: content}); for
                                      counters in /proc and /sys. A process gone by then is missing from .after.

Performance, Gregg's 60-second checklist and the USE method (utilization, saturation, errors per resource):
  checklist(seconds=5, top=10, cgroup_depth=4) -> dict   one interval, as uptime, vmstat, mpstat, pidstat, iostat
                                      -xz, free, sar -n DEV and sar -n TCP,ETCP would show it, plus pressure (PSI)
                                      and cgroup CPU throttling:
      .use [{resource, utilization, saturation, errors}]  the USE reading as text: read this first
      .load {load1 load5 load15 runnable cpus ctxt_per_s intr_per_s forks_per_s procs_running procs_blocked}
      .cpu {usr sys iowait steal idle busy} (%)  .cpus [{cpu, ...the same}]
      .memory {total_mb available_mb used_pct swap_used_mb dirty_mb swapin_per_s swapout_per_s majflt_per_s
               pgscan_per_s oom_kills}
      .psi {cpu_some memory_some memory_full io_some io_full}  % of the interval stalled
      .disks [{disk r_per_s w_per_s rkb_per_s wkb_per_s r_await_ms w_await_ms queue_len util_pct}]  with I/O only
      .nics [{nic rx_kb_per_s tx_kb_per_s rx_pkt_per_s tx_pkt_per_s rx_errs tx_errs rx_drop tx_drop}]
      .tcp {active_opens_per_s passive_opens_per_s retrans_per_s retrans_pct curr_estab in_errs out_rsts_per_s
            listen_drops timeouts udp_in_errors udp_rcvbuf_errors}  (counts over the interval)
      .procs [{command procs cpu_pct cpu_max_pct cpu_min_pct running blocked threads majflt_per_s}]  the busiest
            commands, and any with a process in D state; max and min show one process of many (one slow rank)
      .cgroups [{cgroup cpu_pct throttled_pct throttled_periods_pct quota_cpus}]  most throttled, then busiest
      .notes   what was left out (idle disks, exited processes, a source this kernel lacks)
  Short-lived processes do not show in .procs (they exit within the interval): forks_per_s does.
  emit_checklist(c)                   records: subjects host, cpu, cpu:<n>, memory, psi, disk:<name>, nic:<name>,
                                      tcp, proc:<command>, cgroup:<path>; all kind="metric"
  The answer is a few KB whatever the load. For the kernel's messages: log_summary(lines=[e["message"] for e in
  journal(kernel=True)]).

Tracing, B. Gregg's tools (eBPF), where the sensor has the catalog; the answer is a reduction, never the events:
  trace(entry, seconds=5, options={}, filter={}, key=[], sum=[], hist=None, top=20, examples=3) -> dict
      entry is a literal (it decides the question's privileges):
        biolatency  block I/O latency       options: per_disk, queued, disk=, cgroup=
        runqlat     wait for a CPU          options: per_process, pid=, cgroup=
        cpudist     time on CPU per run     options: per_process, offcpu, pid=, cgroup=
        execsnoop   new processes           fields: comm pid ppid ret args        options: failed, uid=
        opensnoop   files opened            fields: pid comm fd err path          options: failed, pid=, uid=
        tcpconnect  connections made        fields: pid comm ip saddr daddr dport options: pid=, ports=
        tcplife     connections closed      fields: pid comm laddr lport raddr rport tx_kb rx_kb ms
                                                                                  options: pid=, local_ports=, remote_ports=
      Histogram entries: .histogram {unit count p50 p90 p99 max buckets [[lo, hi, n]]}, or with per_disk /
        per_process .histograms [{disk | pid comm, ...}] (the `top` busiest) and .histograms_total.
      Event entries: filter {field: "x" | "x*" (prefix) | "!x" | [a, b]}; key: fields, coarsened with
        "path:dir2" (first 2 directories), "path:basename", "daddr:/24", "args:template" (numbers as <N>);
        sum: numeric fields to add up per key; hist: one numeric field as a log2 histogram per key.
        -> .events {seen matched unparsed own_left_out lost per_s} .keys {distinct shown overflow_events}
           .groups [{key, count, per_s, sum?, hist?, examples}]  (the `top` keys by count)
      .seconds, .entry. lost > 0: the kernel dropped events; the counts are a lower bound.
  How to ask (raw events never leave the host):
    1. the rate first: trace(entry, seconds=1, key=[]) on one host; is there anything, how much
    2. the shape: a coarse key (comm; path:dir2; daddr:/24), examples=3
    3. drill: filter to what stands out, a finer key, a hist of a duration
    4. one number that answers the question; then ask that same question of every host
  Do not ask for every event: a key of pid or full path on a busy host is thousands of groups.

The host's network (sensor 0.2.3 on): `/proc/net`, `/proc/sys/net` and osquery's `routes`, `interface_details`,
`interface_addresses`, `arp_cache` describe the host. On older sensors they describe an empty sandbox; read
`/proc/1/net` there. Firewall rules (`iptables`) stay empty: reading them needs a privilege questions do not have.

Traffic (where the sensor has tcpdump): headers, DNS questions and the TLS handshake, reduced on the host:
  capture(view, interface=None, host=None, port=None, proto=None, seconds=5, filter={}, key=[], sum=[], hist=None,
          top=20, examples=3) -> dict          one capture at a time per host; seconds 1..60
      The sensor writes the capture filter from host (an IP address), port, proto ("tcp", "udp", "icmp"); there is no
      free-form filter. interface: the route to host, or the default route's; "any" for all (a packet crossing a
      bridge is then seen more than once). The packets and flows views also keep ICMP errors from anywhere.
      Views and their fields (for filter, key, sum, hist as in trace()):
        packets  one per packet: t proto src dst sport dport flags (tcpdump's letters) win icmp dir len payload
        flows    one per flow, at the end: proto client cport server port orient packets pkts_c2s pkts_s2c bytes_c2s
                 bytes_s2c duration_ms syn syn_retrans synack rst rst_by fin retrans_c2s retrans_s2c zero_win
                 max_seg_c2s max_seg_s2c handshake_ms icmp_errors state (open, closed, reset, syn_unanswered, mid)
        dns      one per query (udp port 53 by default): qname qtype client server sends rcode answers latency_ms;
                 rcode no_answer: never answered within the capture
        tls      one per TCP flow that starts with TLS: client server port sni alpn_offered versions_offered version
                 cipher alpn alert alert_by alert_level hello_ms state tcp_state tcp_handshake_ms
      -> .events .keys .groups as trace(); .capture {view frames packets truncated over_1514 ... interface filter
         snaplen tcpdump {end captured received dropped}}. tcpdump.dropped > 0: the kernel dropped packets.
      Read with care: on the receiving side offloads merge segments (sizes are the kernel's; retransmits a lower
      bound); TLS 1.3 encrypts the server's alerts, and a client may close without one: no alert proves nothing.
  How to ask: flows first (key=["server", "port", "state"]); then the view that answers (dns for names, tls for a
  handshake), filtered to the server that stands out.

Logs (when drain is among the tools; input: path= a file, tail= its last N lines, or lines= e.g. journal messages):
  log_summary(path=, lines=, tail=0, self_names=[], header=0, templates=None, masks={}, examples=3, top=200,
              minutes=60, levels=12)  -> dict: .lines, .templates: [{id, template, count, params: [{distinct,
                                      values: [[v, n]], min?, max?, categorical?, minutes?}], examples, new?,
                                      minutes: [[minute, n]]}]. A parameter with 2..levels values (a status, a
                                      method) is categorical: counted per value per minute. Lines are grouped into
                                      templates (Drain): variables become <*>, and <TIME> <IP> <UUID> <HEX> <PID>
                                      are masked. Pass the host's names in self_names (they become <SELF>, so
                                      templates compare across hosts) and header=3 for syslog-style files.
                                      templates=[...] (from an earlier summary): match exactly those, so hosts
                                      report the same ones; other lines come back mined, with new=True.
  emit_log_summary(name, summary)     records in one shape: subject log:<name>#<template id>; keys template,
                                      lines_count, p<i> (one per value), p<i>_distinct_count, example, new,
                                      lines_count@<minute>; for categorical parameters p<i>=<value> and
                                      p<i>@<minute> (lines per value, per minute). The record index keeps them as
                                      time series (log_minutes, log_values): no need to count in the probe, e.g.
                                      statuses with awk; make the status a <*> of a template instead
  log_extract(path=, lines=, tail=0, templates=None, grep=None, limit=20, first=False, self_names=[], header=0)
                                      -> dict: .matched, .lines: the lines as written, last `limit` of them
  Both return .span {lines_read, first_time, last_time}: what they covered. Give a summary and an extract over
  one file the same tail=, or they cover different stretches of it.
  Explore with log_summary, pick templates, ask again with templates=[...]; log_extract for the lines behind one.

Text (pure):
  re_match(re, s) -> list | None      [whole, group1, ...] of the first match (Rust regex syntax)
  re_find_all(re, s) -> list[str]     group 1 if the regex has one, else the whole match
  re_sub(re, repl, s) -> str          $1 in repl is group 1
  path_join(*parts)  path_dirname(p)  path_basename(p)  iso_utc(epoch_seconds) -> "YYYY-MM-DDTHH:MM:SSZ"
  and Starlark's own: str methods (split, splitlines, strip, startswith, partition, ...), json.decode, sorted,
  enumerate, dict, list comprehensions, "%s" % x. No while loops, no recursion.

Tools (WebAssembly programs; arguments are passed as given, never through a shell). A tool has /proc's own files and
/proc/sys, not /proc/<pid>, nor / itself (list_dir("/")); a path through a symlink out of its top-level directory, such
as /etc/os-release, works when it is a whole argument: pipe(["wc", "-l"], stdin = read("/proc/1/mounts")):
  <tool>(*args, stdin="") -> struct   .stdout .stderr .status (list of exit codes) .ok
  pipe([tool, arg...], [tool, arg...], stdin="")   the same, stdout of each into the next
  A non-zero exit is a value, not a failure: check .ok or .status yourself.
  Available tools: {tools}
  A binary's text (paths, messages, format strings): pipe(["cat", path], ["strings", "-n", "6"]).
