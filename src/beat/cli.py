"""beat: the operator CLI. Questions to the beat service over HTTP (ask, sensors, survey, ...: BEAT_API), the org's
signing keys (keys), signing in (login, whoami, logout), the org's trust policies (org trust), estate repositories (init, run). The service has its own command,
`beat-service`."""
from __future__ import annotations

import argparse
import os
from pathlib import Path


def main() -> None:
    try:
        _main()
    except RuntimeError as e:  # not signed in, the service not answering or refusing: one line, not a traceback
        raise SystemExit(f"error: {e}")


def _main() -> None:
    ap = argparse.ArgumentParser(prog="beat")
    sub = ap.add_subparsers(dest="cmd", required=True)
    ei = sub.add_parser("init", help="create an estate repository (git)")
    ei.add_argument("dir", nargs="?", default=".", help="a new or empty directory (default: this one)")
    er = sub.add_parser("run", help="run a probe on hosts; records go to hosts/<host>/facts/<probe>.jsonl "
                        "in the estate repo here, committed if they changed")
    er.add_argument("probe", help="probes/<name>.star by name, or a .star file")
    er.add_argument("hosts", nargs="+")
    er.add_argument("--no-commit", action="store_true")
    er.add_argument("--stdout", action="store_true", help="also print the probe's text output (print())")
    pr = sub.add_parser("probes", help="the probes this estate runs: its own (probes/) and beat's default pack; "
                        "`fork NAME`: copy the pack's into probes/ to change it; `run [HOSTS]`: every probe at once on "
                        "the hosts (default: every trusted live sensor), facts committed as `beat run` does")
    pr.add_argument("action", nargs="?", choices=["list", "fork", "run"], default="list")
    pr.add_argument("args", nargs="*", help="fork: the probe's name; run: the hosts")
    pr.add_argument("--no-commit", action="store_true", help="run: write the facts, commit nothing")
    ak = sub.add_parser("ask", help="ask a question (a .star file) of every live sensor, or of --host ones; "
                        "answers grouped by answer hash")
    ak.add_argument("question", help="a .star file")
    ak.add_argument("--host", action="append", default=[], help="only this sensor (repeatable)")
    ak.add_argument("--timeout", type=int, default=120, help="the question's time limit on each sensor, seconds")
    ak.add_argument("--show", action="store_true", help="print each distinct answer")
    ak.add_argument("--json", action="store_true", help="print the whole survey as JSON")
    ak.add_argument("--analyze", action="store_true", help="answer with the comparison across the hosts (as MCP "
                    "`survey`): categories, then `beat analyze` of the survey, and its logs if the probe emits them")
    ak.add_argument("--dataset", action="store_true", help="answer with a pointer to the survey's dataset "
                    "(Parquet tables to analyse): `beat dataset` of the survey")
    lg = sub.add_parser("login", help="sign in to the beat service: a code to approve in a browser (the issuer the "
                        "service trusts), then this machine's login is kept and renewed (login.py)")
    lg.add_argument("url", nargs="?", help="the service (https://HOST, or http://HOST:8480), kept as this machine's "
                    "from then on; without it, the one kept, else https://api.walkthebeat.ai (BEAT_API, when set, wins over all)")
    wh = sub.add_parser("whoami", help="who this machine is signed in as, as the service sees it, and which service")
    wh.add_argument("--sensor-api", action="store_true", help="print only the URL the org's sensors call (their "
                    "--api: the service's, with /o/<org>), for scripts")
    sub.add_parser("logout", help="forget this machine's login to its service, and revoke it")
    sn = sub.add_parser("sensors", help="list the live sensors (the NATS directory); `add`: the command that "
                        "configures a host's sensor for this service and org; `pending`, `approve CODE`, `deny CODE`: "
                        "sensors asking to join (beat-sensor configure or enroll on the host); `remove NAME`: "
                        "unenrol one; `token`: a rollout token, which enrols up to --hosts sensors with no approval; "
                        "`tokens`, `revoke-token ID`")
    sn.add_argument("action", nargs="?",
                    choices=["add", "pending", "approve", "deny", "remove", "token", "tokens", "revoke-token"],
                    help="adding a sensor, enrolment by approval or by rollout token, removing one")
    sn.add_argument("code", nargs="?", help="the code the host printed (approve, deny); the sensor's name (remove); "
                    "the token's id (revoke-token)")
    sn.add_argument("--hosts", type=int, default=1, help="token: how many sensors it may enrol (default 1)")
    sn.add_argument("--expires", default="24h", help="token: how long it lasts: 30m, 24h, 7d (default 24h)")
    sn.add_argument("--note", default="", help="token: what it is for, shown in `beat sensors tokens`")
    sn.add_argument("--yes", action="store_true", help="approve without asking to compare the fingerprint")
    sn.add_argument("--attest", metavar="oidc:FILE|aws", help="add: the configure line for hosts that prove who they "
                    "are with the identity token in FILE, or one the sensor asks AWS STS for (a trust policy accepts "
                    "it: beat org trust)")
    og = sub.add_parser("org", help="the org's settings at the service: `org trust` lists its trust policies, which "
                        "admit sensors by an identity their platform gives them (docs/security.md H13); `org trust add "
                        "NAME --issuer URL --name-from CLAIM`, `org trust remove NAME`")
    og.add_argument("what", choices=["trust"])
    og.add_argument("action", nargs="?", choices=["add", "remove"])
    og.add_argument("name", nargs="?", help="the policy's name")
    og.add_argument("--issuer", help="add: the OIDC issuer, as tokens name it in iss (a cluster's, a cloud's)")
    og.add_argument("--audience", help="add: what the platform was told the token is for (default beat-enroll)")
    og.add_argument("--claim", action="append", default=[], metavar="PATH=VALUE",
                    help="add: a claim the token must carry (repeatable); nested claims as kubernetes.io/namespace")
    og.add_argument("--any-workload", action="store_true", help="add: no --claim: every workload the issuer "
                    "vouches for may be a sensor (in Kubernetes, any pod can get such a token for itself)")
    og.add_argument("--name-from", help="add: the claim that names the sensor, e.g. kubernetes.io/node/name")
    og.add_argument("--jwks", metavar="FILE", help="add: the issuer's public keys (JWKS), for an issuer the service "
                    "cannot reach; default: its discovery document")
    sv = sub.add_parser("survey", help="recorded surveys: list them, drill into one, its answers and question")
    svs = sv.add_subparsers(dest="survey_cmd", required=True)
    sl = svs.add_parser("list", help="recent surveys, newest first")
    sl.add_argument("--limit", type=int, default=20)
    sl.add_argument("--host", help="only surveys that asked this host")
    sl.add_argument("--question", help="only surveys of this question (hash or prefix)")
    ss = svs.add_parser("show", help="one survey: who asked what, answers grouped by hash, every target")
    ss.add_argument("id", help="survey id or a unique prefix")
    sa = svs.add_parser("answer", help="one target's answer in a survey: records, failures, error, diag")
    sa.add_argument("id", help="survey id or a unique prefix")
    sa.add_argument("target")
    sd = svs.add_parser("delete", help="delete a survey from the store (e.g. it holds a leaked secret): prints what "
                        "it removes; --yes removes it, and this machine's cached dataset of it")
    sd.add_argument("id", help="the full survey id")
    sd.add_argument("--reason", help="why, kept with the tombstone (deleted_surveys)")
    sd.add_argument("--yes", action="store_true", help="delete; without it, only print what would go")
    sq = svs.add_parser("question", help="the question a survey asked (its Starlark source)")
    sq.add_argument("id", help="survey id or a unique prefix")
    sx = svs.add_parser("sql", help="read-only SQL on the survey store: surveys, survey_answers, and the record index (observations: one row per record per host, with asked_at, probe, value_num, value_time; see beat.index)")
    sx.add_argument("sql")
    for x in (sl, ss, sa, sq, sx):
        x.add_argument("--json", action="store_true", help="print the API's JSON reply")
    lg = sub.add_parser("logs", help="log summaries in a survey's answers (log_summary): templates across targets, "
                        "and a proposed curated set for the next question")
    lgs = lg.add_subparsers(dest="logs_cmd", required=True)
    lsh = lgs.add_parser("show", help="each log's templates, every target's line counts side by side")
    lsh.add_argument("id", help="survey id or a unique prefix")
    lsh.add_argument("--log", help="only this log (the name given to emit_log_summary)")
    lsh.add_argument("--top", type=int, default=30, help="templates per log, most lines first")
    lst = lgs.add_parser("templates", help="a curated template set for --log, as a Starlark constant to paste into "
                         "the next question (key=value tokens and versions become <*>)")
    lst.add_argument("id", help="survey id or a unique prefix")
    lst.add_argument("--log", required=True)
    lst.add_argument("--min-lines", type=int, default=1, help="leave out templates with fewer lines in total")
    for x in (lsh, lst):
        x.add_argument("--json", action="store_true", help="print the API's JSON reply")
    an = sub.add_parser("analyze", help="a survey's answers across its targets: slot kinds, groups, dimensions, rare "
                        "values, inconsistencies, and drift since the same question's previous survey")
    an.add_argument("id", help="survey id or a unique prefix")
    an.add_argument("--history", type=int, default=3, help="earlier surveys of the question to learn kinds from")
    an.add_argument("--cap", type=int, default=20, help="host names listed per value")
    an.add_argument("--slots", action="store_true", help="also list every slot with its kind")
    an.add_argument("--json", action="store_true", help="print the API's JSON reply")
    ds = sub.add_parser("dataset", help="a survey's dataset: its answers as Parquet tables (hosts, records) "
                        "for analysis tools, downloaded into ~/.cache/beat/datasets; prints where they are and their "
                        "shape")
    ds.add_argument("id", help="survey id or a unique prefix")
    ds.add_argument("--json", action="store_true", help="print the API's JSON reply")
    ky = sub.add_parser("keys", help="the org's root keys, which certify members; sensors pin them (BEAT_KEYS/org, "
                        "docs/security.md H16): list; rotate with new, deploy (infra/deploy-sensor), use, retire, deploy")
    keys_arguments(ky, deny=True)
    cr = sub.add_parser("creds", help="this machine's member key and credential, which sign every question "
                        "(docs/security.md H16), kept in BEAT_CCACHE (default $XDG_RUNTIME_DIR/beat): show (klist); init: a "
                        "fresh key signed by the org's root, like kinit -kt from a keytab (with the root on this "
                        "machine, renewed silently as well); destroy (kdestroy)")
    cr.add_argument("action", nargs="?", choices=["show", "init", "destroy"], default="show")
    cr.add_argument("--root", metavar="FILE", help="init: the root's key file (default: the root in use here, "
                    "BEAT_KEYS/org)")
    cr.add_argument("--name", help="init: the member's name (default: the login's subject, else user@host)")
    cr.add_argument("--days", type=int, default=30, help="init: how long it lasts (default 30, at most 90)")
    a = ap.parse_args()

    if a.cmd in ("login", "whoami", "logout"):
        return _login(a)

    if a.cmd == "keys":
        from . import seal
        if a.action in ("deny", "allow", "denied"):
            return _deny(a)
        return keys(a, seal.org_keys(), "roots", "beat keys")

    if a.cmd == "creds":
        return _creds(a)

    if a.cmd in ("ask", "sensors", "survey", "logs", "analyze", "dataset"):
        return _service(a)

    if a.cmd == "org":
        return _trust(a)

    if a.cmd == "probes":
        return _probes(a)

    if a.cmd == "run":
        from . import estate
        failed = False
        try:
            survey, answers = estate.ask_star(a.probe, a.hosts)  # one survey: comparable across the hosts
        except estate.EstateError as e:
            raise SystemExit(f"error: {e}")
        for host in a.hosts:
            try:
                r = estate.run_probe(a.probe, host, commit=not a.no_commit, answer=answers.get(host))
            except estate.EstateError as e:
                print(f"{host}: error: {e}")
                failed = True
                continue
            print(f"{host}: {r['path']}: {r['records']} records, exit {r['exit']}, {r['seconds']} s; "
                  + (f"committed {r['commit']}" if r["commit"] else "no change"))
            for f in r["assertions_failed"]:
                print(f"{host}:   assertion failed: {f}")
                failed = True
            for n in r["notes"]:
                print(f"{host}:   note: {n}")
            if a.stdout and r["stdout"]:
                print(r["stdout"])
        if len(a.hosts) > 1:
            print(f"survey {survey}: compare the hosts with `beat analyze {survey}` (MCP analyze), logs with "
                  f"`beat logs show {survey}` (MCP logs)")
        raise SystemExit(1 if failed else 0)

    if a.cmd == "init":
        from . import estate
        try:
            estate.init(Path(a.dir))
            print(f"estate repository at {Path(a.dir).resolve()}; next: cd there and run claude")
        except estate.EstateError as e:
            raise SystemExit(f"error: {e}")
        return


def _probes(a) -> None:
    """`beat probes`: list, fork, run (estate.py)."""
    import asyncio
    from . import ask, estate
    try:
        repo = estate.root()
        if a.action == "list":
            for p in estate.probes(repo):
                print(f"{p['name']}\t{p['origin']}\t{p['summary']}")
            return
        if a.action == "fork":
            if len(a.args) != 1:
                raise SystemExit("error: beat probes fork NAME")
            path = estate.fork(repo, a.args[0])
            print(f"{path.relative_to(repo)}: the estate's now (the pack's upgrades no longer reach it); commit it "
                  "when you have changed it")
            return
        hosts = a.args or sorted(h for h, e in asyncio.run(ask.sensors()).items() if "untrusted" not in e)
        if not hosts:
            raise SystemExit("error: no trusted live sensor (`beat sensors`)")
        failed = False
        for name, survey, results in estate.run_every(hosts, commit=not a.no_commit):
            for host, r in results.items():
                if isinstance(r, Exception):
                    print(f"{name}\t{host}\terror: {r}")
                    failed = True
                    continue
                bad = r["assertions_failed"] or ([n for n in r["notes"] if n.startswith("error")] if r["exit"] else [])
                failed = failed or r["exit"] != 0
                print(f"{name}\t{host}\t{r['records']} records, {r['seconds']} s, "
                      + (f"{'assertion failed' if r['assertions_failed'] else 'failed'}: {bad[0]}" if bad
                         else "ok" if r["exit"] == 0 else f"exit {r['exit']}")
                      + (f"; committed {r['commit']}" if r["commit"] else ""))
            if survey and len(hosts) > 1:
                print(f"{name}\tsurvey {survey}: `beat analyze {survey}` compares the hosts")
    except (estate.EstateError, RuntimeError) as e:
        raise SystemExit(f"error: {e}")
    raise SystemExit(1 if failed else 0)


def _service(a) -> None:
    import asyncio
    import json
    from . import ask

    if a.cmd == "sensors" and a.action:
        return _enroll(a)

    if a.cmd == "sensors":
        for name, e in sorted(asyncio.run(ask.sensors(untrusted=True)).items()):
            labels = " ".join(f"{k}={v}" for k, v in sorted((e.get("labels") or {}).items()))
            sandbox = "" if e.get("sandbox", "full") == "full" else f"\tsandbox: {e['sandbox']}"
            bad = f"\tUNTRUSTED: {e['untrusted']} (not asked)" if "untrusted" in e else ""
            print(f"{name}\t{e.get('sensor', '?')}\tsince {e.get('started', '?')}\t{labels}{sandbox}{bad}")
        return

    if a.cmd == "survey":
        return _survey(a)

    if a.cmd == "logs":
        return _logs(a)

    if a.cmd == "analyze":
        return _analyze(a)

    if a.cmd == "dataset":
        return _dataset(a)

    src = Path(a.question).read_text()
    if a.dataset:
        try:
            return _print_dataset(asyncio.run(ask.dataset(Path(a.question).name, src, a.host or None, a.timeout)),
                                  a.json)
        except RuntimeError as e:
            raise SystemExit(f"error: {e}")
    if a.analyze:
        return _ask_analyze(a, src)
    try:
        s = asyncio.run(ask.ask(Path(a.question).name, src, a.host or None, a.timeout))
    except RuntimeError as e:
        raise SystemExit(f"error: {e}")
    if a.json:
        print(json.dumps(s, indent=2))
        return
    print(f"survey {s['survey']}  question {s['question'][:12]}  expected {len(s['expected'])}")
    for c in ask.categories(s):
        h = c["answer_hash"][:12] if c["answer_hash"] else "-"
        n = len(c["answer"]["records"]) if c["answer"] else 0
        print(f"  {len(c['targets']):4}  {c['outcome']:8} {h:12}  {n:4} records  {', '.join(sorted(c['targets']))}")
        for why in c.get("why", []):
            print(f"        {why}")
        if a.show and c["answer"]:
            ans = c["answer"]
            if ans.get("error"):
                print(f"        error: {ans['error'].get('kind')}: {ans['error'].get('message')}")
            for f in ans.get("failures") or []:
                print(f"        failure: {json.dumps(f)}")
            for r in ans.get("records") or []:
                print(f"        {json.dumps(r, ensure_ascii=False)}")
    for line in s["standing"]:
        print(f"  {line}")
    missing = s["down"] or s["no_answer"] or s["running"]
    raise SystemExit(0 if not missing and all(x["outcome"] == "ok" for x in s["answers"].values()) else 1)


def _dataset(a) -> None:
    """`beat dataset <survey>`: a thin client of the read API's dataset.get (api.py, dataset.py)."""
    import asyncio

    try:
        _print_dataset(asyncio.run(_dataset_get(a.id)), a.json)
    except RuntimeError as e:
        raise SystemExit(f"error: {e}")


async def _dataset_get(sid: str) -> dict:
    from . import ask
    return await ask.with_live(await ask.fetch(await ask.api("dataset.get", {"survey": sid}, timeout=120)))


def _size(n: float) -> str:
    return f"{n / 1e6:.1f} MB" if n >= 1e6 else f"{n / 1e3:.1f} KB" if n >= 1e3 else f"{n:.0f} B"


LIMIT = 1024 * 1024  # NATS's default max_payload: an answer over it is a too_large error (beat-sensor)


def _secs(x: float) -> str:
    return "under 1 s" if x < 1 else f"{x:.0f} s"


def cost_lines(p: dict) -> list[str]:
    """What the answers took per host, and, when fewer hosts were asked than are live, what asking all would take."""
    c = p.get("cost") or {}
    out = []
    b, t = c.get("bytes"), c.get("seconds")
    if b:
        out.append(f"cost  answers: median {_size(b['median'])}, largest {_size(b['max'])} ({b['max_host']}), "
                   f"{_size(b['total'])} in all")
        if b["max"] > LIMIT / 2:
            out.append(f"      {b['max_host']}'s answer is {b['max'] / LIMIT:.0%} of the 1 MB limit an answer has: "
                       "it will not fit once what it reads grows (aggregate more in the probe)")
    if t:
        out.append(f"      probe time on a host: median {_secs(t['median'])}, longest {_secs(t['max'])} ({t['max_host']})")
    live = p.get("live")
    if b and live and live > b["hosts"]:
        out.append(f"      asked {b['hosts']} of {live} live hosts: asked of all, expect about "
                   f"{_size(b['median'] * live)} (median) to {_size(b['max'] * live)} (if all were like the largest), "
                   f"and the probe's time on each")
    return out


def _print_dataset(p: dict, as_json: bool = False) -> None:
    import json
    if as_json or "dataset" not in p:
        return print(json.dumps(p, indent=1, ensure_ascii=False))
    outcomes = ", ".join(f"{n} {k}" for k, n in p["outcomes"].items())
    print(f"survey {p['survey']}  question {p['question']}  asked {p['asked']} ({outcomes})"
          + ("" if p["sealed"] else "  not complete: rewritten on the next request"))
    for line in p.get("standing") or []:
        print(f"  {line}")
    print(f"dataset {p['dataset']}")
    for name, t in p["tables"].items():
        print(f"  {name}.parquet  {t['rows']} rows, {t['bytes'] / 1e6:.1f} MB: {', '.join(t['columns'])}")
    for line in cost_lines(p):
        print(line)
    print(p["next"])


def _ask_analyze(a, src: str) -> None:
    """`beat ask --analyze`: ask.report (the MCP `survey` tool's answer) for a person: categories, the analysis as
    `beat analyze` prints it, and the logs it has."""
    import argparse
    import asyncio
    import json
    from . import ask

    try:
        r = asyncio.run(ask.report(Path(a.question).name, src, a.host or None, a.timeout))
    except RuntimeError as e:
        raise SystemExit(f"error: {e}")
    if a.json:
        return print(json.dumps(r, indent=1, ensure_ascii=False))
    print(f"survey {r['survey']}  asked {len(r['asked'])}")
    for c in r["answers"]:
        err = f"  error: {c['error'].get('kind')}: {c['error'].get('message', '')[:80]}" if c.get("error") else ""
        print(f"  {len(c['hosts']):4}  {c['outcome']:8} {c['records']:4} records  {', '.join(c['hosts'])}{err}")
        for why in c.get("why", []):
            print(f"        {why}")
    if "note" in r:
        return print(r["note"])
    _analyze(argparse.Namespace(id=r["survey"], history=3, cap=20, json=False, slots=False))
    for name, log in (r.get("logs") or {}).items():
        print(f"log {name}: {len(log.get('templates', []))} templates across the hosts; beat logs show {r['survey']}")


def _analyze(a) -> None:
    """`beat analyze <survey>`: a thin client of the read API's analysis.get (api.py, analysis.py)."""
    import asyncio
    import json
    from . import ask

    try:
        r = asyncio.run(ask.api("analysis.get", {"survey": a.id, "history": a.history, "cap": a.cap}))
    except RuntimeError as e:
        raise SystemExit(f"error: {e}")
    if a.json:
        return print(json.dumps(r, indent=1, ensure_ascii=False))
    x = r["analysis"]
    names = lambda v: ", ".join(v["targets"]) + (f" +{v['more']}" if v.get("more") else "")
    hist = f"{len(r['history_surveys'])} earlier survey(s) of this question" if r["history_surveys"] else \
        "no earlier survey of this question (kinds from this one only: measurements may look like settings)"
    print(f"survey {r['survey']}  question {r['question_name']}  {x['targets']} targets; history: {hist}")
    kinds = ", ".join(f"{k} {n}" for k, n in sorted(x["slots"]["kinds"].items(), key=lambda kv: -kv[1]))
    print(f"slots: {x['slots']['count']} ({kinds}); {x['slots']['declared']} declared by the probe")
    print(f"{len(x['groups'])} exact groups = combinations of "
          f"{sum(1 for d in x['dimensions'] if 'derived_from' not in d)} dimensions")
    for d in x["dimensions"]:
        more = f"  (+{len(d['slots']) - 1} slots moving with it)" if len(d["slots"]) > 1 else ""
        within = f"  within D{d['within']['dimension']}={d['within']['value'][:30]}" if "within" in d else ""
        if "derived_from" in d:
            print(f"  D{d['id']} = D{d['derived_from'][0]} × D{d['derived_from'][1]}: {d['slots'][0]}")
            continue
        print(f"  D{d['id']} {d['slots'][0]}{more}{within}")
        for v in d["values"]:
            mark = f"  RARE: {names(v)}" if v["rare"] else ""
            print(f"       {v['count']:5}  {v['value'][:70]}{mark}")
    for i in x["inconsistencies"]:
        print(f"  INCONSISTENT D{i['dimensions'][0]} ~ D{i['dimensions'][1]} except on {names(i)}")
        for t, (va, vb) in i["values"].items():
            print(f"       {t}: {i['slots'][0]} = {va[:40]}, {i['slots'][1]} = {vb[:40]}")
    if a.slots:
        print("slots:")
        for s in x["slots"]["by_slot"]:
            print(f"  {s['kind']:9} {s['slot']}")
    if "drift" in r:
        d = r["drift"]
        print(f"drift since {d['since']}: {d['unchanged']} unchanged, "
              f"{sum(c['count'] for c in d['changes'])} changed"
              + (f", new {', '.join(d['new_targets'])}" if d["new_targets"] else "")
              + (f", missing {', '.join(d['missing_targets'])}" if d["missing_targets"] else ""))
        for c in d["changes"]:
            print(f"  {names(c)}:")
            for f in c["added"]:
                print(f"       + {f[:110]}")
            for f in c["removed"]:
                print(f"       - {f[:110]}")


def _logs(a) -> None:
    """`beat logs ...`: a thin client of the read API's logs.get (api.py, logs.py)."""
    import asyncio
    import json
    from . import ask

    params = {"survey": a.id, "log": a.log}
    if a.logs_cmd == "templates":
        params["min_lines"] = a.min_lines
    try:
        r = asyncio.run(ask.api("logs.get", params))
    except RuntimeError as e:
        raise SystemExit(f"error: {e}")
    if a.json:
        return print(json.dumps(r, indent=1, ensure_ascii=False))
    if a.logs_cmd == "templates":
        log = r["logs"][a.log]
        print(f"# curated from survey {r['survey']}, log {a.log}: {len(log['proposed'])} templates "
              f"(from {len(log['templates'])}); edit, then pass as log_summary(templates = TEMPLATES)")
        print("TEMPLATES = [")
        for p in log["proposed"]:
            merged = f", merged from {len(p['from'])}" if len(p["from"]) > 1 else ""
            changed = "" if p["from"] == [p["template"]] else f"  # was: {p['from'][0]}"
            print(f"    {json.dumps(p['template'], ensure_ascii=False)},   # {p['lines']} lines, "
                  f"{len(p['targets'])} targets{merged}{changed}")
        return print("]")
    for name, log in sorted(r["logs"].items()):
        targets = sorted(log["targets"])
        print(f"== log {name}   survey {r['survey']}")
        for t in targets:
            x = log["targets"][t]
            print(f"   {t:20} {x.get('lines_count', '?'):>7} lines   read {x.get('lines_read_count', '?'):>7}   "
                  f"{x.get('first_time', '?')} -> {x.get('last_time', '?')}")
        rows = sorted(log["templates"].values(),
                      key=lambda t: -sum(p["lines_count"] for p in t["targets"].values()))
        print(f"   {'  '.join(f'{t[:10]:>10}' for t in targets)}   template   ({len(rows)} templates)")
        for t in rows[: a.top]:
            counts = "  ".join(f"{t['targets'].get(x, {}).get('lines_count', '-'):>10}" for x in targets)
            new = " NEW" if any(p["new"] for p in t["targets"].values()) else ""
            print(f"   {counts}   {t['template']}{new}")
            params = {}
            for p in t["targets"].values():
                for i, v in p["params"].items():
                    d = params.setdefault(i, {"distinct": 0, "values": []})
                    d["distinct"] = max(d["distinct"], v["distinct"] or 0)
                    d["values"] += [x for x in v["values"] if x not in d["values"]]
            for i, d in sorted(params.items(), key=lambda kv: int(kv[0])):
                vals = ", ".join(d["values"][:5]) + (" ..." if d["distinct"] > 5 else "")
                print(f"   {'':{12 * len(targets)}}   p{i}: {d['distinct']} distinct: {vals}")
        if len(rows) > a.top:
            print(f"   ... {len(rows) - a.top} more (--top)")
        print(f"\n   curated set: beat logs templates {r['survey']} --log {name}")


def _enroll(a) -> None:
    """`beat sensors pending|approve|deny`: enrolment by approval (docs/security.md H14; the service's enroll.py)."""
    import asyncio
    from . import ask

    def show(e: dict) -> str:
        return f"{e['code']}  {e['name']}  host {e['host'] or '?'}  key {e['fingerprint']}  {e['version']}".rstrip()

    if a.action == "add" and a.attest:
        print("On each EC2 instance whose role may call sts:GetWebIdentityToken, with the sensor installed, run:\n"
              if a.attest.split(":")[0] == "aws" else
              "On each host, with the sensor installed and the identity token in place, run:\n")
        print(f"  {configure_line(attest=a.attest)}\n")
        print("The service enrols it at once if one of the org's trust policies accepts the token (beat org trust),")
        print("under the name the policy takes from it. No secret in the line: it can go in any configuration.")
        return
    if a.action == "add":
        print("On the host, with the sensor installed, run:\n")
        print(f"  {configure_line()}\n")
        print("It points the sensor at this service (bus and collector keys come from the service) and pins your")
        print("org's root above: the sensor runs only questions of members it certified. Then it prints a code to")
        print("approve here:")
        print("beat sensors approve CODE. Many hosts: `beat sensors token --hosts N`, no approval each.")
        return
    if a.action == "token":
        units = {"m": 60, "h": 3600, "d": 86400}
        try:
            expires_s = int(a.expires[:-1]) * units[a.expires[-1]]
        except (ValueError, KeyError, IndexError):
            raise SystemExit(f"error: --expires {a.expires}: a number and m, h or d (30m, 24h, 7d)")
        r = asyncio.run(ask.api("enroll.token", {"hosts": a.hosts, "expires_s": expires_s, "note": a.note}))
        print(f"Rollout token {r['id']}: enrols up to {r['hosts']} sensor(s) until {r['expires']}, no approval each.\n")
        print(f"  {r['token']}\n")
        print("Shown once: the service keeps only its hash. Anyone holding it can enrol sensors until then: put it in a")
        print("root-only file on each host (configuration management's secret store), not on a command line:\n")
        print(f"  {configure_line('/etc/beat-sensor/rollout-token')}\n")
        print(f"See who used it: beat sensors tokens. End it early: beat sensors revoke-token {r['id']}.")
        return
    if a.action == "tokens":
        for e in asyncio.run(ask.api("enroll.tokens"))["tokens"]:
            used = f"{e['used']}/{e['hosts']} used" + (f" ({', '.join(e['sensors'])})" if e["sensors"] else "")
            print(f"{e['id']}  {e['state']:8}  {used}  until {e['expires']}  by {e['by']}  {e['note']}".rstrip())
        return
    if a.action == "revoke-token":
        if not a.code:
            raise SystemExit("error: beat sensors revoke-token ID (beat sensors tokens)")
        r = asyncio.run(ask.api("enroll.revoke", {"id": a.code}))
        print(f"revoked token {r['id']}: no sensor enrols with it from now on; the {r['used']} it enrolled stay "
              "(beat sensors remove NAME)")
        return
    if a.action == "pending":
        waiting = asyncio.run(ask.api("enroll.pending"))["pending"]
        for e in waiting:
            note = "  REPLACES the enrolled key of that name" if e["replaces"] else ""
            print(f"{show(e)}  waiting {e['waiting_s'] // 60} min{note}")
        if not waiting:
            print("no sensor is waiting (on the host: sudo beat-sensor enroll --api ...)")
        return
    if a.action == "remove":
        if not a.code:
            raise SystemExit("error: beat sensors remove NAME")
        r = asyncio.run(ask.api("enroll.remove", {"name": a.code}))
        print(f"removed {r['name']} (key {r['fingerprint']}): its answers are refused from now on; the host still runs "
              "it until uninstalled, and can ask to join again")
        return
    if not a.code:
        raise SystemExit(f"error: beat sensors {a.action} CODE: the code the host printed")
    code = a.code.strip().upper()
    if a.action == "approve" and not a.yes:
        e = next((e for e in asyncio.run(ask.api("enroll.pending"))["pending"] if e["code"] == code), None)
        if e is None:
            raise SystemExit(f"error: no sensor is waiting with code {code} (`beat sensors pending`)")
        print(f"Sensor {e['name']!r} on host {e['host'] or '?'} asks to join, with key {e['fingerprint']}.")
        if e["replaces"]:
            print(f"A sensor named {e['name']!r} is enrolled already, with another key: approving replaces it "
                  "(a reinstalled host, or someone else's host by that name).")
        print("Compare the host and the key with what the host printed.")
        if input("Approve? [y/N] ").strip().lower() not in ("y", "yes"):
            raise SystemExit("not approved")
    r = asyncio.run(ask.api(f"enroll.{a.action}", {"code": code}))
    if a.action == "approve":
        print(f"enrolled {r['name']} (key {r['fingerprint']}): its answers are accepted from now on")
    else:
        print(f"denied {r['name']} on {r['host'] or '?'}")


def _trust(a) -> None:
    """`beat org trust [add|remove]`: the org's trust policies (docs/security.md H13; the service's attest.py)."""
    import asyncio
    import json
    from . import ask

    if a.action is None:
        policies = asyncio.run(ask.api("trust.list"))["policies"]
        for p in policies:
            claims = " ".join(f"{k}={v}" for k, v in p["claims"].items())
            print(f"{p['name']}  {p['kind']}  {p['issuer']}  aud {p['audience']}  name from {p['name_from']}  "
                  f"keys {p['keys']}  {claims or 'ANY WORKLOAD'}  (by {p['by']})".replace("    ", "  "))
        if not policies:
            print("no trust policy: sensors enrol by approval or rollout token (beat org trust add NAME --issuer ...)")
        return
    if not a.name:
        raise SystemExit(f"error: beat org trust {a.action} NAME")
    if a.action == "remove":
        asyncio.run(ask.api("trust.remove", {"name": a.name}))
        print(f"removed trust policy {a.name}: no sensor enrols by it from now on; the ones it enrolled stay "
              "(beat sensors remove NAME)")
        return
    if not a.issuer or not a.name_from:
        raise SystemExit("error: beat org trust add NAME --issuer URL --name-from CLAIM --claim PATH=VALUE... "
                         "[--audience AUD] [--jwks FILE] (or --any-workload instead of --claim)")
    claims = {}
    for c in a.claim:
        k, eq, v = c.partition("=")
        if not eq:
            raise SystemExit(f"error: --claim {c}: PATH=VALUE")
        claims[k] = v
    body = {"name": a.name, "issuer": a.issuer, "audience": a.audience, "claims": claims, "name_from": a.name_from,
            "any_workload": a.any_workload}
    if a.jwks:
        with open(a.jwks) as f:
            body["jwks"] = json.load(f)
    p = asyncio.run(ask.api("trust.add", body))
    print(f"trust policy {p['name']}: sensors with a token from {p['issuer']} for audience {p['audience']}"
          + (f", with {', '.join(f'{k}={v}' for k, v in p['claims'].items())}" if p["claims"]
             else ", from ANY workload it vouches for")
          + f", enrol at once, named by {p['name_from']} (keys: {p['keys']}).")
    print("The configure line for those hosts: beat sensors add --attest oidc:FILE (FILE: where the platform puts "
          "the token), or --attest aws on EC2")


def sensor_api(me: dict) -> str:
    """The URL the org's sensors call (their --api): the service's, with the org's path the service names in whoami
    (/o/<org>: one service serves every org, docs/protocol.md); a service that names none serves one org at its root."""
    from . import wire
    return wire.api_url() + (me.get("sensor_api") or "")


def configure_line(token_file: str | None = None, attest: str | None = None) -> str:
    """The `beat-sensor configure` command for a host: this service and org, this machine's org root(s), and a token
    file or the identity token's file."""
    import asyncio
    from . import ask, seal
    keys = seal.org_keys().public()
    if not keys:
        raise SystemExit("error: no org root on this machine to give the sensor (beat keys)")
    try:
        api = sensor_api(asyncio.run(ask.whoami()))
    except RuntimeError as e:
        raise SystemExit(f"error: {e}")
    flags = " ".join(f"--org-root {n}={k}" for n, k in keys.items())
    token = (f" \\\n    --token-file {token_file}" if token_file else "") + (f" \\\n    --attest {attest}" if attest else "")
    return f"sudo /opt/beat-sensor/current/bin/beat-sensor configure --api {api} \\\n    {flags}{token}"


def _login(a) -> None:
    """`beat login`, `beat whoami`, `beat logout` (login.py)."""
    import asyncio
    import time
    from . import ask, login, wire

    try:
        if a.cmd == "login":
            login.login(a.url)
            print("")
        elif a.cmd == "logout":
            e = login.logout()
            print(f"signed out of {wire.api_url()}" if e else f"not signed in to {wire.api_url()}")
            return
        me = asyncio.run(ask.whoami())
    except RuntimeError as e:
        raise SystemExit(f"error: {e}")
    if getattr(a, "sensor_api", False):
        print(sensor_api(me))
        return
    print(f"Signed in to {wire.api_url()} as {me.get('sub')}" + (f", org {me['org']}" if me.get("org") else "")
          + (f", role {me['role']}" if me.get("role") else "") + (f" (issuer {me['iss']})" if me.get("iss") else ""))
    if me.get("sensor_api"):
        print(f"  the org's sensors call {sensor_api(me)} (beat sensors add)")
    why = wire.api_source()[1]
    print("  the service: " + ("BEAT_API's" if why == "BEAT_API" else "walkthebeat's (the default; `beat login URL` changes it)"
                               if why == "the default" else f"kept in {why} (`beat login URL` changes it)"))
    e = login.current()
    if os.environ.get("BEAT_TOKEN"):
        print("  the access token is BEAT_TOKEN's")
    elif e:
        left = int(e["expires_at"] - time.time())
        print(f"  access token: {max(left, 0) // 60} min left, renewed by itself"
              + ("" if e.get("refresh_token") else " (no refresh token: `beat login` when it ends)"))
        print(f"  kept in {login.logins_file()}")


def keys_arguments(p, deny: bool = False) -> None:
    """`beat keys` and `beat-service keys` take the same arguments; `beat keys` also the root's deny list."""
    p.add_argument("action", nargs="?", default="list",
                   choices=["list", "new", "use", "retire", "deployed"] + (["deny", "allow", "denied"] if deny else []),
                   help="deployed: NAME KEY lines, what every sensor and the service are given"
                   + ("; deny NAME: refuse the member's credentials issued until now, everywhere (the deny list, "
                      "signed by the root); allow NAME: take it off; denied: the list, and which sensors hold it"
                      if deny else ""))
    p.add_argument("name", nargs="?")
    p.add_argument("--force", action="store_true", help="use: even when live sensors do not trust the key yet")


def keys(a, ring, field: str, prog: str) -> None:
    """`beat keys` (the org's keyring) and `beat-service keys` (the collector's): its keys, and which live sensors trust
    them (their heartbeats list them under `field`: "roots" or "collectors")."""
    import asyncio
    from . import ask, seal
    if a.action == "destroy":
        print(f"member key and credential removed from {seal.ccache_dir()}" if seal.destroy_member()
              else f"no member credential in {seal.ccache_dir()}")
        return
    try:
        if a.action == "init":
            if not a.name:
                raise ValueError(f"{prog} new NAME")
            ring.new(a.name)
            print(f"{ring.what} key {a.name} made, not in use: deploy it to the sensors, "
                  f"then `{prog} use {a.name}`")
            return
        if a.action == "retire":
            if not a.name:
                raise ValueError(f"{prog} retire NAME")
            ring.retire(a.name)
            print(f"{ring.what} key {a.name} retired: its private key is destroyed; deploy again to remove it from "
                  "the sensors")
            return
        if a.action == "deployed":
            for n, k in ring.public().items():
                print(n, k)
            return
        keys = ring.public()
        live = asyncio.run(ask.sensors())
        def trusting(n: str) -> list[str]:
            want = f"{n}:{seal.fingerprint(seal.unb64(keys[n]))}"
            return sorted(h for h, e in live.items() if want in (e.get(field) or []))
        if a.action == "use":
            if a.name not in keys:
                raise ValueError(f"no {ring.what} key named {a.name} (see `{prog}`)")
            missing = sorted(set(live) - set(trusting(a.name)))
            if missing and not a.force:
                raise ValueError(f"{len(missing)} live sensor(s) do not trust {a.name} yet (deploy first, or "
                                 f"--force): {', '.join(missing[:10])}")
            ring.use(a.name)
            print(f"{ring.what} key {a.name} signs from the next question on")
            return
    except ValueError as e:
        raise SystemExit(f"error: {e}")
    current = ring.current()
    for n, k in keys.items():
        t = trusting(n)
        print(f"{n}\t{seal.fingerprint(seal.unb64(k))}\t{'in use' if n == current else 'not in use'}\t"
              f"trusted by {len(t)} of {len(live)} live sensors")
    for n, k in ring.public(retired=True).items():
        if n not in keys:
            print(f"{n}\t{seal.fingerprint(seal.unb64(k))}\tretired")


def _deny(a) -> None:
    """`beat keys deny NAME | allow NAME | denied`: the org root's deny list (seal.deny_list, docs/security.md H16),
    signed here with the root in use and put to the service (deny.put), which publishes it to the sensors. The list
    held is the newest of this machine's copy (BEAT_KEYS/org/deny.json) and the service's that the root signed."""
    import asyncio
    import time
    from . import ask, seal, wire
    ring = seal.org_keys()
    if not (ring.dir / "current").exists():
        raise SystemExit("error: no org root on this machine: only the root signs the deny list")
    roots = {n: seal.public_key(k) for n, k in ring.public(retired=True).items()}
    local = ring.dir / "deny.json"
    held = {"seq": 0, "entries": []}
    sources = [lambda: local.read_bytes(), lambda: (asyncio.run(ask.api("deny.get"))["list"] or "").encode()]
    for read in sources:
        try:
            d = seal.check_deny(read(), roots)
        except (OSError, RuntimeError, seal.Refused):
            continue
        held = d if d["seq"] > held["seq"] else held
    if a.action == "denied":
        print(f"deny list {held['seq']}" + (f", issued {wire.iso(held['issued'])} by {held['issuer']}"
                                            if held["seq"] else " (none yet)"))
        for e in held["entries"]:
            print(f"  {e['name']}\tcredentials issued before {wire.iso(e['before'])}\t(entry kept until "
                  f"{wire.iso(e['until'])})")
        try:
            live = asyncio.run(ask.sensors())
            have = sorted(h for h, e in live.items() if (e.get("deny") or 0) >= held["seq"])
            print(f"held by {len(have)} of {len(live)} live sensors")
        except RuntimeError:
            pass
        return
    if not a.name:
        raise SystemExit(f"error: beat keys {a.action} NAME (a member's name, as `beat creds` shows it)")
    now = int(time.time())
    entries = [e for e in held["entries"] if e["name"] != a.name]
    if a.action == "deny":
        entries.append({"name": a.name, "before": now, "until": now + seal.MAX_MEMBER_LIFE_S + seal.SKEW_S})
    elif len(entries) == len(held["entries"]):
        raise SystemExit(f"error: {a.name} is not on the deny list (beat keys denied)")
    raw = seal.deny_list(ring.key(), ring.current(), entries, held["seq"] + 1, now)
    local.write_bytes(raw)
    what = (f"{a.name}: credentials issued until now are refused" if a.action == "deny"
            else f"{a.name} is off the deny list")
    try:
        asyncio.run(ask.api("deny.put", {"list": raw.decode()}))
    except RuntimeError as e:
        raise SystemExit(f"deny list {held['seq'] + 1} ({what}) is kept here ({local}) but not published: {e}")
    print(f"deny list {held['seq'] + 1} published: {what}. Sensors take it within seconds (beat keys denied)."
          + (f" {a.name} gets a new credential with `beat creds init`." if a.action == "deny" else ""))


def _creds(a) -> None:
    """`beat creds [init|destroy]`: this machine's member credential (seal.current_member: klist), a fresh one signed
    by a root key file (seal.new_member: kinit -kt), or none (seal.destroy_member: kdestroy)."""
    import asyncio
    from . import ask, seal, wire
    if a.action == "destroy":
        print(f"member key and credential removed from {seal.ccache_dir()}" if seal.destroy_member()
              else f"no member credential in {seal.ccache_dir()}")
        return
    try:
        if a.action == "init":
            ring = seal.org_keys()
            if a.root:
                root, root_name = seal.read_root(a.root)
            elif (ring.dir / "current").exists():
                root, root_name = ring.key(), ring.current()
            else:
                raise seal.Refused("no root on this machine: --root FILE, the org root's key file")
            _, cred = seal.new_member(root, root_name, a.name, a.days * 86400)
            c = seal.read_credential(cred)
        else:
            _, _, c = seal.current_member()
    except (seal.Refused, ValueError) as e:
        raise SystemExit(f"error: {e}")
    local = (seal.org_keys().dir / "current").exists()
    print(f"member {c['name']}  key {seal.fingerprint(seal.unb64(c['key']))}  certified by root {c['issuer']}")
    print(f"  valid {wire.iso(c['not_before'])} to {wire.iso(c['not_after'])}"
          + (f"; renewed here {seal.RENEW_BEFORE_S // 86400} days before it ends (the root is on this machine)"
             if local else "; then `beat creds init --root FILE` again"))
    try:  # which live sensors pin its root (their heartbeats): a credential of a root none pins is refused by all
        live = asyncio.run(ask.sensors())
    except Exception:
        return
    pinned = sorted(h for h, e in live.items() if c["issuer"] in (e.get("roots") or []))
    print(f"  its root is pinned by {len(pinned)} of {len(live)} live sensors")


def _survey_delete(a) -> None:
    """`beat survey delete`: the plan, then (--yes) the deletion and this machine's cached copy."""
    import asyncio
    import shutil
    from . import ask

    try:
        p = asyncio.run(ask.api("survey.delete", {"survey": a.id, "reason": a.reason, "confirm": a.yes,
                                                  **ask.asker("beat survey delete")}, timeout=60))
    except RuntimeError as e:
        raise SystemExit(f"error: {e}")
    gone, kept = p["blobs_deleted"], p["blobs_kept"]
    print(f"survey {p['survey']}  asked {(p['asked_at'] or '')[:19]}  {p['targets']} targets, {p['answers']} distinct answers"
          + ("" if p["sealed"] else "  NOT SEALED: cannot be deleted before its deadline"))
    print(f"  {'deleted' if a.yes else 'would delete'}: the survey's rows, {len(gone)} answer blobs and their index rows"
          + (", its dataset files" if p["dataset"] else "") + (", its messages on the stream" if a.yes else ""))
    for k in kept:
        print(f"  kept (shared): answer {k['answer_hash'][:12]} is also in {', '.join(k['also_in'])}: "
              f"delete those surveys too if it holds the secret")
    if not a.yes:
        return print("nothing deleted; run again with --yes")
    cached = ask.cache_dir() / p["survey"]
    if cached.exists():
        shutil.rmtree(cached)
        print(f"  deleted this machine's cached dataset {cached}")
    print("not reached: cached datasets on other machines (~/.cache/beat/datasets/<survey>), agent transcripts "
          "that showed the answer, and the secret itself on the host: rotate it")


def _survey(a) -> None:
    """`beat survey ...`: a thin client of the read API (api.py); --json prints its reply as is."""
    import asyncio
    import json
    from . import ask

    if a.survey_cmd == "sql":
        r = asyncio.run(ask.sql(a.sql))
        if "error" in r:
            raise SystemExit(f"error: {r['error']}")
        if a.json:
            return print(json.dumps(r, indent=1))
        print("\t".join(r["columns"]))
        for row in r["rows"]:
            print("\t".join("" if v is None else str(v) for v in row))
        return
    if a.survey_cmd == "delete":
        return _survey_delete(a)
    method, params = {
        "list": ("surveys.list", lambda: {"limit": a.limit, "host": a.host, "question": a.question}),
        "show": ("survey.get", lambda: {"survey": a.id}),
        "answer": ("answer.get", lambda: {"survey": a.id, "target": a.target}),
        "question": ("question.get", lambda: {"survey": a.id}),
    }[a.survey_cmd]
    try:
        r = asyncio.run(ask.api(method, params()))
    except RuntimeError as e:
        raise SystemExit(f"error: {e}")
    if a.json:
        return print(json.dumps(r, indent=1, ensure_ascii=False))
    t = lambda v: (v or "")[:19].replace("T", " ")  # timestamps to the second, UTC
    if a.survey_cmd == "list":
        print(f"{'survey':23}  {'asked (UTC)':19}  {'question':22} {'q-hash':8}  ok part err down noans pend  distinct  asked by")
        for s in r["surveys"]:
            print(f"{s['survey_id']:23}  {t(s['asked_at']):19}  {(s['question_name'] or '?')[:22]:22} "
                  f"{s['question_hash'][:8]}  {s['ok']:2} {s['partial']:4} {s['error']:3} {s['down']:4} "
                  f"{s['no_answer']:5} {s['pending']:4}  {s['distinct_answers']:8}  {s['asked_by']}")
    elif a.survey_cmd == "show":
        s = r["survey"]
        print(f"survey    {s['survey_id']}  ({'sealed ' + t(s['sealed_at']) if s['sealed_at'] else 'open until ' + t(s['deadline'])})")
        print(f"question  {s['question_name']}  {s['question_hash'][:12]}   (beat survey question {s['survey_id']})")
        print(f"asked     {t(s['asked_at'])} by {s['asked_by']}, selector {s['selector']}")
        counts: dict = {}
        for x in r["targets"]:
            counts[x["outcome"]] = counts.get(x["outcome"], 0) + 1
        for line in ask.standing(counts, bool(s["sealed_at"]), (r.get("collector") or {}).get("behind") or 0):
            print(f"          {line}")
        print(f"\nanswers by hash ({len(r['categories'])} distinct):")
        for c in r["categories"]:
            h = c["answer_hash"][:12] if c["answer_hash"] else "-"
            extra = f"{c['records']} records" if c["records"] is not None else ""
            if c.get("error"):
                extra = f"error {c['error'].get('kind')}: {c['error'].get('message', '')[:70]}"
            print(f"  {len(c['targets']):4}  {c['outcome']:8} {h:12}  {extra}")
            print(f"        {', '.join(c['targets'])}")
        print("\ntargets:")
        for x in r["targets"]:
            print(f"  {x['target']:20} {x['outcome']:8} {(x['answer_hash'] or '-')[:12]:12}  "
                  f"{t(x['started'])}  {x['sensor_version'] or ''}")
        print(f"\none answer: beat survey answer {s['survey_id']} <target>")
    elif a.survey_cmd == "answer":
        ans = r["answer"] or {}
        print(f"survey {r['survey_id']}  target {r['target']}  {r['outcome']}  answer {r['answer_hash']}")
        print(f"started {t(r['started'])}  finished {t(r['finished'])}  sensor {r['sensor_version']}")
        if ans.get("error"):
            e = ans["error"]
            print(f"\nerror ({e.get('kind')}): {e.get('message')}" + (f"  at {e['span']}" if e.get("span") else ""))
        for f in ans.get("failures") or []:
            print(f"failure ({f.get('kind')}): {f.get('message')}  at {f.get('span')}")
        recs = ans.get("records") or []
        print(f"\n{len(recs)} records")
        for rec in recs:
            print(f"  {rec.get('subject')}  {rec.get('key')} = {json.dumps(rec.get('value'), ensure_ascii=False)}"
                  f"   [{rec.get('source')}]")
        for n in ans.get("notes") or []:
            print(f"note: {n}")
        if ans.get("diag"):
            print("\ndiag (print output):\n" + ans["diag"].rstrip())
    elif a.survey_cmd == "question":
        print(f"# {r.get('name')}  question {r['question_hash']}")
        if r.get("params"):
            print(f"# params {json.dumps(r['params'])}")
        print(r.get("source", "").rstrip())
