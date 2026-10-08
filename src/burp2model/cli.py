"""burp2model command-line interface."""

from __future__ import annotations

import argparse
import json
import os
import re
import sqlite3
import sys

from . import __version__
from .parse import Exchange, parse_items
from .model import build, to_dict, from_dict, cross_role
from .context import LENSES, SOURCE, query as run_query, context_package
from .animate import render_terminal, write_svg
from .redact import set_fingerprint_key
from .report import write_html_report
from .graph import (
    ReasonGraph, reason_graph, to_graphml, to_cypher, to_graph_json,
)
from .methodology import (
    investigation_plan, methodology_package, rank_gaps,
    METHODOLOGY_PROMPT, FALSIFY_PROMPT,
)
from .changes import diff_models
from . import store, bql

_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
DEFAULT_INPUT = "_default"


def _name(kind: str):
    def check(value: str) -> str:
        if not _NAME_RE.match(value):
            raise argparse.ArgumentTypeError(
                f"{kind} must be letters, digits, '.', '_' or '-' (got {value!r})")
        return value
    return check


def _init_key() -> None:
    """Keep one fingerprint key per user, outside any output directory.

    Fingerprints from separate runs (e.g. one per role) must be comparable, but
    the key must not travel with the outputs — otherwise anyone holding
    model.json could confirm a guessed secret against its fingerprint.
    """
    if os.environ.get("BURP2MODEL_FP_KEY"):
        return
    base = os.environ.get("XDG_CONFIG_HOME") or os.path.join(os.path.expanduser("~"), ".config")
    path = os.path.join(base, "burp2model", "fingerprint.key")
    try:
        if not os.path.exists(path) or os.path.getsize(path) < 16:
            # never run with a missing, empty or truncated key
            os.makedirs(os.path.dirname(path), exist_ok=True)
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "wb") as f:
                f.write(os.urandom(32))
        with open(path, "rb") as f:
            set_fingerprint_key(f.read())
    except OSError as e:
        print(f"warning: no persistent fingerprint key ({e}); fingerprints from "
              "separate runs will not match", file=sys.stderr)


# ------------------------------------------------------------ inputs ---------

def _inputs_dir(outdir: str) -> str:
    return os.path.join(outdir, "inputs")


INPUTS_VERSION = 1


def _save_input(outdir: str, key: str, exchanges: list[Exchange], stats: dict) -> None:
    d = _inputs_dir(outdir)
    os.makedirs(d, exist_ok=True)
    with open(os.path.join(d, key + ".jsonl"), "w", encoding="utf-8") as f:
        f.write(json.dumps({"_stats": stats, "_version": INPUTS_VERSION}) + "\n")
        for ex in exchanges:
            f.write(json.dumps(ex.to_record()) + "\n")


def _clear_inputs(outdir: str, only: str | None = None) -> None:
    d = _inputs_dir(outdir)
    if not os.path.isdir(d):
        return
    for fn in os.listdir(d):
        if fn.endswith(".jsonl") and (only is None or fn == only + ".jsonl"):
            os.remove(os.path.join(d, fn))


def _load_inputs(outdir: str) -> tuple[list[Exchange], dict, list[str]]:
    """All saved inputs, re-indexed so evidence ids are unique across them."""
    d = _inputs_dir(outdir)
    exchanges: list[Exchange] = []
    stats = {"items": 0, "parsed": 0, "skipped": 0}
    names = []
    for fn in sorted(os.listdir(d)) if os.path.isdir(d) else []:
        if not fn.endswith(".jsonl"):
            continue
        try:
            with open(os.path.join(d, fn), encoding="utf-8") as f:
                loaded = []
                for line in f:
                    rec = json.loads(line)
                    if "_stats" in rec:
                        if rec.get("_version", 1) > INPUTS_VERSION:
                            raise ValueError(f"saved by a newer burp2model "
                                             f"(inputs v{rec['_version']})")
                        for k in stats:
                            stats[k] += rec["_stats"].get(k, 0)
                        continue
                    loaded.append(Exchange.from_record(rec))
        except (ValueError, KeyError, TypeError) as e:
            print(f"warning: skipping unreadable saved input {fn}: {e}\n"
                  f"  re-run the build for that capture (or use --fresh)", file=sys.stderr)
            continue
        names.append(fn[:-6])
        for ex in loaded:
            ex.index = len(exchanges)
            exchanges.append(ex)
    return exchanges, stats, names


# ------------------------------------------------------------ commands -------

def _scope(args) -> list[str] | None:
    """Normalise --scope values: accept `https://shop.com:443/x` for `shop.com`."""
    if not args.scope:
        return None
    out = []
    for s in args.scope:
        for x in s.split(","):
            x = x.strip().lower()
            if not x:
                continue
            x = re.sub(r"^[a-z][a-z0-9+.-]*://", "", x)   # scheme
            x = x.split("/")[0]                            # path
            if not x.startswith("[") and x.count(":") == 1:
                x = x.split(":")[0]                        # port
            if x:
                out.append(x)
    return out or None


def cmd_build(args) -> int:
    _init_key()
    stats: dict = {}
    try:
        exchanges = list(parse_items(
            args.log, role=args.role, stats=stats,
            skip_tools=tuple((args.skip_tools or "").split(",")),
            only_tools=tuple((args.only_tools or "").split(","))))
    except (OSError, ValueError, SyntaxError) as e:
        if str(args.log).lower().endswith(".csv"):
            extra = ("\nExpected a Burp Logger++ CSV export with Method, Host, Request and Response "
                     "columns (Request/Response base64 or raw HTTP).")
        elif isinstance(e, SyntaxError):
            extra = ("\nThis does not look like a Burp 'Save items' export.\n"
                     "In Burp: Proxy → HTTP history → select all → right-click → "
                     "Save items → history.xml (keep base64 encoding on).")
        else:
            extra = ""
        print(f"could not read {args.log}: {e}{extra}", file=sys.stderr)
        return 2
    if stats.get("tools"):
        mix = ", ".join(f"{t} {n}" for t, n in sorted(stats["tools"].items(), key=lambda kv: -kv[1]))
        print(f"logger csv: {mix}" + (f" · skipped {stats['filtered']} by tool" if stats.get("filtered") else ""),
              file=sys.stderr)
        if "Scanner" in stats["tools"] and not stats.get("filtered") and stats["tools"]["Scanner"] >= 20:
            print("  note: this export includes Scanner traffic (active-scan probes). They show up as "
                  "endpoints in the model; add --skip-tools Scanner to model the app without them.",
                  file=sys.stderr)
    if not exchanges:
        if stats.get("items", 0) == 0:
            print(f"{args.log}: no <item> elements found. This does not look like a Burp "
                  "'Save items' export.\n"
                  "In Burp: Proxy → HTTP history → select all → right-click → "
                  "Save items → history.xml (keep base64 encoding on).", file=sys.stderr)
        else:
            print(f"{args.log}: found {stats['items']} item(s) but none could be parsed. "
                  "Check the export is a full Burp 'Save items' XML with base64-encoded "
                  "requests and responses.", file=sys.stderr)
        return 2
    return _build_from(args, exchanges, stats)


def _build_from(args, exchanges: list, stats: dict) -> int:
    """Everything after parsing: save inputs, merge roles, build, write every output."""
    outdir = os.path.join(args.out, args.webapp)
    os.makedirs(outdir, exist_ok=True)

    # A role build adds to (or replaces) that role's input; anything else starts over.
    if args.role is None or args.fresh:
        _clear_inputs(outdir)
    else:
        _clear_inputs(outdir, only=DEFAULT_INPUT)
    _save_input(outdir, args.role or DEFAULT_INPUT, exchanges, stats)
    exchanges.clear()                   # the saved input is the source from here; free the copy
    all_ex, all_stats, merged = _load_inputs(outdir)

    m = build(all_ex, name=args.webapp, scope=_scope(args), stats=all_stats)
    all_ex.clear()                      # the model holds what it needs; keeps peak memory down
    if m.counts()["hosts"] == 0:
        print(f"warning: no captured host matched the scope "
              f"({', '.join(m.scope) or 'none'}); every request was treated as "
              f"third-party. Check --scope.", file=sys.stderr)
    osint_path = os.path.join(outdir, "osint.json")
    osint_data = _collect_osint(args, m, osint_path)

    try:
        with open(os.path.join(outdir, "model.json"), "w", encoding="utf-8") as f:
            json.dump(to_dict(m), f, indent=2)
        db_path = os.path.join(outdir, store.DB_NAME)
        dbs = store.write_db(m, db_path, osint=osint_data)
        write_html_report(m, os.path.join(outdir, "report.html"),
                          osint=osint_data, lens=args.lens, db_path=db_path)
        write_svg(m, os.path.join(outdir, "build.svg"))
        with open(os.path.join(outdir, "context.json"), "w", encoding="utf-8") as f:
            # compact: this file is pasted into an AI, where indentation is tokens
            json.dump(context_package(m, lens=args.lens, cap=args.cap,
                                      osint=osint_data), f, separators=(",", ":"))
        with open(os.path.join(outdir, "graph.json"), "w", encoding="utf-8") as f:
            json.dump(to_graph_json(m), f, indent=2)
        with open(os.path.join(outdir, "graph.graphml"), "w", encoding="utf-8") as f:
            f.write(to_graphml(m))
    except (OSError, sqlite3.Error) as e:
        print(f"could not write outputs to {outdir}: {e}", file=sys.stderr)
        return 2

    if args.animate:
        render_terminal(m, fast=args.no_type)
    else:
        c = m.counts()
        st = c["api_state"]
        print(f"routes {c['routes']} · APIs {c['endpoints']} "
              f"({st.get('BOTH', 0)} both, {st.get('RUNTIME_ONLY', 0)} runtime-only, "
              f"{st.get('STATIC_ONLY', 0)} static-only) · edges {c['edges']} "
              f"· nodes {c['nodes']}")
        print(f"{c['unknowns']} named unknowns")
    if all_stats.get("skipped"):
        print(f"skipped {all_stats['skipped']} of {all_stats['items']} items "
              f"across merged inputs (unparseable)", file=sys.stderr)
    roles = [n for n in merged if n != DEFAULT_INPUT]
    if roles:
        print(f"merged role inputs: {', '.join(roles)}")
    print(f"scope: {', '.join(m.scope)}")
    print(f"\nwrote {outdir}/  (model.json · report.html · build.svg · "
          f"context.json · graph.json · graph.graphml · graph.db)")
    print(f"graph.db: {dbs['nodes']} nodes · {dbs['edges']} edges · "
          f"{dbs['exchanges']} requests · {dbs['external_nodes']} external (OSINT) nodes"
          f"  →  burp2model q {args.webapp} help")
    return 0


def _primary_host(m) -> str | None:
    """The first-party host with the most evidence — the one worth probing."""
    hosts = [n for n in m.nodes.values() if n.type == "host"]
    if not hosts:
        return None
    return max(sorted(hosts, key=lambda n: n.label), key=lambda n: len(n.evidence)).label


def _probe_host(host: str | None) -> str | None:
    """A hostname OSINT can meaningfully look up, or None."""
    if not host:
        return None
    host = host.lower().split(":")[0]
    if (not re.match(r"^[a-z0-9.\-]{1,253}$", host) or "." not in host
            or re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host)
            or host.endswith((".local", ".localhost", ".internal", ".test", ".invalid",
                              ".example", ".lan", ".corp", ".home"))
            or host in ("example.com", "example.net", "example.org")
            or host.endswith((".example.com", ".example.net", ".example.org"))):
        return None
    return host


def _collect_osint(args, m, osint_path: str) -> dict | None:
    """External recon runs only with --osint and never fails a build.

    Live results replace the stored osint.json; if the lookup is skipped or
    fails, the last saved run is reused so the graph keeps its recon layer.
    """
    saved = None
    if os.path.exists(osint_path):
        try:
            with open(osint_path, encoding="utf-8") as f:
                saved = json.load(f)
        except (OSError, ValueError):
            saved = None
    if not getattr(args, "osint", False) or os.environ.get("BURP2MODEL_OFFLINE") == "1":
        return saved
    host = _probe_host(_primary_host(m))
    if host is None:
        print("osint: skipped (no public hostname among first-party hosts)", file=sys.stderr)
        return saved
    from . import osint as osint_mod
    print(f"osint: probing {host} — DNS, TLS, headers, CT logs, RDAP "
          f"(BURP2MODEL_OFFLINE=1 forces offline)", file=sys.stderr)
    try:
        result = osint_mod.run(host, timeout=args.osint_timeout, want_ports=False,
                               want_subdomains=True).to_dict()
        with open(osint_path, "w", encoding="utf-8") as f:
            json.dump(result, f, indent=2)
        return result
    except Exception as e:                                   # fail soft: recon is optional
        print(f"osint: failed ({e}); continuing without fresh recon", file=sys.stderr)
        return saved


def _db_path(args) -> str | None:
    path = os.path.join(args.out, args.webapp, store.DB_NAME)
    if not os.path.exists(path):
        print(f"no graph database at {path} — run `burp2model build` first", file=sys.stderr)
        return None
    return path


def cmd_q(args) -> int:
    path = _db_path(args)
    if path is None:
        return 2
    try:
        conn = bql.connect(path)
    except (ValueError, sqlite3.Error) as e:
        print(f"could not open {path}: {e}", file=sys.stderr)
        return 2

    def run_one(text: str) -> int:
        try:
            res = bql.run_query(conn, text, limit=args.limit)
        except (bql.BQLError, sqlite3.Error) as e:
            print(f"error: {e}", file=sys.stderr)
            return 2
        print(bql.render_json(res) if args.format == "json" else bql.render_text(res))
        return 0

    try:
        if args.query:
            return run_one(" ".join(args.query))
        print(f"burp2model q · {args.webapp} · graph.db — `help` for the language, Ctrl-D to exit")
        while True:
            try:
                line = input("bql> ").strip()
            except (EOFError, KeyboardInterrupt):
                print()
                return 0
            if line in ("exit", "quit"):
                return 0
            if line:
                run_one(line)
    finally:
        conn.close()


def cmd_crawl(args) -> int:
    from . import crawl as crawl_mod
    from .parse import parse_elements
    _init_key()
    if not (args.yes or os.environ.get("BURP2MODEL_CRAWL_CONSENT") == "1"):
        print(
            "crawl sends live requests to the target (GET only unless --submit-forms).\n"
            "Only crawl applications you are authorized to test.\n"
            f"  target: {args.url}\n"
            "Re-run with --yes to confirm you have authorization.", file=sys.stderr)
        return 2
    headers = {}
    for h in args.header or []:
        k, sep, v = h.partition(":")
        if not sep or not k.strip():
            print(f"--header must look like 'Name: value' (got {h!r})", file=sys.stderr)
            return 2
        headers[k.strip()] = v.strip()
    cookies = {}
    for c in (args.cookie or "").split(";"):
        k, sep, v = c.strip().partition("=")
        if sep and k:
            cookies[k] = v
    auth_body = args.auth_body
    if auth_body and auth_body.startswith("@"):
        try:
            with open(auth_body[1:], encoding="utf-8") as f:
                auth_body = f.read()
        except OSError as e:
            print(f"could not read {auth_body[1:]}: {e}", file=sys.stderr)
            return 2
    if args.auth_login and not auth_body:
        print("--auth-login needs --auth-body (JSON, or @file)", file=sys.stderr)
        return 2
    scope = [x.strip() for v in (args.scope or []) for x in v.split(",") if x.strip()]
    from . import journey as jy
    journeys = []
    for path in args.journey or []:
        try:
            journeys.append(jy.load(path))
        except jy.JourneyError as e:
            print(f"journey: {e}", file=sys.stderr)
            return 2
    journey_vars = {}
    for kv in args.var or []:
        k, sep, v = kv.partition("=")
        if not sep or not k:
            print(f"--var must look like name=value (got {kv!r})", file=sys.stderr)
            return 2
        journey_vars[k] = v
    if args.journey_only and not journeys:
        print("--journey-only needs at least one --journey FILE", file=sys.stderr)
        return 2
    local_storage = {}
    for kv in args.local_storage or []:
        k, sep, v = kv.partition("=")
        if not sep or not k:
            print(f"--local-storage must look like key=value (got {kv!r})", file=sys.stderr)
            return 2
        local_storage[k] = v
    try:
        cfg = crawl_mod.CrawlConfig(
            start=args.url, scope=scope, include_subdomains=args.include_subdomains,
            max_requests=args.max_requests, max_depth=args.depth, delay=args.delay,
            timeout=args.timeout, threads=args.threads, headers=headers, cookies=cookies,
            probe_js=not args.no_probe_js, submit_forms=args.submit_forms,
            respect_robots=args.respect_robots, insecure=args.insecure,
            auth_login=args.auth_login, auth_body=auth_body, auth_token=args.auth_token,
            auth_scheme=args.auth_scheme, max_seconds=args.max_seconds, browser=args.browser,
            chrome=args.chrome, max_clicks=args.max_clicks, no_interact=args.no_interact,
            no_forms=args.no_forms, read_only=args.read_only, headful=args.headful,
            auth_storage=args.auth_storage, local_storage=local_storage,
            per_template_cap=args.per_template_cap, journeys=journeys, journey_vars=journey_vars,
            journey_only=args.journey_only, max_assets=args.max_assets)
        crawler = crawl_mod.make_crawler(cfg)
    except ValueError as e:
        print(f"crawl: {e}", file=sys.stderr)
        return 2
    browser_mode = bool(getattr(crawler, "chrome", None))
    mode = ("a real browser (JavaScript on; clicks and benign form fills; "
            + ("read-only" if cfg.read_only else "in-scope POST/PUT/DELETE the app itself makes are allowed")
            + ")") if browser_mode else ("static: GET only" if not cfg.submit_forms
                                           else "static: GET + benign form posts")
    print(f"crawl: {args.url}  scope: {', '.join(crawler.scope)}  mode: {mode}  "
          f"(budget {cfg.max_requests or 'unlimited'} requests, depth {cfg.max_depth})", file=sys.stderr)
    try:
        res = crawler.run()
    except KeyboardInterrupt:
        print("crawl: interrupted; building from what was fetched", file=sys.stderr)
        res = crawl_mod.CrawlResult(crawler.items, crawler.stats, crawler.forms, crawler.scope)
    st = res.stats
    print(f"crawl: {st['requests']} requests ({st['pages']} pages, {st['assets']} assets, "
          f"{st['js_probes']} API/code calls) · {st['forms_found']} forms · "
          f"skipped: {st['skipped_out_of_scope']} out of scope, {st['skipped_unsafe']} unsafe-looking, "
          f"{st['skipped_duplicate']} duplicate, {st['skipped_cap']} over a cap · "
          f"{st['errors']} errors", file=sys.stderr)
    if journeys:
        print(f"crawl: journeys — {st['journey_steps'] - st['journey_failed']} of {st['journey_steps']} "
              f"steps ran cleanly", file=sys.stderr)
    if st.get("browser"):
        print(f"crawl: browser — {st['states']} page states, {st['clicks']} clicks, "
              f"{st['forms_submitted']} forms submitted, blocked before sending: "
              f"{st['blocked_scope']} out of scope, {st['blocked_unsafe']} unsafe-looking, "
              f"{st['blocked_method']} non-GET (read-only), {st.get('blocked_asset_cap', 0)} over the asset cap, "
              f"{st['dialogs_dismissed']} dialogs dismissed",
              file=sys.stderr)
    if st["js_refs_not_requested"]:
        print(f"crawl: {st['js_refs_not_requested']} code reference(s) name a non-GET method "
              "and were not sent", file=sys.stderr)
    if args.save_xml:
        try:
            with open(args.save_xml, "w", encoding="utf-8") as f:
                f.write(crawl_mod.to_burp_xml(res.items))
            print(f"wrote {args.save_xml} (Burp 'Save items' format; holds raw values, "
                  "unlike every burp2model output)", file=sys.stderr)
        except OSError as e:
            print(f"could not write {args.save_xml}: {e}", file=sys.stderr)
    pstats: dict = {}
    exchanges = list(parse_elements(res.items, source="crawl", role=args.role, stats=pstats))
    if not exchanges:
        print("crawl: nothing was fetched — is the target reachable?", file=sys.stderr)
        return 2
    return _build_from(args, exchanges, pstats)


def _model_path(args) -> str | None:
    path = os.path.join(args.out, args.webapp, "model.json")
    if not os.path.exists(path):
        print(f"no model at {path} — run `burp2model build` first", file=sys.stderr)
        return None
    return path


def _reload(path: str):
    try:
        with open(path, encoding="utf-8") as f:
            return from_dict(json.load(f))
    except (OSError, ValueError, KeyError, TypeError) as e:
        print(f"could not load {path}: {e}\nre-run `burp2model build` to regenerate it.",
              file=sys.stderr)
        return None


def cmd_query(args) -> int:
    path = _model_path(args)
    if path is None:
        return 2
    m = _reload(path)
    if m is None:
        return 2
    print(run_query(m, args.question))
    return 0


def cmd_crossrole(args) -> int:
    path = _model_path(args)
    if path is None:
        return 2
    m = _reload(path)
    if m is None:
        return 2
    missing = [r for r in (args.low, args.high) if r not in m.roles]
    if missing:
        print(f"role(s) not in this model: {', '.join(missing)} "
              f"(model has: {', '.join(sorted(m.roles)) or 'none'}).\n"
              f"Build each capture with --role <name> into the same --out/--webapp.",
              file=sys.stderr)
        return 2
    result = cross_role(m, args.low, args.high)
    if args.json:
        print(json.dumps(result, indent=2))
        return 0

    def show(title, items):
        print(f"{title} ({len(items)})")
        for s in items:
            ev = ", ".join(f"ev_{e}" for e in s["evidence"])
            st = " ".join(f"{r}={v}" for r, v in s["statuses"].items())
            print(f"  {s['endpoint']:<44} {ev}  {st}")
            print(f"    unknown: {s['unknown']} · next: {s['next']}")
        print()

    show(f"'{args.low}' reached privileged-looking endpoints", result["low_reached_privileged"])
    show(f"'{args.high}' reached, '{args.low}' never tried", result["high_only"])
    show("both roles got 2xx", result["shared_same_success"])
    print("Each is a hypothesis, not a finding.")
    return 0


def cmd_osint(args) -> int:
    from . import osint as osint_mod

    host = args.host.strip().lower().replace("https://", "").replace("http://", "")
    host = host.split("/")[0].split(":")[0]
    if not re.match(r"^[a-z0-9.\-]{1,253}$", host) or "." not in host:
        print(f"not a hostname: {args.host!r}", file=sys.stderr)
        return 2
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host):
        print(f"{host} is an IP address — osint needs a hostname "
              "(DNS, certificate transparency and RDAP are domain lookups)", file=sys.stderr)
        return 2
    # Active recon reaches out to the target and to public services. Gate it.
    if not (args.yes or os.environ.get("BURP2MODEL_OSINT_CONSENT") == "1"):
        print(
            "osint sends live requests to the target and to public services "
            "(DNS, TLS, HTTP" + (", TCP ports" if args.ports else "") + ", CT logs, RDAP).\n"
            f"Only run this against hosts you are authorized to test.\n"
            f"  target: {host}\n"
            "Re-run with --yes to confirm you have authorization.",
            file=sys.stderr)
        return 2

    result = osint_mod.run(host, timeout=args.timeout, want_ports=args.ports,
                           want_subdomains=not args.no_subdomains)
    blob = json.dumps(result.to_dict(), indent=2)
    saved = None
    try:
        if args.webapp:
            outdir = os.path.join(args.out, args.webapp)
            os.makedirs(outdir, exist_ok=True)
            saved = os.path.join(outdir, "osint.json")
            with open(saved, "w", encoding="utf-8") as f:
                f.write(blob)
        if args.out_file:
            with open(args.out_file, "w", encoding="utf-8") as f:
                f.write(blob)
            saved = args.out_file
    except OSError as e:
        print(f"could not write osint report: {e}", file=sys.stderr)
        return 2
    if args.json:
        print(blob)
    else:
        print(osint_mod.render_text(result))
    if saved:
        print(f"\nwrote {saved}", file=sys.stderr)
        if args.webapp:
            mp = os.path.join(args.out, args.webapp, "model.json")
            if os.path.exists(mp):
                try:
                    with open(mp, encoding="utf-8") as f:
                        model = from_dict(json.load(f))
                    dbs = store.write_db(model, os.path.join(args.out, args.webapp,
                                                             store.DB_NAME),
                                         osint=result.to_dict())
                    print(f"graph.db updated ({dbs['external_nodes']} external nodes, "
                          f"{dbs['osint_runs']} recon run(s) stored)", file=sys.stderr)
                except (OSError, ValueError, KeyError, TypeError, sqlite3.Error) as e:
                    print(f"could not update graph.db: {e}", file=sys.stderr)
            print("run the build again for this webapp to fold it into "
                  "report.html and context.json.", file=sys.stderr)
    return 0


def _render_reason(rg, m) -> str:
    """A compact text overview of the graph's reasoning views."""
    L = [f"{m.name} — graph reasoning  ({len(m.nodes)} nodes, {len(m.edges)} edges)", ""]
    comms = rg.communities()
    L.append(f"Communities ({len(comms)}) — functional areas")
    for c in comms[:8]:
        kinds = ", ".join(f"{v} {k}" for k, v in c["kinds"].items())
        L.append(f"  {c['id']}  '{c['name']}'  {c['size']} nodes  ({kinds})")
    L.append("")
    L.append("Hubs — the load-bearing nodes")
    for h in rg.hubs(8):
        L.append(f"  {h['degree']:>3}  {h['type']:<12} {h['label']}")
    L.append("")
    zones = rg.trust_zones()
    L.append("Trust zones — how identity reaches the surface")
    for z, rows in zones.items():
        L.append(f"  {z:<18} {len(rows)} endpoint(s)")
    L.append("")
    coup = rg.coupling()
    L.append(f"Coupling — {len(coup['cross_community'])} cross-area edge(s), "
             f"{len(coup['to_third_party'])} to third parties")
    L.append("")
    L.append("Source: model graph · Model call: none")
    return "\n".join(L)


def cmd_graph(args) -> int:
    path = _model_path(args)
    if path is None:
        return 2
    m = _reload(path)
    if m is None:
        return 2
    rg = ReasonGraph(m)

    if args.reach or args.blast or args.touched_by:
        target = (args.reach or args.blast or args.touched_by).lower()
        # rank: prefer a label hit over an id hit, a meaningful node over a
        # parameter/operation/cookie, and the shortest label among equals
        leaf = ("parameter", "operation", "cookie")
        scored = []
        for nid, n in m.nodes.items():
            lbl = n.label.lower()
            if target in lbl:
                rank = 0 if lbl == target else 1
            elif target in nid.lower():
                rank = 2
            else:
                continue
            scored.append(((rank, n.type in leaf, len(n.label)), nid))
        if not scored:
            print(f"no node matches {target!r}", file=sys.stderr)
            return 2
        scored.sort()
        nid = scored[0][1]
        if args.reach:
            result = rg.reach(nid)
        elif args.blast:
            result = rg.blast(nid, depth=args.depth)
        else:
            result = rg.touched_by(nid, depth=args.depth)
        print(json.dumps(result, indent=2))
        return 0

    fmt = args.format
    if fmt == "graphml":
        out = to_graphml(m)
    elif fmt == "cypher":
        out = to_cypher(m)
    elif fmt == "json":
        out = json.dumps(to_graph_json(m), indent=2)
    elif fmt == "reason":
        out = json.dumps(reason_graph(m), indent=2)
    else:
        out = _render_reason(rg, m)

    if args.out_file:
        try:
            with open(args.out_file, "w", encoding="utf-8") as f:
                f.write(out)
        except OSError as e:
            print(f"could not write {args.out_file}: {e}", file=sys.stderr)
            return 2
        print(f"wrote {args.out_file}", file=sys.stderr)
    else:
        print(out)
    return 0


def _render_plan(plan: dict) -> str:
    p = plan["posture"]
    L = [f"{plan['app']} — investigation scaffold  (scope: {', '.join(plan['scope']) or '?'})", ""]
    L.append(f"{p['endpoints']} endpoints · {p['feature_areas']} feature areas · "
             f"roles: {', '.join(p['roles']) or 'none'}")
    L.append(f"{p['static_only']} code-only · {p['privileged']} privileged · "
             f"{p['credentialed']} credentialed · {p['open_questions']} open questions")
    L.append("")
    L.append("RECON — establish first")
    for r in plan["recon"]:
        L.append(f"  • {r['step']}")
        L.append(f"      why: {r['why']}")
        L.append(f"      how: {r['how']}")
    L.append("")
    L.append("LINES OF INQUIRY — by leverage")
    for ln in plan["lines_of_inquiry"]:
        if not ln["endpoints"]:
            continue
        L.append(f"  [{ln['leverage']:>2}] {ln['area']} — {ln['why_it_matters']}")
        if ln["reach"]:
            L.append(f"       reached {'; '.join(ln['reach'])}")
        for s in ln["signals"][:5]:
            ev = ", ".join(f"ev_{i}" for i in s["evidence"])
            L.append(f"       - {s['endpoint']}: {s['observation']}  [{ev}]")
            L.append(f"         → {s['question']}")
            L.append(f"         next: {s['next']}")
        for q in ln["open_questions"][:4]:
            ent = f"{q['entity']}: " if q.get("entity") else ""
            L.append(f"       ? {ent}{q['unknown']} — {q['to_find_out']}")
        L.append("")
    if plan["watch"]["third_party_trust"]:
        L.append("WATCH — trust leaving the app")
        for e in plan["watch"]["third_party_trust"][:8]:
            L.append(f"  {e['from']} → {e['to']}  ({e['edge'].lower()})")
        L.append("")
    L.append("This is a scaffold, not the methodology. Hand it to an AI with "
             "`--prompt` to reason a sequenced, target-specific plan.")
    L.append("Source: model graph · Model call: none")
    return "\n".join(L)


def cmd_methodology(args) -> int:
    path = _model_path(args)
    if path is None:
        return 2
    m = _reload(path)
    if m is None:
        return 2
    if args.json:
        out = json.dumps(investigation_plan(m), indent=2)
    elif args.prompt:
        pkg = methodology_package(m)
        out = ("\n".join(METHODOLOGY_PROMPT) + "\n\n"
               + "MODEL AND SCAFFOLD (JSON):\n```json\n"
               + json.dumps({"plan_scaffold": pkg["plan_scaffold"],
                             "model": pkg["model"]}, separators=(",", ":")) + "\n```")
    else:
        out = _render_plan(investigation_plan(m))
    if args.out_file:
        try:
            with open(args.out_file, "w", encoding="utf-8") as f:
                f.write(out)
        except OSError as e:
            print(f"could not write {args.out_file}: {e}", file=sys.stderr)
            return 2
        print(f"wrote {args.out_file}", file=sys.stderr)
    else:
        print(out)
    return 0


def cmd_gaps(args) -> int:
    path = _model_path(args)
    if path is None:
        return 2
    m = _reload(path)
    if m is None:
        return 2
    g = rank_gaps(m)
    if args.json:
        print(json.dumps(g, indent=2))
        return 0
    print(f"{g['app']} — gaps, ranked by how much resolving each improves the picture")
    print()
    for i, gap in enumerate(g["gaps"], 1):
        print(f"#{i}  [{gap['leverage']:>2}]  {gap['entity']}")
        print(f"      unknown: {gap['unknown']}")
        print(f"      next:    {gap['next']}")
    print()
    print("absence = a gap in observation, never a statement about the target")
    print(SOURCE)
    return 0


def cmd_changes(args) -> int:
    new = _reload(_model_path(args)) if _model_path(args) else None
    if new is None:
        return 2
    if bool(args.against) == bool(args.against_build):
        print("give exactly one of --against OLD_MODEL_JSON or --against-build "
              "(an id from graph.db's build history, or `previous`)", file=sys.stderr)
        return 2
    try:
        if args.against:
            with open(args.against, encoding="utf-8") as f:
                old = from_dict(json.load(f))
        else:
            dbp = _db_path(args)
            if dbp is None:
                return 2
            conn = store.open_db(dbp)
            try:
                bid = None if args.against_build == "previous" else int(args.against_build)
                if bid is None:
                    rows = conn.execute("SELECT id FROM builds ORDER BY id DESC LIMIT 2").fetchall()
                    if len(rows) < 2:
                        print("graph.db holds only one build so far — build again after "
                              "the app changes", file=sys.stderr)
                        return 2
                    bid = rows[1][0]
                snap = store.load_build(conn, bid)
            finally:
                conn.close()
            if snap is None:
                print(f"no build #{bid} in graph.db", file=sys.stderr)
                return 2
            old = from_dict(snap)
    except (OSError, ValueError, KeyError, TypeError, sqlite3.Error) as e:
        what = f"--against {args.against}" if args.against else "the stored build"
        print(f"could not load {what}: {e}", file=sys.stderr)
        return 2
    d = diff_models(old, new)
    if args.json:
        print(json.dumps(d, indent=2))
        return 0
    print(f"{d['app']} — what changed  (+{d['totals']['appeared']} appeared, "
          f"-{d['totals']['gone']} gone)")
    print()
    if not d["areas"]:
        print("No drift between these two models.")
        return 0
    for a in d["areas"]:
        print(f"● {a['area']}")
        for x in a["appeared"]:
            ev = ", ".join(f"ev_{i}" for i in x.get("evidence", []))
            print(f"   + {x['kind']:<11} {x['label']}")
            print(f"       {x['why']}" + (f"  [{ev}]" if ev else ""))
        for x in a["gone"]:
            print(f"   - {x['kind']:<11} {x['label']}")
            print(f"       {x['why']}")
        print()
    print(d["note"])
    print(SOURCE)
    return 0


def cmd_falsify(args) -> int:
    path = _model_path(args)
    if path is None:
        return 2
    m = _reload(path)
    if m is None:
        return 2
    pkg = methodology_package(m, prompt=FALSIFY_PROMPT)
    out = ("\n".join(FALSIFY_PROMPT) + "\n\n"
           + "MODEL AND HYPOTHESES (JSON):\n```json\n"
           + json.dumps({"plan_scaffold": pkg["plan_scaffold"],
                         "model": pkg["model"]}, indent=2) + "\n```")
    if args.out_file:
        try:
            with open(args.out_file, "w", encoding="utf-8") as f:
                f.write(out)
        except OSError as e:
            print(f"could not write {args.out_file}: {e}", file=sys.stderr)
            return 2
        print(f"wrote {args.out_file}", file=sys.stderr)
    else:
        print(out)
    return 0


def cmd_animate(args) -> int:
    """Standalone animation from an existing model or a fresh build."""
    if args.log:
        _init_key()
        try:
            m = build(list(parse_items(args.log)), name=args.webapp)
        except (OSError, ValueError, SyntaxError) as e:
            print(f"could not read {args.log}: {e}", file=sys.stderr)
            return 2
    else:
        path = _model_path(args)
        if path is None:
            return 2
        m = _reload(path)
        if m is None:
            return 2
    if args.svg:
        try:
            write_svg(m, args.svg)
        except OSError as e:
            print(f"could not write {args.svg}: {e}", file=sys.stderr)
            return 2
        print(f"wrote {args.svg}")
    else:
        render_terminal(m, fast=args.no_type)
    return 0


def main(argv=None) -> int:
    p = argparse.ArgumentParser(
        prog="burp2model",
        description="Turn a Burp Suite history into an evidence-backed web-app model.",
    )
    p.add_argument("--version", action="version", version=f"burp2model {__version__}")
    p.set_defaults(func=None)
    sub = p.add_subparsers(dest="cmd")

    b = sub.add_parser("build", help="build the model (also the default: `burp2model file.xml`)")
    b.add_argument("log", help="Burp 'Save items' XML export to build from")
    b.add_argument("--webapp", "-w", default="app", type=_name("--webapp"),
                   help="name for this app's model (default: app)")
    b.add_argument("--role", type=_name("--role"),
                   help="tag this capture with a role; role builds into the same "
                        "--out/--webapp are merged into one model")
    b.add_argument("--fresh", action="store_true",
                   help="discard previously merged role inputs first")
    b.add_argument("--scope", action="append",
                   help="first-party host or domain (repeatable or comma-separated); "
                        "default: the registrable domain of the busiest host")
    b.add_argument("--lens", choices=LENSES, default="attention",
                   help="ordering/filter for context.json")
    b.add_argument("--cap", type=int, default=40, metavar="N",
                   help="max items per section in context.json (default: 40)")
    b.add_argument("--out", default="burp2model-out",
                   help="output directory (default: burp2model-out)")
    b.add_argument("--osint", action="store_true",
                   help="also run light external recon on the primary host (off by default; "
                        "sends DNS/TLS/HTTP requests; BURP2MODEL_OFFLINE=1 forces it off)")
    b.add_argument("--osint-timeout", type=float, default=5.0, metavar="SEC",
                   help="per-lookup timeout for the build's OSINT (default: 5)")
    b.add_argument("--skip-tools", metavar="TOOLS",
                   help="Logger++ CSV: drop rows from these Burp tools (comma-separated), e.g. Scanner")
    b.add_argument("--only-tools", metavar="TOOLS",
                   help="Logger++ CSV: keep only rows from these Burp tools, e.g. Proxy,Extensions")
    b.add_argument("--animate", action="store_true",
                   help="play the build animation in the terminal")
    b.add_argument("--no-type", action="store_true",
                   help="animation: skip the typing effect")
    b.set_defaults(func=cmd_build)

    cw = sub.add_parser("crawl", help="crawl a running web app and build the model from it, "
                                      "no Burp needed; authorized targets only")
    cw.add_argument("url", help="start URL, e.g. https://shop.example.com/")
    cw.add_argument("--yes", action="store_true", help="confirm you are authorized to test this target")
    cw.add_argument("--webapp", "-w", default="app", type=_name("--webapp"),
                    help="name for this app's model (default: app)")
    cw.add_argument("--role", type=_name("--role"),
                    help="tag this crawl with a role; crawls into the same --out/--webapp merge")
    cw.add_argument("--fresh", action="store_true", help="discard previously merged role inputs first")
    cw.add_argument("--scope", action="append",
                    help="extra in-scope hosts (host or host:port; repeatable or comma-separated). "
                         "The crawl never leaves the start origin plus these")
    cw.add_argument("--include-subdomains", action="store_true",
                    help="also crawl subdomains of the start host's registrable domain")
    cw.add_argument("--max-requests", type=int, default=3000, metavar="N",
                    help="request budget; 0 = no limit (default: 3000)")
    cw.add_argument("--max-assets", type=int, default=2000, metavar="N",
                    help="browser mode: cap on image/font/media loads (0 = no cap), so they don't "
                         "starve page and API budget on an asset-heavy site (default: 2000)")
    cw.add_argument("--depth", type=int, default=12, help="link depth from the start page (default: 12)")
    cw.add_argument("--max-seconds", type=float, default=0, metavar="SEC",
                    help="wall-clock limit for the whole crawl; 0 = none")
    cw.add_argument("--delay", type=float, default=0.1, metavar="SEC",
                    help="static mode: minimum seconds between requests (default: 0.1)")
    cw.add_argument("--threads", type=int, default=4, help="static mode: parallel fetches, 1-8 (default: 4)")
    cw.add_argument("--per-template-cap", type=int, default=25, metavar="N",
                    help="max variants of one path template, e.g. /item/{id} (default: 25)")
    cw.add_argument("--browser", choices=["auto", "on", "off"], default="auto",
                    help="crawl with a real Chrome/Chromium so JavaScript runs: auto (default) uses one "
                         "if installed, on requires it, off is the static crawler")
    cw.add_argument("--chrome", metavar="PATH", help="Chrome/Chromium binary (else found automatically, "
                                                      "or BURP2MODEL_CHROME)")
    cw.add_argument("--max-clicks", type=int, default=25, metavar="N",
                    help="browser: clicks per page state (default: 25)")
    cw.add_argument("--no-interact", action="store_true", help="browser: load pages, do not click or fill")
    cw.add_argument("--no-forms", action="store_true", help="browser: fill fields but do not submit forms")
    cw.add_argument("--read-only", action="store_true",
                    help="browser: block every request that is not GET/HEAD/OPTIONS")
    cw.add_argument("--headful", action="store_true", help="browser: show the window (debugging)")
    cw.add_argument("--journey", action="append", metavar="FILE",
                    help="run a scripted journey (JSON: login, register, checkout, uploads …) before the "
                         "crawl, in the same session; repeatable. See the docs for the format")
    cw.add_argument("--var", action="append", metavar="name=value",
                    help="a variable for journeys, as ${name} (use ${env:NAME} for secrets)")
    cw.add_argument("--journey-only", action="store_true",
                    help="run the journeys and skip the autonomous crawl")
    cw.add_argument("--auth-storage", metavar="KEY",
                    help="browser: after --auth-login, store the token in localStorage[KEY] and cookie KEY "
                         "(what many SPAs read), e.g. token")
    cw.add_argument("--local-storage", action="append", metavar="key=value",
                    help="browser: set a localStorage value before the app loads (repeatable)")
    cw.add_argument("--timeout", type=float, default=10.0, help="per-request timeout in seconds")
    cw.add_argument("--header", action="append", metavar="'Name: value'",
                    help="extra request header, e.g. 'Authorization: Bearer ...' (repeatable)")
    cw.add_argument("--cookie", metavar="'a=b; c=d'", help="initial cookies, to crawl as a logged-in user")
    cw.add_argument("--auth-login", metavar="URL",
                    help="POST credentials here first and carry the token (see --auth-body, --auth-token)")
    cw.add_argument("--auth-body", metavar="JSON|@FILE", help="JSON body for --auth-login")
    cw.add_argument("--auth-token", metavar="PATH",
                    help="dotted path to the token in the login reply, e.g. authentication.token")
    cw.add_argument("--auth-scheme", default="Bearer", help="Authorization scheme for the token (default: Bearer)")
    cw.add_argument("--no-probe-js", action="store_true",
                    help="do not request the GET endpoints that scripts and pages name")
    cw.add_argument("--submit-forms", action="store_true",
                    help="also POST forms with benign sample values (never forms with a password field)")
    cw.add_argument("--respect-robots", action="store_true", help="skip paths robots.txt disallows")
    cw.add_argument("--insecure", action="store_true", help="do not verify TLS certificates")
    cw.add_argument("--save-xml", metavar="PATH",
                    help="also write the crawl as a Burp 'Save items' XML (contains raw values)")
    cw.add_argument("--lens", choices=LENSES, default="attention", help="ordering/filter for context.json")
    cw.add_argument("--cap", type=int, default=40, metavar="N", help="max items per section in context.json")
    cw.add_argument("--out", default="burp2model-out", help="output directory (default: burp2model-out)")
    cw.add_argument("--animate", action="store_true", help="play the build animation in the terminal")
    cw.add_argument("--no-type", action="store_true", help="animation: skip the typing effect")
    cw.add_argument("--osint", action="store_true",
                    help="also run light external recon on the primary host (off by default)")
    cw.add_argument("--osint-timeout", type=float, default=5.0, metavar="SEC")
    cw.set_defaults(func=cmd_crawl)

    q = sub.add_parser("query", help="ask the model a factual question (no AI); try 'help'")
    q.add_argument("webapp", type=_name("webapp"), help="model name used at build time")
    q.add_argument("question", help="the question; `help` lists what can be asked")
    q.add_argument("--out", default="burp2model-out",
                   help="output directory used at build time")
    q.set_defaults(func=cmd_query)

    bq = sub.add_parser("q", help="query graph.db with BQL (HTTPQL-style filters + graph "
                                  "verbs); no query opens an interactive prompt")
    bq.add_argument("webapp", type=_name("webapp"), help="model name used at build time")
    bq.add_argument("query", nargs="*", help="a BQL query; `help` prints the language")
    bq.add_argument("--format", choices=["table", "json"], default="table")
    bq.add_argument("--limit", type=int, default=bql.DEFAULT_LIMIT, help="max rows (default: 100)")
    bq.add_argument("--out", default="burp2model-out", help="output directory used at build time")
    bq.set_defaults(func=cmd_q)

    cr = sub.add_parser("cross-role", help="compare what two roles reached")
    cr.add_argument("webapp", type=_name("webapp"), help="model name used at build time")
    cr.add_argument("--low", required=True, type=_name("--low"),
                    help="the less-privileged role (as tagged with --role)")
    cr.add_argument("--high", required=True, type=_name("--high"),
                    help="the more-privileged role (as tagged with --role)")
    cr.add_argument("--json", action="store_true", help="print JSON instead of text")
    cr.add_argument("--out", default="burp2model-out",
                    help="output directory used at build time")
    cr.set_defaults(func=cmd_crossrole)

    o = sub.add_parser("osint", help="external recon for a host (DNS, TLS, headers, tech, "
                                     "email, subdomains, RDAP); authorized targets only")
    o.add_argument("host")
    o.add_argument("--webapp", "-w", type=_name("--webapp"),
                   help="save osint.json into OUT/WEBAPP/ so build folds it into context.json")
    o.add_argument("--yes", action="store_true", help="confirm you are authorized to test this host")
    o.add_argument("--ports", action="store_true", help="also TCP-connect common ports")
    o.add_argument("--no-subdomains", action="store_true", help="skip certificate-transparency lookup")
    o.add_argument("--timeout", type=float, default=6.0,
                   help="per-lookup timeout in seconds (default: 6)")
    o.add_argument("--out", default="burp2model-out",
                   help="output directory (default: burp2model-out)")
    o.add_argument("--json", action="store_true", help="print JSON instead of the text summary")
    o.add_argument("--out-file", help="write the JSON report to this path")
    o.set_defaults(func=cmd_osint)

    g = sub.add_parser("graph", help="reason over the graph, or export it "
                                     "(GraphML / Cypher / JSON) for tooling and AI")
    g.add_argument("webapp", type=_name("webapp"), help="model name used at build time")
    g.add_argument("--format", choices=["overview", "reason", "json", "graphml", "cypher"],
                   default="overview",
                   help="overview (text), reason (graph+reasoning JSON for an LLM), "
                        "json (node-link), graphml (Gephi/yEd), cypher (Neo4j)")
    g.add_argument("--reach", metavar="NODE",
                   help="show how a node is reached (entry-point paths)")
    g.add_argument("--blast", metavar="NODE",
                   help="show what a node touches downstream")
    g.add_argument("--touched-by", metavar="NODE",
                   help="show what leads into a node upstream")
    g.add_argument("--depth", type=int, default=3, help="hops for --blast/--touched-by")
    g.add_argument("--out-file", help="write the output to this path")
    g.add_argument("--out", default="burp2model-out", help="output directory used at build time")
    g.set_defaults(func=cmd_graph)

    gp = sub.add_parser("gaps", help="rank the model's open questions by how much "
                                     "resolving each improves the picture")
    gp.add_argument("webapp", type=_name("webapp"), help="model name used at build time")
    gp.add_argument("--json", action="store_true", help="print JSON")
    gp.add_argument("--out", default="burp2model-out", help="output directory used at build time")
    gp.set_defaults(func=cmd_gaps)

    ch = sub.add_parser("changes", help="diff this model against an older one, "
                                        "grouped by feature area (drift, never findings)")
    ch.add_argument("webapp", type=_name("webapp"), help="model name used at build time")
    ch.add_argument("--against", metavar="OLD_MODEL_JSON",
                    help="path to an earlier model.json to compare against")
    ch.add_argument("--against-build", metavar="ID|previous",
                    help="compare against a build stored in graph.db (see `q shop "
                         "\"sql SELECT id, built_at FROM builds\"`), or `previous`")
    ch.add_argument("--json", action="store_true", help="print JSON")
    ch.add_argument("--out", default="burp2model-out", help="output directory used at build time")
    ch.set_defaults(func=cmd_changes)

    fa = sub.add_parser("falsify", help="emit an AI prompt that stress-tests the "
                                        "scaffold's hypotheses (tries to eliminate them)")
    fa.add_argument("webapp", type=_name("webapp"), help="model name used at build time")
    fa.add_argument("--out-file", help="write the prompt to this path")
    fa.add_argument("--out", default="burp2model-out", help="output directory used at build time")
    fa.set_defaults(func=cmd_falsify)

    me = sub.add_parser("methodology", help="a target-specific recon & hunting "
                                           "scaffold, or the AI prompt that turns it "
                                           "into a methodology (no generic checklist)")
    me.add_argument("webapp", type=_name("webapp"), help="model name used at build time")
    me.add_argument("--prompt", action="store_true",
                    help="emit the full AI-ready prompt + model to paste into a chat model")
    me.add_argument("--json", action="store_true", help="the scaffold as JSON")
    me.add_argument("--out-file", help="write the output to this path")
    me.add_argument("--out", default="burp2model-out", help="output directory used at build time")
    me.set_defaults(func=cmd_methodology)

    an = sub.add_parser("animate", help="render the build animation (terminal or --svg)")
    an.add_argument("--webapp", "-w", default="app", type=_name("--webapp"),
                    help="model name used at build time")
    an.add_argument("--log", help="build fresh from this export instead of a saved model")
    an.add_argument("--svg", help="write an animated SVG to this path")
    an.add_argument("--out", default="burp2model-out",
                    help="output directory used at build time")
    an.add_argument("--no-type", action="store_true", help="skip the typing effect")
    an.set_defaults(func=cmd_animate)

    argv = list(sys.argv[1:] if argv is None else argv)
    known = {"build", "crawl", "query", "q", "cross-role", "osint", "graph", "methodology",
             "gaps", "changes", "falsify", "animate", "-h", "--help", "--version"}
    # bare `burp2model file.xml ...` → treat as build, but only when the first
    # word is a real file; a typo'd subcommand gets a clear error instead
    if argv and argv[0] not in known and not argv[0].startswith("-"):
        if not os.path.exists(argv[0]):
            print(f"burp2model: {argv[0]!r} is not a command or an existing file.\n"
                  f"commands: build, crawl, query, q, cross-role, osint, graph, gaps, changes, "
                  f"falsify, methodology, animate "
                  f"(or `burp2model <export.xml>` to build)", file=sys.stderr)
            return 2
        argv = ["build"] + argv

    args = p.parse_args(argv)

    if getattr(args, "func", None) is None:
        p.print_help()
        return 1
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
