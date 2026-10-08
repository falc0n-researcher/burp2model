"""
The burp2model report: a single self-contained, offline, interactive HTML
dashboard built from the model.

Design goals, in order:
  * safe — every string in the model came from the target, so the embedded JSON
    is escaped so it cannot close its <script>, the page carries a strict CSP,
    and all model-derived text is inserted through an escaping helper, never as
    raw HTML.
  * offline — no network, no CDN, no fonts to fetch; opens from disk.
  * useful — multiple views (Overview, Priorities, Attack surface, Client code,
    Supply chain, Trust, Cross-role, Evidence), faceted filters, global search,
    and an evidence drawer that resolves every ev_N to its request.

The Python side builds one flat, view-agnostic payload; all rendering, filtering
and searching happens client-side from that payload.
"""

from __future__ import annotations

import json
import os
import time

from . import __version__
from .context import context_package
from .methodology import METHODOLOGY_PROMPT, investigation_plan
from .model import PRIV_RE, Model, to_dict
from .bql_js import BQL_JS
from .report_dash import DASH_CSS, DASH_JS
from .report_view import RR_CSS, RR_JS
from .report_pages import PG_CSS, PG_JS
from .report_inventory import INV_CSS, INV_JS
from .report_query import QRY_CSS, QRY_JS
from .report_map import MAP_CSS, MAP_JS
from .report_fonts import TYPE_CSS, font_css

# Version of the JSON embedded in report.html. Bump on any breaking change to
# the payload shape so the page's code and the data can't silently drift.
SCHEMA_VERSION = 2


def _safe_json(obj) -> str:
    """JSON safe to embed inside an inline <script> element."""
    s = json.dumps(obj, ensure_ascii=False, sort_keys=False)
    return (s.replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026")
            .replace("\u2028", "\\u2028").replace("\u2029", "\\u2029"))


def _params_index(m: Model) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    for e in m.edges:
        if e.type == "USES_PARAMETER" and e.dst in m.nodes:
            out.setdefault(e.src, []).append(m.nodes[e.dst].label)
    return {k: sorted(set(v)) for k, v in out.items()}


def _osint_graph(osint: dict, primary_host: str | None, node_ids: set[str] | None = None):
    """Turn an osint.json report into map nodes/edges hung off the app host."""
    nodes, edges = [], []
    if not osint:
        return nodes, edges, None
    host = osint.get("host") or primary_host
    anchor = f"host:{host}" if host else None
    # never emit edges to a node the graph does not hold
    if node_ids is not None and anchor not in node_ids:
        anchor = f"host:{primary_host}" if f"host:{primary_host}" in node_ids else None
    summary = {"host": host}

    # External recon is a different provenance from the capture, so its edges
    # carry their own state (EXTERNAL) and the map draws them distinctly —
    # never as "seen in traffic" or "found in code".
    def add(nid, label, detail, kind="fact", extra_edge=True):
        nodes.append({"id": nid, "label": label, "type": "infra", "layer": 5,
                      "state": None, "evidence": [], "detail": detail, "kind": kind})
        if anchor and extra_edge:
            edges.append({"s": anchor, "d": nid, "type": "OSINT", "state": "EXTERNAL"})

    tls = osint.get("tls") or {}
    if tls.get("issuer") and not tls.get("error"):
        exp = tls.get("not_after")
        days = tls.get("days_until_expiry")
        add("infra:tls", f"TLS · {tls['issuer']}",
            f"Issuer: {tls['issuer']}"
            + (f" · expires {exp}" if exp else "")
            + (f" ({days} days)" if days is not None else "")
            + (f" · {tls['tls_version']}" if tls.get("tls_version") else "")
            + (f" · {len(tls['san'])} SANs" if tls.get("san") else ""), "tls")
        summary["tls"] = tls
    dns = osint.get("dns") or {}
    for ip in (dns.get("A") or [])[:3]:
        add(f"infra:ip:{ip}", f"IP · {ip}", f"DNS A record: {ip}", "dns")
    if dns.get("A"):
        summary["ips"] = dns["A"][:3]
    if dns.get("CNAME"):
        summary["cname"] = dns["CNAME"][0]
    if dns.get("CNAME"):
        add("infra:cname", f"CNAME · {dns['CNAME'][0]}",
            "Canonical name: " + ", ".join(dns["CNAME"][:3]), "dns")
    if dns.get("NS"):
        add("infra:ns", f"Nameservers · {len(dns['NS'])}", "NS: " + ", ".join(dns["NS"][:4]), "dns")
        summary["nameservers"] = dns["NS"][:4]
    if dns.get("MX"):
        add("infra:mx", "Mail (MX)", "MX: " + ", ".join(dns["MX"][:3]), "dns")
    geo = osint.get("ip_geo") or {}
    if geo.get("network"):
        add("infra:host", f"Hosting · {geo['network']}",
            f"Network: {geo['network']}" + (f" · {geo.get('country')}" if geo.get("country") else ""),
            "hosting")
        summary["hosting"] = geo
    for t in (osint.get("technology") or [])[:8]:
        name = t.get("name") if isinstance(t, dict) else t
        via = t.get("evidence") if isinstance(t, dict) else None
        add(f"infra:tech:{name}", f"Tech · {name}",
            f"Technology: {name}" + (f" · seen in {via}" if via else ""), "tech")
    http = osint.get("http") or {}
    missing = http.get("security_headers_missing") or []
    if not http.get("error") and (missing or http.get("security_headers_present")):
        present = len(http.get("security_headers_present") or {})
        add("infra:headers", f"Security headers · {len(missing)} missing",
            f"{present} present, {len(missing)} missing"
            + (": " + ", ".join(missing[:6]) if missing else ""), "http")
        summary["headers_missing"] = missing
        summary["headers_present"] = sorted((http.get("security_headers_present") or {}).keys())
    em = osint.get("email_security") or {}
    if em.get("dmarc_policy") or em.get("spf_note"):
        add("infra:email", "Email auth",
            f"SPF: {em.get('spf_note','?')} · DMARC: {em.get('dmarc_policy') or em.get('dmarc_note','?')}",
            "email")
        summary["email_security"] = em
    subs = osint.get("subdomains") or {}
    if subs.get("count"):
        names = subs.get("names") or []
        add("infra:subs", f"Subdomains · {subs['count']}",
            f"{subs['count']} names from certificate transparency"
            + (": " + ", ".join(names[:6]) + (" …" if len(names) > 6 else "") if names else ""),
            "dns")
        summary["subdomains"] = subs.get("count")
    reg = osint.get("registration") or {}
    if reg.get("registrar") and not reg.get("error"):
        add("infra:registrar", f"Registrar · {reg['registrar']}",
            f"Registered {reg.get('registration') or '?'} · expires {reg.get('expiration') or '?'}",
            "registration")
        summary["registrar"] = reg["registrar"]
    ports = (osint.get("ports") or {}).get("open") or []
    if ports:
        add("infra:ports", f"Open ports · {len(ports)}",
            "TCP connect: " + ", ".join(f"{p['port']}/{p.get('service','?')}" for p in ports[:8]),
            "ports")
        summary["open_ports"] = [p["port"] for p in ports]
    robots = ((osint.get("files") or {}).get("robots")) or {}
    if robots.get("present"):
        dis = robots.get("disallow") or []
        add("infra:robots", f"robots.txt · {len(dis)} disallow",
            ("Disallow: " + ", ".join(dis[:6])) if dis else "robots.txt present, no Disallow rules",
            "http")
    arch = osint.get("archive") or {}
    if arch.get("archived"):
        add("infra:archive", "Wayback snapshot", f"Last archived {arch.get('last_snapshot')}", "http")
    summary["technology"] = [t.get("name") if isinstance(t, dict) else t
                             for t in (osint.get("technology") or [])]
    return nodes, edges, summary


def build_payload(m: Model, osint: dict | None = None, lens: str = "attention") -> dict:
    data = to_dict(m)
    nodes = {n["id"]: n for n in data["nodes"]}
    params = _params_index(m)

    refs_in: dict[str, list[str]] = {}      # endpoint id -> script/route labels referencing it
    calls_in: dict[str, list[str]] = {}     # endpoint id -> route labels calling it (OBSERVED)
    script_refs: dict[str, list[str]] = {}  # script id -> endpoint labels
    route_calls: dict[str, list[str]] = {}  # route id -> endpoint labels
    route_scripts: dict[str, list[str]] = {}
    tp_refs: dict[str, list[str]] = {}      # third_party id -> referrer labels
    auth_eps: dict[str, list[str]] = {}     # auth id -> endpoint labels
    for e in data["edges"]:
        src, dst = nodes.get(e["src"]), nodes.get(e["dst"])
        if not src or not dst:
            continue
        if e["type"] == "REFERENCES":
            if dst["type"] == "endpoint":
                refs_in.setdefault(dst["id"], []).append(src["label"])
                if src["type"] == "script":
                    script_refs.setdefault(src["id"], []).append(dst["label"])
            elif dst["type"] == "third_party":
                tp_refs.setdefault(dst["id"], []).append(src["label"])
        elif e["type"] == "CALLS" and dst["type"] == "endpoint":
            calls_in.setdefault(dst["id"], []).append(src["label"])
            route_calls.setdefault(src["id"], []).append(dst["label"])
        elif e["type"] == "INCLUDES" and dst["type"] == "script":
            route_scripts.setdefault(src["id"], []).append(dst["label"])
        elif e["type"] == "SENT_CREDENTIAL" and src["type"] == "endpoint":
            auth_eps.setdefault(dst["id"], []).append(src["label"])

    def uniq(xs):
        return sorted(set(xs))

    endpoints = []
    for n in data["nodes"]:
        if n["type"] != "endpoint":
            continue
        a = n["attrs"]
        endpoints.append({
            "id": n["id"], "label": n["label"], "method": a.get("method") or "*",
            "host": a.get("host"), "path": a.get("path"), "state": a.get("api_state"),
            "statuses": a.get("statuses") or [], "status_by_role": a.get("status_by_role") or {},
            "credentials": a.get("credentials") or [], "roles": n["roles"],
            "anon": bool(a.get("anonymous_requests") and a.get("credentials")),
            "requests": a.get("requests", 0), "params": params.get(n["id"], []),
            "referenced_by": uniq(refs_in.get(n["id"], [])),
            "called_from": uniq(calls_in.get(n["id"], [])),
            "privileged": bool(PRIV_RE.search(a.get("path", "") or "")),
            "evidence": n["evidence"],
        })

    routes = [{
        "id": n["id"], "label": n["label"], "host": n["attrs"].get("host"),
        "statuses": n["attrs"].get("statuses") or [], "roles": n["roles"],
        "calls": uniq(route_calls.get(n["id"], [])),
        "scripts": uniq(route_scripts.get(n["id"], [])), "evidence": n["evidence"],
    } for n in data["nodes"] if n["type"] == "route"]

    scripts = [{
        "id": n["id"], "label": n["label"], "host": n["attrs"].get("host"),
        "scope": n["attrs"].get("scope"), "references": uniq(script_refs.get(n["id"], [])),
        "evidence": n["evidence"],
    } for n in data["nodes"] if n["type"] == "script"]

    third_parties = [{
        "id": n["id"], "label": n["label"], "requests": n["attrs"].get("requests", 0),
        "referenced_by": uniq(tp_refs.get(n["id"], [])), "evidence": n["evidence"],
    } for n in data["nodes"] if n["type"] == "third_party"]

    auth = [{"id": n["id"], "label": n["label"],
             "endpoints": uniq(auth_eps.get(n["id"], []))}
            for n in data["nodes"] if n["type"] == "auth"]
    cookies = [{"name": n["label"], "httponly": n["attrs"].get("httponly"),
                "secure": n["attrs"].get("secure"), "samesite": n["attrs"].get("samesite"),
                "evidence": n["evidence"]}
               for n in data["nodes"] if n["type"] == "cookie"]
    operations = [{"label": n["label"], "evidence": n["evidence"], "roles": n["roles"]}
                  for n in data["nodes"] if n["type"] == "operation"]
    hosts = [{"label": n["label"], "schemes": n["attrs"].get("schemes"),
              "ports": n["attrs"].get("ports"), "tech": n["attrs"].get("tech") or {},
              "evidence": n["evidence"]}
             for n in data["nodes"] if n["type"] == "host"]

    unknowns = [{"type": u["type"],
                 "entity": nodes[u["entity"]]["label"] if u["entity"] in nodes
                 else u["entity"].split(":")[-1],
                 "we_know": u["we_know"], "we_dont_know": u["we_dont_know"],
                 "next": u["next_step"]} for u in data["unknowns"]]

    graph = {
        "nodes": [{"id": n["id"], "label": n["label"], "type": n["type"],
                   "layer": n["layer"], "state": n["attrs"].get("api_state"),
                   "evidence": n["evidence"][:6]} for n in data["nodes"]],
        "edges": [{"s": e["src"], "d": e["dst"], "type": e["type"], "state": e["state"]}
                  for e in data["edges"]],
    }
    # primary host = the busiest first-party host, not merely the first one
    primary = max(hosts, key=lambda h: len(h.get("evidence") or []), default=None)
    primary = primary["label"] if primary else None
    node_ids = {n["id"] for n in graph["nodes"]}
    o_nodes, o_edges, o_summary = _osint_graph(osint, primary, node_ids)
    graph["nodes"].extend(o_nodes)
    graph["edges"].extend(o_edges)

    return {
        "tool": "burp2model", "version": __version__, "schema": SCHEMA_VERSION,
        "generated": (time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime(int(os.environ["SOURCE_DATE_EPOCH"])))
                      if os.environ.get("SOURCE_DATE_EPOCH", "").isdigit()
                      else time.strftime("%Y-%m-%d %H:%M %Z")),
        "app": data["app"], "scope": data["scope"], "roles": data["roles"],
        "counts": data["counts"], "stats": data.get("stats", {}),
        "hosts": hosts, "routes": routes, "scripts": scripts, "endpoints": endpoints,
        "operations": operations, "third_parties": third_parties, "auth": auth,
        "cookies": cookies, "secrets": data["secrets"], "unknowns": unknowns,
        "graph": graph,
        "stack": m.stack,
        "context": context_package(m, lens=lens, osint=osint),
        "methodology": {"prompt": METHODOLOGY_PROMPT, "scaffold": investigation_plan(m)},
        "osint": o_summary,
        "evidence": {f"ev_{e['id']}": e for e in data.get("evidence", [])},
    }


def write_html_report(m: Model, path: str, osint: dict | None = None,
                      lens: str = "attention", db_path: str | None = None,
                      screenshot: tuple[str, bytes] | None = None) -> None:
    payload = build_payload(m, osint=osint, lens=lens)
    if screenshot:
        from . import shot
        payload["screenshot"] = shot.data_uri(*screenshot)
    if db_path:
        # the in-page query console reads the same graph.db the CLI queries
        from . import store
        conn = store.open_db(db_path)
        try:
            payload["bql"] = store.export_for_report(conn)
        finally:
            conn.close()
    html = (_TEMPLATE.replace("__BQLJS__", BQL_JS)
            .replace("__DASHCSS__", DASH_CSS).replace("__DASHJS__", DASH_JS)
            .replace("__RRCSS__", RR_CSS).replace("__PGCSS__", PG_CSS).replace("__PGJS__", PG_JS).replace("__RRJS__", RR_JS).replace("__INVCSS__", INV_CSS).replace("__INVJS__", INV_JS)
            .replace("__QRYCSS__", QRY_CSS).replace("__QRYJS__", QRY_JS)
            .replace("__MAPCSS__", MAP_CSS).replace("__TYPECSS__", TYPE_CSS).replace("__FONTCSS__", font_css()).replace("__MAPJS__", MAP_JS)
            .replace("__DATA__", _safe_json(payload)))
    with open(path, "w", encoding="utf-8") as f:
        f.write(html)


_TEMPLATE = r"""<!doctype html>
<html lang="en" data-theme="light">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; img-src data:; font-src data:">
<meta name="color-scheme" content="light dark">
<link rel="icon" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 32 32'%3E%3Cpath d='M6 21.5 16 26l10-4.5' fill='none' stroke='%230e8fd6' stroke-width='2.2' stroke-linecap='round' stroke-linejoin='round'/%3E%3Cpath d='M6 16.5 16 21l10-4.5' fill='none' stroke='%237a5cff' stroke-width='2.2' stroke-linecap='round' stroke-linejoin='round'/%3E%3Cpath d='M16 6 6 10.5 16 15l10-4.5z' fill='%23e85002'/%3E%3C/svg%3E">
<title>burp2model report</title>
<style>
__FONTCSS__
:root{
--ink:#fff;--panel:#fff;--panel2:#f7f8fa;--panel3:#fafbfc;--line:#e7eaef;--line2:#cfd5dd;
--text:#141924;--muted:#6b7580;--faint:#98a1ac;--signal:#e85002;--signal-soft:#fdece3;
--observed:#0e8fd6;--inferred:#7a5cff;--ok:#0fa79a;--warn:#c9820a;--bad:#d64545;--hot:#e85002;
--l1:#7a8794;--l2:#0fa79a;--l3:#7a5cff;--l4:#0e8fd6;--l5:#3a424e;--l6:#e85002;
--mono:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;
--sans:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;
--shadow:0 8px 30px -12px rgba(20,25,36,.22);--radius:12px;
}
html[data-theme="dark"]{
--ink:#0c0f14;--panel:#11151c;--panel2:#141922;--panel3:#0f131a;--line:#222a36;--line2:#2e3846;
--text:#e6edf3;--muted:#93a0b0;--faint:#5f6b7a;--signal:#ff6a1a;--signal-soft:#2a1608;
--observed:#39d0ff;--inferred:#a594ff;--ok:#3fd6c3;--warn:#e2b23c;--bad:#ff6b6b;--hot:#ff6a1a;
--l1:#8a97a6;--l2:#3fd6c3;--l3:#a594ff;--l4:#39d0ff;--l5:#c0cad6;--l6:#ff6a1a;
--shadow:0 12px 40px -16px rgba(0,0,0,.7);
}
*{box-sizing:border-box}
html,body{margin:0;height:100%}
body{background:var(--ink);color:var(--text);font:14px/1.55 var(--sans);-webkit-font-smoothing:antialiased}
a{color:var(--signal);text-decoration:none}
.mono{font-family:var(--mono)}
button{font:inherit;cursor:pointer;color:inherit}
::selection{background:var(--signal);color:#fff}
:focus-visible{outline:2px solid var(--signal);outline-offset:2px;border-radius:6px}

/* header */
header{position:sticky;top:0;z-index:40;display:flex;align-items:center;gap:16px;height:58px;
padding:0 18px;background:var(--panel);border-bottom:1px solid var(--line)}
.logo{display:flex;align-items:center;gap:9px;font:700 15px var(--mono);letter-spacing:-.02em;white-space:nowrap}
.logo b{color:var(--signal)}
.logo svg{width:26px;height:26px}
.crumbs{color:var(--muted);font:12px var(--mono);white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.crumbs b{color:var(--text)}
.search{margin-left:auto;position:relative;flex:0 1 340px}
.search input{width:100%;height:36px;padding:0 12px 0 34px;border:1px solid var(--line2);border-radius:9px;
background:var(--panel2);color:var(--text);font:13px var(--sans)}
.search svg{position:absolute;left:10px;top:9px;width:16px;height:16px;color:var(--faint)}
.hbtn{display:inline-grid;place-items:center;width:34px;height:34px;border:1px solid var(--line);border-radius:8px;background:var(--panel2)}
.hbtn:hover{border-color:var(--line2)}
.hbtn svg{width:16px;height:16px}
.copyai{position:relative;display:flex}
.btnai{display:inline-flex;align-items:center;gap:7px;height:34px;padding:0 12px;border:1px solid var(--signal);border-radius:8px 0 0 8px;background:var(--signal);color:#fff;font:600 13px var(--sans);white-space:nowrap}
.btnai:hover{filter:brightness(1.06)}
.btnai svg{width:15px;height:15px}
.btnai .tok{font:600 10px var(--mono);opacity:.85;padding-left:4px;border-left:1px solid rgba(255,255,255,.35);margin-left:2px}
.btnai.split{padding:0 8px;border-left:1px solid rgba(255,255,255,.35);border-radius:0 8px 8px 0;font-size:11px}
.btnai.done{background:var(--ok);border-color:var(--ok)}
.menu{position:absolute;top:40px;right:0;min-width:240px;background:var(--panel);border:1px solid var(--line);border-radius:10px;box-shadow:var(--shadow);padding:6px;z-index:60}
.menu button{display:flex;flex-direction:column;gap:2px;width:100%;text-align:left;padding:8px 10px;border:0;border-radius:7px;background:none;color:var(--text)}
.menu button:hover{background:var(--panel2)}
.menu button b{font:600 13px var(--sans)}
.menu button span{color:var(--muted);font-size:11.5px}
.menu button .tk{color:var(--faint);font:600 10px var(--mono)}
.htheme .sun{display:none}html[data-theme="dark"] .htheme .sun{display:block}html[data-theme="dark"] .htheme .moon{display:none}

/* shell */
.shell{display:grid;grid-template-columns:212px minmax(0,1fr);height:calc(100% - 58px)}
nav.views{border-right:1px solid var(--line);background:var(--panel);padding:14px 10px;overflow:auto}
nav.views h3{font:600 10px var(--mono);letter-spacing:.13em;text-transform:uppercase;color:var(--faint);margin:14px 8px 6px}
nav.views h3:first-child{margin-top:0}
.vbtn{display:flex;align-items:center;gap:9px;width:100%;padding:8px 10px;border:0;border-radius:8px;background:none;
color:var(--muted);font:500 13.5px var(--sans);text-align:left;margin-bottom:1px}
.vbtn:hover{background:var(--panel2);color:var(--text)}
.vbtn.on{background:var(--signal-soft);color:var(--signal);font-weight:600}
.vbtn .ct{margin-left:auto;font:600 11px var(--mono);color:var(--faint);background:var(--panel2);padding:1px 7px;border-radius:999px}
.vbtn.on .ct{color:var(--signal);background:#fff}
html[data-theme="dark"] .vbtn.on .ct{background:var(--panel3)}
.vbtn .dot{width:8px;height:8px;border-radius:2px;flex:none}

main{overflow:auto;padding:26px 32px 60px;min-width:0}
.view{display:none}
.view.on{display:block;animation:fade .2s ease}
@keyframes fade{from{opacity:0;transform:translateY(4px)}to{opacity:1}}
h1.vt{font:700 24px/1.2 var(--sans);letter-spacing:-.02em;margin:0 0 4px}
.vsub{color:var(--muted);margin:0 0 20px;max-width:80ch}

/* kpis */
.kpis{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:12px;margin-bottom:22px}
.kpi{background:var(--panel);border:1px solid var(--line);border-radius:var(--radius);padding:14px 16px}
.kpi .n{font:700 28px var(--sans);letter-spacing:-.02em;line-height:1}
.kpi .k{color:var(--muted);font-size:12px;margin-top:5px}
.kpi.sig .n{color:var(--signal)}
.kpi.ok .n{color:var(--ok)}

/* cards + tables */
.card{background:var(--panel);border:1px solid var(--line);border-radius:var(--radius);margin-bottom:18px;overflow:hidden}
.card>.hd{display:flex;align-items:center;gap:10px;padding:13px 16px;border-bottom:1px solid var(--line);font:600 13px var(--sans)}
.card>.hd .ct{color:var(--faint);font:600 11px var(--mono)}
.card>.bd{padding:6px 0}
table{width:100%;border-collapse:collapse;font-size:13px}
th{position:sticky;top:0;text-align:left;font:600 11px var(--mono);letter-spacing:.04em;text-transform:uppercase;
color:var(--muted);background:var(--panel2);padding:9px 14px;border-bottom:1px solid var(--line);cursor:pointer;white-space:nowrap}
th .ar{opacity:.4;font-size:9px}
td{padding:9px 14px;border-bottom:1px solid var(--line);vertical-align:middle}
tr:last-child td{border-bottom:0}
tbody tr{cursor:pointer}
tbody tr:hover{background:var(--panel2)}
.trunc{max-width:420px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.empty{padding:26px 16px;color:var(--faint);text-align:center;font-size:13px}

/* pills */
.pill{display:inline-flex;align-items:center;gap:5px;font:600 11px var(--mono);padding:2px 8px;border-radius:999px;
border:1px solid currentColor;white-space:nowrap}
.p-both{color:var(--ok)}.p-static{color:var(--inferred)}.p-runtime{color:var(--observed)}
.p-get{color:var(--muted)}.p-post,.p-put,.p-patch,.p-delete{color:var(--signal)}
.m{font:600 11px var(--mono);padding:2px 7px;border-radius:6px;background:var(--panel2);color:var(--muted)}
.m.w{color:var(--signal);background:var(--signal-soft)}
.st{font:600 11px var(--mono);padding:1px 6px;border-radius:5px;background:var(--panel2)}
.st.g{color:var(--ok)}.st.r{color:var(--bad)}.st.y{color:var(--warn)}
.chipwrap{display:flex;flex-wrap:wrap;gap:6px}
.chip{display:inline-flex;align-items:center;gap:6px;font:500 12px var(--sans);padding:5px 11px;border-radius:999px;
border:1px solid var(--line2);background:var(--panel);color:var(--muted)}
.chip:hover{border-color:var(--faint);color:var(--text)}
.chip.on{background:var(--text);color:var(--ink);border-color:var(--text)}
.chip .c{font:600 11px var(--mono);opacity:.7}
.filters{display:flex;flex-wrap:wrap;gap:16px;align-items:flex-start;margin-bottom:16px}
.fg{display:flex;flex-direction:column;gap:6px}
.fg>.lab{font:600 10px var(--mono);letter-spacing:.1em;text-transform:uppercase;color:var(--faint)}

/* priorities */
.prio{display:flex;gap:14px;padding:14px 16px;border:1px solid var(--line);border-left:3px solid var(--sev);border-radius:10px;
background:var(--panel);margin-bottom:10px;cursor:pointer}
.prio:hover{border-color:var(--line2)}
.prio .rank{font:700 13px var(--mono);color:var(--sev);flex:none;width:22px}
.prio .body{min-width:0;flex:1}
.prio .ttl{font:600 14px var(--sans);display:flex;align-items:center;gap:8px;flex-wrap:wrap}
.prio .why{color:var(--muted);font-size:13px;margin-top:3px}
.prio .nx{color:var(--text);font-size:12.5px;margin-top:6px}
.prio .nx b{color:var(--signal);font:600 10px var(--mono);letter-spacing:.06em;text-transform:uppercase;margin-right:6px}
.sev-hot{--sev:var(--signal)}.sev-warn{--sev:var(--warn)}.sev-info{--sev:var(--observed)}


/* query console */
.tag-ext{font:600 10px var(--mono);letter-spacing:.05em;color:var(--inferred);border:1px solid var(--inferred);border-radius:5px;padding:0 5px}
.icard{margin-bottom:14px}
.icard .bd{padding:0}
.icard td.k{width:190px;color:var(--muted);font:12px var(--mono)}
.icard td.v{font:12.5px var(--mono);overflow-wrap:anywhere}
.miss{color:var(--warn)}

/* unknowns list */
.unk{padding:14px 16px;border:1px solid var(--line);border-radius:10px;background:var(--panel);margin-bottom:10px}
.unk .ut{font:600 12px var(--mono);color:var(--signal);letter-spacing:.03em}
.unk .ue{font:600 14px var(--sans);margin:4px 0}
.unk ul{margin:6px 0 0;padding-left:18px;color:var(--muted);font-size:13px}
.unk .nx{margin-top:8px;font-size:12.5px}.unk .nx b{color:var(--signal);font:600 10px var(--mono);text-transform:uppercase;margin-right:6px}

/* matrix */
.matrix td,.matrix th{text-align:center}
.matrix td:first-child,.matrix th:first-child{text-align:left}
.cell{display:inline-block;min-width:42px;font:600 11px var(--mono);padding:2px 6px;border-radius:5px}
.cell.hit{background:var(--signal-soft);color:var(--signal)}
.cell.miss{color:var(--faint)}

/* ask (AI-off query) */
.askbar{position:relative;margin-bottom:14px}
.askbar input{width:100%;height:52px;padding:0 18px 0 46px;border:1px solid var(--line2);border-radius:12px;background:var(--panel);color:var(--text);font:16px var(--sans)}
.askbar input:focus{border-color:var(--signal);outline:none}
.askbar svg{position:absolute;left:16px;top:17px;width:18px;height:18px;color:var(--faint)}
.presets{display:flex;flex-wrap:wrap;gap:8px;margin-bottom:20px}
.preset{font:500 13px var(--sans);padding:7px 13px;border-radius:999px;border:1px solid var(--line2);background:var(--panel);color:var(--muted)}
.preset:hover{border-color:var(--faint);color:var(--text)}
.answer .ahd{font:600 15px var(--sans);margin:0 0 12px}
.answer .arow{display:flex;align-items:center;gap:10px;padding:10px 14px;border:1px solid var(--line);border-radius:9px;margin-bottom:7px;cursor:pointer}
.answer .arow:hover{border-color:var(--line2);background:var(--panel2)}
.answer .arow .p{flex:1;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.answer .arow .ev{font:600 11px var(--mono);color:var(--faint)}
.answer .note{color:var(--muted);font-size:14px;margin:0 0 14px;max-width:70ch}
.askfoot{display:inline-flex;align-items:center;gap:8px;margin-top:16px;padding:7px 12px;border-radius:999px;background:var(--panel2);border:1px solid var(--line);color:var(--muted);font:500 12.5px var(--sans)}
.askfoot::before{content:"";width:8px;height:8px;border-radius:50%;background:var(--ok)}

/* drawer */
.scrim{position:fixed;inset:0;background:rgba(20,25,36,.35);opacity:0;visibility:hidden;transition:.18s;z-index:50}
.scrim.on{opacity:1;visibility:visible}
.drawer{position:fixed;top:0;right:0;height:100%;width:min(720px,94vw);background:var(--panel);border-left:1px solid var(--line);
box-shadow:var(--shadow);transform:translateX(100%);transition:transform .22s cubic-bezier(.4,0,.2,1);z-index:51;display:flex;flex-direction:column}
.drawer.on{transform:none}
.drawer .dh{display:flex;align-items:center;gap:10px;padding:16px 18px;border-bottom:1px solid var(--line)}
.drawer .dh .x{margin-left:auto;width:30px;height:30px;border:1px solid var(--line);border-radius:7px;background:var(--panel2)}
.drawer .db{overflow:auto;padding:18px}
.drv{height:560px;border:1px solid var(--line);border-radius:10px;overflow:hidden}
.drawer h4{font:600 10px var(--mono);letter-spacing:.12em;text-transform:uppercase;color:var(--faint);margin:20px 0 8px}
.drawer h4:first-child{margin-top:0}
.kv{display:grid;grid-template-columns:120px 1fr;gap:6px 12px;font-size:13px}
.kv .k{color:var(--muted)}
.kv .v{word-break:break-word}
.taglist{display:flex;flex-wrap:wrap;gap:6px}
.taglist span{font:500 12px var(--mono);padding:3px 8px;border-radius:6px;background:var(--panel2);color:var(--text)}
.foot{color:var(--faint);font-size:12px;border-top:1px solid var(--line);padding:16px 0 0;margin-top:24px}
.callout{display:flex;gap:12px;padding:13px 15px;border:1px solid var(--line);border-radius:10px;background:var(--panel2);margin-bottom:18px}
.callout .i{color:var(--signal);font:700 13px var(--mono);flex:none}
.callout p{margin:0;color:var(--muted);font-size:13px}
.hide{display:none!important}

/* stacked distribution bars (overview) */
.segbar{display:flex;height:10px;border-radius:999px;overflow:hidden;background:var(--panel2);margin:10px 0 8px}
.segbar span{display:block;height:100%}
.seglegend{display:flex;flex-wrap:wrap;gap:14px;font-size:12px;color:var(--muted)}
.seglegend .k{display:inline-flex;align-items:center;gap:6px}
.seglegend .sw{width:9px;height:9px;border-radius:3px}
.seglegend b{color:var(--text);font:600 12px var(--mono)}

/* grouped priority signals */
.prio .sig{display:flex;gap:8px;color:var(--muted);font-size:13px;margin-top:5px;align-items:baseline}
.prio .sig::before{content:"›";color:var(--sev);font-weight:700;flex:none}
.prio .sig b{color:var(--text);font-weight:600}

__DASHCSS__
__RRCSS__
__PGCSS__
__INVCSS__
__QRYCSS__
__MAPCSS__
__TYPECSS__
@media(max-width:820px){
 .shell{display:flex;flex-direction:column;height:auto}
 nav.views{display:flex;gap:2px;overflow-x:auto;border-right:0;border-bottom:1px solid var(--line);padding:8px 10px;white-space:nowrap}
 nav.views h3{display:none}
 .vbtn{width:auto;flex:none}
 main{padding:16px}.search{flex-basis:150px}.crumbs{display:none}
 body{height:auto}html{height:auto}
}
@media print{header,nav.views,.search,.hbtn,.scrim,.drawer{display:none!important}.shell{display:block}.view{display:block!important;page-break-after:always}main{overflow:visible}}
</style>
</head>
<body>
<header>
  <div class="logo"><svg viewBox="0 0 32 32" aria-hidden="true"><path d="M6 21.5 16 26l10-4.5" fill="none" stroke="var(--observed)" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"/><path d="M6 16.5 16 21l10-4.5" fill="none" stroke="var(--inferred)" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"/><path d="M16 6 6 10.5 16 15l10-4.5z" fill="var(--signal)"/></svg><span>burp<b>2</b>model</span></div>
  <div class="crumbs" id="crumbs"></div>
  <div class="search"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="11" cy="11" r="7"/><path d="M21 21l-4.3-4.3"/></svg>
    <input id="q" type="search" placeholder="Search endpoints, hosts, params, evidence…" aria-label="Search"></div>
  <div class="copyai">
    <button class="btnai" id="copyai"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="9" y="9" width="11" height="11" rx="2"/><path d="M5 15V5a2 2 0 0 1 2-2h10"/></svg><span>Copy for AI</span><span class="tok" id="copytok"></span></button>
    <button class="btnai split" id="copymenu" aria-label="Copy scope" aria-haspopup="true">▾</button>
    <div class="menu" id="copyopts" role="menu" hidden></div>
  </div>
  <button class="hbtn htheme" id="theme" title="Toggle theme" aria-label="Toggle theme"><svg class="moon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 12.8A9 9 0 1 1 11.2 3a7 7 0 0 0 9.8 9.8z"/></svg><svg class="sun" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4"/></svg></button>
  <button class="hbtn" id="print" title="Print / PDF" aria-label="Print"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M6 9V3h12v6M6 18H4a2 2 0 0 1-2-2v-3a2 2 0 0 1 2-2h16a2 2 0 0 1 2 2v3a2 2 0 0 1-2 2h-2M6 14h12v7H6z"/></svg></button>
  <button class="hbtn" id="export" title="Export model.json" aria-label="Export JSON"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 3v12M7 10l5 5 5-5M5 21h14"/></svg></button>
</header>
<div class="shell">
  <nav class="views" id="nav"></nav>
  <main id="main"></main>
</div>
<div class="scrim" id="scrim"></div>
<aside class="drawer" id="drawer" aria-hidden="true"><div class="dh"><span id="dtitle" style="font-weight:600"></span><button class="x" id="dclose" aria-label="Close">✕</button></div><div class="db" id="dbody"></div></aside>

<script>
const D = __DATA__;
__BQLJS__
const BQLDB=D.bql?Object.assign({},D.bql,{requests:BQL.requestsFrom(D.evidence)}):null;
const $=(s,r)=>(r||document).querySelector(s), $$=(s,r)=>[...(r||document).querySelectorAll(s)];
const esc=s=>String(s==null?"":s).replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
const PRIV=/\/(admin|administrator|internal|manage|management|config|privileged|superuser|staff|root|debug|actuator|console|backoffice|ops)(\/|$)/i;
/* turn the model's ALL_CAPS_TOKENS into readable text, keeping known acronyms.
   Only ever applied to the tool's own vocabulary — never to paths/hosts/params. */
const ACR=new Set(["API","URL","URI","TLS","SSL","DNS","JWT","OTP","HTTP","HTTPS","CORS","SPF","DKIM","DMARC","ID","JS","HTML","CSS","IP","RDAP","SAN","CDN","XSS","CSRF","SSO","MFA","2FA","PII","GET","POST","PUT","PATCH","DELETE","HEAD"]);
function humanize(t){if(t==null)return"";return String(t).split(/[_\s]+/).map((w,i)=>{const u=w.toUpperCase();if(ACR.has(u))return u;const l=w.toLowerCase();return i===0?l.charAt(0).toUpperCase()+l.slice(1):l;}).join(" ");}
const c=D.counts, EP=D.endpoints;
const EVD=i=>"EVD "+i;
document.title=(D.app?D.app+" · ":"")+"burp2model report";

/* theme (persist per-viewer, fail-safe) */
try{const t=localStorage.getItem("b2m-report-theme");if(t)document.documentElement.setAttribute("data-theme",t);}catch(e){}
$("#theme").onclick=()=>{const n=document.documentElement.getAttribute("data-theme")==="dark"?"light":"dark";document.documentElement.setAttribute("data-theme",n);try{localStorage.setItem("b2m-report-theme",n)}catch(e){}};
$("#print").onclick=()=>window.print();
$("#export").onclick=()=>{const b=new Blob([JSON.stringify(D,null,2)],{type:"application/json"});const u=URL.createObjectURL(b);const a=document.createElement("a");a.href=u;a.download=(D.app||"model")+".burp2model.json";a.click();URL.revokeObjectURL(u);};
$("#crumbs").innerHTML=`<b>${esc(D.app)}</b> · scope ${esc((D.scope||[]).join(", ")||"—")} · ${esc(D.version)}`;

/* ---------- Copy for AI (hands the context to the user's own model) ---------- */
const CTX=D.context||{};
const PROMPT=[
"You are a senior application security researcher. Below is an evidence-backed model of a single web application, built from traffic that was actually captured. It is structure, not raw bytes. Reason only from it.",
"",
"The model includes a `graph`: an `adjacency` map (each node id -> the nodes it points to, with the edge type and whether it was OBSERVED in traffic or INFERRED from code), plus derived reasoning views — `communities` (functional areas), `execution_flows` (how each endpoint is reached from an entry point), `trust_zones` (how identity reaches the surface), `hubs` and `coupling`. Walk the graph to understand how the app fits together before you judge any one part.",
"",
"Ground rules:",
"- Cite the evidence id(s) — ev_N — for every claim. The `evidence` map resolves each one to a real request.",
"- Never name an endpoint, parameter, route, host or cookie that is not in the model, and never assert an edge the graph does not contain.",
"- Everything you produce is a hypothesis to verify safely, never a finding, an exploit or a payload. The goal is to understand the app deeply, not to attack it.",
"- An absence in the model is an absence in the capture, not proof of absence in the target. `inferred` means found in code, not confirmed called.",
"",
"Do this:",
"",
"1. ATTACK SURFACE — group the endpoints by function (authentication, payments / gift cards, account, admin, catalog, config, etc.). For each endpoint give: method + path, its parameters, whether a credential was seen on it, the statuses observed, and which host / trust boundary it sits behind. Flag anything reached without a credential and anything on a privileged-looking path.",
"",
"2. WHERE TO HUNT — a prioritised list, highest value first, of what to test and why. For each item name the endpoint or parameter, the evidence that makes it interesting, the specific issue class worth checking (BOLA / IDOR, broken auth or missing authorization, injection, SSRF, business-logic / price or balance tampering, secrets, mass assignment), and the single next request or two-account comparison that would confirm or kill it. Prefer what the evidence supports over generic OWASP advice. Give me the shortlist I should spend my time on.",
"",
"3. OPEN QUESTIONS — restate each unknown the model lists and the exact capture or request needed to close it.",
"",
"4. WHAT STAYS UNCERTAIN — and why this capture cannot answer it.",
].join("\n");
const METH=D.methodology||{};
function buildCopy(scope){
  let obj, note;
  if(scope==="methodology"){
    // a distinct prompt: turn the model + scaffold into a target-specific methodology
    const obj={app:CTX.app,scope:CTX.scope,shape:CTX.shape,plan_scaffold:METH.scaffold,
      graph:CTX.graph,endpoints:CTX.endpoints,unknowns:CTX.unknowns,evidence:CTX.evidence};
    return [(METH.prompt||[]).join("\n"),"","MODEL AND SCAFFOLD (JSON):","```json",JSON.stringify(obj,null,2),"```"].join("\n");
  }
  if(scope==="endpoints"){obj={app:CTX.app,scope:CTX.scope,endpoints:CTX.endpoints,evidence:CTX.evidence};note="endpoints and evidence only";}
  else if(scope==="open"){obj={app:CTX.app,unknowns:CTX.unknowns,endpoints:CTX.endpoints,evidence:CTX.evidence};note="open questions, with endpoints for context";}
  else if(scope==="graph"){obj={app:CTX.app,scope:CTX.scope,shape:CTX.shape,graph:CTX.graph,evidence:CTX.evidence};note="reasoning graph — adjacency and derived views";}
  else{obj=CTX;note="whole model";}
  return [PROMPT,"",`MODEL (${note}, JSON):`,"```json",JSON.stringify(obj,null,2),"```"].join("\n");
}
function doCopy(scope,btn){
  const text=buildCopy(scope);
  const done=()=>{const b=$("#copyai");b.classList.add("done");$("#copyai span").textContent="Copied";setTimeout(()=>{b.classList.remove("done");$("#copyai span").textContent="Copy for AI";},1500);$("#copyopts").hidden=true;};
  if(navigator.clipboard&&navigator.clipboard.writeText)navigator.clipboard.writeText(text).then(done,()=>fallbackCopy(text,done));
  else fallbackCopy(text,done);
}
function fallbackCopy(text,done){const ta=document.createElement("textarea");ta.value=text;ta.style.position="fixed";ta.style.opacity="0";document.body.append(ta);ta.select();try{document.execCommand("copy");done();}catch(e){}ta.remove();}
$("#copytok").textContent="~"+Math.max(1,Math.round((CTX.token_estimate||0)/1000))+"k tok";
$("#copyai").onclick=()=>doCopy("whole");
const OPTS=[["methodology","Hunting methodology","have the AI reason a recon & hunting plan for THIS app, not a checklist",null],
  ["whole","Whole model","everything an AI needs, with the rules",CTX.token_estimate],
  ["graph","Reasoning graph","adjacency + communities, flows, trust zones, for the AI to traverse",null],
  ["endpoints","Endpoints only","the API surface with parameters and evidence",null],
  ["open","Open questions only","what to test next, for a focused prompt",null]];
$("#copyopts").innerHTML=OPTS.map(([k,t,d,tok])=>`<button role="menuitem" data-scope="${k}"><b>${esc(t)}</b><span>${esc(d)}${tok?` · ~${Math.round(tok/1000)}k tok`:""}</span></button>`).join("");
$("#copymenu").onclick=e=>{e.stopPropagation();$("#copyopts").hidden=!$("#copyopts").hidden;};
$$("#copyopts button").forEach(b=>b.onclick=()=>doCopy(b.dataset.scope));
document.addEventListener("click",e=>{if(!e.target.closest(".copyai"))$("#copyopts").hidden=true;});

/* ---------- priority scoring: "the important stuff" ----------
   One card per endpoint. Each matching signal is listed on the card; the
   card's severity is the strongest signal's. */
const SEV_RANK={hot:0,warn:1,info:2};
function signalsFor(e){
  const sig=[];
  if(e.state==="STATIC_ONLY") sig.push({sev:"hot",ttl:"Referenced in code, never called",
    why:"The client code names this endpoint but no request to it was captured, so nobody has walked this path.",
    next:"Request it directly in an authorised session and observe the response."});
  if(e.privileged&&e.requests>0) sig.push({sev:"hot",ttl:"Privileged-looking path was reached",
    why:"The path matches an admin/internal pattern and appears in the capture"+(e.roles.length?` (roles: ${e.roles.join(", ")})`:"")+".",
    next:"Confirm the response was meant for the caller; replay across accounts."});
  else if(e.privileged) sig.push({sev:"hot",ttl:"Privileged-looking path referenced",
    why:"The path matches an admin/internal pattern; it was only referenced in code, never requested.",
    next:"Request it in an authorised session and observe who is allowed in."});
  const ss=e.statuses||[];
  if(ss.length&&ss.every(s=>s>=400)) sig.push({sev:"warn",ttl:"Only ever returned errors",
    why:`Every observed status was ${ss.join(", ")} so behaviour with valid input or auth has not been seen.`,
    next:"Exercise the feature normally in an authorised session."});
  if(e.anon) sig.push({sev:"warn",ttl:"Seen with and without credentials",
    why:"Some requests carried a credential and some did not, so it is unclear whether auth is required.",
    next:"Replay it unauthenticated and compare the response."});
  if(e.requests>0&&e.method!=="*"&&e.method!=="GET"&&e.method!=="HEAD"&&!e.credentials.length)
    sig.push({sev:"info",ttl:"State-changing call without an observed credential",
      why:`A ${e.method} request with no credential seen on it.`,
      next:"Check whether it is meant to require authentication."});
  return sig;
}
function priorities(){
  const out=[];
  EP.forEach(e=>{
    const sig=signalsFor(e);
    if(!sig.length)return;
    sig.sort((a,b)=>SEV_RANK[a.sev]-SEV_RANK[b.sev]);
    out.push({sev:sig[0].sev,ep:e,sig});
  });
  return out.sort((a,b)=>SEV_RANK[a.sev]-SEV_RANK[b.sev]||b.sig.length-a.sig.length||a.ep.label.localeCompare(b.ep.label));
}
const PRIO=priorities();

/* cookies missing flags → also priorities-worthy */
const weakCookies=(D.cookies||[]).filter(k=>!k.httponly||!k.secure);

/* ---------- views ---------- */
const hasRoles=(D.roles||[]).length>=2;
const VIEWS=[
  {id:"overview",name:"Overview",grp:"Start here",ct:()=>null},
  {id:"priorities",name:"To check",grp:"Start here",ct:()=>PRIO.length+weakCookies.length},
  {id:"graph",name:"Map",grp:"Start here",ct:()=>null},
  {id:"inventory",name:"Requests",grp:"Start here",ct:()=>EVL.length},
  {id:"ask",name:"Ask",grp:"Start here",ct:()=>null},
  {id:"reference",name:"Reference",grp:"Start here",ct:()=>null},
];
let view="overview", filters={method:new Set(),host:new Set(),role:new Set(),cred:new Set()}, sortKey="label", sortDir=1, query="";

function renderNav(){
  const nav=$("#nav");let html="",grp="";
  VIEWS.filter(v=>v.cond!==false).forEach(v=>{
    if(v.grp!==grp){grp=v.grp;html+=`<h3>${esc(grp)}</h3>`;}
    const n=v.ct();
    html+=`<button class="vbtn${v.id===view?" on":""}" data-v="${v.id}">${v.dot?`<span class="dot" style="background:${v.dot}"></span>`:""}${esc(v.name)}${n!=null?`<span class="ct">${n}</span>`:""}</button>`;
  });
  nav.innerHTML=html;
  $$(".vbtn",nav).forEach(b=>b.onclick=()=>{view=b.dataset.v;render();});
}

/* ---------- shared renderers ---------- */
function methodm(m){return `<span class="m ${m&&m!=='GET'&&m!=='*'?'w':''}">${esc(m||"*")}</span>`;}
function statuses(ss){if(!ss||!ss.length)return '<span class="st">—</span>';return ss.map(s=>{const cls=s>=500?"r":s>=400?"y":s>=200&&s<300?"g":"";return `<span class="st ${cls}">${s}</span>`;}).join(" ");}
function matchQ(e){if(!query)return true;const q=query.toLowerCase();return (e.label+" "+(e.host||"")+" "+(e.params||[]).join(" ")+" "+(e.referenced_by||[]).join(" ")).toLowerCase().includes(q);}

__DASHJS__
function prioCard(p,i){
  const e=p.ep, lead=p.sig[0];
  const more=p.sig.slice(1).map(s=>`<div class="sig"><span><b>${esc(s.ttl)}.</b> ${esc(s.why)}</span></div>`).join("");
  return `<div class="prio sev-${p.sev}" data-ep="${esc(e.id)}"><div class="rank">${i+1}</div><div class="body">
   <div class="ttl">${methodm(e.method)} <span class="mono">${esc(e.label.replace(/^\S+\s/,''))}</span> <span style="color:var(--muted);font-weight:400;font-size:13px">${esc(lead.ttl)}</span></div>
   <div class="why">${esc(lead.why)}</div>${more}<div class="nx"><b>Next</b> ${esc(lead.next)}</div></div></div>`;
}

/* ---------- ASK (answers from the model, no AI) ---------- */
const ARROW='<svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2" style="color:var(--faint)"><path d="M9 6l6 6-6 6"/></svg>';
function arow(e){return `<div class="arow" data-ep="${esc(e.id)}">${methodm(e.method)}<span class="p mono">${esc(e.path)}</span><span class="ev">${(e.evidence||[]).slice(0,2).map(EVD).join(", ")}</span>${ARROW}</div>`;}
function alist(title,note,rows){return {title,html:`<div class="answer">${note?`<p class="note">${note}</p>`:""}${rows.length?rows.join(""):'<div class="empty">Nothing in this model matches.</div>'}</div>`};}
function ans_endpoints(){const r=[...EP].sort((a,b)=>a.path.localeCompare(b.path));return alist("Endpoints",`The model holds <b>${r.length}</b> API endpoint${r.length===1?"":"s"}. Click any to see its parameters and the request that produced it.`,r.map(arow));}
function ans_incode(){const r=EP.filter(e=>e.state==="STATIC_ONLY").sort((a,b)=>a.path.localeCompare(b.path));return alist("Referenced in code, never called",r.length?`These URLs appear in the client code but no request to them was captured, unwalked paths worth trying.`:`Every endpoint referenced in the code was also seen in traffic.`,r.map(arow));}
function ans_errors(){const r=EP.filter(e=>e.statuses.length&&e.statuses.every(s=>s>=400)).sort((a,b)=>a.path.localeCompare(b.path));return alist("Only ever returned errors",r.length?`Every response captured for these was 4xx/5xx, their behaviour with valid input and auth is unseen.`:`No endpoint returned only errors.`,r.map(arow));}
function ans_priv(){const r=EP.filter(e=>e.privileged).sort((a,b)=>a.path.localeCompare(b.path));return alist("Privileged-looking paths",r.length?`Paths that match an admin/internal pattern.`:`No privileged-looking paths in this capture.`,r.map(arow));}
function ans_thirdparty(){const r=(D.third_parties||[]);return {title:"Third parties",html:`<div class="answer"><p class="note">${r.length} host${r.length===1?"":"s"} outside the app's own domain, code you don't control running in your users' context.</p>${r.map(t=>`<div class="arow"><span class="p mono">${esc(t.label)}</span><span class="ev">${t.requests} req</span></div>`).join("")||'<div class="empty">None.</div>'}</div>`};}
function ans_auth(){const a=D.auth||[],k=D.cookies||[];return {title:"Authentication & cookies",html:`<div class="answer"><p class="note">How the app carries identity.</p>
  ${a.map(x=>`<div class="arow"><span class="p mono">${esc(x.label)}</span><span class="ev">${x.endpoints.length} endpoint${x.endpoints.length===1?"":"s"}</span></div>`).join("")}
  ${k.map(x=>{const miss=[!x.httponly&&"HttpOnly",!x.secure&&"Secure"].filter(Boolean);return `<div class="arow"><span class="p mono">cookie ${esc(x.name)}</span><span class="ev">${miss.length?"missing "+miss.join("+"):"HttpOnly+Secure"}</span></div>`;}).join("")}
  ${!a.length&&!k.length?'<div class="empty">No credentials or cookies observed.</div>':""}</div>`};}
function ans_unknowns(){return {title:"Open questions",html:`<div class="answer"><p class="note">What the capture could not answer.</p>${(D.unknowns||[]).map(u=>`<div class="arow"><span class="p">${esc(openTitle(u.type))}, <span class="mono" style="color:var(--muted)">${esc(u.entity)}</span></span></div>`).join("")||'<div class="empty">Nothing left open.</div>'}</div>`};}
function ans_endpoint(path){
  const q=path.toLowerCase();const hits=EP.filter(e=>e.path.toLowerCase().includes(q)).sort((a,b)=>a.path.length-b.path.length);
  if(!hits.length)return {title:"No such endpoint",html:`<div class="answer"><p class="note">Nothing in the model matches <span class="mono">${esc(path)}</span>. The model can only answer for endpoints it actually holds, that's the point.</p></div>`};
  return {title:"Endpoint",html:`<div class="answer">${hits.slice(0,6).map(e=>{
    const bits=[];if(e.statuses.length)bits.push("status "+e.statuses.join("/"));if(e.params.length)bits.push(e.params.length+" params");if(e.referenced_by.length)bits.push("referenced by "+e.referenced_by.join(", "));if(e.called_from.length)bits.push("called from "+e.called_from.join(", "));
    return `<div class="arow" data-ep="${esc(e.id)}">${methodm(e.method)}<span class="p mono">${esc(e.path)}</span>${ARROW}</div><p class="note" style="margin:-2px 0 12px 6px">${esc(bits.join(" · ")||"seen in traffic")}</p>`;}).join("")}</div>`};
}
function ans_shape(){const c2=D.counts;return {title:D.app,html:`<div class="answer"><p class="note"><b>${esc(D.app)}</b>, ${c2.hosts} host${c2.hosts===1?"":"s"}, ${c2.routes} route${c2.routes===1?"":"s"}, <b>${c2.endpoints} endpoints</b>, ${c2.parameters} parameters, ${c2.third_parties} third part${c2.third_parties===1?"y":"ies"}, ${c2.unknowns} open question${c2.unknowns===1?"":"s"}. Ask about any of them, or open the Map.</p></div>`};}
function askEngine(q){
  q=(q||"").toLowerCase().trim();
  if(!q)return ans_shape();
  const p=q.match(/\/[a-z0-9_\-{}\/.]+/i);if(p)return ans_endpoint(p[0]);
  if(/(in ?code|referenced|static).*(never|not|un).*(call|walk|use)|never called|unwalked|only in code/.test(q))return ans_incode();
  if(/error|fail|4\d\d|5\d\d|broken/.test(q))return ans_errors();
  if(/admin|privileg|internal|manage/.test(q))return ans_priv();
  if(/third|vendor|external|supply|dependen/.test(q))return ans_thirdparty();
  if(/auth|login|cookie|session|credential|token|sign ?in/.test(q))return ans_auth();
  if(/unknown|open question|couldn'?t|can'?t see|don'?t know|what.*miss|gap/.test(q))return ans_unknowns();
  if(/param|field|input|argument/.test(q)){const r=EP.filter(e=>e.params.length).sort((a,b)=>b.params.length-a.params.length);return alist("Endpoints with parameters",`Parameter <b>names</b> only, values were masked at capture.`,r.map(e=>`<div class="arow" data-ep="${esc(e.id)}">${methodm(e.method)}<span class="p mono">${esc(e.path)}</span><span class="ev">${e.params.length}</span>${ARROW}</div>`));}
  if(/endpoint|api|route|url|path|list|what.*(exist|there)|surface/.test(q))return ans_endpoints();
  return ans_shape();
}
__QRYJS__

/* ---------- INFRASTRUCTURE (external recon, stored in graph.db) ---------- */
function vInfra(){
  const B=D.bql;
  if(!B||!B.osint)return `<h1 class="vt">Infrastructure</h1><p class="vsub">External recon: DNS, certificates, subdomains, mail policy, headers.</p><div class="empty">No recon stored. Recon is opt-in: rebuild with <span class="mono">--osint</span>, or run <span class="mono">burp2model osint HOST -w ${esc(D.app)} --yes</span>.</div>`;
  const by={};(B.facts||[]).forEach(f=>{(by[f.section]=by[f.section]||[]).push(f);});
  const order=["dns","tls","http","technology","email_security","registration","ip_geo","files","archive","ports","notes"];
  const titles={dns:"DNS",tls:"TLS certificate",http:"HTTP headers",technology:"Technology",email_security:"Mail authentication",registration:"Registration",ip_geo:"Hosting",files:"robots / security.txt / sitemap",archive:"Web archive",ports:"Open ports",notes:"Notes"};
  const cards=order.filter(k=>by[k]).map(k=>`<div class="card icard"><div class="hd">${esc(titles[k]||k)} <span class="ct">${by[k].length}</span></div><div class="bd"><table><tbody>${by[k].map(f=>`<tr><td class="k">${esc(f.key)}</td><td class="v">${esc(f.value)}</td></tr>`).join("")}</tbody></table></div></div>`).join("");
  const byId=new Map((B.nodes||[]).map(n=>[n.id,n]));
  const seenName=new Set(),subs=[];
  (B.edges||[]).filter(e=>e.type==="SUBDOMAIN_OF"||e.type==="COVERS").forEach(e=>{
    const n=byId.get(e.dst);if(!n||n.type==="wildcard_san"||seenName.has(n.id))return;seenName.add(n.id);
    subs.push({label:n.label,inCapture:n.source==="traffic",via:(n.attrs&&n.attrs.via)||(e.type==="COVERS"?"certificate":"first-party host")});});
  subs.sort((a,b)=>a.inCapture-b.inCapture||a.label.localeCompare(b.label));
  const unseen=subs.filter(n=>!n.inCapture);
  const subCard=subs.length?`<div class="card icard"><div class="hd">Subdomains <span class="ct">${subs.length}</span></div><div class="bd"><table><thead><tr><th>Name</th><th>In your capture?</th><th>Found via</th></tr></thead><tbody>${
    subs.map(n=>`<tr><td class="mono">${esc(n.label)}</td><td class="${n.inCapture?"":"miss"}">${n.inCapture?"yes":"never visited"}</td><td class="mono" style="color:var(--muted)">${esc(n.via)}</td></tr>`).join("")}</tbody></table></div></div>`:"";
  return `<h1 class="vt">Infrastructure <span class="tag-ext">EXTERNAL</span></h1><p class="vsub">Public recon on <b class="mono">${esc(B.osint.host)}</b> (run #${B.osint.id}, ${esc(B.osint.generated_at)}). It lives in the graph as <span class="mono">EXTERNAL</span> edges, a separate provenance from traffic you captured or code that referenced a path. ${unseen.length?`<b>${unseen.length}</b> of ${subs.length} subdomain(s) never appeared in your capture.`:""}</p>${subCard}${cards}`;
}

/* ---------- PRIORITIES ---------- */
/* ---------- CROSS-ROLE ---------- */
function vCrossrole(){
  const roles=D.roles||[];
  const reached=EP.filter(e=>e.roles.length);
  let h=`<h1 class="vt">Cross-role surface</h1><p class="vsub">Which role reached which endpoint, and the status each got back. Divergence is a broken-access-control <b>hypothesis</b>, replay across accounts to confirm.</p>`;
  // privileged / divergence highlights — one card per endpoint, notes merged
  const hiBy={};
  const note=(e,t)=>{(hiBy[e.id]=hiBy[e.id]||{e,notes:[]}).notes.push(t);};
  reached.forEach(e=>{
    const sbr=e.status_by_role||{};
    const ok=r=>(sbr[r]||[]).some(s=>s>=200&&s<300);
    if(e.privileged&&e.roles.length) note(e,"privileged path reached by "+e.roles.join(", "));
    roles.forEach(lo=>roles.forEach(hiR=>{if(lo!==hiR&&(sbr[lo]||[]).some(s=>s===403||s===401)&&ok(hiR))note(e,`${lo} got ${sbr[lo].join("/")}, ${hiR} got ${sbr[hiR].join("/")}`);}));
  });
  const hi=Object.values(hiBy).map(x=>({e:x.e,note:x.notes.join(" · ")}));
  if(hi.length){h+=`<div class="card"><div class="hd">Divergences worth checking <span class="ct">${hi.length}</span></div><div class="bd" style="padding:14px 16px">${hi.map(x=>`<div class="prio sev-hot" data-ep="${esc(x.e.id)}"><div class="rank">⚑</div><div class="body"><div class="ttl">${methodm(x.e.method)} <span class="mono">${esc(x.e.path)}</span></div><div class="why">${esc(x.note)}.</div></div></div>`).join("")}</div></div>`;}
  // matrix
  h+=`<div class="card"><div class="hd">Role reach matrix</div><div class="bd" style="padding:0"><table class="matrix"><thead><tr><th>Endpoint</th>${roles.map(r=>`<th>${esc(r)}</th>`).join("")}</tr></thead><tbody>`;
  h+=reached.filter(e=>matchQ(e)).map(e=>`<tr data-ep="${esc(e.id)}"><td><span class="mono">${methodm(e.method)} ${esc(e.path)}</span></td>${roles.map(r=>{const ss=(e.status_by_role||{})[r];return `<td>${ss?`<span class="cell hit">${ss.join(",")}</span>`:'<span class="cell miss">·</span>'}</td>`;}).join("")}</tr>`).join("");
  h+=`</tbody></table></div></div>`;
  return h;
}

/* ---------- UNKNOWNS ---------- */
const OPEN_TITLE={
  AUTHENTICATED_STATE_NOT_OBSERVED:"No signed-in traffic in this capture",
  ROLE_NOT_TAGGED:"Traffic was not tagged with a role",
  API_PURPOSE_UNKNOWN:"Referenced in code but never called",
  AUTHORIZATION_UNKNOWN:"Access control not verified",
  ENDPOINT_ONLY_ERRORED:"Only ever returned errors",
  SCRIPT_PARTIALLY_SCANNED:"Script too large to read in full",
  CAPTURE_ITEMS_SKIPPED:"Some requests could not be parsed",
};
function openTitle(t){return OPEN_TITLE[t]||humanize(t);}
__PGJS__

__RRJS__
__INVJS__
function openEv(i){
  const ev=D.evidence["ev_"+i];if(!ev)return;
  $("#dtitle").innerHTML=`<span class="mono">${EVD(i)}</span>`;
  $("#dbody").innerHTML=`<h4>Attributes</h4><div class="kv">
    <div class="k">Request</div><div class="v mono">${esc(ev.method)} ${esc(ev.host)}${esc(ev.path)}</div>
    <div class="k">Status</div><div class="v mono">${ev.status==null?"?":ev.status}</div>
    ${ev.mime?`<div class="k">MIME</div><div class="v mono">${esc(ev.mime)}</div>`:""}
    ${ev.role?`<div class="k">Role</div><div class="v mono">${esc(ev.role)}</div>`:""}
    ${ev.source?`<div class="k">Source</div><div class="v mono">${esc(ev.source)}${ev.item!=null?` · item ${ev.item}`:""}</div>`:""}
   </div><h4>Request &amp; response</h4><div class="drv" id="drv"></div>`;
  rrMount($("#drv"),[i],{vert:true,title:" "});
  $("#drawer").classList.add("on");$("#scrim").classList.add("on");$("#drawer").setAttribute("aria-hidden","false");
}

__MAPJS__

/* ---------- drawer ---------- */
function openEp(id){
  const e=EP.find(x=>x.id===id);if(!e)return;
  const sbr=e.status_by_role||{};
  const staticOnly=e.state==="STATIC_ONLY";
  const kv=(k,v)=>v!=null&&v!==""&&!(Array.isArray(v)&&!v.length)?`<div class="k">${k}</div><div class="v">${v}</div>`:"";
  $("#dtitle").innerHTML=`${methodm(e.method)} <span class="mono">${esc(e.path)}</span>`;
  $("#dbody").innerHTML=`
   ${staticOnly?`<div class="callout" style="margin-bottom:16px"><span class="i">i</span><p>This endpoint was <b>referenced in the client code but never requested</b> in the capture, so there is no request or response for it. The evidence below is the page or script that names it, a good thing to try next.</p></div>`:""}
   <h4>Attributes</h4><div class="kv">
    ${kv("Host",`<span class="mono">${esc(e.host)}</span>`)}
    ${kv("Statuses",statuses(e.statuses))}${kv("Requests",e.requests)}
    ${kv("Credentials",e.credentials.map(x=>`<span class="m">${esc(x)}</span>`).join(" "))}
    ${e.anon?kv("Note",'<span style="color:var(--warn)">also seen without credentials</span>'):""}
    ${e.privileged?kv("Note",'<span style="color:var(--signal)">privileged-looking path</span>'):""}
   </div>
   ${e.roles.length?`<h4>Reached by</h4><div class="kv">${e.roles.map(r=>`<div class="k mono">${esc(r)}</div><div class="v mono">${(sbr[r]||[]).join(", ")||"—"}</div>`).join("")}</div>`:""}
   ${e.params.length?`<h4>Parameters (${e.params.length})</h4><div class="taglist">${e.params.map(p=>`<span>${esc(p)}</span>`).join("")}</div>`:""}
   ${e.referenced_by.length?`<h4>Referenced by (inferred)</h4><div class="taglist">${e.referenced_by.map(p=>`<span>${esc(p)}</span>`).join("")}</div>`:""}
   ${e.called_from.length?`<h4>Called from (observed)</h4><div class="taglist">${e.called_from.map(p=>`<span>${esc(p)}</span>`).join("")}</div>`:""}
   <h4>Evidence: request and response</h4>${(e.evidence||[]).length?'<div class="drv" id="drv"></div>':'<div style="color:var(--faint)">None captured.</div>'}`;
  if((e.evidence||[]).length)rrMount($("#drv"),e.evidence,{vert:true,title:" "});
  $("#drawer").classList.add("on");$("#scrim").classList.add("on");$("#drawer").setAttribute("aria-hidden","false");
}
const NBYID=Object.fromEntries((D.graph.nodes||[]).map(n=>[n.id,n]));
const NODE_KIND={infra:"Infrastructure (external recon)",host:"First-party host",tech:"Technology marker (from response headers)",route:"Page / route",script:"Client script",third_party:"Third party",auth:"Auth scheme",cookie:"Cookie",role:"Role",operation:"GraphQL operation",parameter:"Parameter"};
function openNode(id){
  if(EP.find(x=>x.id===id))return openEp(id);
  const n=NBYID[id];if(!n)return;
  $("#dtitle").innerHTML=`<span class="mono">${esc(n.label)}</span>`;
  const conns=(D.graph.edges||[]).filter(e=>e.s===id||e.d===id).slice(0,30);
  $("#dbody").innerHTML=`<h4>Attributes</h4><div class="kv">
    <div class="k">Kind</div><div class="v">${esc(NODE_KIND[n.type]||humanize(n.type))}</div>
    ${n.detail?`<div class="k">Detail</div><div class="v">${esc(n.detail)}</div>`:""}
   </div>
   ${n.type==="infra"?`<div class="callout" style="margin-top:14px"><span class="i">i</span><p>Collected by external recon (<span class="mono">burp2model osint</span>), not from the capture. It describes the app's public footprint.</p></div>`:""}
   ${conns.length?`<h4>Connections (${conns.length})</h4><div class="taglist">${conns.map(e=>{const o=e.s===id?e.d:e.s;const nn=NBYID[o];const dir=e.s===id?"→":"←";return `<span>${dir} ${esc(humanize(e.type))}: ${esc(nn?nn.label:o)}</span>`;}).join("")}</div>`:""}
   ${(n.evidence||[]).length?'<h4>Evidence: request and response</h4><div class="drv" id="drv"></div>':""}`;
  if((n.evidence||[]).length)rrMount($("#drv"),n.evidence,{vert:true,title:" "});
  $("#drawer").classList.add("on");$("#scrim").classList.add("on");$("#drawer").setAttribute("aria-hidden","false");
}
function closeDrawer(){$("#drawer").classList.remove("on");$("#scrim").classList.remove("on");$("#drawer").setAttribute("aria-hidden","true");}
$("#scrim").onclick=closeDrawer;$("#dclose").onclick=closeDrawer;
addEventListener("keydown",e=>{if(e.key==="Escape")closeDrawer();});

/* ---------- wire ---------- */
const RENDER={overview:vOverview,priorities:vPriorities,graph:vGraph,inventory:vEvidence,ask:vAsk,reference:vReference};
function render(){
  renderNav();
  try{if(!(view==="ask"&&(location.hash||"").startsWith("#query=")))history.replaceState(null,"","#"+view);}catch(e){}
  const main=$("#main");
  main.className="m-"+view;
  main.innerHTML=`<section class="view view-${view} on">${(RENDER[view]||vOverview)()}</section>
   <div class="foot">Generated by <b>burp2model ${esc(D.version)}</b>${D.generated?` on ${esc(D.generated)}`:""}. An evidence-backed model of a capture you provided. Not a scanner; nothing here is a vulnerability. · <a href="https://falc0n-researcher.github.io/burp2model/">docs</a></div>`;
  if(view==="graph")initGraph();
  if(view==="ask")initAsk();
  if(view==="overview")initOverview();
  if(view==="priorities")initPriorities();
  if(view==="reference")initReference();
  if(view==="inventory")initEvq();
  // row / card clicks → drawer
  $$("[data-ep]",main).forEach(el=>el.onclick=()=>openEp(el.dataset.ep));
  $$("[data-ev]",main).forEach(el=>el.onclick=()=>openEv(el.dataset.ev));
  $$("th[data-sort]",main).forEach(th=>th.onclick=()=>{const k=th.dataset.sort;if(sortKey===k)sortDir*=-1;else{sortKey=k;sortDir=1;}render();});
  $$(".chip[data-fk]",main).forEach(ch=>ch.onclick=()=>{const s=filters[ch.dataset.fk];s.has(ch.dataset.fv)?s.delete(ch.dataset.fv):s.add(ch.dataset.fv);render();});
  $$("[data-goto]",main).forEach(b=>b.onclick=()=>{go(b.dataset.goto);render();});
}
$("#q").addEventListener("input",e=>{query=e.target.value.trim();
  // a search jumps to the most relevant list view if on a summary view
  // on the Map, a search highlights matching nodes in place instead
  REF.q=query;if(query&&["overview","ask","priorities"].includes(view))go("surface");
  render();});
addEventListener("keydown",e=>{
  if(e.key==="/"&&!e.metaKey&&!e.ctrlKey&&!/^(INPUT|TEXTAREA)$/.test(document.activeElement.tagName)){e.preventDefault();$("#q").focus();}
});
/* deep link: report.html#priorities opens that view */
/* report.html#query=<urlencoded BQL> opens the console with that query already run */
function fromHash(){
  const h=(location.hash||"").slice(1);
  if(h.startsWith("query=")){let q="";try{q=decodeURIComponent(h.slice(6));}catch(e){}view="ask";if(q&&q!==qText){qText=q;aNL=null;qErr=null;qRes=null;if(looksBql(q)&&BQLDB)qRun(q);else aNL=askEngine(q);}return true;}
  if(h==="evidence"){view="inventory";return true;}
  if(h==="query"){view="ask";return true;}
  if(LEGACY[h]){go(h);return true;}
  if(RENDER[h]){view=h;return true;}
  return false;
}
fromHash();
addEventListener("hashchange",()=>{const was=view,h=(location.hash||"").slice(1);if(fromHash()&&(view!==was||view==="ask"||LEGACY[h]))render();});
render();
</script>
</body>
</html>
"""
