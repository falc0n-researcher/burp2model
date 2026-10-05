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
    if dns.get("CNAME"):
        add("infra:cname", f"CNAME · {dns['CNAME'][0]}",
            "Canonical name: " + ", ".join(dns["CNAME"][:3]), "dns")
    if dns.get("NS"):
        add("infra:ns", f"Nameservers · {len(dns['NS'])}", "NS: " + ", ".join(dns["NS"][:4]), "dns")
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
        "context": context_package(m, lens=lens, osint=osint),
        "methodology": {"prompt": METHODOLOGY_PROMPT, "scaffold": investigation_plan(m)},
        "osint": o_summary,
        "evidence": {f"ev_{e['id']}": e for e in data.get("evidence", [])},
    }


def write_html_report(m: Model, path: str, osint: dict | None = None,
                      lens: str = "attention", db_path: str | None = None) -> None:
    payload = build_payload(m, osint=osint, lens=lens)
    if db_path:
        # the in-page query console reads the same graph.db the CLI queries
        from . import store
        conn = store.open_db(db_path)
        try:
            payload["bql"] = store.export_for_report(conn)
        finally:
            conn.close()
    html = (_TEMPLATE.replace("__BQLJS__", BQL_JS)
            .replace("__DATA__", _safe_json(payload)))
    with open(path, "w", encoding="utf-8") as f:
        f.write(html)


_TEMPLATE = r"""<!doctype html>
<html lang="en" data-theme="light">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; img-src data:">
<meta name="color-scheme" content="light dark">
<link rel="icon" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 32 32'%3E%3Cpath d='M6 21.5 16 26l10-4.5' fill='none' stroke='%230e8fd6' stroke-width='2.2' stroke-linecap='round' stroke-linejoin='round'/%3E%3Cpath d='M6 16.5 16 21l10-4.5' fill='none' stroke='%237a5cff' stroke-width='2.2' stroke-linecap='round' stroke-linejoin='round'/%3E%3Cpath d='M16 6 6 10.5 16 15l10-4.5z' fill='%23e85002'/%3E%3C/svg%3E">
<title>burp2model report</title>
<style>
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

main{overflow:auto;padding:22px 26px 60px;min-width:0}
.view{display:none;max-width:1120px}
.view.on{display:block;animation:fade .2s ease}
@keyframes fade{from{opacity:0;transform:translateY(4px)}to{opacity:1}}
h1.vt{font:700 24px/1.2 var(--sans);letter-spacing:-.02em;margin:0 0 4px}
.vsub{color:var(--muted);margin:0 0 20px;max-width:70ch}

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
.qbar{display:flex;gap:8px;margin-bottom:10px}
.qbar textarea{flex:1;min-height:52px;max-height:160px;resize:vertical;padding:13px 16px;border:1px solid var(--line2);border-radius:12px;background:var(--panel);color:var(--text);font:14px/1.45 var(--mono)}
.qbar textarea:focus{border-color:var(--signal);outline:none}
.qrun{align-self:flex-start;height:52px;padding:0 20px;border:1px solid var(--signal);border-radius:12px;background:var(--signal);color:#fff;font:600 13px var(--sans)}
.qrun:hover{filter:brightness(1.06)}
.qex{display:flex;flex-wrap:wrap;gap:6px;margin:0 0 14px}
.qex button,.qhist button{border:1px solid var(--line);background:var(--panel2);border-radius:999px;padding:4px 11px;font:500 12px var(--mono);color:var(--muted)}
.qex button:hover,.qhist button:hover{border-color:var(--signal);color:var(--text)}
.qerr{padding:12px 14px;border:1px solid var(--bad);border-radius:10px;color:var(--bad);font:13px var(--mono);background:var(--panel)}
.qnote{display:flex;align-items:center;gap:10px;margin:0 0 10px;color:var(--muted);font:12.5px var(--mono)}
.qnote .sp{flex:1}
.qnote button{border:1px solid var(--line);background:var(--panel2);border-radius:7px;padding:3px 9px;font:500 12px var(--sans)}
.qtbl td{vertical-align:top;font:12.5px var(--mono);max-width:520px;overflow-wrap:anywhere}
.qtbl tr[data-ev],.qtbl tr[data-node]{cursor:pointer}
.qtbl tr[data-ev]:hover,.qtbl tr[data-node]:hover{background:var(--panel2)}
.qhist{display:flex;flex-wrap:wrap;gap:6px;margin-top:14px}
.qhelp{white-space:pre-wrap;color:var(--muted);font:12.5px/1.6 var(--mono);padding:14px 16px;border:1px solid var(--line);border-radius:10px;background:var(--panel)}
.tag-ext{font:600 10px var(--mono);letter-spacing:.05em;color:var(--inferred);border:1px solid var(--inferred);border-radius:5px;padding:0 5px}
.icard{margin-bottom:14px}
.icard .bd{padding:0}
.icard td.k{width:190px;color:var(--muted);font:12px var(--mono)}
.icard td.v{font:12.5px var(--mono);overflow-wrap:anywhere}
.miss{color:var(--warn)}
.evq{display:flex;gap:8px;align-items:center;margin:0 0 14px}
.evq input{flex:1;height:38px;padding:0 12px;border:1px solid var(--line2);border-radius:9px;background:var(--panel);color:var(--text);font:13px var(--mono)}
.evq input:focus{border-color:var(--signal);outline:none}

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

/* graph */
.graphwrap{background:var(--panel);border:1px solid var(--line);border-radius:var(--radius);overflow:hidden;position:relative}
#gsvg{width:100%;height:min(72vh,720px);display:block;cursor:grab}
.glegend svg{width:12px;height:12px;flex:none}
.glegend{display:flex;flex-wrap:wrap;gap:14px;padding:12px 16px;border-top:1px solid var(--line);font-size:12px;color:var(--muted)}
.glegend .k{display:inline-flex;align-items:center;gap:6px}
.glegend .sw{width:10px;height:10px;border-radius:3px}
.glegend .ln2{width:18px;height:0;border-top:2px solid var(--line2)}
.glegend .ln2.inf{border-top-style:dashed}
.gnode circle{cursor:pointer;stroke:var(--panel);stroke-width:2;transition:opacity .12s}
.gnode text{font:10px var(--mono);fill:var(--text);paint-order:stroke;stroke:var(--panel);stroke-width:3px;stroke-linejoin:round;pointer-events:none;transition:opacity .12s}
.gedge{fill:none;stroke:var(--line2);stroke-width:1.2;transition:opacity .12s,stroke-width .12s}
.gedge.inf{stroke-dasharray:4 4;stroke:var(--inferred);opacity:.55}
/* hover focus: connected stays, the rest fades */
svg.gfocus .gnode:not(.hi) circle,svg.gfocus .gnode:not(.hi) text{opacity:.16}
svg.gfocus .gedge{opacity:.06}
svg.gfocus .gedge.hi{opacity:1;stroke-width:1.8}
svg.gfocus .gedge.hi.inf{opacity:.9}
.gnode.hi text{font-weight:700}
.gedge.ext{stroke-dasharray:1.5 3.5;stroke:var(--l6);opacity:.55}
svg.gfocus .gedge.hi.ext{opacity:.95}
/* search: matching nodes stay, the rest fades */
svg.gsearch .gnode:not(.q) .shape,svg.gsearch .gnode:not(.q) text{opacity:.14}
svg.gsearch .gedge{opacity:.08}
.gnode .shape{cursor:pointer;stroke:var(--panel);stroke-width:2;transition:opacity .12s}
.gnode.q .shape{stroke:var(--signal);stroke-width:2.5}
.ghint{position:absolute;bottom:10px;right:12px;font-size:11px;color:var(--faint);background:var(--panel2);padding:4px 8px;border-radius:6px;border:1px solid var(--line);pointer-events:none}
.gtools{display:flex;flex-wrap:wrap;gap:10px 16px;align-items:center;padding:10px 14px;border-bottom:1px solid var(--line);background:var(--panel2)}
.gtools .chipwrap{flex:1;min-width:240px}
.gtools .chip{padding:4px 10px;font-size:12px}
.gtools .chip .sw{width:9px;height:9px;border-radius:2px;display:inline-block}
.gtools .chip.off{opacity:.45;text-decoration:line-through}
.gseg{display:inline-flex;border:1px solid var(--line2);border-radius:8px;overflow:hidden}
.gseg button,.gbtn{font:600 12px var(--sans);padding:5px 10px;border:0;background:var(--panel);color:var(--muted)}
.gseg button.on{background:var(--text);color:var(--ink)}
.gseg button+button{border-left:1px solid var(--line2)}
.gbtn{border:1px solid var(--line2);border-radius:8px}
.gbtn:hover,.gseg button:hover{color:var(--text)}
.gbtns{display:inline-flex;gap:6px}

/* drawer */
.scrim{position:fixed;inset:0;background:rgba(20,25,36,.35);opacity:0;visibility:hidden;transition:.18s;z-index:50}
.scrim.on{opacity:1;visibility:visible}
.drawer{position:fixed;top:0;right:0;height:100%;width:min(460px,92vw);background:var(--panel);border-left:1px solid var(--line);
box-shadow:var(--shadow);transform:translateX(100%);transition:transform .22s cubic-bezier(.4,0,.2,1);z-index:51;display:flex;flex-direction:column}
.drawer.on{transform:none}
.drawer .dh{display:flex;align-items:center;gap:10px;padding:16px 18px;border-bottom:1px solid var(--line)}
.drawer .dh .x{margin-left:auto;width:30px;height:30px;border:1px solid var(--line);border-radius:7px;background:var(--panel2)}
.drawer .db{overflow:auto;padding:18px}
.drawer h4{font:600 10px var(--mono);letter-spacing:.12em;text-transform:uppercase;color:var(--faint);margin:20px 0 8px}
.drawer h4:first-child{margin-top:0}
.kv{display:grid;grid-template-columns:120px 1fr;gap:6px 12px;font-size:13px}
.kv .k{color:var(--muted)}
.kv .v{word-break:break-word}
.evrow{border:1px solid var(--line);border-radius:8px;margin-bottom:8px;font-size:12.5px;overflow:hidden}
.evrow>summary{padding:9px 11px;cursor:pointer;list-style:none;display:flex;align-items:center;gap:8px}
.evrow>summary::-webkit-details-marker{display:none}
.evrow>summary::before{content:"▸";color:var(--faint);font-size:10px;transition:transform .15s}
.evrow[open]>summary::before{transform:rotate(90deg)}
.evrow .id{font:600 11px var(--mono);color:var(--signal)}
.evrow .meta{color:var(--muted);font-family:var(--mono);font-size:11px;word-break:break-all;flex:1}
.http{border-top:1px solid var(--line);background:var(--panel3)}
.http .tabs{display:flex;gap:2px;padding:8px 10px 0}
.http .tab{font:600 11px var(--mono);padding:5px 11px;border-radius:7px 7px 0 0;color:var(--muted);border:1px solid transparent;background:none}
.http .tab.on{color:var(--text);background:var(--panel);border-color:var(--line);border-bottom-color:var(--panel)}
.http pre{margin:0;padding:12px 13px;font:11.5px/1.5 var(--mono);white-space:pre-wrap;word-break:break-word;max-height:340px;overflow:auto;border-top:1px solid var(--line)}
.http .ln{color:var(--signal);font-weight:700}
.http .hn{color:var(--observed)}.http .hv{color:var(--text)}
.http .rd{color:var(--inferred);font-weight:600}
.http .bd2{color:var(--muted)}
.http .trunc-note{color:var(--faint);font-style:italic}
.http .empty2{padding:14px;color:var(--faint);font-size:12px}
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
  ["graph","Reasoning graph","adjacency + communities, flows, trust zones — for the AI to traverse",null],
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
    why:"The client code names this endpoint but no request to it was captured — an unwalked path.",
    next:"Request it directly in an authorised session and observe the response."});
  if(e.privileged&&e.requests>0) sig.push({sev:"hot",ttl:"Privileged-looking path was reached",
    why:"The path matches an admin/internal pattern and appears in the capture"+(e.roles.length?` (roles: ${e.roles.join(", ")})`:"")+".",
    next:"Confirm the response was meant for the caller; replay across accounts."});
  else if(e.privileged) sig.push({sev:"hot",ttl:"Privileged-looking path referenced",
    why:"The path matches an admin/internal pattern; it was only referenced in code, never requested.",
    next:"Request it in an authorised session and observe who is allowed in."});
  const ss=e.statuses||[];
  if(ss.length&&ss.every(s=>s>=400)) sig.push({sev:"warn",ttl:"Only ever returned errors",
    why:`Every observed status was ${ss.join(", ")} — behaviour with valid input/auth is unseen.`,
    next:"Exercise the feature normally in an authorised session."});
  if(e.anon) sig.push({sev:"warn",ttl:"Seen with and without credentials",
    why:"Some requests carried a credential and some did not — the auth requirement is ambiguous.",
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
  {id:"overview",name:"Overview",grp:"Summary",ct:()=>null},
  {id:"ask",name:"Ask the model",grp:"Summary",hot:true,ct:()=>null},
  {id:"graph",name:"Map",grp:"Summary",ct:()=>(D.graph.nodes||[]).length},
  {id:"priorities",name:"Priorities",grp:"Summary",ct:()=>PRIO.length+weakCookies.length},
  {id:"surface",name:"Endpoints",grp:"Model",dot:"var(--l4)",ct:()=>EP.length},
  {id:"code",name:"Client code",grp:"Model",dot:"var(--l3)",ct:()=>D.scripts.length},
  {id:"supply",name:"Third parties",grp:"Model",dot:"var(--l5)",ct:()=>D.third_parties.length},
  {id:"trust",name:"Trust",grp:"Model",dot:"var(--l5)",ct:()=>D.auth.length+D.cookies.length},
  {id:"crossrole",name:"Cross-role",grp:"Model",dot:"var(--l6)",ct:()=>hasRoles?EP.filter(e=>e.roles.length).length:null,cond:hasRoles},
  {id:"unknowns",name:"Open questions",grp:"Model",dot:"var(--l6)",ct:()=>D.unknowns.length},
  {id:"evidence",name:"Evidence",grp:"Model",dot:"var(--l1)",ct:()=>Object.keys(D.evidence||{}).length},
  {id:"query",name:"Query (BQL)",grp:"Explore",hot:true,ct:()=>null,cond:!!BQLDB},
  {id:"infra",name:"Infrastructure",grp:"Explore",dot:"var(--inferred)",ct:()=>BQLDB&&BQLDB.osint?BQLDB.facts.length:null,cond:!!BQLDB},
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

/* ---------- OVERVIEW ---------- */
function vOverview(){
  const kpi=(n,k,cls)=>`<div class="kpi ${cls||''}"><div class="n">${n}</div><div class="k">${esc(k)}</div></div>`;
  const cap=D.stats||{};
  const cats=[["Hosts",c.hosts],["Routes",c.routes],["Scripts",c.scripts],["Endpoints",c.endpoints],
    ["Parameters",c.parameters],["GraphQL operations",c.operations],["Third parties",c.third_parties],
    ["Auth schemes",c.auth],["Cookies",c.cookies],["Roles",c.roles]].filter(x=>x[1]);
  return `<h1 class="vt">Overview</h1><p class="vsub">A structural model of <b>${esc(D.app)}</b> built from traffic you captured. Every fact is cited to the request that produced it; nothing here is a vulnerability — the model maps what the app is and where to look.</p>
  <div class="kpis">
   ${kpi(c.hosts||0,"first-party hosts")}${kpi(c.routes||0,"routes / pages")}${kpi(c.endpoints||0,"API endpoints","sig")}
   ${kpi(c.parameters||0,"parameters")}${kpi(c.third_parties||0,"third parties")}${kpi(c.unknowns||0,"open questions")}
  </div>
  ${provenanceBar()}
  ${PRIO.length?`<div class="card"><div class="hd">Worth looking at first <span class="ct">top ${Math.min(3,PRIO.length)} of ${PRIO.length}</span></div><div class="bd" style="padding:14px 16px">
   ${PRIO.slice(0,3).map((p,i)=>prioCard(p,i)).join("")}
   <button class="chip" style="margin-top:4px" data-goto="priorities">See all priorities →</button></div></div>`:""}
  <div class="card"><div class="hd">Model at a glance <span class="ct">click Map to explore</span></div><div class="bd" style="padding:6px 0">
   <table><tbody>${cats.map(([k,v])=>`<tr data-goto="graph"><td>${esc(k)}</td><td class="mono">${v}</td></tr>`).join("")}</tbody></table></div></div>
  ${hostsCard()}
  <div class="card"><div class="hd">Capture coverage</div><div class="bd" style="padding:6px 0">
   <table><tbody>
    <tr><td>Requests parsed</td><td class="mono">${cap.parsed??cap.exchanges??"—"} of ${cap.items??"—"}${cap.skipped?` · <span style="color:var(--warn)">${cap.skipped} skipped</span>`:""}</td></tr>
    <tr><td>Static assets (not mapped)</td><td class="mono">${cap.static_assets??0}</td></tr>
    <tr><td>CORS preflights</td><td class="mono">${cap.preflight??0}</td></tr>
    <tr><td>Roles</td><td class="mono">${(D.roles||[]).join(", ")||"none"}</td></tr>
   </tbody></table></div></div>
  ${osintCard()}
  <div class="callout"><span class="i">i</span><p><b>Honesty.</b> An absence in this model is an absence in the <b>capture</b>, never a statement about the target. Edges are <b>observed</b> (seen in traffic) or <b>inferred</b> (a reference found in code) — never blurred.</p></div>`;
}
function provenanceBar(){
  const st=(c.api_state||{}),both=st.BOTH||0,rt=st.RUNTIME_ONLY||0,so=st.STATIC_ONLY||0,total=both+rt+so;
  if(!total)return "";
  const seg=(n,col)=>n?`<span style="width:${(n/total*100).toFixed(1)}%;background:${col}"></span>`:"";
  return `<div class="card"><div class="hd">Endpoint provenance <span class="ct">${total} endpoints</span></div><div class="bd" style="padding:12px 16px">
   <div class="segbar">${seg(both,"var(--ok)")}${seg(rt,"var(--observed)")}${seg(so,"var(--signal)")}</div>
   <div class="seglegend">
    <span class="k"><span class="sw" style="background:var(--ok)"></span>seen in code <b>and</b> traffic <b>${both}</b></span>
    <span class="k"><span class="sw" style="background:var(--observed)"></span>traffic only <b>${rt}</b></span>
    <span class="k"><span class="sw" style="background:var(--signal)"></span>code only — never called <b>${so}</b></span>
   </div></div></div>`;
}
function hostsCard(){
  const hs=D.hosts||[];
  if(!hs.length)return "";
  return `<div class="card"><div class="hd">First-party hosts <span class="ct">${hs.length}</span></div><div class="bd" style="padding:0">
   <table><thead><tr><th>Host</th><th>Scheme</th><th>Ports</th><th>Tech markers</th></tr></thead><tbody>
   ${hs.map(h=>`<tr><td class="mono">${esc(h.label)}</td><td class="mono" style="color:var(--muted)">${esc((h.schemes||[]).join(", ")||"—")}</td>
    <td class="mono" style="color:var(--muted)">${esc((h.ports||[]).join(", ")||"—")}</td>
    <td class="mono" style="color:var(--muted);font-size:12px">${esc(Object.entries(h.tech||{}).map(([k,v])=>v?`${k}: ${v}`:k).join(" · ")||"—")}</td></tr>`).join("")}
   </tbody></table></div></div>`;
}
function osintCard(){
  const o=D.osint;
  if(!o)return "";
  const rows=[];
  if(o.tls&&o.tls.issuer)rows.push(["TLS",`${o.tls.issuer}${o.tls.not_after?` · expires ${o.tls.not_after}`:""}`]);
  if(o.hosting&&o.hosting.network)rows.push(["Hosting",`${o.hosting.network}${o.hosting.country?` · ${o.hosting.country}`:""}`]);
  if((o.technology||[]).length)rows.push(["Technology",o.technology.join(", ")]);
  if(o.headers_missing)rows.push(["Security headers",o.headers_missing.length?`${o.headers_missing.length} missing: ${o.headers_missing.join(", ")}`:"all common headers present"]);
  if(o.registrar)rows.push(["Registrar",o.registrar]);
  if((o.open_ports||[]).length)rows.push(["Open ports",o.open_ports.join(", ")]);
  if(o.email_security)rows.push(["Email auth",`SPF: ${o.email_security.spf_note||"?"} · DMARC: ${o.email_security.dmarc_policy||o.email_security.dmarc_note||"?"}`]);
  if(o.subdomains)rows.push(["Subdomains",`${o.subdomains} from certificate transparency`]);
  if(!rows.length)return "";
  return `<div class="card"><div class="hd">External recon <span class="ct">${esc(o.host||"")}</span></div><div class="bd" style="padding:6px 0">
   <table><tbody>${rows.map(([k,v])=>`<tr data-goto="graph"><td>${esc(k)}</td><td class="mono" style="color:var(--muted)">${esc(v)}</td></tr>`).join("")}</tbody></table>
   </div><div class="glegend" style="border-top:1px solid var(--line)">Collected live by <span class="mono">burp2model osint</span>, not from the capture. Shown on the Map as infrastructure.</div></div>`;
}
function prioCard(p,i){
  const e=p.ep, lead=p.sig[0];
  const more=p.sig.slice(1).map(s=>`<div class="sig"><span><b>${esc(s.ttl)}.</b> ${esc(s.why)}</span></div>`).join("");
  return `<div class="prio sev-${p.sev}" data-ep="${esc(e.id)}"><div class="rank">${i+1}</div><div class="body">
   <div class="ttl">${methodm(e.method)} <span class="mono">${esc(e.label.replace(/^\S+\s/,''))}</span> <span style="color:var(--muted);font-weight:400;font-size:13px">${esc(lead.ttl)}</span></div>
   <div class="why">${esc(lead.why)}</div>${more}<div class="nx"><b>Next</b> ${esc(lead.next)}</div></div></div>`;
}

/* ---------- ASK (answers from the model, no AI) ---------- */
const ARROW='<svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2" style="color:var(--faint)"><path d="M9 6l6 6-6 6"/></svg>';
function arow(e){return `<div class="arow" data-ep="${esc(e.id)}">${methodm(e.method)}<span class="p mono">${esc(e.path)}</span><span class="ev">${(e.evidence||[]).slice(0,2).map(i=>"ev_"+i).join(", ")}</span>${ARROW}</div>`;}
function alist(title,note,rows){return {title,html:`<div class="answer">${note?`<p class="note">${note}</p>`:""}${rows.length?rows.join(""):'<div class="empty">Nothing in this model matches.</div>'}</div>`};}
function ans_endpoints(){const r=[...EP].sort((a,b)=>a.path.localeCompare(b.path));return alist("Endpoints",`The model holds <b>${r.length}</b> API endpoint${r.length===1?"":"s"}. Click any to see its parameters and the request that produced it.`,r.map(arow));}
function ans_incode(){const r=EP.filter(e=>e.state==="STATIC_ONLY").sort((a,b)=>a.path.localeCompare(b.path));return alist("Referenced in code, never called",r.length?`These URLs appear in the client code but no request to them was captured — unwalked paths worth trying.`:`Every endpoint referenced in the code was also seen in traffic.`,r.map(arow));}
function ans_errors(){const r=EP.filter(e=>e.statuses.length&&e.statuses.every(s=>s>=400)).sort((a,b)=>a.path.localeCompare(b.path));return alist("Only ever returned errors",r.length?`Every response captured for these was 4xx/5xx — their behaviour with valid input and auth is unseen.`:`No endpoint returned only errors.`,r.map(arow));}
function ans_priv(){const r=EP.filter(e=>e.privileged).sort((a,b)=>a.path.localeCompare(b.path));return alist("Privileged-looking paths",r.length?`Paths that match an admin/internal pattern.`:`No privileged-looking paths in this capture.`,r.map(arow));}
function ans_thirdparty(){const r=(D.third_parties||[]);return {title:"Third parties",html:`<div class="answer"><p class="note">${r.length} host${r.length===1?"":"s"} outside the app's own domain — code you don't control running in your users' context.</p>${r.map(t=>`<div class="arow"><span class="p mono">${esc(t.label)}</span><span class="ev">${t.requests} req</span></div>`).join("")||'<div class="empty">None.</div>'}</div>`};}
function ans_auth(){const a=D.auth||[],k=D.cookies||[];return {title:"Authentication & cookies",html:`<div class="answer"><p class="note">How the app carries identity.</p>
  ${a.map(x=>`<div class="arow"><span class="p mono">${esc(x.label)}</span><span class="ev">${x.endpoints.length} endpoint${x.endpoints.length===1?"":"s"}</span></div>`).join("")}
  ${k.map(x=>{const miss=[!x.httponly&&"HttpOnly",!x.secure&&"Secure"].filter(Boolean);return `<div class="arow"><span class="p mono">cookie ${esc(x.name)}</span><span class="ev">${miss.length?"missing "+miss.join("+"):"HttpOnly+Secure"}</span></div>`;}).join("")}
  ${!a.length&&!k.length?'<div class="empty">No credentials or cookies observed.</div>':""}</div>`};}
function ans_unknowns(){return {title:"Open questions",html:`<div class="answer"><p class="note">What the capture could not answer.</p>${(D.unknowns||[]).map(u=>`<div class="arow"><span class="p">${esc(openTitle(u.type))} — <span class="mono" style="color:var(--muted)">${esc(u.entity)}</span></span></div>`).join("")||'<div class="empty">Nothing left open.</div>'}</div>`};}
function ans_endpoint(path){
  const q=path.toLowerCase();const hits=EP.filter(e=>e.path.toLowerCase().includes(q)).sort((a,b)=>a.path.length-b.path.length);
  if(!hits.length)return {title:"No such endpoint",html:`<div class="answer"><p class="note">Nothing in the model matches <span class="mono">${esc(path)}</span>. The model can only answer for endpoints it actually holds — that's the point.</p></div>`};
  return {title:"Endpoint",html:`<div class="answer">${hits.slice(0,6).map(e=>{
    const bits=[];if(e.statuses.length)bits.push("status "+e.statuses.join("/"));if(e.params.length)bits.push(e.params.length+" params");if(e.referenced_by.length)bits.push("referenced by "+e.referenced_by.join(", "));if(e.called_from.length)bits.push("called from "+e.called_from.join(", "));
    return `<div class="arow" data-ep="${esc(e.id)}">${methodm(e.method)}<span class="p mono">${esc(e.path)}</span>${ARROW}</div><p class="note" style="margin:-2px 0 12px 6px">${esc(bits.join(" · ")||"seen in traffic")}</p>`;}).join("")}</div>`};
}
function ans_shape(){const c2=D.counts;return {title:D.app,html:`<div class="answer"><p class="note"><b>${esc(D.app)}</b> — ${c2.hosts} host${c2.hosts===1?"":"s"}, ${c2.routes} route${c2.routes===1?"":"s"}, <b>${c2.endpoints} endpoints</b>, ${c2.parameters} parameters, ${c2.third_parties} third part${c2.third_parties===1?"y":"ies"}, ${c2.unknowns} open question${c2.unknowns===1?"":"s"}. Ask about any of them, or open the Map.</p></div>`};}
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
  if(/param|field|input|argument/.test(q)){const r=EP.filter(e=>e.params.length).sort((a,b)=>b.params.length-a.params.length);return alist("Endpoints with parameters",`Parameter <b>names</b> only — values were masked at capture.`,r.map(e=>`<div class="arow" data-ep="${esc(e.id)}">${methodm(e.method)}<span class="p mono">${esc(e.path)}</span><span class="ev">${e.params.length}</span>${ARROW}</div>`));}
  if(/endpoint|api|route|url|path|list|what.*(exist|there)|surface/.test(q))return ans_endpoints();
  return ans_shape();
}
const ASK_PRESETS=[
  ["List the endpoints","list the endpoints"],
  ["Referenced in code but never called","what is referenced in code but never called"],
  ["Third parties","third parties"],
  ["Auth & cookies","auth and cookies"],
  ["Open questions","what are the open questions"],
  ["Endpoints that only errored","which endpoints only returned errors"],
];
function vAsk(){
  return `<h1 class="vt">Ask the model</h1><p class="vsub">Type a question about the app and get an answer straight from the model — instant, cited, and with no AI involved. For judgement calls, use <b>Copy for AI</b> instead.</p>
  <div class="askbar"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="11" cy="11" r="7"/><path d="M21 21l-4.3-4.3"/></svg>
   <input id="askq" type="search" placeholder="e.g. what is referenced in code but never called?" autocomplete="off"></div>
  <div class="presets">${ASK_PRESETS.map(([t,q])=>`<button class="preset" data-q="${esc(q)}">${esc(t)}</button>`).join("")}</div>
  <div id="askout"></div>
  <div class="askfoot">Answered from the model — no AI was called.</div>`;
}
function initAsk(){
  const out=$("#askout"),inp=$("#askq");if(!out)return;
  const run=q=>{const a=askEngine(q);out.innerHTML=`<div class="answer"><div class="ahd">${esc(a.title)}</div>${a.html}</div>`;
    $$("[data-ep]",out).forEach(el=>el.onclick=()=>openEp(el.dataset.ep));};
  run("");
  inp.addEventListener("input",e=>run(e.target.value));
  $$(".preset").forEach(b=>b.onclick=()=>{inp.value=b.dataset.q;run(b.dataset.q);inp.focus();});
}


/* ---------- QUERY (BQL) ---------- */
const Q_EXAMPLES=[
 ["POST, not an error",'req.method:POST AND resp.code.lt:400'],
 ["API errors",'req.path.cont:"/api/" AND resp.code.gte:400'],
 ["Only in code",'node.type:endpoint AND node.state:STATIC_ONLY'],
 ["Stack traces / tokens",'resp.body.regex:"stack ?trace|exception|token"'],
 ["Set-Cookie responses",'resp.header.cont:"set-cookie"'],
 ["Recon edges",'edge.state:EXTERNAL limit 40'],
 ["Hosts seen only via recon",'node.type:subdomain AND node.attr.seen_in_capture:0'],
 ["Open questions",'unknowns'],
 ["Recon: TLS",'osint tls'],
];
let qText="",qRes=null,qErr=null,qHist=[];
try{qHist=JSON.parse(localStorage.getItem("b2m-qhist")||"[]");}catch(e){}
function qRun(text){
  qText=text;qErr=null;qRes=null;
  if(!BQLDB){qErr="This report was built without graph.db — rebuild with burp2model to enable queries.";return;}
  try{qRes=BQL.run(BQLDB,text);
    qHist=[text].concat(qHist.filter(x=>x!==text)).slice(0,12);
    try{localStorage.setItem("b2m-qhist",JSON.stringify(qHist));}catch(e){}
  }catch(e){qErr=e instanceof BQL.BQLError?e.message:"error: "+e.message;}
}
function qCell(v){if(Array.isArray(v))return esc(v.join(", "));return v==null?"":esc(String(v));}
function qTable(r){
  if(r.kind==="text")return `<div class="qhelp">${esc(r.note)}</div>`;
  const rowAttr=row=>row.ev&&/^ev_\d+$/.test(row.ev)?` data-ev="${row.ev.slice(3)}"`:(row.id&&r.kind==="nodes"?` data-node="${esc(row.id)}"`:"");
  return `<div class="card"><div class="bd" style="padding:0;overflow:auto"><table class="qtbl"><thead><tr>${r.columns.map(c=>`<th>${esc(c)}</th>`).join("")}</tr></thead><tbody>${
    r.rows.length?r.rows.map(row=>`<tr${rowAttr(row)}>${r.columns.map(c=>`<td>${qCell(row[c])}</td>`).join("")}</tr>`).join("")
    :`<tr><td colspan="${r.columns.length}"><div class="empty">No rows.</div></td></tr>`}</tbody></table></div></div>`;
}
function vQuery(){
  return `<h1 class="vt">Query</h1><p class="vsub">Ask the graph with <b>BQL</b> — HTTPQL-style filters over requests, nodes and edges, plus graph verbs (<span class="mono">reach</span>, <span class="mono">blast</span>, <span class="mono">path</span>). Answered from the model, cited, no AI. The same language runs against <span class="mono">graph.db</span> with <span class="mono">burp2model q</span>.</p>
  <div class="qbar"><textarea id="qin" spellcheck="false" placeholder='req.method:POST AND resp.code.gte:400    ·    reach "POST /api/checkout"    ·    help'>${esc(qText)}</textarea><button class="qrun" id="qgo">Run ⏎</button></div>
  <div class="qex">${Q_EXAMPLES.map(([t,q])=>`<button data-q="${esc(q)}" title="${esc(q)}">${esc(t)}</button>`).join("")}</div>
  <div id="qout">${qErr?`<div class="qerr">${esc(qErr)}</div>`:qRes?qOut():""}</div>
  ${qHist.length?`<div class="qhist">${qHist.map(h=>`<button data-q="${esc(h)}">${esc(h.length>60?h.slice(0,59)+"…":h)}</button>`).join("")}</div>`:""}`;
}
function qOut(){const r=qRes;return `<div class="qnote"><span>${esc(r.kind==="text"?"help":r.note)}</span><span class="sp"></span>${r.kind!=="text"?`<button id="qcopy">Copy JSON</button>`:""}</div>${qTable(r)}`;}
function initQuery(){
  const inp=$("#qin"),go=()=>{qRun(inp.value);render();};
  $("#qgo").onclick=go;
  inp.addEventListener("keydown",e=>{if(e.key==="Enter"&&!e.shiftKey){e.preventDefault();go();}});
  $$("[data-q]",$("#main")).forEach(b=>b.onclick=()=>{qRun(b.dataset.q);render();});
  const cp=$("#qcopy");if(cp)cp.onclick=()=>fallbackCopy(JSON.stringify(qRes,null,2),()=>{cp.textContent="Copied";});
  $$("tr[data-node]",$("#main")).forEach(r=>r.onclick=()=>{try{openNode(r.dataset.node);}catch(e){}});
  inp.focus();inp.setSelectionRange(inp.value.length,inp.value.length);
}

/* ---------- INFRASTRUCTURE (external recon, stored in graph.db) ---------- */
function vInfra(){
  const B=D.bql;
  if(!B||!B.osint)return `<h1 class="vt">Infrastructure</h1><p class="vsub">External recon — DNS, certificates, subdomains, mail policy, headers.</p><div class="empty">No recon stored. Builds run OSINT by default; it was skipped (offline / <span class="mono">--no-osint</span>) or failed. Run <span class="mono">burp2model osint HOST -w ${esc(D.app)} --yes</span>.</div>`;
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
  return `<h1 class="vt">Infrastructure <span class="tag-ext">EXTERNAL</span></h1><p class="vsub">Public recon on <b class="mono">${esc(B.osint.host)}</b> (run #${B.osint.id}, ${esc(B.osint.generated_at)}). It lives in the graph as <span class="mono">EXTERNAL</span> edges — a separate provenance from traffic you captured or code that referenced a path. ${unseen.length?`<b>${unseen.length}</b> of ${subs.length} subdomain(s) never appeared in your capture.`:""}</p>${subCard}${cards}`;
}

/* ---------- PRIORITIES ---------- */
function vPriorities(){
  let h=`<h1 class="vt">Priorities</h1><p class="vsub">The endpoints and trust gaps worth a look first, ranked. Each is a <b>hypothesis</b> with the evidence to test it — never a finding. Click any item for its evidence.</p>`;
  if(!PRIO.length && !weakCookies.length) return h+`<div class="empty">Nothing stood out in this capture. That is a statement about the capture, not the target.</div>`;
  h+=PRIO.map((p,i)=>prioCard(p,i)).join("");
  if(weakCookies.length){
    h+=`<h1 class="vt" style="font-size:16px;margin:22px 0 10px">Cookie flags</h1>`;
    h+=weakCookies.map(k=>{const miss=[!k.httponly&&"HttpOnly",!k.secure&&"Secure"].filter(Boolean);
      return `<div class="prio sev-warn"><div class="rank">⚑</div><div class="body"><div class="ttl"><span class="mono">${esc(k.name)}</span> <span style="color:var(--muted);font-weight:400">cookie set without ${miss.join(" + ")}</span></div>
      <div class="why">SameSite=${esc(k.samesite||"unset")}. Missing ${miss.join("/")} weakens the cookie against theft or cross-site use.</div>
      <div class="nx"><b>Next</b> Confirm whether this cookie carries session or auth state.</div></div></div>`;}).join("");
  }
  return h;
}

/* ---------- ATTACK SURFACE ---------- */
function facets(){
  const hosts=[...new Set(EP.map(e=>e.host))].sort();
  const methods=[...new Set(EP.map(e=>e.method))].sort();
  const roles=D.roles||[];
  const grp=(lab,key,opts,fmt)=>`<div class="fg"><span class="lab">${lab}</span><div class="chipwrap">
   ${opts.map(o=>`<button class="chip${filters[key].has(o)?' on':''}" data-fk="${key}" data-fv="${esc(o)}">${fmt?fmt(o):esc(o)}</button>`).join("")}</div></div>`;
  return `<div class="filters">
   ${grp("Method","method",methods)}
   ${grp("Host","host",hosts)}
   ${roles.length?grp("Reached by","role",roles):""}
   ${grp("Credentials","cred",["with","without"],o=>o==="with"?"sent":"none seen")}
  </div>`;
}
function epPass(e){
  if(filters.method.size&&!filters.method.has(e.method))return false;
  if(filters.host.size&&!filters.host.has(e.host))return false;
  if(filters.role.size&&![...filters.role].every(r=>e.roles.includes(r)))return false;
  if(filters.cred.size){const has=e.credentials.length>0;if(filters.cred.has("with")&&!has)return false;if(filters.cred.has("without")&&has)return false;}
  return matchQ(e);
}
function vSurface(){
  const rows=EP.filter(epPass).sort(sortEP);
  const th=(k,l)=>`<th data-sort="${k}">${l} <span class="ar">${sortKey===k?(sortDir>0?"▲":"▼"):""}</span></th>`;
  return `<h1 class="vt">Endpoints</h1><p class="vsub">Every API endpoint the model knows — from the requests in your capture and from URLs found in the client code. Click any row for its parameters and the full request &amp; response.</p>
  ${facets()}
  <div class="card"><div class="hd">Endpoints <span class="ct">${rows.length} of ${EP.length}</span></div><div class="bd" style="padding:0">
  <table><thead><tr>${th("method","M")}${th("label","Endpoint")}${th("host","Host")}${th("statuses","Status")}${th("params","Params")}<th>Evidence</th></tr></thead><tbody>
  ${rows.length?rows.map(e=>`<tr data-ep="${esc(e.id)}">
    <td>${methodm(e.method)}</td>
    <td><span class="mono trunc" title="${esc(e.path)}">${esc(e.path)}</span>${e.privileged?' <span class="m w">admin</span>':""}</td>
    <td class="mono" style="color:var(--muted)">${esc(e.host)}</td>
    <td>${statuses(e.statuses)}</td>
    <td class="mono" style="color:var(--muted)">${e.params.length||"—"}</td>
    <td class="mono" style="color:var(--faint);font-size:11px">${(e.evidence||[]).slice(0,3).map(i=>"ev_"+i).join(", ")||"—"}</td></tr>`).join(""):`<tr><td colspan="6"><div class="empty">No endpoints match these filters.</div></td></tr>`}
  </tbody></table></div></div>`;
}
function sortEP(a,b){let x=a[sortKey],y=b[sortKey];if(sortKey==="params"){x=a.params.length;y=b.params.length;}if(sortKey==="statuses"){x=a.statuses[0]||0;y=b.statuses[0]||0;}
  if(Array.isArray(x))x=x.join();if(Array.isArray(y))y=y.join();return (x>y?1:x<y?-1:0)*sortDir;}

/* ---------- CLIENT CODE ---------- */
function vCode(){
  if(!D.scripts.length) return `<h1 class="vt">Client code</h1><p class="vsub">No JavaScript was captured. Re-run the capture with the app's script bundles included, and the map can add the endpoints the code references.</p><div class="empty">0 scripts in this model.</div>`;
  return `<h1 class="vt">Client code</h1><p class="vsub">Scripts served to the browser and the endpoints they reference. A reference is <b>inferred</b> — a URL in code is not proof of a call.</p>
  ${D.scripts.filter(s=>matchQ({label:s.label,host:s.host,params:s.references})).map(s=>`<div class="card"><div class="hd">${methodm("JS")} <span class="mono">${esc(s.label)}</span> <span class="ct">${esc(s.host)} · ${s.references.length} ref${s.references.length===1?"":"s"}</span></div>
   <div class="bd" style="padding:12px 16px">${s.references.length?`<div class="taglist">${s.references.map(r=>`<span>${esc(r)}</span>`).join("")}</div>`:'<div style="color:var(--faint)">No endpoint references extracted.</div>'}</div></div>`).join("")}`;
}

/* ---------- SUPPLY CHAIN ---------- */
function vSupply(){
  if(!D.third_parties.length) return `<h1 class="vt">Supply chain</h1><p class="vsub">Off-scope hosts the app talked to or referenced.</p><div class="empty">No third parties in this capture.</div>`;
  return `<h1 class="vt">Supply chain</h1><p class="vsub">Hosts outside the app's own domain that it loaded code from or sent requests to. Each is code you don't control running in your users' context.</p>
  <div class="card"><div class="bd" style="padding:0"><table><thead><tr><th>Third party</th><th>Requests</th><th>Referenced by</th><th>Evidence</th></tr></thead><tbody>
  ${D.third_parties.filter(t=>matchQ({label:t.label,params:t.referenced_by})).map(t=>`<tr><td class="mono">${esc(t.label)}</td><td class="mono">${t.requests}</td>
   <td class="mono" style="color:var(--muted)">${(t.referenced_by||[]).map(esc).join(", ")||"—"}</td>
   <td class="mono" style="color:var(--faint);font-size:11px">${(t.evidence||[]).slice(0,3).map(i=>"ev_"+i).join(", ")}</td></tr>`).join("")}
  </tbody></table></div></div>`;
}

/* ---------- TRUST ---------- */
function vTrust(){
  const cookies=D.cookies||[],auth=D.auth||[];
  let h=`<h1 class="vt">Trust</h1><p class="vsub">How the app authenticates and keeps state: credential schemes seen on requests, and cookies with their protective flags.</p>`;
  h+=`<div class="card"><div class="hd">Authentication <span class="ct">${auth.length}</span></div><div class="bd" style="padding:0">`;
  h+=auth.length?`<table><thead><tr><th>Scheme</th><th>Seen on endpoints</th></tr></thead><tbody>${auth.map(a=>`<tr><td class="mono">${esc(a.label)}</td><td class="mono" style="color:var(--muted)">${a.endpoints.length}</td></tr>`).join("")}</tbody></table>`:`<div class="empty">No credentials observed in the capture.</div>`;
  h+=`</div></div>`;
  h+=`<div class="card"><div class="hd">Cookies <span class="ct">${cookies.length}</span></div><div class="bd" style="padding:0">`;
  h+=cookies.length?`<table><thead><tr><th>Name</th><th>HttpOnly</th><th>Secure</th><th>SameSite</th></tr></thead><tbody>${cookies.map(k=>{
    const f=(v)=>v?'<span class="st g">yes</span>':'<span class="st r">no</span>';
    return `<tr><td class="mono">${esc(k.name)}</td><td>${f(k.httponly)}</td><td>${f(k.secure)}</td><td class="mono">${esc(k.samesite||"unset")}</td></tr>`;}).join("")}</tbody></table>`:`<div class="empty">No Set-Cookie observed.</div>`;
  h+=`</div></div>`;
  if((D.operations||[]).length)h+=`<div class="card"><div class="hd">GraphQL operations <span class="ct">${D.operations.length}</span></div><div class="bd" style="padding:12px 16px"><div class="taglist">${D.operations.map(o=>`<span>${esc(o.label)}</span>`).join("")}</div></div></div>`;
  const secrets=D.secrets||[];
  h+=`<div class="card"><div class="hd">Masked secrets <span class="ct">${secrets.length}</span></div><div class="bd" style="padding:0">`;
  h+=secrets.length?`<table><thead><tr><th>Kind</th><th>Length</th><th>Entropy</th><th>Seen</th><th>Evidence</th></tr></thead><tbody>${secrets.map(s=>
    `<tr><td class="mono">${esc(s.kind)}</td><td class="mono" style="color:var(--muted)">${s.length} chars</td>
     <td class="mono" style="color:var(--muted)">${(s.entropy??0).toFixed(2)} bits/char</td><td class="mono">×${s.count}</td>
     <td class="mono" style="color:var(--faint);font-size:11px">${(s.evidence||[]).slice(0,3).map(i=>"ev_"+i).join(", ")}</td></tr>`).join("")}</tbody></table>
   <div class="glegend" style="border-top:1px solid var(--line)">Values were masked before anything reached disk; only kind, shape and a keyed fingerprint are kept.</div>`
   :`<div class="empty">No secret-shaped values were observed in the capture.</div>`;
  h+=`</div></div>`;
  return h;
}

/* ---------- CROSS-ROLE ---------- */
function vCrossrole(){
  const roles=D.roles||[];
  const reached=EP.filter(e=>e.roles.length);
  let h=`<h1 class="vt">Cross-role surface</h1><p class="vsub">Which role reached which endpoint, and the status each got back. Divergence is a broken-access-control <b>hypothesis</b> — replay across accounts to confirm.</p>`;
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
function vUnknowns(){
  let h=`<h1 class="vt">Open questions</h1><p class="vsub">What this capture could not answer, spelled out rather than left blank. Each says what we saw, what stays unknown, and how to find out.</p>`;
  if(!D.unknowns.length)return h+`<div class="empty">Nothing was left open in this capture.</div>`;
  h+=D.unknowns.map(u=>`<div class="unk"><div class="ut">${esc(openTitle(u.type))}</div><div class="ue mono">${esc(u.entity)}</div>
   <ul>${u.we_know.map(k=>`<li>${esc(k)}</li>`).join("")}<li style="color:var(--signal)">Unknown: ${esc(u.we_dont_know)}</li></ul>
   <div class="nx"><b>To find out</b> ${esc(u.next)}</div></div>`).join("");
  return h;
}

/* ---------- EVIDENCE ---------- */
let evQ="",evErr=null;
function evFilter(all){
  evErr=null;
  if(!evQ||!BQLDB)return all;
  try{const r=BQL.run(BQLDB,evQ+" limit 5000");
    if(r.kind!=="requests"){evErr="Evidence filters requests — use req.* / resp.* fields.";return all;}
    const ids=new Set(r.rows.map(x=>+x.ev.slice(3)));return all.filter(e=>ids.has(e.id));}
  catch(e){evErr=e.message;return all;}
}
function vEvidence(){
  const all=Object.values(D.evidence||{}).sort((a,b)=>a.id-b.id);
  const base=evFilter(all);
  const rows=base.filter(ev=>!query||`${ev.method} ${ev.host}${ev.path} ${ev.status} ${ev.role||""}`.toLowerCase().includes(query.toLowerCase()));
  return `<h1 class="vt">Evidence</h1><p class="vsub">Every request the model was built from, in capture order. Each <span class="mono">ev_N</span> cited anywhere in this report resolves to one of these rows. Click a row for the redacted request &amp; response.</p>
  ${BQLDB?`<div class="evq"><input id="evq" spellcheck="false" placeholder='filter with BQL — e.g. req.method:POST AND resp.code.gte:400' value="${esc(evQ)}"></div>${evErr?`<div class="qerr" style="margin-bottom:12px">${esc(evErr)}</div>`:""}`:""}
  <div class="card"><div class="hd">Requests <span class="ct">${rows.length} of ${all.length}</span></div><div class="bd" style="padding:0">
  <table><thead><tr><th>Id</th><th>Method</th><th>Request</th><th>Status</th><th>Role</th></tr></thead><tbody>
  ${rows.length?rows.map(ev=>`<tr data-ev="${ev.id}">
    <td class="mono" style="color:var(--signal);font-weight:600">ev_${ev.id}</td>
    <td>${methodm(ev.method)}</td>
    <td><span class="mono trunc" title="${esc(ev.host)}${esc(ev.path)}">${esc(ev.host)}<span style="color:var(--muted)">${esc(ev.path)}</span></span></td>
    <td>${statuses(ev.status==null?[]:[ev.status])}</td>
    <td class="mono" style="color:var(--muted)">${esc(ev.role||"—")}</td></tr>`).join("")
   :`<tr><td colspan="5"><div class="empty">No evidence rows match this search.</div></td></tr>`}
  </tbody></table></div></div>`;
}
function initEvq(){
  const i=$("#evq");if(!i)return;
  i.addEventListener("keydown",e=>{if(e.key==="Enter"){evQ=i.value.trim();render();const n=$("#evq");if(n){n.focus();n.setSelectionRange(n.value.length,n.value.length);}}});
}
function openEv(i){
  const ev=D.evidence["ev_"+i];if(!ev)return;
  $("#dtitle").innerHTML=`<span class="mono">ev_${i}</span>`;
  $("#dbody").innerHTML=`<h4>Attributes</h4><div class="kv">
    <div class="k">Request</div><div class="v mono">${esc(ev.method)} ${esc(ev.host)}${esc(ev.path)}</div>
    <div class="k">Status</div><div class="v mono">${ev.status==null?"?":ev.status}</div>
    ${ev.mime?`<div class="k">MIME</div><div class="v mono">${esc(ev.mime)}</div>`:""}
    ${ev.role?`<div class="k">Role</div><div class="v mono">${esc(ev.role)}</div>`:""}
    ${ev.source?`<div class="k">Source</div><div class="v mono">${esc(ev.source)}${ev.item!=null?` · item ${ev.item}`:""}</div>`:""}
   </div><h4>Request &amp; response</h4>${evidenceBlock(i,true)}`;
  $("#drawer").classList.add("on");$("#scrim").classList.add("on");$("#drawer").setAttribute("aria-hidden","false");
}

/* ---------- MAP (stable, categorized) ---------- */
const CAT=[
  {id:"infra",label:"Infrastructure",short:"Infra",types:["infra"],color:"var(--l6)",shape:"square"},
  {id:"host",label:"Hosts",short:"Hosts",types:["host"],color:"var(--l1)",shape:"rsquare"},
  {id:"tech",label:"Technology",short:"Tech",types:["tech"],color:"var(--l5)",shape:"hex"},
  {id:"route",label:"Pages / routes",short:"Pages",types:["route"],color:"var(--l2)",shape:"circle"},
  {id:"script",label:"Scripts",short:"Scripts",types:["script"],color:"var(--l3)",shape:"diamond"},
  {id:"endpoint",label:"API endpoints",short:"Endpoints",types:["endpoint"],color:"var(--l4)",shape:"circle"},
  {id:"param",label:"Parameters & operations",short:"Params",types:["parameter","operation"],color:"var(--l4)",shape:"dot"},
  {id:"trust",label:"Trust & third parties",short:"Trust",types:["third_party","auth","cookie","role"],color:"var(--l5)",shape:"tri"},
];
function catOf(t){for(let i=0;i<CAT.length;i++)if(CAT[i].types.includes(t))return i;return CAT.length-1;}
/* map state: which layers are shown, which layout, per viewer */
const GN=(D.graph.nodes||[]).length;
let gHidden=new Set(GN>80?["param"]:[]), gLayout="layered";
try{const s=JSON.parse(localStorage.getItem("b2m-map")||"null");if(s){gHidden=new Set(s.hidden||[]);gLayout=s.layout||gLayout;}}catch(e){}
function gSave(){try{localStorage.setItem("b2m-map",JSON.stringify({hidden:[...gHidden],layout:gLayout}));}catch(e){}}
/* node glyphs: one shape per kind, so the map reads without the legend */
function shapePath(shape,r){
  const s=r*1.15;
  switch(shape){
    case "square":return `M${-s} ${-s}H${s}V${s}H${-s}Z`;
    case "rsquare":{const k=s*.45;return `M${-s+k} ${-s}H${s-k}Q${s} ${-s} ${s} ${-s+k}V${s-k}Q${s} ${s} ${s-k} ${s}H${-s+k}Q${-s} ${s} ${-s} ${s-k}V${-s+k}Q${-s} ${-s} ${-s+k} ${-s}Z`;}
    case "diamond":return `M0 ${-s*1.2}L${s*1.2} 0L0 ${s*1.2}L${-s*1.2} 0Z`;
    case "hex":return [0,1,2,3,4,5].map(i=>{const a=Math.PI/3*i;return (i?"L":"M")+(s*Math.cos(a)).toFixed(2)+" "+(s*Math.sin(a)).toFixed(2);}).join("")+"Z";
    case "tri":return `M0 ${-s*1.15}L${s*1.1} ${s*.75}L${-s*1.1} ${s*.75}Z`;
    case "dot":{const d=Math.max(3,r*.7);return `M${-d} 0a${d} ${d} 0 1 0 ${2*d} 0a${d} ${d} 0 1 0 ${-2*d} 0`;}
    default:return `M${-r} 0a${r} ${r} 0 1 0 ${2*r} 0a${r} ${r} 0 1 0 ${-2*r} 0`;
  }
}
function vGraph(){
  const present=CAT.map((cat,i)=>({cat,i,n:(D.graph.nodes||[]).filter(x=>catOf(x.type)===i).length})).filter(x=>x.n);
  const hasInfra=present.some(x=>x.cat.id==="infra");
  return `<h1 class="vt">Map</h1><p class="vsub">The whole app as one graph: hosts and the technology they run, pages, scripts, endpoints and their parameters, the trust layer${hasInfra?", and the external footprint from recon":""}. <b>Solid</b> lines were seen in traffic, <b>dashed</b> lines were found in the client code${hasInfra?", <b>dotted</b> lines come from external recon":""}. Hover to trace, click to open, drag to rearrange.</p>
  <div class="graphwrap">
   <div class="gtools">
    <div class="chipwrap" id="glayers">${present.map(x=>`<button class="chip${gHidden.has(x.cat.id)?" off":""}" data-glayer="${x.cat.id}" title="show / hide"><span class="sw" style="background:${x.cat.color}"></span>${esc(x.cat.label)} <span class="c">${x.n}</span></button>`).join("")}</div>
    <div class="gseg" role="group" aria-label="Layout"><button data-glayout="layered" class="${gLayout==="layered"?"on":""}">Layered</button><button data-glayout="force" class="${gLayout==="force"?"on":""}">Force</button></div>
    <div class="gbtns"><button class="gbtn" data-gz="in" aria-label="Zoom in">+</button><button class="gbtn" data-gz="out" aria-label="Zoom out">−</button><button class="gbtn" data-gz="fit">Fit</button><button class="gbtn" id="gexport" title="Download the map as an SVG file">Export SVG</button></div>
   </div>
   <div style="position:relative"><div class="ghint">${GN} nodes · hover to trace · drag node or canvas · scroll to zoom · double-click to reset</div><svg id="gsvg" role="img" aria-label="Web-app model graph"></svg></div>
   <div class="glegend">
    ${present.map(x=>`<span class="k"><svg width="12" height="12" viewBox="-7 -7 14 14"><path d="${shapePath(x.cat.shape,5)}" fill="${x.cat.color}"/></svg>${esc(x.cat.label)}</span>`).join("")}
    <span class="k"><span class="ln2"></span>seen in traffic</span><span class="k"><span class="ln2 inf"></span>found in code</span>${hasInfra?`<span class="k"><span class="ln2" style="border-top-style:dotted;border-color:var(--l6)"></span>external recon</span>`:""}
   </div></div>`;
}
function initGraph(){
  const svg=$("#gsvg");if(!svg)return;
  svg.innerHTML="";
  const NS="http://www.w3.org/2000/svg";
  const nodes=D.graph.nodes.map(n=>({...n,cat:catOf(n.type)})).filter(n=>!gHidden.has(CAT[n.cat].id));
  const idx=Object.fromEntries(nodes.map((n,i)=>[n.id,i]));
  const edges=D.graph.edges.filter(e=>idx[e.s]!=null&&idx[e.d]!=null);
  const deg={};edges.forEach(e=>{deg[e.s]=(deg[e.s]||0)+1;deg[e.d]=(deg[e.d]||0)+1;});
  const nbr={};edges.forEach(e=>{(nbr[e.s]=nbr[e.s]||[]).push(e.d);(nbr[e.d]=nbr[e.d]||[]).push(e.s);});
  if(!nodes.length){svg.setAttribute("viewBox","0 0 600 200");svg.innerHTML='<text x="300" y="100" text-anchor="middle" font-size="13" fill="var(--faint)">Every layer is hidden — turn one back on above.</text>';}

  /* deterministic column layout. Rows are ordered by repeated barycenter
     sweeps (each node moves toward the average row of its neighbours), which
     collapses most edge crossings while staying perfectly reproducible:
     same model, same picture. */
  const cols=CAT.map((_,i)=>i).filter(i=>nodes.some(n=>n.cat===i));
  const ROWH=30, TOP=64, maxL=cols.length>6?22:26;
  const byCol={};cols.forEach(ci=>byCol[ci]=nodes.filter(n=>n.cat===ci)
    .sort((a,b)=>String(a.label).localeCompare(String(b.label))));
  /* each column is as wide as its longest (truncated) label needs, so eight
     sparse columns don't force the whole picture to shrink */
  /* a column longer than SUB rows wraps into side-by-side sub-columns, so a
     real app's 80 endpoints read as a block instead of a thin 2,500px strip */
  const SUB=26, colX={};let left=70;
  cols.forEach(ci=>{const longest=Math.max(...byCol[ci].map(n=>Math.min(maxL,String(n.label||"").length)));
    const w=Math.min(250,Math.max(140,46+longest*6.4));
    const nsub=Math.max(1,Math.ceil(byCol[ci].length/SUB));
    colX[ci]=[];for(let k=0;k<nsub;k++){colX[ci].push(left+16);left+=w;}});
  const COLW=cols.length?(left-70)/cols.length:248;
  const rank={};cols.forEach(ci=>byCol[ci].forEach((n,r)=>rank[n.id]=r));
  for(let sweep=0;sweep<6;sweep++){
    const order=sweep%2?cols.slice().reverse():cols;
    order.forEach(ci=>{
      const col=byCol[ci];
      const bary=n=>{const ns=(nbr[n.id]||[]).map(o=>rank[o]).filter(v=>v!=null);
        return ns.length?ns.reduce((a,b)=>a+b,0)/ns.length:rank[n.id];};
      col.sort((a,b)=>bary(a)-bary(b)||String(a.label).localeCompare(String(b.label)));
      col.forEach((n,r)=>rank[n.id]=r);
    });
  }
  const maxRows=Math.max(1,...cols.map(ci=>Math.min(SUB,byCol[ci].length)));
  cols.forEach(ci=>{
    const col=byCol[ci];
    const off=(maxRows-Math.min(SUB,col.length))*ROWH/2;   // centre short columns vertically
    col.forEach((n,r)=>{n.x=colX[ci][Math.floor(r/SUB)];n.y=TOP+off+(r%SUB)*ROWH;n.hx=n.x;n.hy=n.y;});
  });
  let W=left+40, H=Math.max(320,TOP+maxRows*ROWH+30);

  /* force layout: a small deterministic simulation seeded from the layered
     positions. Nodes repel, edges pull, each kind is loosely tethered to its
     column so the picture stays readable. No randomness, so it is stable. */
  if(gLayout==="force"&&nodes.length){
    const cy=H/2;
    nodes.forEach((n,i)=>{n.x=n.hx+((i*37)%11-5)*3;n.y=n.hy+((i*53)%13-6)*3;n.vx=0;n.vy=0;});
    const K=Math.max(90,Math.sqrt(W*H/nodes.length)*0.55);
    for(let it=0;it<260;it++){
      const t=1-it/260, step=0.85*t+0.05;
      for(let i=0;i<nodes.length;i++){const a=nodes[i];
        for(let j=i+1;j<nodes.length;j++){const b=nodes[j];
          let dx=b.x-a.x,dy=b.y-a.y;let d2=dx*dx+dy*dy;if(d2<1){dx=(i-j)*.01;dy=.01;d2=.0002;}
          if(d2>K*K*9)continue;
          const d=Math.sqrt(d2), f=(K*K)/d2*0.9, fx=dx/d*f, fy=dy/d*f;
          a.vx-=fx;a.vy-=fy;b.vx+=fx;b.vy+=fy;}}
      edges.forEach(e=>{const a=nodes[idx[e.s]],b=nodes[idx[e.d]];const dx=b.x-a.x,dy=b.y-a.y;const d=Math.max(1,Math.sqrt(dx*dx+dy*dy));
        const f=(d-K*0.9)/d*0.06;a.vx+=dx*f;a.vy+=dy*f;b.vx-=dx*f;b.vy-=dy*f;});
      nodes.forEach(n=>{n.vx+=(n.hx-n.x)*0.012;n.vy+=(cy-n.y)*0.004;   // column tether + light gravity
        n.x+=n.vx*step;n.y+=n.vy*step;n.vx*=0.55;n.vy*=0.55;});
    }
    let minX=1e9,minY=1e9,maxX=-1e9,maxY=-1e9;
    nodes.forEach(n=>{minX=Math.min(minX,n.x);minY=Math.min(minY,n.y);maxX=Math.max(maxX,n.x);maxY=Math.max(maxY,n.y);});
    const pad=140;nodes.forEach(n=>{n.x=n.x-minX+pad;n.y=n.y-minY+60;n.hx=n.x;n.hy=n.y;});
    W=maxX-minX+pad*2+120;H=Math.max(480,maxY-minY+120);
  }

  svg.setAttribute("viewBox",`0 0 ${W} ${H}`);
  /* let the box follow the graph's own aspect ratio instead of letterboxing a
     wide graph inside a tall fixed frame */
  {const bw=svg.getBoundingClientRect().width||1100;svg.style.height=Math.round(Math.max(360,Math.min(820,bw*H/W)))+"px";}
  const gHead=document.createElementNS(NS,"g"),gE=document.createElementNS(NS,"g"),gN=document.createElementNS(NS,"g");
  /* arrowheads: direction is part of the fact (a page CALLS an endpoint) */
  const defs=document.createElementNS(NS,"defs");
  defs.innerHTML='<marker id="mArr" viewBox="0 0 8 8" refX="7" refY="4" markerWidth="7" markerHeight="7" orient="auto-start-reverse"><path d="M0 0.6 8 4 0 7.4z" fill="var(--line2)"/></marker>'
    +'<marker id="mArrInf" viewBox="0 0 8 8" refX="7" refY="4" markerWidth="7" markerHeight="7" orient="auto-start-reverse"><path d="M0 0.6 8 4 0 7.4z" fill="var(--inferred)" opacity=".7"/></marker>'
    +'<marker id="mArrExt" viewBox="0 0 8 8" refX="7" refY="4" markerWidth="7" markerHeight="7" orient="auto-start-reverse"><path d="M0 0.6 8 4 0 7.4z" fill="var(--l6)" opacity=".6"/></marker>';
  svg.append(defs,gE,gN,gHead);
  if(gLayout==="layered")cols.forEach(ci=>{const t=document.createElementNS(NS,"text");t.setAttribute("x",colX[ci][0]);t.setAttribute("y",30);
    t.setAttribute("text-anchor","middle");t.setAttribute("font-size","11");t.setAttribute("font-weight","700");
    t.setAttribute("fill","var(--muted)");t.setAttribute("letter-spacing",".04em");t.textContent=(cols.length>6?CAT[ci].short:CAT[ci].label).toUpperCase();gHead.append(t);});
  const rOf=n=>5+Math.min(7,(deg[n.id]||0)*1.1);
  const edgeCls=s=>s==="INFERRED"?" inf":s==="EXTERNAL"?" ext":"";
  const edgeNote=s=>s==="INFERRED"?" (found in code)":s==="EXTERNAL"?" (external recon)":" (seen in traffic)";
  const eEls=edges.map(e=>{const l=document.createElementNS(NS,"path");l.setAttribute("class","gedge"+edgeCls(e.state));
    l.setAttribute("marker-end",e.state==="INFERRED"?"url(#mArrInf)":e.state==="EXTERNAL"?"url(#mArrExt)":"url(#mArr)");
    const ti=document.createElementNS(NS,"title");
    ti.textContent=`${nodes[idx[e.s]].label} ${humanize(e.type).toLowerCase()} ${nodes[idx[e.d]].label}`+edgeNote(e.state);
    l.append(ti);gE.append(l);return{e,l};});
  const q=(query||"").toLowerCase();
  const nEls=nodes.map(n=>{const g=document.createElementNS(NS,"g");g.setAttribute("class","gnode"+(q&&String(n.label).toLowerCase().includes(q)?" q":""));
    const r=rOf(n);
    const c=document.createElementNS(NS,"path");c.setAttribute("class","shape");
    c.setAttribute("d",shapePath(CAT[n.cat].shape,r));c.setAttribute("fill",CAT[n.cat].color);
    const t=document.createElementNS(NS,"text");let lbl=n.label||"";if(lbl.length>maxL)lbl=lbl.slice(0,maxL-1)+"…";
    t.textContent=lbl;t.setAttribute("x",r*1.15+6);t.setAttribute("y",4);t.setAttribute("text-anchor","start");
    const ti=document.createElementNS(NS,"title");ti.textContent=n.label+(n.detail?" — "+n.detail:"");g.append(c,t,ti);
    g.style.cursor="pointer";g.onclick=()=>{if(!dragged)openNode(n.id);};
    g.onpointerdown=ev=>{ev.preventDefault();ev.stopPropagation();drag=n;dragged=false;svg.setPointerCapture(ev.pointerId);};
    g.onpointerenter=()=>focus(n.id);g.onpointerleave=unfocus;
    gN.append(g);return{n,g};});
  svg.classList.toggle("gsearch",!!q&&nEls.some(({g})=>g.classList.contains("q")));

  /* hover: keep the node and everything it touches, fade the rest */
  function focus(id){
    svg.classList.add("gfocus");
    const keep=new Set([id]);
    eEls.forEach(({e,l})=>{const on=e.s===id||e.d===id;l.classList.toggle("hi",on);
      if(on){keep.add(e.s);keep.add(e.d);}});
    nEls.forEach(({n,g})=>g.classList.toggle("hi",keep.has(n.id)));
  }
  function unfocus(){svg.classList.remove("gfocus");
    eEls.forEach(({l})=>l.classList.remove("hi"));nEls.forEach(({g})=>g.classList.remove("hi"));}

  let drag=null,dragged=false,pan=null;
  function pt(ev){const m=svg.getScreenCTM().inverse();const p=svg.createSVGPoint();p.x=ev.clientX;p.y=ev.clientY;const q=p.matrixTransform(m);return{x:q.x,y:q.y};}
  let vb={x:0,y:0,w:W,h:H};
  const setVB=()=>svg.setAttribute("viewBox",`${vb.x} ${vb.y} ${vb.w} ${vb.h}`);
  const zoom=f=>{const cx=vb.x+vb.w/2,cy=vb.y+vb.h/2;vb={x:cx-vb.w*f/2,y:cy-vb.h*f/2,w:vb.w*f,h:vb.h*f};setVB();};
  /* drag empty canvas to pan */
  svg.addEventListener("pointerdown",ev=>{if(drag)return;pan={px:ev.clientX,py:ev.clientY,vx:vb.x,vy:vb.y};svg.setPointerCapture(ev.pointerId);});
  svg.addEventListener("pointermove",ev=>{
    if(drag){dragged=true;const p=pt(ev);drag.x=p.x;drag.y=p.y;draw();return;}
    if(pan){const k=vb.w/svg.getBoundingClientRect().width;
      vb.x=pan.vx-(ev.clientX-pan.px)*k;vb.y=pan.vy-(ev.clientY-pan.py)*k;setVB();}});
  svg.addEventListener("pointerup",()=>{if(drag){drag=null;setTimeout(()=>dragged=false,0);}pan=null;});
  svg.addEventListener("dblclick",()=>{nodes.forEach(n=>{n.x=n.hx;n.y=n.hy;});vb={x:0,y:0,w:W,h:H};setVB();draw();});
  svg.addEventListener("wheel",ev=>{ev.preventDefault();const p=pt(ev);const f=ev.deltaY<0?.85:1.18;
    vb={x:p.x-(p.x-vb.x)*f,y:p.y-(p.y-vb.y)*f,w:vb.w*f,h:vb.h*f};setVB();},{passive:false});

  /* toolbar */
  $$("[data-glayer]").forEach(b=>b.onclick=()=>{const k=b.dataset.glayer;gHidden.has(k)?gHidden.delete(k):gHidden.add(k);gSave();render();});
  $$("[data-glayout]").forEach(b=>b.onclick=()=>{if(gLayout!==b.dataset.glayout){gLayout=b.dataset.glayout;gSave();render();}});
  $$("[data-gz]").forEach(b=>b.onclick=()=>{const k=b.dataset.gz;if(k==="in")zoom(.8);else if(k==="out")zoom(1.25);else{vb={x:0,y:0,w:W,h:H};setVB();}});
  const ex=$("#gexport");if(ex)ex.onclick=()=>exportSvg(svg);

  function draw(){
    eEls.forEach(({e,l})=>{const A=nodes[idx[e.s]],B=nodes[idx[e.d]];
      const ra=rOf(A)*1.15, rb=rOf(B)*1.15;
      if(gLayout==="force"){
        /* straight, trimmed to the glyph edge on both ends */
        const dx=B.x-A.x,dy=B.y-A.y,d=Math.max(1,Math.sqrt(dx*dx+dy*dy)),ux=dx/d,uy=dy/d;
        l.setAttribute("d",`M${A.x+ux*ra} ${A.y+uy*ra} L${B.x-ux*(rb+2)} ${B.y-uy*(rb+2)}`);return;}
      /* leave the source at the side facing the target, land the same way */
      const sgn=B.x>=A.x?1:-1;
      const ax=A.x+sgn*ra, bx=B.x-sgn*rb;
      const dx=Math.max(30,Math.abs(bx-ax)*0.4);
      l.setAttribute("d",`M${ax} ${A.y} C ${ax+sgn*dx} ${A.y}, ${bx-sgn*dx} ${B.y}, ${bx} ${B.y}`);});
    nEls.forEach(({n,g})=>g.setAttribute("transform",`translate(${n.x} ${n.y})`));}
  draw();
}
/* download the map as a standalone SVG: CSS variables are resolved to the
   current theme's colours so the file renders anywhere */
function exportSvg(svg){
  const cs=getComputedStyle(document.documentElement);
  const resolve=s=>String(s).replace(/var\((--[a-z0-9-]+)\)/gi,(m,v)=>cs.getPropertyValue(v).trim()||m);
  const clone=svg.cloneNode(true);
  clone.setAttribute("xmlns","http://www.w3.org/2000/svg");
  clone.querySelectorAll("*").forEach(el=>{["fill","stroke"].forEach(a=>{const v=el.getAttribute(a);if(v&&v.includes("var("))el.setAttribute(a,resolve(v));});});
  const style=document.createElementNS("http://www.w3.org/2000/svg","style");
  style.textContent=resolve(`text{font:10px ui-monospace,Menlo,Consolas,monospace;fill:var(--text);paint-order:stroke;stroke:var(--panel);stroke-width:3px;stroke-linejoin:round}
.gedge{fill:none;stroke:var(--line2);stroke-width:1.2}.gedge.inf{stroke-dasharray:4 4;stroke:var(--inferred);opacity:.55}.gedge.ext{stroke-dasharray:1.5 3.5;stroke:var(--l6);opacity:.55}
.shape{stroke:var(--panel);stroke-width:2}`);
  clone.insertBefore(style,clone.firstChild);
  const rect=document.createElementNS("http://www.w3.org/2000/svg","rect");
  const vb=(clone.getAttribute("viewBox")||"0 0 800 600").split(" ");
  rect.setAttribute("x",vb[0]);rect.setAttribute("y",vb[1]);rect.setAttribute("width",vb[2]);rect.setAttribute("height",vb[3]);rect.setAttribute("fill",resolve("var(--panel)"));
  clone.insertBefore(rect,style.nextSibling);
  const blob=new Blob(['<?xml version="1.0" encoding="UTF-8"?>\n'+clone.outerHTML],{type:"image/svg+xml"});
  const u=URL.createObjectURL(blob);const a=document.createElement("a");a.href=u;a.download=(D.app||"model")+".map.svg";a.click();URL.revokeObjectURL(u);
}

/* ---------- HTTP panes (Burp-style, fully redacted) ---------- */
function httpHeaders(hs){return (hs||[]).map(([k,v])=>`<span class="hn">${esc(k)}</span>: <span class="${/\[REDACTED/i.test(v)?'rd':'hv'}">${esc(v)}</span>`).join("\n");}
function httpMsg(m){
  if(!m||(!m.line&&!(m.headers||[]).length&&!m.body))return `<div class="empty2">Not captured in this export.</div>`;
  const body=m.body?`\n\n<span class="bd2">${esc(m.body)}</span>${m.truncated?'\n<span class="trunc-note">… body truncated</span>':''}`
    :(m.truncated?'\n<span class="trunc-note">(body present but not stored)</span>':'');
  return `<pre><span class="ln">${esc(m.line||"")}</span>\n${httpHeaders(m.headers)}${body}</pre>`;
}
function evidenceBlock(i,open){
  const ev=D.evidence["ev_"+i];
  const meta=ev?`${esc(ev.method)} ${esc(ev.host)}${esc(ev.path)} → ${ev.status==null?"?":ev.status}`:"";
  const uid="e"+i+"x"+Math.random().toString(36).slice(2,7);
  const hasHttp=ev&&(ev.request||ev.response);
  return `<details class="evrow"${open?" open":""}><summary><span class="id">ev_${i}</span><span class="meta">${meta}</span></summary>${
   hasHttp?`<div class="http"><div class="tabs"><button class="tab on" data-tab="${uid}r">Request</button><button class="tab" data-tab="${uid}s">Response</button></div>
    <div id="${uid}r" class="pane">${httpMsg(ev.request)}</div><div id="${uid}s" class="pane hide">${httpMsg(ev.response)}</div>
    <div style="padding:7px 12px;color:var(--faint);font-size:11px;border-top:1px solid var(--line)">Every value masked at capture time.</div></div>`
   :`<div class="http"><div class="empty2">No request/response body was stored for this evidence id.</div></div>`}</details>`;
}

/* ---------- drawer ---------- */
function openEp(id){
  const e=EP.find(x=>x.id===id);if(!e)return;
  const sbr=e.status_by_role||{};
  const staticOnly=e.state==="STATIC_ONLY";
  const evrows=(e.evidence||[]).map((i,k)=>evidenceBlock(i,k===0)).join("");
  const kv=(k,v)=>v!=null&&v!==""&&!(Array.isArray(v)&&!v.length)?`<div class="k">${k}</div><div class="v">${v}</div>`:"";
  $("#dtitle").innerHTML=`${methodm(e.method)} <span class="mono">${esc(e.path)}</span>`;
  $("#dbody").innerHTML=`
   ${staticOnly?`<div class="callout" style="margin-bottom:16px"><span class="i">i</span><p>This endpoint was <b>referenced in the client code but never requested</b> in the capture, so there is no request or response for it. The evidence below is the page or script that names it — a good thing to try next.</p></div>`:""}
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
   <h4>Evidence — request &amp; response</h4>${evrows||'<div style="color:var(--faint)">—</div>'}`;
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
   ${(n.evidence||[]).length?`<h4>Evidence — request &amp; response</h4>${n.evidence.map((i,k)=>evidenceBlock(i,k===0)).join("")}`:""}`;
  $("#drawer").classList.add("on");$("#scrim").classList.add("on");$("#drawer").setAttribute("aria-hidden","false");
}
function closeDrawer(){$("#drawer").classList.remove("on");$("#scrim").classList.remove("on");$("#drawer").setAttribute("aria-hidden","true");}
$("#scrim").onclick=closeDrawer;$("#dclose").onclick=closeDrawer;
addEventListener("keydown",e=>{if(e.key==="Escape")closeDrawer();});
/* request/response tab switching inside the drawer (delegated) */
$("#dbody").addEventListener("click",e=>{const t=e.target.closest(".tab");if(!t)return;const pane=document.getElementById(t.dataset.tab);if(!pane)return;const wrap=t.closest(".http");$$(".tab",wrap).forEach(x=>x.classList.remove("on"));t.classList.add("on");$$(".pane",wrap).forEach(p=>p.classList.add("hide"));pane.classList.remove("hide");});

/* ---------- wire ---------- */
const RENDER={overview:vOverview,ask:vAsk,priorities:vPriorities,surface:vSurface,code:vCode,supply:vSupply,trust:vTrust,crossrole:vCrossrole,unknowns:vUnknowns,evidence:vEvidence,graph:vGraph,query:vQuery,infra:vInfra};
function render(){
  renderNav();
  try{if(!(view==="query"&&(location.hash||"").startsWith("#query=")))history.replaceState(null,"","#"+view);}catch(e){}
  const main=$("#main");
  main.innerHTML=`<section class="view on">${(RENDER[view]||vOverview)()}</section>
   <div class="foot">Generated by <b>burp2model ${esc(D.version)}</b>${D.generated?` on ${esc(D.generated)}`:""} — an evidence-backed model of a capture you provided. Not a scanner; nothing here is a vulnerability. · <a href="https://falc0n-researcher.github.io/burp2model/">docs</a></div>`;
  if(view==="graph")initGraph();
  if(view==="ask")initAsk();
  if(view==="query")initQuery();
  if(view==="evidence")initEvq();
  // row / card clicks → drawer
  $$("[data-ep]",main).forEach(el=>el.onclick=()=>openEp(el.dataset.ep));
  $$("[data-ev]",main).forEach(el=>el.onclick=()=>openEv(el.dataset.ev));
  $$("th[data-sort]",main).forEach(th=>th.onclick=()=>{const k=th.dataset.sort;if(sortKey===k)sortDir*=-1;else{sortKey=k;sortDir=1;}render();});
  $$(".chip[data-fk]",main).forEach(ch=>ch.onclick=()=>{const s=filters[ch.dataset.fk];s.has(ch.dataset.fv)?s.delete(ch.dataset.fv):s.add(ch.dataset.fv);render();});
  $$("[data-goto]",main).forEach(b=>b.onclick=()=>{view=b.dataset.goto;render();});
}
$("#q").addEventListener("input",e=>{query=e.target.value.trim();
  // a search jumps to the most relevant list view if on a summary view
  // on the Map, a search highlights matching nodes in place instead
  if(query&&["overview","ask","priorities"].includes(view))view="surface";
  render();});
addEventListener("keydown",e=>{
  if(e.key==="/"&&!e.metaKey&&!e.ctrlKey&&!/^(INPUT|TEXTAREA)$/.test(document.activeElement.tagName)){e.preventDefault();$("#q").focus();}
});
/* deep link: report.html#priorities opens that view */
/* report.html#query=<urlencoded BQL> opens the console with that query already run */
function fromHash(){
  const h=(location.hash||"").slice(1);
  if(h.startsWith("query=")&&BQLDB){let q="";try{q=decodeURIComponent(h.slice(6));}catch(e){}view="query";if(q&&q!==qText)qRun(q);return true;}
  if(RENDER[h]){view=h;return true;}
  return false;
}
fromHash();
addEventListener("hashchange",()=>{const was=view;if(fromHash()&&(view!==was||view==="query"))render();});
render();
</script>
</body>
</html>
"""
