"""
Deterministic queries over the model, plus the AI context package.

The queries answer facts with no language model involved — every line cites an
evidence index. The context package is what you hand an LLM *instead of* a raw
dump: the structure, not the bytes, with strict rules that keep the model
honest. Every evidence id the package cites is resolved in its `evidence`
table (method, host, templated path, status, role, source item), so a claim
can be checked against the capture without the capture being in the prompt.
"""

from __future__ import annotations

import json

from .model import PRIV_RE, Model

SOURCE = "Source: Knowledge Graph · Model call: none"

LENSES = ("attention", "auth", "all")


def _ev(n) -> str:
    return f"ev_{n.evidence[0]}" if n.evidence else "ev_?"


def _endpoints(m: Model):
    return [n for n in m.nodes.values() if n.type == "endpoint"]


def _params(m: Model, node_id: str) -> list[str]:
    return sorted(m.nodes[e.dst].label for e in m.edges
                  if e.src == node_id and e.type == "USES_PARAMETER" and e.dst in m.nodes)


def _mentioned_endpoints(m: Model, question: str):
    """Endpoints whose templated path appears in the question (longest first)."""
    hits = []
    for n in _endpoints(m):
        path = n.attrs.get("path", "")
        if len(path) > 1 and path in question:
            hits.append(n)
    hits.sort(key=lambda n: -len(n.attrs.get("path", "")))
    if not hits:
        return []
    best = len(hits[0].attrs["path"])
    return [n for n in hits if len(n.attrs["path"]) == best]


HELP = """intents query() answers (no AI, every line cited):
  list-apis                  every endpoint with state, statuses, evidence
  reconcile                  code vs runtime (also: "code vs runtime")
  list-routes                every route (pages, SPA states, forms)
  route-apis /x              APIs a route calls, directly or through its scripts
  provenance /api/orders     where an endpoint was seen: evidence, statuses, roles, callers
  third-parties              off-scope hosts
  auth-surface               credentials, roles, cookie flags
  unknowns                   what the capture could not answer
  entity-evidence <name>     evidence ids behind any node, by label
also: parameters, secrets (masked), privileged, errors, shape
anything else is refused: this answers from the model or says it cannot"""

# intent name -> canonical intent
_INTENTS = {
    "list-apis": "list-apis", "list apis": "list-apis", "apis": "list-apis",
    "endpoints": "list-apis", "list endpoints": "list-apis",
    "reconcile": "reconcile", "code vs runtime": "reconcile",
    "list-routes": "list-routes", "list routes": "list-routes", "routes": "list-routes",
    "third-parties": "third-parties", "third parties": "third-parties",
    "auth-surface": "auth-surface", "auth surface": "auth-surface",
    "unknowns": "unknowns", "shape": "shape", "summary": "shape", "overview": "shape",
}
_WITH_ARG = ("route-apis", "provenance", "entity-evidence")


def _refuse(m: Model, question: str) -> str:
    return "\n".join([
        f"cannot answer {question!r} from the {m.name} model.",
        "  nothing here matches a known intent, and this never guesses.",
        "  try: burp2model query <app> help",
        SOURCE])


def _list_apis(m: Model) -> str:
    eps = sorted(_endpoints(m), key=lambda n: n.label)
    lines = [f"{len(eps)} endpoints"]
    for n in eps:
        lines.append(f"  {n.label}  [{n.attrs.get('api_state')}]  "
                     f"{n.attrs.get('statuses', [])}  {_ev(n)}")
    lines.append(SOURCE)
    return "\n".join(lines)


def _list_routes(m: Model) -> str:
    rs = sorted((n for n in m.nodes.values() if n.type == "route"), key=lambda n: n.label)
    lines = [f"{len(rs)} routes"]
    for n in rs:
        lines.append(f"  {n.label}  {_ev(n)}")
    lines.append(SOURCE)
    return "\n".join(lines)


def _route_apis(m: Model, arg: str) -> str:
    routes = [n for n in m.nodes.values() if n.type == "route" and n.label == arg]
    if not routes:
        routes = sorted((n for n in m.nodes.values()
                         if n.type == "route" and arg and arg in n.label),
                        key=lambda n: (len(n.label), n.label))[:1]
    if not routes:
        return "\n".join([f"no route matching {arg!r} in the {m.name} model "
                          "(see: list-routes)", SOURCE])
    r = routes[0]
    scripts = {e.dst for e in m.edges if e.src == r.id and e.type == "INCLUDES"}
    lines = [f"route {r.label}"]
    seen = set()
    for e in m.edges:
        if e.type not in ("CALLS", "REFERENCES") or e.dst in seen:
            continue
        dst = m.nodes.get(e.dst)
        if dst is None or dst.type != "endpoint":
            continue
        if e.src == r.id:
            via = "directly"
        elif e.src in scripts:
            via = f"via {m.nodes[e.src].label}"
        else:
            continue
        seen.add(e.dst)
        lines.append(f"  {dst.label}  [{e.state}] {via}  "
                     f"ev_{e.evidence[0] if e.evidence else '?'}")
    if not seen:
        lines.append("  no API linked to this route in the capture "
                     "(a gap in observation, not a statement about the target)")
    lines.append(SOURCE)
    return "\n".join(lines)


def _entity_evidence(m: Model, arg: str) -> str:
    hits = sorted((n for n in m.nodes.values() if arg and (n.label == arg or arg in n.label)),
                  key=lambda n: (n.label != arg, len(n.label), n.label))[:10]
    if not hits:
        return "\n".join([f"no entity matching {arg!r} in the {m.name} model", SOURCE])
    by_id = {e["id"]: e for e in m.evidence_log}
    lines = []
    for n in hits:
        lines.append(f"{n.type} {n.label}")
        for i in n.evidence[:5]:
            e = by_id.get(i)
            what = f"{e['method']} {e['host']}{e['path']} -> {e['status']}" if e else ""
            lines.append(f"  ev_{i}  {what}")
        if not n.evidence:
            lines.append("  no evidence ids recorded")
    lines.append(SOURCE)
    return "\n".join(lines)


def query(m: Model, question: str) -> str:
    """Answer a factual question deterministically. No LLM."""
    q = question.lower().strip()
    lines: list[str] = []

    if q in ("help", "?", "") or q.startswith("help"):
        return HELP

    q = q.replace("_", "-")
    intent = _INTENTS.get(q)
    if intent == "list-apis":
        return _list_apis(m)
    if intent == "list-routes":
        return _list_routes(m)
    if intent == "shape":
        return _shape(m)
    if intent:
        q = {"third-parties": "third parties", "auth-surface": "auth",
             "reconcile": "code vs runtime"}.get(intent, intent)
    for word in _WITH_ARG:
        if q == word or q.startswith(word + " "):
            arg = question.strip()[len(word):].strip()
            if word == "route-apis":
                return _route_apis(m, arg)
            if word == "entity-evidence":
                return _entity_evidence(m, arg)
            if not arg:
                return "\n".join(["provenance needs an endpoint, e.g. provenance /api/orders",
                                  SOURCE])
            q = "endpoint " + arg.lower()
            question = "endpoint " + arg

    if "code vs runtime" in q or "reconcile" in q or "static" in q:
        eps = _endpoints(m)
        states: dict[str, list] = {"BOTH": [], "STATIC_ONLY": [], "RUNTIME_ONLY": []}
        for e in eps:
            states.setdefault(e.attrs.get("api_state", "RUNTIME_ONLY"), []).append(e)
        lines.append(f"APIs: {len(eps)} endpoints")
        for st in ("BOTH", "STATIC_ONLY", "RUNTIME_ONLY"):
            lines.append(f"  {st:<12} {len(states.get(st, []))}")
        static = sorted(states.get("STATIC_ONLY", []), key=lambda n: n.label)
        for e in static[:20]:
            lines.append(f"    static-only  {e.label}  {_ev(e)}")
        if len(static) > 20:
            lines.append(f"    … {len(static) - 20} more (see context.json)")
        lines.append("")
        lines.append(SOURCE)
        return "\n".join(lines)

    mentioned = _mentioned_endpoints(m, question)
    if mentioned and "route" not in q:
        for n in mentioned:
            a = n.attrs
            lines.append(f"endpoint {n.label}  [{a.get('api_state')}]")
            lines.append(f"  evidence    {', '.join(f'ev_{i}' for i in n.evidence[:8])}")
            if a.get("statuses"):
                lines.append(f"  statuses    {', '.join(map(str, a['statuses']))}")
            if n.roles:
                sbr = a.get("status_by_role", {})
                lines.append("  reached by  " + ", ".join(
                    f"{r} {sbr.get(r, [])}" for r in n.roles))
            if a.get("credentials"):
                lines.append(f"  credentials {', '.join(a['credentials'])}")
            if a.get("anonymous_requests"):
                lines.append(f"  anonymous   {a['anonymous_requests']} request(s) without credentials")
            params = _params(m, n.id)
            if params:
                lines.append(f"  params      {', '.join(params[:15])}")
            for e in m.edges:
                if e.dst == n.id and e.type in ("REFERENCES", "CALLS"):
                    src = m.nodes.get(e.src)
                    lines.append(f"  {e.type.lower():<11} from {src.label if src else e.src}"
                                 f"  [{e.state}]  ev_{e.evidence[0] if e.evidence else '?'}")
        lines.append(SOURCE)
        return "\n".join(lines)

    if "route" in q and ("where" in q or "come from" in q):
        routes = [n for n in m.nodes.values() if n.type == "route" and n.label in question]
        routes.sort(key=lambda n: -len(n.label))
        if routes:
            n = routes[0]
            lines.append(f"route {n.label}")
            for e in n.evidence[:4]:
                lines.append(f"   observed at runtime  ev_{e}")
            for e in m.edges:
                if e.dst == n.id and e.type == "NAVIGATES_TO":
                    lines.append(f"   navigated from {m.nodes[e.src].label}  ev_{e.evidence[0]}")
            lines.append(SOURCE)
            return "\n".join(lines)

    if "unknown" in q or "not known" in q or "missing" in q:
        lines.append(f"{len(m.unknowns)} named unknowns")
        for u in m.unknowns[:20]:
            ent = m.nodes[u.entity].label if u.entity in m.nodes else u.entity.split(":")[-1]
            lines.append(f"  {u.type:<34} {ent[:50]}")
        if len(m.unknowns) > 20:
            lines.append(f"  … {len(m.unknowns) - 20} more (see context.json)")
        lines.append("")
        lines.append("absence = a gap in observation, never a statement about the target")
        lines.append(SOURCE)
        return "\n".join(lines)

    if "param" in q:
        eps = sorted(_endpoints(m), key=lambda n: n.label)
        lines.append("parameters by endpoint (names only — values are never stored)")
        for n in eps:
            params = _params(m, n.id)
            if params:
                lines.append(f"  {n.label}  {_ev(n)}")
                lines.append(f"      {', '.join(params[:15])}")
        lines.append(SOURCE)
        return "\n".join(lines)

    if "secret" in q or "credential leak" in q:
        lines.append(f"{len(m.secrets)} distinct masked values (kind · length · entropy · seen)")
        for s in sorted(m.secrets, key=lambda s: (-s["count"], s["kind"]))[:20]:
            ev = ", ".join(f"ev_{i}" for i in s["evidence"][:3])
            lines.append(f"  {s['kind']:<22} {s['length']:>4} chars  {s['entropy']:.2f} bits/char"
                         f"  ×{s['count']}  {ev}")
        lines.append("values are never stored; fingerprints are keyed hashes")
        lines.append(SOURCE)
        return "\n".join(lines)

    if any(w in q for w in ("auth", "role", "cookie", "session", "trust")):
        lines.append(f"roles: {', '.join(sorted(m.roles)) or 'none tagged'}")
        for n in sorted((n for n in m.nodes.values() if n.type == "auth"), key=lambda n: n.label):
            used = sum(1 for e in m.edges if e.dst == n.id)
            lines.append(f"  auth    {n.label}  on {used} endpoint(s)  {_ev(n)}")
        for n in sorted((n for n in m.nodes.values() if n.type == "cookie"), key=lambda n: n.label):
            a = n.attrs
            flags = [f for f, on in (("HttpOnly", a.get("httponly")), ("Secure", a.get("secure"))) if on]
            missing = [f for f, on in (("HttpOnly", a.get("httponly")), ("Secure", a.get("secure"))) if not on]
            lines.append(f"  cookie  {n.label}  set {'+'.join(flags) or 'no flags'}"
                         f"{' · missing ' + '+'.join(missing) if missing else ''}"
                         f" · SameSite={a.get('samesite') or 'unset'}  {_ev(n)}")
        anon = [n for n in _endpoints(m) if n.attrs.get("anonymous_requests") and n.attrs.get("credentials")]
        for n in sorted(anon, key=lambda n: n.label)[:10]:
            lines.append(f"  mixed   {n.label} seen with and without credentials  {_ev(n)}")
        lines.append(SOURCE)
        return "\n".join(lines)

    if "privileg" in q or "admin" in q:
        eps = sorted((n for n in _endpoints(m) if PRIV_RE.search(n.attrs.get("path", ""))),
                     key=lambda n: n.label)
        lines.append(f"{len(eps)} privileged-looking endpoints (path heuristic)")
        for n in eps:
            who = f" reached by {', '.join(n.roles)}" if n.roles else ""
            lines.append(f"  {n.label}  [{n.attrs.get('api_state')}]{who}  {_ev(n)}")
        lines.append(SOURCE)
        return "\n".join(lines)

    if "error" in q or "fail" in q:
        eps = [n for n in _endpoints(m)
               if n.attrs.get("statuses") and all(s >= 400 for s in n.attrs["statuses"])]
        lines.append(f"{len(eps)} endpoints only ever returned errors")
        for n in sorted(eps, key=lambda n: n.label):
            lines.append(f"  {n.label}  {n.attrs['statuses']}  {_ev(n)}")
        lines.append(SOURCE)
        return "\n".join(lines)

    if "third" in q or "vendor" in q:
        tps = sorted((n for n in m.nodes.values() if n.type == "third_party"), key=lambda n: n.label)
        lines.append(f"{len(tps)} third parties")
        for t in tps[:30]:
            lines.append(f"  {t.label}  {t.attrs.get('requests', 0)} request(s)  {_ev(t)}")
        lines.append(SOURCE)
        return "\n".join(lines)

    return _refuse(m, question)


def _shape(m: Model) -> str:
    lines: list[str] = []
    c = m.counts()
    lines.append(f"{m.name} — model shape  (scope: {', '.join(m.scope) or '?'})")
    lines.append(f"  hosts {c['hosts']} · routes {c['routes']} · APIs {c['endpoints']} · scripts {c['scripts']}")
    lines.append(f"  third parties {c['third_parties']} · roles {c['roles']} · auth {c['auth']}"
                 f" · cookies {c['cookies']} · unknowns {c['unknowns']}")
    lines.append("  try: burp2model query <app> help")
    lines.append(SOURCE)
    return "\n".join(lines)


CONTEXT_RULES = [
    "Cite an evidence id (ev_N) for every claim; each id is resolved in `evidence`.",
    "Never name an endpoint, route or parameter that is not in this package.",
    "State unknowns explicitly; do not guess authorization behaviour.",
    "Output hypotheses and the evidence needed to test them, never findings or payloads.",
    "Treat an absence in this package as an absence in the capture, never in the target.",
    "REFERENCES edges are INFERRED from code; only OBSERVED facts happened in traffic.",
]


def _priority(n) -> tuple:
    a = n.attrs
    path = a.get("path", "")
    if a.get("api_state") == "STATIC_ONLY":
        rank = 0
    elif PRIV_RE.search(path):
        rank = 1
    elif n.roles:
        rank = 2
    elif a.get("credentials") and a.get("anonymous_requests"):
        rank = 3
    elif a.get("method") not in (None, "GET", "HEAD"):
        rank = 4
    else:
        rank = 5
    return (rank, n.label)


def osint_summary(osint: dict) -> dict:
    """A trimmed, LLM-facing view of an osint.json report. Facts, not findings."""
    if not osint:
        return {}
    tls = osint.get("tls", {})
    http = osint.get("http", {})
    email = osint.get("email_security", {})
    subs = osint.get("subdomains", {})
    reg = osint.get("registration", {})
    out = {
        "host": osint.get("host"),
        "collected_at": osint.get("generated_at"),
        "dns": {k: osint.get("dns", {}).get(k) for k in ("A", "AAAA", "MX", "NS", "CNAME")
                if osint.get("dns", {}).get(k)},
        "tls": {k: tls.get(k) for k in ("tls_version", "issuer", "not_after",
                                        "days_until_expiry") if tls.get(k) is not None},
        "security_headers_missing": http.get("security_headers_missing", []),
        "technology": [t["name"] for t in osint.get("technology", [])],
        "email_security": {k: email.get(k) for k in ("spf_note", "dmarc_policy", "dmarc_note",
                                                     "dkim_selector_found") if email.get(k)},
        "subdomains_count": subs.get("count"),
        "subdomains_sample": subs.get("names", [])[:25],
        "registrar": reg.get("registrar"),
        "hosting": {k: osint.get("ip_geo", {}).get(k) for k in ("network", "country")
                    if osint.get("ip_geo", {}).get(k)},
        "robots_disallow": (osint.get("files", {}).get("robots") or {}).get("disallow", [])[:20],
        "wayback_last_snapshot": (osint.get("archive") or {}).get("last_snapshot"),
        "open_ports": [p["port"] for p in osint.get("ports", {}).get("open", [])],
        "notes": osint.get("notes", []),
        "provenance": "external recon, collected live against the target; not from the capture",
    }
    return {k: v for k, v in out.items() if v not in (None, [], {}, "")}


def context_package(m: Model, lens: str = "attention", cap: int = 40,
                    osint: dict | None = None, graph: bool = True) -> dict:
    """Build the evidence package for an LLM. Capped and honest about it.

    lens:
      attention  every endpoint, most interesting first (STATIC_ONLY,
                 privileged-looking, role-reached, mixed auth, state-changing)
      auth       only endpoints with credentials or roles, plus the trust layer
      all        every endpoint in model order

    graph: also hand the model the graph itself (adjacency + reasoning views)
           so it can traverse and reason about structure, not just read a list.
    """
    if lens not in LENSES:
        raise ValueError(f"unknown lens {lens!r}; choose one of {', '.join(LENSES)}")

    nodes = list(m.nodes.values())
    eps_all = [n for n in nodes if n.type == "endpoint"]
    if lens == "auth":
        eps_all = [n for n in eps_all if n.roles or n.attrs.get("credentials")]
    if lens != "all":
        eps_all.sort(key=_priority)
    routes_all = [n for n in nodes if n.type == "route"]
    scripts_all = [n for n in nodes if n.type == "script"]
    tps_all = sorted((n for n in nodes if n.type == "third_party"),
                     key=lambda n: -n.attrs.get("requests", 0))

    rels: dict[str, dict[str, list[str]]] = {}
    refs_out: dict[str, int] = {}
    params_of: dict[str, list[str]] = {}
    for e in m.edges:
        if e.type == "REFERENCES":
            refs_out[e.src] = refs_out.get(e.src, 0) + 1
        elif e.type == "USES_PARAMETER" and e.dst in m.nodes:
            params_of.setdefault(e.src, []).append(m.nodes[e.dst].label)
        if e.type in ("REFERENCES", "CALLS"):
            src = m.nodes.get(e.src)
            if src is not None:
                key = "referenced_by" if e.type == "REFERENCES" else "called_from"
                rels.setdefault(e.dst, {}).setdefault(key, []).append(src.label)

    cited: set[int] = set()

    def evs(n, k=3):
        ids = n.evidence[:k]
        cited.update(ids)
        return [f"ev_{i}" for i in ids]

    def endpoint_view(n):
        a = n.attrs
        v = {"id": n.id, "type": n.type, "label": n.label, "api_state": a.get("api_state"),
             "evidence": evs(n)}
        if a.get("statuses"):
            v["statuses"] = a["statuses"]
        params = sorted(params_of.get(n.id, []))
        if params:
            v["params"] = params[:12]
        if n.roles:
            v["reached_by"] = n.roles
            v["status_by_role"] = a.get("status_by_role", {})
        if a.get("credentials"):
            v["credentials"] = a["credentials"]
        if a.get("anonymous_requests") and a.get("credentials"):
            v["also_seen_without_credentials"] = True
        for k, vals in rels.get(n.id, {}).items():
            v[k] = sorted(set(vals))[:5]
        if a.get("method_known") is False:
            v["method"] = "unknown (static reference)"
        return v

    def simple_view(n):
        return {"id": n.id, "type": n.type, "label": n.label, "evidence": evs(n)}

    endpoints = eps_all[:cap]
    routes = routes_all[:cap]
    scripts = scripts_all[:cap]
    tps = tps_all[:cap]
    # AUTHORIZATION_UNKNOWN exists for every role-reached endpoint, so when the
    # cap bites, keep the rarer, more specific unknowns first (stable order)
    unknowns = sorted(m.unknowns, key=lambda u: u.type == "AUTHORIZATION_UNKNOWN")[:cap]

    trust = {
        "auth": [dict(simple_view(n)) for n in nodes if n.type == "auth"],
        "cookies": [{**simple_view(n), "httponly": n.attrs.get("httponly"),
                     "secure": n.attrs.get("secure"), "samesite": n.attrs.get("samesite")}
                    for n in nodes if n.type == "cookie"],
    }
    stack = []
    for t in m.stack[:cap]:
        ids = t.get("evidence", [])[:2]
        cited.update(ids)
        stack.append({k: t[k] for k in ("name", "category") if t.get(k)}
                     | ({"kind": t["kind"]} if t.get("kind") else {})
                     | ({"version": t["version"]} if t.get("version") else {})
                     | {"evidence": [f"ev_{i}" for i in ids]})
    top_secrets = sorted(m.secrets, key=lambda s: (-s["count"], s["kind"]))[:20]
    secrets = [{"kind": s["kind"], "length": s["length"], "entropy": s["entropy"],
                "count": s["count"], "evidence": [f"ev_{i}" for i in s["evidence"][:3]]}
               for s in top_secrets]
    for s in top_secrets:
        cited.update(s["evidence"][:3])

    def cov(shown, total):
        return f"{shown}/{total}" + (" (capped)" if total > shown else "")

    from . import __version__
    package = {
        "tool": "burp2model",
        "version": __version__,
        "app": m.name,
        "lens": lens,
        "rules": CONTEXT_RULES,
        "scope": m.scope,
        "roles": sorted(m.roles),
        "shape": m.counts(),
        "routes": [simple_view(n) for n in routes],
        "endpoints": [endpoint_view(n) for n in endpoints],
        "scripts": [{**simple_view(n), "references": refs_out.get(n.id, 0)} for n in scripts],
        "third_parties": [simple_view(n) for n in tps],
        "stack": stack,
        "trust": trust,
        "secrets": secrets,
        "unknowns": [{"type": u.type,
                      "entity": m.nodes[u.entity].label if u.entity in m.nodes
                      else u.entity.split(":")[-1],
                      "we_know": u.we_know, "we_dont_know": u.we_dont_know,
                      "next": u.next_step} for u in unknowns],
        "coverage": {
            "routes": cov(len(routes), len(routes_all)),
            "endpoints": cov(len(endpoints), len(eps_all)),
            "scripts": cov(len(scripts), len(scripts_all)),
            "third_parties": cov(len(tps), len(tps_all)),
            "unknowns": cov(len(unknowns), len(m.unknowns)),
            "capture": {k: m.stats[k] for k in sorted(m.stats)},
            "note": "endpoints are ordered by the lens, so capping drops the least "
                    "interesting ones first" if lens != "all" else "model order",
        },
    }
    if graph:
        from .graph import reason_graph
        g = reason_graph(m, cap=max(cap, 60))
        package["graph"] = g

        def _collect_ev(obj):
            if isinstance(obj, dict):
                for k, v in obj.items():
                    if k == "evidence" and isinstance(v, list):
                        cited.update(i for i in v if isinstance(i, int))
                    else:
                        _collect_ev(v)
            elif isinstance(obj, list):
                for v in obj:
                    _collect_ev(v)
        _collect_ev(g)
    osint_view = osint_summary(osint)
    if osint_view:
        package["osint"] = osint_view
        package["rules"] = CONTEXT_RULES + [
            "OSINT is external recon, not from the capture; label it as such and don't "
            "conflate a subdomain or open port with an observed endpoint."]
    by_id = {e["id"]: e for e in m.evidence_log}
    package["evidence"] = {
        f"ev_{i}": {k: by_id[i][k] for k in ("method", "host", "path", "status", "role",
                                             "source", "item")}
        for i in sorted(cited) if i in by_id
    }
    package["token_estimate"] = len(json.dumps(package, separators=(",", ":"))) // 4
    return package
