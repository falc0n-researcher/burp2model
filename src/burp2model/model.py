"""
Build a web-app model from redacted Burp exchanges.

The model is a six-layer graph. Every node cites the exchange indices it came
from (its evidence). Every edge is OBSERVED (seen in traffic) or INFERRED
(deduced from static references). Nothing here is called a vulnerability.

Layers:
  1 edge      first-party hosts: schemes, ports, tech markers
  2 routes    pages / navigations
  3 code      scripts (JS)
  4 apis      endpoints, parameters, GraphQL operations, with api_state
  5 trust     third parties, roles, auth schemes, cookies (names + flags only)
  6 unknowns  named blind spots

Scope: the app is not one host. By default every host under the registrable
domain of the busiest host (per the Public Suffix List, see domains.py) is
first-party: www., api., cdn. of the same site. Pass `scope` to set it.
"""

from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import asdict, dataclass, field

from .domains import registrable_domain  # noqa: F401  (re-exported)
from .parse import Exchange

API_HINT = re.compile(r"/(api|v\d+|graphql|rest|gql)(/|$)", re.I)
PRIV_RE = re.compile(
    r"/(admin|administrator|internal|manage|management|config|privileged|superuser|"
    r"staff|root|debug|actuator|console|backoffice|ops)(/|$)", re.I)
STATIC_EXT_RE = re.compile(
    r"\.(?:png|jpe?g|gif|svg|ico|webp|avif|bmp|css|woff2?|ttf|otf|eot|map|mp4|webm|"
    r"mp3|wav|pdf|zip)$", re.I)
_PLACEHOLDER_RE = re.compile(r"\{[^/{}]*\}")


@dataclass
class Node:
    id: str
    type: str
    layer: int
    label: str
    attrs: dict = field(default_factory=dict)
    evidence: list[int] = field(default_factory=list)
    roles: list[str] = field(default_factory=list)


@dataclass
class Edge:
    src: str
    dst: str
    type: str
    state: str            # OBSERVED | INFERRED
    evidence: list[int] = field(default_factory=list)


@dataclass
class Unknown:
    type: str
    entity: str
    we_know: list[str]
    we_dont_know: str
    next_step: str


class Model:
    def __init__(self, name: str):
        self.name = name
        self.nodes: dict[str, Node] = {}
        self.edges: list[Edge] = []
        self.unknowns: list[Unknown] = []
        self.roles: set[str] = set()
        self.secrets: list[dict] = []
        self.scope: list[str] = []
        self.stats: dict = {}
        self.evidence_log: list[dict] = []
        self._edge_index: dict[tuple, Edge] = {}
        self._secret_index: dict[tuple, dict] = {}

    # ---- graph helpers ----
    def add_node(self, id, type, layer, label, **attrs) -> Node:
        n = self.nodes.get(id)
        if n is None:
            n = Node(id=id, type=type, layer=layer, label=label, attrs=dict(attrs))
            self.nodes[id] = n
        return n

    def evidence(self, node_id: str, idx: int) -> None:
        n = self.nodes.get(node_id)
        if n and idx not in n.evidence:
            n.evidence.append(idx)

    def add_edge(self, src, dst, type, state, idx=None) -> None:
        key = (src, dst, type)
        e = self._edge_index.get(key)
        if e is not None:
            if idx is not None and idx not in e.evidence:
                e.evidence.append(idx)
            return
        e = Edge(src, dst, type, state, [idx] if idx is not None else [])
        self._edge_index[key] = e
        self.edges.append(e)

    def edges_of(self, node_id: str):
        return [e for e in self.edges if e.src == node_id or e.dst == node_id]

    # ---- counts ----
    def counts(self) -> dict:
        by_type: dict[str, int] = defaultdict(int)
        for n in self.nodes.values():
            by_type[n.type] += 1
        states: dict[str, int] = defaultdict(int)
        for n in self.nodes.values():
            if n.type == "endpoint":
                states[n.attrs.get("api_state", "UNKNOWN")] += 1
        return {
            "nodes": len(self.nodes),
            "edges": len(self.edges),
            "hosts": by_type.get("host", 0),
            "routes": by_type.get("route", 0),
            "scripts": by_type.get("script", 0),
            "endpoints": by_type.get("endpoint", 0),
            "parameters": by_type.get("parameter", 0),
            "operations": by_type.get("operation", 0),
            "third_parties": by_type.get("third_party", 0),
            "auth": by_type.get("auth", 0),
            "cookies": by_type.get("cookie", 0),
            "tech": by_type.get("tech", 0),
            "roles": len(self.roles),
            "unknowns": len(self.unknowns),
            "api_state": dict(states),
            "secrets": len(self.secrets),
        }


# ------------------------------------------------------------------ scope -----

def _bare_host(host: str) -> str:
    """Lower-case host with any port stripped; IPv6 literals keep their form."""
    h = host.lower().strip()
    if h.startswith("["):                       # [::1] or [::1]:8080
        return h[1:h.index("]")] if "]" in h else h[1:]
    if h.count(":") > 1:                        # bare IPv6, no brackets
        return h
    return h.split(":")[0]


def in_scope(host: str, scope: list[str]) -> bool:
    h = _bare_host(host)
    for s in scope:
        s = _bare_host(s).lstrip("*").lstrip(".")
        if h == s or h.endswith("." + s):
            return True
    return False


def match_key(path: str) -> str:
    """Placeholder-insensitive key: `/users/{id}` and `/users/{param}` match."""
    key = _PLACEHOLDER_RE.sub("{}", path)
    return key.rstrip("/") or "/"


# --------------------------------------------------------------- classify -----

def _is_js(ex: Exchange) -> bool:
    m = ex.mime.lower()
    return "script" in m or "ecmascript" in m or ex.path_template.endswith((".js", ".mjs"))


def _is_html(ex: Exchange) -> bool:
    return "html" in ex.mime.lower()


def _is_static_asset(ex: Exchange) -> bool:
    m = ex.mime.lower()
    return (bool(STATIC_EXT_RE.search(ex.path_template))
            or m in ("css", "image", "gif", "jpeg", "png", "svg", "font", "woff", "woff2", "ico"))


def _is_api(ex: Exchange) -> bool:
    if API_HINT.search(ex.path_template):
        return True
    m = ex.mime.lower()
    return m in ("json", "xml") or "json" in m


def classify(ex: Exchange) -> str:
    """script | asset | preflight | route | endpoint for a first-party exchange."""
    if ex.preflight:
        return "preflight"
    if _is_js(ex):
        return "script"
    if _is_static_asset(ex) and ex.method in ("GET", "HEAD"):
        return "asset"
    if ex.method not in ("GET", "HEAD"):
        return "endpoint"          # form posts, redirects after POST, actions
    if _is_html(ex):
        return "route"
    if _is_api(ex) or ex.query_params and not _is_html(ex) and not _is_redirect(ex):
        return "endpoint"
    return "route"                 # HTML pages, GET redirects, other GET resources


def _is_redirect(ex: Exchange) -> bool:
    return ex.status is not None and 300 <= ex.status < 400


# ------------------------------------------------------------------ build -----

# Traversal, null-byte and overlong-UTF-8 paths are a scanner's payloads, not the app's routes.
_PROBE_PATH = re.compile(
    r"(?i)(?:\.\.[/\\]|\.\.%2f|\.\.%5c|%2e%2e|%252e|%00|%c0%ae|%c0%af|%0d%0a|%0a[a-z0-9]|\\x00"
    r"|%2a%7e1|\*~1|~1[/\\]"                                   # IIS short-name probing
    r"|%25%7b|%24%7b|\$\{|%23_?member|ognl|jndi:"                 # expression / log4shell injection
    r"|%3cscript|<script|union(?:%20|\+|\s)select"                 # XSS / SQLi in the path
    r"|\.(?:js|css|png|jpe?g|svg|ico|woff2?|map)/)")              # a file used as a directory
_PROBE_METHODS = ("TRACE", "DEBUG", "TRACK")


def is_probe(ex: Exchange) -> bool:
    return ex.method in _PROBE_METHODS or bool(_PROBE_PATH.search(ex.path or ""))


_FILE_SEG = re.compile(r"\.[A-Za-z0-9]{1,6}$")
SIBLING_STEM = 8          # this many siblings sharing a stem (`best-laundry-in-`): the stem is a pattern
SIBLING_SHAPE = 12       # this many siblings with the same children: the segment is a variable


def collapse_siblings(exchanges: list[Exchange]) -> int:
    """Fold human-readable slugs into placeholders: `/live-channel/aaj-tak`, `/live-channel/dangal` ...

    Id-shaped segments are already `{id}`; a slug (`best-laundry-in-leh`) is not shaped like one,
    so a site with a page per city, channel or product would otherwise get a route per page. Two
    signals say a segment is a variable and not a name:

      * stem   - 8+ siblings share a stem (`best-laundry-in-`): they become `best-laundry-in-{slug}`;
      * shape  - 12+ siblings each have the same children (`/channels/*/{id}`): they become `{slug}`.

    Ten different endpoint names under `/api/` have neither, and are left alone. Files
    (`logo.png`) and anything already templated are untouched. Rewrites `path_template` and the
    referer path the same way, and returns how many templates changed.
    """
    seen: dict[tuple, set] = {}
    for ex in exchanges:
        if ex.method == "OPTIONS" or is_probe(ex) or _FILE_SEG.search(ex.path_template.rsplit("/", 1)[-1] or ""):
            continue
        seen.setdefault((ex.host, ex.path_template.partition("?")[0]), set())
    templates = {k: [x for x in k[1].strip("/").split("/") if x] for k in seen}
    depth = max((len(v) for v in templates.values()), default=0)
    cur = {k: list(v) for k, v in templates.items()}
    for d in range(depth):
        groups: dict[tuple, set] = {}
        for k, segs in cur.items():
            if len(segs) > d:
                groups.setdefault((k[0], tuple(segs[:d])), set()).add(segs[d])
        for (host, prefix), values in groups.items():
            plain = {v for v in values if "{" not in v and not _FILE_SEG.search(v)}
            if len(plain) < SIBLING_STEM:
                continue
            fold: dict[str, str] = {}
            stems: dict[str, list] = {}
            for v in plain:
                if "-" in v:
                    stems.setdefault(v.rsplit("-", 1)[0] + "-", []).append(v)
            for st, members in stems.items():
                if len(members) >= SIBLING_STEM and len(st) >= 6:
                    for v in members:
                        fold[v] = st + "{slug}"
            rest = plain - set(fold)
            if len(rest) >= SIBLING_SHAPE:
                kids = {v: frozenset(segs[d + 1] for segs in cur.values()
                                     if len(segs) > d + 1 and segs[d] == v and tuple(segs[:d]) == prefix
                                     for _ in [0] if True)
                        for v in rest}
                shaped = {v: ks for v, ks in kids.items() if ks}
                if shaped:
                    modal = max(set(shaped.values()), key=list(shaped.values()).count)
                    same = [v for v, ks in shaped.items() if ks == modal]
                    if len(same) >= SIBLING_SHAPE and len(same) >= 0.8 * len(shaped):
                        for v in same:
                            fold[v] = "{slug}"
            if not fold:
                continue
            for k, segs in cur.items():
                if k[0] == host and len(segs) > d and tuple(segs[:d]) == prefix and segs[d] in fold:
                    segs[d] = fold[segs[d]]
    mapping = {}
    for k, segs in cur.items():
        new = "/" + "/".join(segs) if segs else "/"
        if templates[k] and new != "/" + "/".join(templates[k]):
            mapping[k] = new
    if not mapping:
        return 0

    def rewrite(host, template):
        base, q, query = template.partition("?")
        new = mapping.get((host, base))
        if new is None:
            return template
        trail = "/" if base.endswith("/") and len(base) > 1 else ""
        return new + trail + (q + query if q else "")

    for ex in exchanges:
        ex.path_template = rewrite(ex.host, ex.path_template)
        if ex.referer_host and ex.referer_path:
            ex.referer_path = rewrite(ex.referer_host, ex.referer_path)
    return len(mapping)


def build(exchanges: list[Exchange], name: str, seed_host: str | None = None,
          scope: list[str] | None = None, stats: dict | None = None) -> Model:
    m = Model(name)
    m.stats = dict(stats or {})
    m.stats.setdefault("exchanges", len(exchanges))
    for k in ("static_assets", "preflight", "third_party_requests"):
        m.stats[k] = 0
    # guard for library callers who chain parse_items() outputs: evidence ids
    # must be unique, or every citation is ambiguous
    if len({ex.index for ex in exchanges}) != len(exchanges):
        for n, ex in enumerate(exchanges):
            ex.index = n
    m.stats["slug_templates_folded"] = collapse_siblings(exchanges)
    if seed_host is None and exchanges:
        hosts: dict[str, int] = defaultdict(int)
        for ex in exchanges:
            hosts[ex.host] += 1
        # the busiest host — within the given scope if there is one, so a noisy
        # CDN or analytics host can never become the app's primary host
        pool = ([h for h in hosts if in_scope(h, scope)] if scope else []) or list(hosts)
        seed_host = max(sorted(pool), key=lambda h: hosts[h])
    m.scope = list(scope) if scope else ([registrable_domain(seed_host)] if seed_host else [])
    primary = seed_host

    runtime_seen: set[str] = set()
    referenced: set[str] = set()
    route_of_page: dict[tuple[str, str], str] = {}   # (host, path) -> route id

    # ---- pass 1: observed traffic ----
    for ex in exchanges:
        i = ex.index
        role = ex.role
        ev_entry = {
            "id": i, "source": ex.source, "item": ex.item, "method": ex.method,
            "host": ex.host, "path": ex.path_template, "status": ex.status,
            "mime": ex.mime, "role": role,
        }
        if ex.ev:
            ev_entry["request"] = ex.ev.get("request")
            ev_entry["response"] = ex.ev.get("response")
        m.evidence_log.append(ev_entry)
        for s in ex.secrets:
            _add_secret(m, s.as_dict(), i)
        if is_probe(ex):                 # a scanner's payload: evidence yes, a node in the app's map no
            m.stats["probe_requests"] = m.stats.get("probe_requests", 0) + 1
            continue
        if role:
            m.roles.add(role)
            m.add_node(f"role:{role}", "role", 5, f"role: {role}")
            m.evidence(f"role:{role}", i)

        first_party = in_scope(ex.host, m.scope)
        if not first_party:
            tp_id = f"host:{ex.host}"
            tp = m.add_node(tp_id, "third_party", 5, ex.host, scope="external", requests=0)
            tp.attrs["requests"] = tp.attrs.get("requests", 0) + 1
            m.evidence(tp_id, i)
            m.stats["third_party_requests"] += 1
            if _is_js(ex):
                sid = f"script:{ex.host}{ex.path_template}"
                m.add_node(sid, "script", 3, ex.path_template.split("/")[-1] or "script.js",
                           host=ex.host, scope="external")
                m.evidence(sid, i)
                m.add_edge(tp_id, sid, "LOADS", "OBSERVED", i)
            continue

        host_id = f"host:{ex.host}"
        h = m.add_node(host_id, "host", 1, ex.host, scope="first-party",
                       schemes=[], ports=[], tech={})
        m.evidence(host_id, i)
        if ex.scheme and ex.scheme not in h.attrs["schemes"]:
            h.attrs["schemes"].append(ex.scheme)
        if ex.port and ex.port not in h.attrs["ports"]:
            h.attrs["ports"].append(ex.port)
        for k, v in ex.tech:
            h.attrs["tech"].setdefault(k, v)
            # a server/framework marker is part of the app's shape: one node
            # per distinct value, hung off every host that advertised it
            tid = f"tech:{v}"
            m.add_node(tid, "tech", 1, v, header=k)
            m.evidence(tid, i)
            m.add_edge(host_id, tid, "RUNS", "OBSERVED", i)
        for c in ex.set_cookies:
            cid = f"cookie:{c['name']}"
            cn = m.add_node(cid, "cookie", 5, c["name"], httponly=c["httponly"],
                            secure=c["secure"], samesite=c["samesite"])
            m.evidence(cid, i)
            m.add_edge(host_id, cid, "SETS_COOKIE", "OBSERVED", i)
            # a cookie set with different flags in different places: keep the weakest
            cn.attrs["httponly"] = cn.attrs["httponly"] and c["httponly"]
            cn.attrs["secure"] = cn.attrs["secure"] and c["secure"]
            rank = {None: 0, "none": 0, "lax": 1, "strict": 2}
            old = (cn.attrs.get("samesite") or "").lower() or None
            new = (c["samesite"] or "").lower() or None
            if rank.get(new, 0) < rank.get(old, 0):
                cn.attrs["samesite"] = c["samesite"]

        kind = classify(ex)
        if kind == "asset":
            m.stats["static_assets"] += 1
            continue
        if kind == "preflight":
            m.stats["preflight"] += 1
            continue

        label_prefix = "" if ex.host == primary else ex.host
        if kind == "script":
            sid = f"script:{ex.host}{ex.path_template}"
            m.add_node(sid, "script", 3, ex.path_template.split("/")[-1] or "script.js",
                       host=ex.host, scope="first-party")
            m.evidence(sid, i)
            m.add_edge(host_id, sid, "LOADS", "OBSERVED", i)
            node = m.nodes[sid]
        elif kind == "route":
            rid = f"route:{ex.host}{ex.path_template}"
            node = m.add_node(rid, "route", 2, label_prefix + ex.path_template,
                              host=ex.host, path=ex.path_template, statuses=[])
            m.evidence(rid, i)
            m.add_edge(host_id, rid, "SERVES", "OBSERVED", i)
            route_of_page[(ex.host, ex.path_template)] = rid
            _add_status(node, ex.status)
        else:
            eid = f"endpoint:{ex.method}:{ex.host}:{ex.path_template}"
            runtime_seen.add(eid)
            node = m.add_node(eid, "endpoint", 4,
                              f"{ex.method} {label_prefix}{ex.path_template}",
                              method=ex.method, host=ex.host, path=ex.path_template,
                              status=ex.status, statuses=[], status_by_role={},
                              credentials=[], anonymous_requests=0, requests=0)
            m.evidence(eid, i)
            m.add_edge(host_id, eid, "EXPOSES", "OBSERVED", i)
            _add_status(node, ex.status)
            node.attrs["requests"] += 1
            if role:
                sbr = node.attrs["status_by_role"].setdefault(role, [])
                if ex.status is not None and ex.status not in sbr:
                    sbr.append(ex.status)
                    sbr.sort()
            if ex.credentials:
                for cred in ex.credentials:
                    if cred not in node.attrs["credentials"]:
                        node.attrs["credentials"].append(cred)
                    aid = f"auth:{cred}"
                    m.add_node(aid, "auth", 5, _auth_label(cred))
                    m.evidence(aid, i)
                    m.add_edge(eid, aid, "SENT_CREDENTIAL", "OBSERVED", i)
            else:
                node.attrs["anonymous_requests"] += 1
            for op in ex.gql_ops:
                oid = f"op:{eid}:{op}"
                m.add_node(oid, "operation", 4, op)
                m.evidence(oid, i)
                m.add_edge(eid, oid, "USES_OPERATION", "OBSERVED", i)
                if role and role not in m.nodes[oid].roles:
                    m.nodes[oid].roles.append(role)

        if role and role not in node.roles:
            node.roles.append(role)
        if role:
            m.add_edge(f"role:{role}", node.id, "REACHED", "OBSERVED", i)

        if kind in ("route", "endpoint"):
            for loc, params in (("query", ex.query_params), ("body", ex.body_params)):
                for pname, _ in params:
                    pid = f"param:{node.id}:{pname}"
                    m.add_node(pid, "parameter", 4, pname, location=loc)
                    m.evidence(pid, i)
                    m.add_edge(node.id, pid, "USES_PARAMETER", "OBSERVED", i)

    # A path that only ever answered 404/410 is not part of the app: a scanner or a typo asked
    # for something that is not there. Keep the requests (they are evidence), drop the nodes.
    gone = [nid for nid, n in m.nodes.items()
            if n.type in ("route", "endpoint") and n.attrs.get("statuses")
            and all(st in (404, 410) for st in n.attrs["statuses"])]
    for nid in gone:
        del m.nodes[nid]
        runtime_seen.discard(nid)
    if gone:
        dead = set(gone)
        m.edges = [e for e in m.edges if e.src not in dead and e.dst not in dead]
        m._edge_index = {(e.src, e.dst, e.type): e for e in m.edges}
        for nid in [k for k in m.nodes if k.startswith("param:") and any(k.startswith(f"param:{g}:") for g in dead)]:
            del m.nodes[nid]
        for key in [k for k, v in route_of_page.items() if v in dead]:
            del route_of_page[key]
    m.stats["not_found_paths_dropped"] = len(gone)

    # ---- pass 2: referer edges and static references ----
    by_key: dict[str, list[str]] = defaultdict(list)
    for nid in sorted(runtime_seen):
        by_key[match_key(m.nodes[nid].attrs["path"])].append(nid)

    for ex in exchanges:
        i = ex.index
        if not in_scope(ex.host, m.scope):
            continue
        kind = classify(ex)
        src = _node_for(m, ex, kind)
        # Referer: which page was open when this request was made
        if src and ex.referer_host and in_scope(ex.referer_host, m.scope):
            page = route_of_page.get((ex.referer_host, ex.referer_path))
            if page and page != src:
                etype = {"endpoint": "CALLS", "script": "INCLUDES"}.get(kind, "NAVIGATES_TO")
                m.add_edge(page, src, etype, "OBSERVED", i)

    for ex in exchanges:
        if not ex.js_refs or is_probe(ex):
            continue
        i = ex.index
        first_party = in_scope(ex.host, m.scope)
        kind = classify(ex) if first_party else ("script" if _is_js(ex) else None)
        src = _node_for(m, ex, kind) if kind else None
        if src is None:
            continue
        # relative references run against the page origin, not the script host
        base_host = ex.host
        if not in_scope(base_host, m.scope) or kind == "script":
            base_host = (ex.referer_host if ex.referer_host and in_scope(ex.referer_host, m.scope)
                         else primary)
        for method, host, path, _ref_kind in ex.js_refs:
            if host and not in_scope(host, m.scope):
                tp_id = f"host:{host}"
                m.add_node(tp_id, "third_party", 5, host, scope="external", requests=0)
                m.evidence(tp_id, i)
                m.add_edge(src, tp_id, "REFERENCES", "INFERRED", i)
                continue
            if host is None and not first_party:
                continue    # vendor code: its relative paths are the vendor's business
            cands = [nid for nid in by_key.get(match_key(path), [])
                     if (host is None or m.nodes[nid].attrs["host"] == host)
                     and (method is None or m.nodes[nid].attrs["method"] == method)]
            if cands:
                for nid in cands:
                    referenced.add(nid)
                    m.evidence(nid, i)
                    m.add_edge(src, nid, "REFERENCES", "INFERRED", i)
                continue
            target_host = host or base_host
            meth = method or "*"
            eid = f"endpoint:{meth}:{target_host}:{path}"
            prefix = "" if target_host == primary else target_host
            node = m.add_node(eid, "endpoint", 4, f"{meth} {prefix}{path}",
                              method=method, host=target_host, path=path,
                              method_known=method is not None, statuses=[],
                              status_by_role={}, credentials=[],
                              anonymous_requests=0, requests=0)
            m.evidence(eid, i)
            referenced.add(eid)
            m.add_edge(src, eid, "REFERENCES", "INFERRED", i)

    _link_script_assets(m, exchanges)
    _reconcile(m, referenced, runtime_seen)
    _emit_unknowns(m, exchanges)
    for n in m.nodes.values():
        n.evidence.sort()
    for e in m.edges:
        e.evidence.sort()
    return m


def _node_for(m: Model, ex: Exchange, kind: str | None) -> str | None:
    if kind == "script":
        nid = f"script:{ex.host}{ex.path_template}"
    elif kind == "route":
        nid = f"route:{ex.host}{ex.path_template}"
    elif kind == "endpoint":
        nid = f"endpoint:{ex.method}:{ex.host}:{ex.path_template}"
    else:
        return None
    return nid if nid in m.nodes else None


def _add_status(node: Node, status) -> None:
    if status is not None and status not in node.attrs["statuses"]:
        node.attrs["statuses"].append(status)
        node.attrs["statuses"].sort()


def _auth_label(cred: str) -> str:
    if cred.startswith("cookie:"):
        return f"session cookie {cred[7:]}"
    if cred.startswith("header:"):
        return f"credential header {cred[7:]}"
    if cred.startswith("query:"):
        return f"credential in query {cred[6:]}"
    return f"Authorization: {cred}"


def _add_secret(m: Model, s: dict, idx: int) -> None:
    key = (s["kind"], s["hmac_12"])
    existing = m._secret_index.get(key)
    if existing is not None:
        existing["count"] += 1
        if idx not in existing["evidence"] and len(existing["evidence"]) < 10:
            existing["evidence"].append(idx)
        return
    entry = {**s, "count": 1, "evidence": [idx]}
    m._secret_index[key] = entry
    m.secrets.append(entry)


def _link_script_assets(m: Model, exchanges: list[Exchange]) -> None:
    """Layer 3: workers a script spawns, and the source map it names (INFERRED from code)."""
    seen = {(ex.host, ex.path_template) for ex in exchanges
            if ex.status is not None and ex.status < 400 and not is_probe(ex)}
    for ex in exchanges:
        if not ex.js_assets or is_probe(ex) or not in_scope(ex.host, m.scope):
            continue
        src = f"script:{ex.host}{ex.path_template}"
        if src not in m.nodes:
            continue
        for kind, host, path in ex.js_assets:
            if not in_scope(host, m.scope):
                continue
            if kind == "sourcemap":
                captured = (host, path) in seen
                m.nodes[src].attrs["sourcemap"] = {"host": host, "path": path, "captured": captured}
                m.evidence(src, ex.index)
                if not captured:
                    m.unknowns.append(Unknown(
                        "SOURCE_MAP_NOT_CAPTURED", src,
                        [f"the script names a source map ({path}) that is not in the capture"],
                        "original source file names and structure",
                        "request the .map file in an authorized session and re-capture",
                    ))
                continue
            wid = f"script:{host}{path}"
            node = m.add_node(wid, "script", 3, path.split("/")[-1] or "worker.js",
                              host=host, scope="first-party")
            node.attrs.setdefault("worker", kind)
            m.evidence(wid, ex.index)
            m.add_edge(src, wid, "SPAWNS", "INFERRED", ex.index)


def _reconcile(m: Model, referenced: set[str], runtime_seen: set[str]) -> None:
    """Label each endpoint STATIC_ONLY / RUNTIME_ONLY / BOTH."""
    for nid, node in m.nodes.items():
        if node.type != "endpoint":
            continue
        in_js = nid in referenced
        in_rt = nid in runtime_seen
        if in_js and in_rt:
            node.attrs["api_state"] = "BOTH"
        elif in_js:
            node.attrs["api_state"] = "STATIC_ONLY"
        else:
            node.attrs["api_state"] = "RUNTIME_ONLY"


def _emit_unknowns(m: Model, exchanges: list[Exchange]) -> None:
    creds_seen = any(ex.credentials for ex in exchanges)
    if not m.roles and not creds_seen:
        m.unknowns.append(Unknown(
            "AUTHENTICATED_STATE_NOT_OBSERVED", f"app:{m.name}",
            ["no credentials were sent in the capture", "capture had no role tag"],
            "how the app behaves for a logged-in user",
            "re-ingest an authenticated capture with --role",
        ))
    elif not m.roles:
        m.unknowns.append(Unknown(
            "ROLE_NOT_TAGGED", f"app:{m.name}",
            ["credentials were sent", "capture had no role tag"],
            "which user/role the traffic belongs to, so access cannot be compared",
            "re-ingest each account's capture with --role <name>",
        ))
    if m.stats.get("skipped"):
        m.unknowns.append(Unknown(
            "CAPTURE_ITEMS_SKIPPED", f"app:{m.name}",
            [f"{m.stats['skipped']} export item(s) could not be parsed"],
            "what those requests contained",
            "re-export the history; check for truncated or non-Burp XML",
        ))
    truncated = {f"script:{ex.host}{ex.path_template}" for ex in exchanges if ex.scan_truncated}
    for sid in sorted(truncated):
        if sid in m.nodes:
            m.unknowns.append(Unknown(
                "SCRIPT_PARTIALLY_SCANNED", sid,
                ["script body exceeded the scan cap"],
                "endpoints referenced past the cap",
                "extract the bundle and scan it separately",
            ))
    for node in m.nodes.values():
        if node.type != "endpoint":
            continue
        state = node.attrs.get("api_state")
        if state == "STATIC_ONLY":
            know = ["referenced in code", "never observed at runtime"]
            if not node.attrs.get("method_known", True):
                know.append("HTTP method not determinable from the reference")
            m.unknowns.append(Unknown(
                "API_PURPOSE_UNKNOWN", node.id, know,
                "what this endpoint does and whether it is reachable",
                "request it directly in an authorised session",
            ))
        statuses = node.attrs.get("statuses") or []
        if statuses and all(s >= 400 for s in statuses):
            m.unknowns.append(Unknown(
                "ENDPOINT_ONLY_ERRORED", node.id,
                [f"observed statuses: {', '.join(map(str, statuses))}"],
                "how it behaves with valid input and authorization",
                "exercise the feature normally in an authorised session",
            ))
        if node.roles:
            m.unknowns.append(Unknown(
                "AUTHORIZATION_UNKNOWN", node.id,
                [f"reached by role(s): {', '.join(node.roles)}"],
                "whether access is authorization-checked",
                "replay across two in-scope accounts and compare",
            ))


# ------------------------------------------------------------- cross-role -----

def _ok(statuses) -> bool:
    return any(200 <= s < 300 for s in statuses or [])


def cross_role(m: Model, low: str, high: str) -> dict:
    """Compare what a low and a high role reached. Output is hypotheses.

    high_only                endpoints the high role reached that the low role
                             never requested — replay each as the low role.
    low_reached_privileged   endpoints the low role reached whose path looks
                             privileged — check the response was meant for it.
    shared_same_success      both roles got a 2xx — compare response content.
    """
    high_only, low_priv, shared = [], [], []
    ev_role = {e["id"]: e.get("role") for e in m.evidence_log}

    def evs(node, prefer_role):
        # cite the preferred role's requests when we have them, so a
        # "low reached privileged" line never points at the high role's request
        ids = [i for i in node.evidence if ev_role.get(i) == prefer_role]
        return (ids or node.evidence)[:3]

    for node in m.nodes.values():
        if node.type not in ("endpoint", "operation"):
            continue
        rl, rh = low in node.roles, high in node.roles
        path = node.attrs.get("path", node.label)
        sbr = node.attrs.get("status_by_role", {})
        entry = {"endpoint": node.label, "id": node.id,
                 "evidence": evs(node, low if rl else high),
                 "statuses": {r: sbr.get(r, []) for r in (low, high) if r in sbr}}
        if rh and not rl:
            high_only.append({**entry, "kind": "high_only",
                              "unknown": f"whether '{low}' can reach it",
                              "next": f"replay as '{low}' and compare with '{high}'"})
        elif rl and PRIV_RE.search(path):
            low_priv.append({**entry, "kind": "low_reached_privileged",
                             "unknown": "whether the low-role response was authorised or a leak",
                             "next": f"compare '{low}' and '{high}' response bodies"})
        elif rl and rh and _ok(sbr.get(low)) and _ok(sbr.get(high)):
            shared.append({**entry, "kind": "shared_same_success",
                           "unknown": "whether both roles see the same data",
                           "next": "diff the two responses for role-specific fields"})
    key = lambda e: e["endpoint"]
    high_only.sort(key=key)
    low_priv.sort(key=key)
    shared.sort(key=key)
    return {"low": low, "high": high,
            "roles_present": sorted(m.roles),
            "surface": low_priv + high_only,
            "low_reached_privileged": low_priv,
            "high_only": high_only,
            "shared_same_success": shared}


# ------------------------------------------------------------ serialise -------

# Version of the model.json shape. Bump on any breaking change.
MODEL_SCHEMA_VERSION = 1


def to_dict(m: Model) -> dict:
    from . import __version__
    return {
        "tool": "burp2model",
        "version": __version__,
        "schema": MODEL_SCHEMA_VERSION,
        "app": m.name,
        "scope": m.scope,
        "counts": m.counts(),
        "stats": m.stats,
        "nodes": [asdict(n) for n in m.nodes.values()],
        "edges": [asdict(e) for e in m.edges],
        "unknowns": [asdict(u) for u in m.unknowns],
        "roles": sorted(m.roles),
        "secrets": m.secrets,
        "evidence": m.evidence_log,
    }


def from_dict(data: dict) -> Model:
    """Rebuild a Model from model.json (for query / cross-role / animate)."""
    if not isinstance(data, dict) or "app" not in data or "nodes" not in data:
        raise ValueError("not a burp2model model.json (missing app/nodes)")
    schema = data.get("schema", 1)
    if isinstance(schema, int) and schema > MODEL_SCHEMA_VERSION:
        raise ValueError(
            f"model.json schema {schema} is newer than this burp2model "
            f"(understands {MODEL_SCHEMA_VERSION}); upgrade the package")
    m = Model(data["app"])
    for nd in data["nodes"]:
        n = Node(**{k: nd[k] for k in ("id", "type", "layer", "label")},
                 attrs=nd.get("attrs", {}), evidence=nd.get("evidence", []),
                 roles=nd.get("roles", []))
        m.nodes[n.id] = n
    for ed in data["edges"]:
        e = Edge(**ed)
        m.edges.append(e)
        m._edge_index[(e.src, e.dst, e.type)] = e
    for u in data["unknowns"]:
        m.unknowns.append(Unknown(**u))
    m.roles = set(data.get("roles", []))
    m.secrets = data.get("secrets", [])
    for s in m.secrets:
        if "kind" in s and "hmac_12" in s:
            m._secret_index[(s["kind"], s["hmac_12"])] = s
    m.scope = data.get("scope", [])
    m.stats = data.get("stats", {})
    m.evidence_log = data.get("evidence", [])
    return m
