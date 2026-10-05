"""
The graph database: one SQLite file (`graph.db`) holding the whole web-app model.

SQLite is in the standard library, so the package stays zero-dependency, and the
result is a single portable file anyone can open with any SQLite client. The
model graph is stored as a property graph:

  nodes / edges            the six-layer graph plus external (OSINT) nodes
  node_evidence / edge_evidence   which request (ev_N) backs each node and edge
  exchanges                every captured request/response, redacted
  unknowns / secrets       named blind spots, secret fingerprints (never values)
  osint_runs / osint_facts external recon, timestamped, one row per run
  builds                   a compressed model snapshot per build, for drift

Only redacted data ever reaches this file: it is loaded from the same masked
`Model` that `model.json` is written from. `osint` edges carry the state
EXTERNAL so recon is never confused with OBSERVED traffic or INFERRED code refs.

The graph tables are rebuilt on every build; the OSINT and build-history tables
are kept, so recon accumulates and drift can be diffed over time.
"""

from __future__ import annotations

import gzip
import json
import os
import re
import sqlite3
from datetime import datetime, timezone

from .model import Model, to_dict

DB_SCHEMA_VERSION = 1
DB_NAME = "graph.db"
KEEP_BUILDS = 20

_GRAPH_TABLES = ("nodes", "edges", "node_evidence", "edge_evidence",
                 "exchanges", "unknowns", "secrets")

SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT);
CREATE TABLE IF NOT EXISTS nodes (
  id TEXT PRIMARY KEY, type TEXT NOT NULL, layer INTEGER, label TEXT,
  source TEXT NOT NULL DEFAULT 'traffic',      -- traffic | osint
  attrs TEXT NOT NULL DEFAULT '{}', roles TEXT NOT NULL DEFAULT '[]'
);
CREATE TABLE IF NOT EXISTS edges (
  id INTEGER PRIMARY KEY, src TEXT NOT NULL, dst TEXT NOT NULL,
  type TEXT NOT NULL, state TEXT NOT NULL      -- OBSERVED | INFERRED | EXTERNAL
);
CREATE TABLE IF NOT EXISTS node_evidence (node_id TEXT NOT NULL, ev_id INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS edge_evidence (edge_id INTEGER NOT NULL, ev_id INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS exchanges (
  id INTEGER PRIMARY KEY, source TEXT, item INTEGER, role TEXT,
  method TEXT, host TEXT, path TEXT, path_template TEXT, status INTEGER, mime TEXT,
  req_line TEXT, req_headers TEXT, req_body TEXT, req_truncated INTEGER,
  resp_line TEXT, resp_headers TEXT, resp_body TEXT, resp_truncated INTEGER
);
CREATE TABLE IF NOT EXISTS unknowns (
  id INTEGER PRIMARY KEY, type TEXT, entity TEXT, we_know TEXT,
  we_dont_know TEXT, next_step TEXT
);
CREATE TABLE IF NOT EXISTS secrets (
  kind TEXT, hmac_12 TEXT, length INTEGER, entropy REAL, count INTEGER, evidence TEXT
);
CREATE TABLE IF NOT EXISTS osint_runs (
  id INTEGER PRIMARY KEY, host TEXT, domain TEXT, generated_at TEXT, data TEXT
);
CREATE TABLE IF NOT EXISTS osint_facts (
  run_id INTEGER NOT NULL, section TEXT, key TEXT, value TEXT
);
CREATE TABLE IF NOT EXISTS builds (
  id INTEGER PRIMARY KEY, built_at TEXT, nodes INTEGER, edges INTEGER,
  exchanges INTEGER, osint_run INTEGER, model_gz BLOB
);
CREATE INDEX IF NOT EXISTS ix_nodes_type ON nodes(type);
CREATE INDEX IF NOT EXISTS ix_edges_src ON edges(src, type);
CREATE INDEX IF NOT EXISTS ix_edges_dst ON edges(dst, type);
CREATE INDEX IF NOT EXISTS ix_ne_node ON node_evidence(node_id);
CREATE INDEX IF NOT EXISTS ix_ee_edge ON edge_evidence(edge_id);
CREATE INDEX IF NOT EXISTS ix_ex_host ON exchanges(host, method, status);
CREATE INDEX IF NOT EXISTS ix_ex_path ON exchanges(path_template);
CREATE INDEX IF NOT EXISTS ix_facts_run ON osint_facts(run_id, section);
"""


def _now() -> str:
    """UTC build time. SOURCE_DATE_EPOCH pins it, so a reproducible build is byte-identical."""
    epoch = os.environ.get("SOURCE_DATE_EPOCH", "")
    when = (datetime.fromtimestamp(int(epoch), timezone.utc) if epoch.isdigit()
            else datetime.now(timezone.utc))
    return when.strftime("%Y-%m-%dT%H:%M:%SZ")


def connect(path: str) -> sqlite3.Connection:
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    return conn


def _init(conn: sqlite3.Connection) -> None:
    conn.executescript(SCHEMA)
    row = conn.execute("SELECT value FROM meta WHERE key='schema'").fetchone()
    if row is None:
        conn.execute("INSERT INTO meta VALUES ('schema', ?)", (str(DB_SCHEMA_VERSION),))
    elif int(row[0]) > DB_SCHEMA_VERSION:
        raise ValueError(f"{DB_NAME} schema {row[0]} is newer than this burp2model "
                         f"(understands {DB_SCHEMA_VERSION}); upgrade the package")


def open_db(path: str) -> sqlite3.Connection:
    """Open an existing graph.db read-only-ish (creates nothing)."""
    if not os.path.exists(path):
        raise FileNotFoundError(path)
    conn = connect(path)
    _init(conn)
    return conn


def _req_path(line: str) -> str:
    parts = (line or "").split(" ")
    return parts[1] if len(parts) >= 2 else ""


def _headers_text(headers) -> str:
    return "\n".join(f"{k}: {v}" for k, v in (headers or []))


# ------------------------------------------------------------------ write ----

def write_db(m: Model, path: str, osint: dict | None = None) -> dict:
    """(Re)build graph.db from a Model, folding in OSINT. Returns a summary."""
    conn = connect(path)
    try:
        _init(conn)
        with conn:
            for t in _GRAPH_TABLES:
                conn.execute(f"DELETE FROM {t}")
            _write_graph(conn, m)
            run_id = None
            if osint:
                run_id = _record_osint(conn, osint)
            else:
                row = conn.execute("SELECT max(id) FROM osint_runs").fetchone()
                run_id = row[0]
            if run_id is not None:
                latest = conn.execute("SELECT data FROM osint_runs WHERE id=?",
                                      (run_id,)).fetchone()
                _write_osint_graph(conn, json.loads(latest[0]), m)
            _snapshot(conn, m, run_id)
            conn.execute("INSERT OR REPLACE INTO meta VALUES ('app', ?)", (m.name,))
            conn.execute("INSERT OR REPLACE INTO meta VALUES ('built_at', ?)", (_now(),))
            conn.execute("INSERT OR REPLACE INTO meta VALUES ('scope', ?)",
                         (json.dumps(m.scope),))
        return summary(conn)
    finally:
        conn.close()


def _write_graph(conn: sqlite3.Connection, m: Model) -> None:
    for n in m.nodes.values():
        conn.execute("INSERT INTO nodes(id,type,layer,label,source,attrs,roles) "
                     "VALUES (?,?,?,?, 'traffic', ?, ?)",
                     (n.id, n.type, n.layer, n.label, json.dumps(n.attrs),
                      json.dumps(sorted(n.roles))))
        conn.executemany("INSERT INTO node_evidence VALUES (?,?)",
                         [(n.id, i) for i in n.evidence])
    for e in m.edges:
        cur = conn.execute("INSERT INTO edges(src,dst,type,state) VALUES (?,?,?,?)",
                           (e.src, e.dst, e.type, e.state))
        conn.executemany("INSERT INTO edge_evidence VALUES (?,?)",
                         [(cur.lastrowid, i) for i in e.evidence])
    for ev in m.evidence_log:
        rq, rs = ev.get("request") or {}, ev.get("response") or {}
        conn.execute(
            "INSERT INTO exchanges VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (ev["id"], ev.get("source"), ev.get("item"), ev.get("role"),
             ev.get("method"), ev.get("host"), _req_path(rq.get("line", "")),
             ev.get("path"), ev.get("status"), ev.get("mime"),
             rq.get("line"), _headers_text(rq.get("headers")), rq.get("body") or "",
             1 if rq.get("truncated") else 0,
             rs.get("line"), _headers_text(rs.get("headers")), rs.get("body") or "",
             1 if rs.get("truncated") else 0))
    for u in m.unknowns:
        conn.execute("INSERT INTO unknowns(type,entity,we_know,we_dont_know,next_step) "
                     "VALUES (?,?,?,?,?)",
                     (u.type, u.entity, json.dumps(u.we_know), u.we_dont_know, u.next_step))
    for s in m.secrets:
        conn.execute("INSERT INTO secrets VALUES (?,?,?,?,?,?)",
                     (s.get("kind"), s.get("hmac_12"), s.get("length"), s.get("entropy"),
                      s.get("count", 1), json.dumps(s.get("evidence", []))))


def _snapshot(conn: sqlite3.Connection, m: Model, osint_run: int | None) -> None:
    blob = gzip.compress(json.dumps(to_dict(m)).encode("utf-8"), mtime=0)
    conn.execute("INSERT INTO builds(built_at,nodes,edges,exchanges,osint_run,model_gz) "
                 "VALUES (?,?,?,?,?,?)",
                 (_now(), len(m.nodes), len(m.edges), len(m.evidence_log), osint_run, blob))
    conn.execute("DELETE FROM builds WHERE id <= (SELECT max(id) FROM builds) - ?",
                 (KEEP_BUILDS,))


# ------------------------------------------------------------------ OSINT ----

def _flatten(section: str, obj, prefix: str = ""):
    """Yield (section, key, value) leaves of an osint section."""
    if isinstance(obj, dict):
        for k, v in obj.items():
            yield from _flatten(section, v, f"{prefix}.{k}" if prefix else str(k))
    elif isinstance(obj, list):
        for x in obj:
            yield from _flatten(section, x, prefix)
    else:
        yield section, prefix, "" if obj is None else str(obj)


def _record_osint(conn: sqlite3.Connection, osint: dict) -> int:
    """Store one run (skipping an identical repeat) and return its id."""
    data = json.dumps(osint, sort_keys=True)
    last = conn.execute("SELECT id, data FROM osint_runs ORDER BY id DESC LIMIT 1").fetchone()
    if last is not None and last[1] == data:
        return last[0]
    cur = conn.execute("INSERT INTO osint_runs(host,domain,generated_at,data) VALUES (?,?,?,?)",
                       (osint.get("host"), osint.get("domain"),
                        osint.get("generated_at") or _now(), data))
    run_id = cur.lastrowid
    rows = []
    for section, val in osint.items():
        if section.startswith("_") or section in ("host", "domain", "generated_at"):
            continue
        rows.extend((run_id, s, k, v) for s, k, v in _flatten(section, val))
    conn.executemany("INSERT INTO osint_facts VALUES (?,?,?,?)", rows)
    return run_id


def _ext(conn, nid: str, type_: str, label: str, anchor: str | None, edge: str,
         **attrs) -> None:
    if type_ == "subdomain" and conn.execute(
            "SELECT 1 FROM nodes WHERE id=?", (f"host:{label}",)).fetchone():
        nid = f"host:{label}"      # already a first-party host: link it, don't duplicate
    else:
        _ext_node(conn, nid, type_, label, attrs)
    if anchor and anchor != nid:
        conn.execute("INSERT INTO edges(src,dst,type,state) VALUES (?,?,?, 'EXTERNAL')",
                     (anchor, nid, edge))


def _ext_node(conn, nid: str, type_: str, label: str, attrs: dict) -> None:
    conn.execute("INSERT OR IGNORE INTO nodes(id,type,layer,label,source,attrs,roles) "
                 "VALUES (?,?,0,?, 'osint', ?, '[]')",
                 (nid, type_, label, json.dumps(attrs)))


def _write_osint_graph(conn: sqlite3.Connection, osint: dict, m: Model) -> None:
    """Hang external recon off the app's host nodes as layer-0, source=osint nodes."""
    host = (osint.get("host") or "").lower()
    anchor = f"host:{host}"
    if anchor not in m.nodes:
        primary = [n.id for n in m.nodes.values() if n.type == "host"]
        anchor = primary[0] if primary else None
        if anchor is None:
            conn.execute("INSERT OR IGNORE INTO nodes(id,type,layer,label,source,attrs,roles) "
                         "VALUES (?, 'host', 1, ?, 'osint', '{}', '[]')",
                         (f"host:{host}", host))
            anchor = f"host:{host}"
    domain = osint.get("domain") or host
    known_hosts = {n.label for n in m.nodes.values() if n.type in ("host", "third_party")}

    dns = osint.get("dns") or {}
    for t in ("A", "AAAA"):
        for ip in dns.get(t, []):
            _ext(conn, f"ext:ip:{ip}", "ip", ip, anchor, "RESOLVES_TO", record=t)
    for c in dns.get("CNAME", []):
        _ext(conn, f"ext:cname:{c}", "dns_name", c, anchor, "ALIASES", record="CNAME")
    for ns in dns.get("NS", []):
        _ext(conn, f"ext:ns:{ns}", "nameserver", ns, anchor, "DELEGATED_TO")
    for mx in dns.get("MX", []):
        _ext(conn, f"ext:mx:{mx}", "mail_server", mx, anchor, "MAIL_VIA")
    for caa in dns.get("CAA", []):
        _ext(conn, f"ext:caa:{caa}", "dns_record", f"CAA {caa}", anchor, "HAS_RECORD",
             record="CAA")

    tls = osint.get("tls") or {}
    if tls.get("issuer") and not tls.get("error"):
        cid = f"ext:cert:{tls.get('subject_cn') or host}"
        _ext(conn, cid, "certificate", f"cert · {tls['issuer']}", anchor, "PRESENTS_CERT",
             issuer=tls.get("issuer"), subject=tls.get("subject_cn"),
             not_after=tls.get("not_after"), days_until_expiry=tls.get("days_until_expiry"),
             tls_version=tls.get("tls_version"))
        for san in tls.get("san", []):
            if san.startswith("*."):        # a wildcard is a pattern, not a host you could visit
                _ext(conn, f"ext:san:{san}", "wildcard_san", san, cid, "COVERS")
            else:
                _ext(conn, f"ext:sub:{san}", "subdomain", san, cid, "COVERS",
                     seen_in_capture=san in known_hosts, via="certificate")

    subs = osint.get("subdomains") or {}
    for name in subs.get("names", []):
        _ext(conn, f"ext:sub:{name}", "subdomain", name, anchor, "SUBDOMAIN_OF",
             seen_in_capture=name in known_hosts, via="certificate transparency")

    for t in osint.get("technology", []):
        name = t.get("name") if isinstance(t, dict) else str(t)
        via = t.get("evidence") if isinstance(t, dict) else None
        _ext(conn, f"ext:tech:{name}", "tech", name, anchor, "RUNS", seen_via=via)

    geo = osint.get("ip_geo") or {}
    if geo.get("network"):
        _ext(conn, f"ext:net:{geo['network']}", "network", geo["network"], anchor,
             "HOSTED_ON", ip=geo.get("ip"), country=geo.get("country"),
             handle=geo.get("handle"))
    reg = osint.get("registration") or {}
    if reg.get("registrar") and not reg.get("error"):
        _ext(conn, f"ext:registrar:{reg['registrar']}", "registration", reg["registrar"],
             anchor, "REGISTERED_WITH", registered=reg.get("registration"),
             expires=reg.get("expiration"), status=reg.get("status"))
    em = osint.get("email_security") or {}
    if em.get("spf") or em.get("dmarc") or em.get("dkim_selector_found"):
        _ext(conn, f"ext:mail_policy:{domain}", "mail_policy", f"mail auth · {domain}",
             anchor, "HAS_POLICY", spf=em.get("spf"), dmarc=em.get("dmarc_policy"),
             spf_note=em.get("spf_note"), dmarc_note=em.get("dmarc_note"),
             dkim=em.get("dkim_selector_found"))
    http = osint.get("http") or {}
    status = http.get("status")
    # an error page's headers say nothing about the app behind it
    if http and not http.get("error") and not (isinstance(status, int) and status >= 400):
        _ext(conn, f"ext:headers:{host}", "security_headers",
             f"security headers · {len(http.get('security_headers_missing', []))} missing",
             anchor, "HAS_POLICY",
             present=http.get("security_headers_present"),
             missing=http.get("security_headers_missing"))
    for p in (osint.get("ports") or {}).get("open", []):
        _ext(conn, f"ext:port:{host}:{p['port']}", "port",
             f"{p['port']}/{p.get('service', '?')}", anchor, "LISTENS_ON", **p)
    robots = (osint.get("files") or {}).get("robots") or {}
    for path in robots.get("disallow", []):
        _ext(conn, f"ext:robots:{path}", "robots_path", path, anchor, "DISCLOSES",
             file="robots.txt")


# ------------------------------------------------------------------- read ----

def summary(conn: sqlite3.Connection) -> dict:
    one = lambda q: conn.execute(q).fetchone()[0]
    return {
        "nodes": one("SELECT count(*) FROM nodes"),
        "edges": one("SELECT count(*) FROM edges"),
        "exchanges": one("SELECT count(*) FROM exchanges"),
        "external_nodes": one("SELECT count(*) FROM nodes WHERE source='osint'"),
        "osint_runs": one("SELECT count(*) FROM osint_runs"),
        "builds": one("SELECT count(*) FROM builds"),
    }


def latest_osint(conn: sqlite3.Connection) -> dict | None:
    row = conn.execute("SELECT data FROM osint_runs ORDER BY id DESC LIMIT 1").fetchone()
    return json.loads(row[0]) if row else None


def load_build(conn: sqlite3.Connection, build_id: int | None = None) -> dict | None:
    """A stored model.json-shaped snapshot (latest when build_id is None)."""
    q = ("SELECT model_gz FROM builds WHERE id=?" if build_id is not None
         else "SELECT model_gz FROM builds ORDER BY id DESC LIMIT 1")
    row = conn.execute(q, (build_id,) if build_id is not None else ()).fetchone()
    return json.loads(gzip.decompress(row[0])) if row else None


def table_names(conn: sqlite3.Connection) -> list[str]:
    return [r[0] for r in conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")]


_SAFE_SQL = re.compile(r"^\s*(select|with)\b", re.I)


def read_only_sql(conn: sqlite3.Connection, sql: str, params=()) -> list[sqlite3.Row]:
    """Run a caller-supplied SELECT. Anything else is refused."""
    if not _SAFE_SQL.match(sql) or ";" in sql.strip().rstrip(";"):
        raise ValueError("only a single SELECT statement is allowed")
    return conn.execute(sql, params).fetchall()


def export_for_report(conn: sqlite3.Connection) -> dict:
    """The graph tables as plain JSON, for the report's in-page BQL console.

    Requests are not included: the report already carries every redacted
    request/response under `evidence`, and the console reads them from there.
    """
    ev_n: dict = {}
    for r in conn.execute("SELECT node_id, ev_id FROM node_evidence ORDER BY ev_id"):
        ev_n.setdefault(r[0], []).append(r[1])
    ev_e: dict = {}
    for r in conn.execute("SELECT edge_id, ev_id FROM edge_evidence ORDER BY ev_id"):
        ev_e.setdefault(r[0], []).append(r[1])
    nodes = [{"id": r["id"], "type": r["type"], "layer": r["layer"], "label": r["label"],
              "source": r["source"], "roles": json.loads(r["roles"]),
              "attrs": json.loads(r["attrs"]), "evidence": ev_n.get(r["id"], [])}
             for r in conn.execute("SELECT * FROM nodes ORDER BY rowid")]
    edges = [{"id": r["id"], "src": r["src"], "dst": r["dst"], "type": r["type"],
              "state": r["state"], "evidence": ev_e.get(r["id"], [])}
             for r in conn.execute("SELECT * FROM edges ORDER BY id")]
    run = conn.execute("SELECT id, host, generated_at FROM osint_runs "
                       "ORDER BY id DESC LIMIT 1").fetchone()
    facts = ([{"section": r[0], "key": r[1], "value": r[2]} for r in conn.execute(
        "SELECT section, key, value FROM osint_facts WHERE run_id=? ORDER BY rowid",
        (run["id"],))] if run else [])
    unknowns = [{"type": r["type"], "entity": r["entity"],
                 "we_dont_know": r["we_dont_know"], "next_step": r["next_step"]}
                for r in conn.execute("SELECT * FROM unknowns ORDER BY id")]
    return {"nodes": nodes, "edges": edges, "facts": facts, "unknowns": unknowns,
            "osint": dict(run) if run else None, "stats": summary(conn)}
