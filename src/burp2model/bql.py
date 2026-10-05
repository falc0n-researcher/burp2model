"""
BQL — the burp2model query language, run against graph.db.

Two kinds of query, both answered from the database with no language model and
every row carrying the evidence ids (`ev_N`) behind it.

Filters — an HTTPQL-style boolean expression over requests, nodes or edges:

    req.method:POST AND resp.code.gte:400
    req.host.cont:"api." AND NOT role:admin
    resp.body.regex:"stack ?trace" OR resp.header.cont:"x-powered-by"
    node.type:endpoint AND node.state:STATIC_ONLY
    edge.state:EXTERNAL
    "login"                                   (free text, on requests)

A term is `field:value` or `field.op:value`. Operators: eq (default), ne, cont,
ncont, like (`*` wildcard), regex, gt, gte, lt, lte. Combine with AND, OR, NOT
and parentheses; add `limit N` at the end. The fields (prefix decides the table):

    requests  req.method req.host req.path req.template req.header req.body
              resp.code resp.mime resp.header resp.body role id source
    nodes     node.type node.label node.id node.layer node.source node.role
              node.state node.evidence node.attr.<name>
    edges     edge.type edge.state edge.src edge.dst edge.src.type edge.dst.type
              edge.src.label edge.dst.label

Graph verbs — the structure, walked in the database:

    reach <node>              how it is reached, back to an entry point
    blast <node> [depth N]    everything downstream of it
    upstream <node> [depth N] everything that leads into it
    neighbors <node> [depth N]
    path <a> to <b>           shortest route between two nodes
    osint [section]           stored external recon (dns, tls, subdomains, ...)
    unknowns | stats | schema | help
    sql <SELECT ...>          a read-only SELECT against the tables

`<node>` is a node id, an exact label, or part of a label (`POST /api/login`).
Every value is bound as a SQL parameter, never spliced into the statement.
"""

from __future__ import annotations

import json
import re
import sqlite3
from collections import deque
from dataclasses import dataclass, field

from . import store

DEFAULT_LIMIT = 100
MAX_LIMIT = 5000

HELP = __doc__


class BQLError(ValueError):
    """A query the language cannot run (bad syntax, unknown field, ambiguity)."""


@dataclass
class Result:
    kind: str                                   # requests | nodes | edges | paths | facts | table | text
    columns: list[str] = field(default_factory=list)
    rows: list[dict] = field(default_factory=list)
    note: str = ""
    total: int | None = None                    # rows matched before `limit`

    def to_dict(self) -> dict:
        return {"kind": self.kind, "columns": self.columns, "rows": self.rows,
                "note": self.note, "total": self.total}


# ----------------------------------------------------------------- lexing ----

_OPS = ("eq", "ne", "cont", "ncont", "like", "regex", "gt", "gte", "lt", "lte")
_TOKEN = re.compile(r"""
    \s*(?:
      (?P<lp>\()|(?P<rp>\))
    | (?P<term>[A-Za-z_][\w.\-]*:(?:"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'|[^\s()]+))
    | (?P<str>"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*')
    | (?P<word>[^\s()"']+)
    )""", re.X)


def _unquote(s: str) -> str:
    if len(s) >= 2 and s[0] == s[-1] and s[0] in "\"'":
        # only the quote itself is escapable; every other backslash is kept, so
        # a regex like "\d+\.\d+" reaches the regex engine exactly as typed
        return s[1:-1].replace("\\" + s[0], s[0])
    return s


def _lex(text: str) -> list[tuple[str, str]]:
    toks, pos = [], 0
    text = text.strip()
    while pos < len(text):
        m = _TOKEN.match(text, pos)
        if not m or m.end() == pos:
            raise BQLError(f"cannot read the query near {text[pos:pos + 20]!r}")
        pos = m.end()
        kind = m.lastgroup
        val = m.group(kind)
        if kind == "word" and val.upper() in ("AND", "OR", "NOT"):
            toks.append((val.upper(), val.upper()))
        elif kind == "term":
            head, _, raw = val.partition(":")
            toks.append(("term", (head, _unquote(raw))))
        elif kind == "str":
            toks.append(("text", _unquote(val)))
        elif kind in ("lp", "rp"):
            toks.append((kind, val))
        else:
            toks.append(("word", val))
    return toks


# ---------------------------------------------------------------- parsing ----

# AST: ("and", a, b) ("or", a, b) ("not", a) ("term", field, op, value) ("text", value)

class _Parser:
    def __init__(self, toks):
        self.t, self.i = toks, 0

    def peek(self):
        return self.t[self.i][0] if self.i < len(self.t) else None

    def take(self):
        tok = self.t[self.i]
        self.i += 1
        return tok

    def parse(self):
        node = self.or_()
        if self.i < len(self.t):
            raise BQLError(f"unexpected {self.t[self.i][1]!r}")
        return node

    def or_(self):
        node = self.and_()
        while self.peek() == "OR":
            self.take()
            node = ("or", node, self.and_())
        return node

    def and_(self):
        node = self.not_()
        while self.peek() in ("AND", "term", "text", "lp", "NOT"):   # adjacent = AND
            if self.peek() == "AND":
                self.take()
            node = ("and", node, self.not_())
        return node

    def not_(self):
        if self.peek() == "NOT":
            self.take()
            return ("not", self.not_())
        return self.atom()

    def atom(self):
        kind = self.peek()
        if kind == "lp":
            self.take()
            node = self.or_()
            if self.peek() != "rp":
                raise BQLError("missing )")
            self.take()
            return node
        if kind == "term":
            _, (head, raw) = self.take()
            parts = head.split(".")
            op = "eq"
            if len(parts) > 1 and parts[-1] in _OPS:
                op = parts.pop()
            return ("term", ".".join(parts), op, raw)
        if kind == "text":
            return ("text", self.take()[1])
        raise BQLError("expected a term like field:value" if kind is None
                       else f"unexpected {self.t[self.i][1]!r}")


# -------------------------------------------------------------- compiling ----

# field -> (sql expression, kind)   kind: text | int
_REQUEST_FIELDS = {
    "req.method": ("method", "text"), "req.host": ("host", "text"),
    "req.path": ("path", "text"), "req.template": ("path_template", "text"),
    "req.header": ("req_headers", "text"), "req.body": ("req_body", "text"),
    "resp.code": ("status", "int"), "resp.mime": ("mime", "text"),
    "resp.header": ("resp_headers", "text"), "resp.body": ("resp_body", "text"),
    "role": ("role", "text"), "id": ("id", "int"), "source": ("source", "text"),
}
_REQUEST_TEXT = ("path", "req_body", "resp_body", "req_headers", "resp_headers", "host")

_NODE_FIELDS = {
    "node.id": ("nodes.id", "text"), "node.type": ("nodes.type", "text"),
    "node.label": ("nodes.label", "text"), "node.layer": ("nodes.layer", "int"),
    "node.source": ("nodes.source", "text"), "node.role": ("nodes.roles", "text"),
    "node.state": ("CAST(json_extract(nodes.attrs,'$.api_state') AS TEXT)", "text"),
}
_NODE_TEXT = ("nodes.label", "nodes.id")

_EDGE_FIELDS = {
    "edge.type": ("edges.type", "text"), "edge.state": ("edges.state", "text"),
    "edge.src": ("edges.src", "text"), "edge.dst": ("edges.dst", "text"),
    "edge.src.type": ("(SELECT type FROM nodes WHERE id=edges.src)", "text"),
    "edge.dst.type": ("(SELECT type FROM nodes WHERE id=edges.dst)", "text"),
    "edge.src.label": ("(SELECT label FROM nodes WHERE id=edges.src)", "text"),
    "edge.dst.label": ("(SELECT label FROM nodes WHERE id=edges.dst)", "text"),
}
_EDGE_TEXT = ("edges.src", "edges.dst", "edges.type")

_ATTR = re.compile(r"^[A-Za-z_][\w\-]*$")


def _target_of(field_name: str) -> str:
    if field_name in _REQUEST_FIELDS:
        return "requests"
    if field_name in _EDGE_FIELDS:
        return "edges"
    if field_name in _NODE_FIELDS or field_name == "node.evidence" \
            or field_name.startswith("node.attr."):
        return "nodes"
    raise BQLError(f"unknown field {field_name!r}; run `help` for the field list")


def _targets(ast) -> set[str]:
    kind = ast[0]
    if kind == "term":
        return {_target_of(ast[1])}
    if kind == "text":
        return set()
    return set().union(*(_targets(a) for a in ast[1:]))


def _esc_like(s: str) -> str:
    return s.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def _term_sql(target: str, fname: str, op: str, value: str, params: list) -> str:
    if target == "requests":
        col, kind = _REQUEST_FIELDS[fname]
    elif target == "edges":
        col, kind = _EDGE_FIELDS[fname]
    elif fname == "node.evidence":
        try:
            ev = int(value.lower().removeprefix("ev_"))
        except ValueError:
            raise BQLError(f"node.evidence needs an evidence id, got {value!r}")
        if op not in ("eq", "ne"):
            raise BQLError("node.evidence supports eq and ne")
        params.append(ev)
        inner = "nodes.id IN (SELECT node_id FROM node_evidence WHERE ev_id=?)"
        return inner if op == "eq" else f"NOT ({inner})"
    elif fname.startswith("node.attr."):
        attr = fname[len("node.attr."):]
        if not _ATTR.match(attr):
            raise BQLError(f"bad attribute name {attr!r}")
        col, kind = f"CAST(json_extract(nodes.attrs,'$.{attr}') AS TEXT)", "text"
    else:
        col, kind = _NODE_FIELDS[fname]

    if fname == "node.role" and op in ("eq", "ne"):
        params.append(f'%"{_esc_like(value)}"%')
        return (f"nodes.roles LIKE ? ESCAPE '\\'" if op == "eq"
                else f"nodes.roles NOT LIKE ? ESCAPE '\\'")

    if kind == "int":
        if op in ("cont", "ncont", "like", "regex"):
            raise BQLError(f"{fname} is numeric; use eq ne gt gte lt lte")
        try:
            params.append(int(value))
        except ValueError:
            raise BQLError(f"{fname} needs a number, got {value!r}")
        sym = {"eq": "=", "ne": "!=", "gt": ">", "gte": ">=", "lt": "<", "lte": "<="}[op]
        return f"{col} {sym} ?"

    if op in ("gt", "gte", "lt", "lte"):
        raise BQLError(f"{fname} is text; {op} is for numbers")
    if op == "eq":
        params.append(value)
        return f"{col} = ? COLLATE NOCASE"
    if op == "ne":
        params.append(value)
        return f"({col} IS NULL OR {col} != ? COLLATE NOCASE)"
    if op in ("cont", "ncont"):
        params.append(f"%{_esc_like(value)}%")
        return (f"{col} LIKE ? ESCAPE '\\'" if op == "cont"
                else f"({col} IS NULL OR {col} NOT LIKE ? ESCAPE '\\')")
    if op == "like":
        params.append("%".join(_esc_like(p) for p in value.split("*")))
        return f"{col} LIKE ? ESCAPE '\\'"
    try:
        re.compile(value)
    except re.error as e:
        raise BQLError(f"bad regex {value!r}: {e}")
    params.append(value)
    return f"{col} REGEXP ?"


def _compile(ast, target: str, params: list) -> str:
    kind = ast[0]
    if kind == "and":
        return f"({_compile(ast[1], target, params)} AND {_compile(ast[2], target, params)})"
    if kind == "or":
        return f"({_compile(ast[1], target, params)} OR {_compile(ast[2], target, params)})"
    if kind == "not":
        return f"(NOT {_compile(ast[1], target, params)})"
    if kind == "text":
        cols = {"requests": _REQUEST_TEXT, "nodes": _NODE_TEXT, "edges": _EDGE_TEXT}[target]
        params.extend([f"%{_esc_like(ast[1])}%"] * len(cols))
        return "(" + " OR ".join(f"{c} LIKE ? ESCAPE '\\'" for c in cols) + ")"
    return _term_sql(target, ast[1], ast[2], ast[3], params)


# --------------------------------------------------------------- connection --

def _regexp(pattern, value):
    if value is None:
        return False
    try:
        return re.search(pattern, value, re.I) is not None
    except re.error:
        return False


def connect(path: str) -> sqlite3.Connection:
    """Open graph.db for querying: read-only semantics plus the REGEXP function."""
    conn = store.open_db(path)
    conn.create_function("regexp", 2, _regexp, deterministic=True)
    conn.execute("PRAGMA query_only = ON")
    try:
        conn.execute("SELECT json_extract('{}','$.a')")
    except sqlite3.OperationalError:
        raise BQLError("this Python's SQLite lacks the JSON1 extension BQL needs")
    return conn


# ---------------------------------------------------------------- filters ----

_LIMIT = re.compile(r"\s+limit\s+(\d+)\s*$", re.I)

_REQ_SELECT = ("SELECT id, method, status, host, path, role, mime FROM exchanges")
_NODE_SELECT = ("SELECT id, type, layer, label, source, roles, attrs, "
                "(SELECT group_concat(ev_id) FROM node_evidence WHERE node_id=nodes.id) AS ev "
                "FROM nodes")
_EDGE_SELECT = ("SELECT edges.id AS id, "
                "(SELECT label FROM nodes WHERE id=edges.src) AS src, edges.type AS type, "
                "edges.state AS state, (SELECT label FROM nodes WHERE id=edges.dst) AS dst, "
                "edges.src AS src_id, edges.dst AS dst_id, "
                "(SELECT group_concat(ev_id) FROM edge_evidence WHERE edge_id=edges.id) AS ev "
                "FROM edges")


def _evs(csv) -> list[int]:
    return sorted({int(x) for x in str(csv).split(",") if x}) if csv else []


def run_filter(conn: sqlite3.Connection, text: str, limit: int = DEFAULT_LIMIT) -> Result:
    m = _LIMIT.search(text)
    if m:
        limit = int(m.group(1))
        text = text[:m.start()]
    limit = max(1, min(limit, MAX_LIMIT))
    ast = _Parser(_lex(text)).parse()
    targets = _targets(ast)
    if len(targets) > 1:
        raise BQLError("a query can filter one of requests, nodes or edges — "
                       f"this mixes {', '.join(sorted(targets))}")
    target = next(iter(targets), "requests")
    params: list = []
    where = _compile(ast, target, params)
    table = {"requests": "exchanges", "nodes": "nodes", "edges": "edges"}[target]
    total = conn.execute(f"SELECT count(*) FROM {table} WHERE {where}", params).fetchone()[0]

    if target == "requests":
        rows = conn.execute(f"{_REQ_SELECT} WHERE {where} ORDER BY id LIMIT ?",
                            params + [limit]).fetchall()
        out = [{"ev": f"ev_{r['id']}", "method": r["method"], "status": r["status"],
                "host": r["host"], "path": r["path"], "role": r["role"] or "",
                "mime": r["mime"] or ""} for r in rows]
        cols = ["ev", "method", "status", "host", "path", "role"]
    elif target == "nodes":
        rows = conn.execute(f"{_NODE_SELECT} WHERE {where} ORDER BY layer, type, label LIMIT ?",
                            params + [limit]).fetchall()
        out = []
        for r in rows:
            attrs = json.loads(r["attrs"])
            out.append({"id": r["id"], "type": r["type"], "layer": r["layer"],
                        "label": r["label"], "source": r["source"],
                        "state": attrs.get("api_state") or "",
                        "roles": ",".join(json.loads(r["roles"])),
                        "evidence": [f"ev_{i}" for i in _evs(r["ev"])]})
        cols = ["type", "label", "state", "source", "roles", "evidence"]
    else:
        rows = conn.execute(f"{_EDGE_SELECT} WHERE {where} ORDER BY edges.id LIMIT ?",
                            params + [limit]).fetchall()
        out = [{"src": r["src"], "type": r["type"], "state": r["state"], "dst": r["dst"],
                "evidence": [f"ev_{i}" for i in _evs(r["ev"])]} for r in rows]
        cols = ["src", "type", "state", "dst", "evidence"]
    note = f"{total} match{'es' if total != 1 else ''}"
    if total > len(out):
        note += f" (showing {len(out)}; add `limit N`)"
    return Result(target, cols, out, note, total)


# ------------------------------------------------------------ graph verbs ----

def resolve(conn: sqlite3.Connection, ref: str) -> str:
    """Turn an id, exact label or label fragment into one node id."""
    ref = ref.strip()
    row = conn.execute("SELECT id FROM nodes WHERE id=?", (ref,)).fetchone()
    if row:
        return row[0]
    rows = conn.execute("SELECT id FROM nodes WHERE label=? COLLATE NOCASE", (ref,)).fetchall()
    if not rows:
        rows = conn.execute("SELECT id FROM nodes WHERE label LIKE ? ESCAPE '\\' "
                            "ORDER BY layer LIMIT 6", (f"%{_esc_like(ref)}%",)).fetchall()
    if not rows:
        raise BQLError(f"no node matches {ref!r}")
    if len(rows) > 1:
        labels = [conn.execute("SELECT label FROM nodes WHERE id=?", (r[0],)).fetchone()[0]
                  for r in rows[:5]]
        raise BQLError(f"{ref!r} is ambiguous — be more specific: " + " | ".join(labels))
    return rows[0][0]


def _label(conn, nid: str) -> str:
    r = conn.execute("SELECT label FROM nodes WHERE id=?", (nid,)).fetchone()
    return r[0] if r else nid


def _edge_evs(conn, edge_id: int) -> list[str]:
    return [f"ev_{r[0]}" for r in conn.execute(
        "SELECT ev_id FROM edge_evidence WHERE edge_id=? ORDER BY ev_id", (edge_id,))]


def _walk(conn, nid: str, depth: int, direction: str) -> Result:
    """Recursive-CTE traversal; `out` follows edges forward, `in` backward."""
    a, b = ("src", "dst") if direction == "out" else ("dst", "src")
    depth = max(1, min(depth, 8))
    rows = conn.execute(f"""
        WITH RECURSIVE walk(id, d) AS (
          SELECT ?, 0
          UNION
          SELECT e.{b}, walk.d + 1 FROM walk JOIN edges e ON e.{a} = walk.id
          WHERE walk.d < ?
        )
        SELECT n.id, n.type, n.label, n.source, min(walk.d) AS d
        FROM walk JOIN nodes n ON n.id = walk.id
        WHERE walk.d > 0 GROUP BY n.id ORDER BY d, n.type, n.label""", (nid, depth)).fetchall()
    out = [{"hops": r["d"], "type": r["type"], "label": r["label"], "source": r["source"]}
           for r in rows]
    word = "downstream of" if direction == "out" else "upstream of"
    return Result("nodes", ["hops", "type", "label", "source"], out,
                  f"{len(out)} node(s) {word} {_label(conn, nid)} (depth {depth})", len(out))


def _paths(conn, start: str, goal: str | None, limit: int = 3, max_depth: int = 8) -> list[list[dict]]:
    """Shortest paths. goal=None walks backwards from `start` to an entry host."""
    back = goal is None
    a, b = ("dst", "src") if back else ("src", "dst")
    found: list[list[dict]] = []
    seen = {start: 0}
    queue = deque([(start, [])])
    while queue and len(found) < limit:
        cur, trail = queue.popleft()
        if len(trail) >= max_depth:
            continue
        for e in conn.execute(
                f"SELECT id, src, dst, type, state FROM edges WHERE {a}=? ORDER BY id", (cur,)):
            nxt = e[b]
            hop = {"from": e["src"], "to": e["dst"], "edge": e["type"], "state": e["state"],
                   "evidence": _edge_evs(conn, e["id"])}
            path = trail + [hop]
            if (back and conn.execute("SELECT type FROM nodes WHERE id=?", (nxt,)).fetchone()[0]
                    == "host") or (not back and nxt == goal):
                found.append(path)
                if len(found) >= limit:
                    break
                continue
            if nxt not in seen or seen[nxt] >= len(path):
                seen[nxt] = len(path)
                queue.append((nxt, path))
    if back:
        found = [list(reversed(p)) for p in found]
    return found


def _paths_result(conn, paths, title: str) -> Result:
    rows = []
    for n, p in enumerate(paths, 1):
        for h, hop in enumerate(p, 1):
            rows.append({"path": n, "hop": h, "from": _label(conn, hop["from"]),
                         "edge": hop["edge"], "state": hop["state"],
                         "to": _label(conn, hop["to"]), "evidence": hop["evidence"]})
    return Result("paths", ["path", "hop", "from", "edge", "state", "to", "evidence"], rows,
                  f"{len(paths)} path(s): {title}" if paths else f"no path: {title}",
                  len(paths))


def _depth_arg(words: list[str]) -> tuple[list[str], int]:
    if len(words) >= 2 and words[-2].lower() == "depth" and words[-1].isdigit():
        return words[:-2], int(words[-1])
    return words, 3


def _osint_result(conn, section: str | None) -> Result:
    row = conn.execute("SELECT id, host, generated_at FROM osint_runs ORDER BY id DESC LIMIT 1"
                       ).fetchone()
    if not row:
        return Result("facts", ["section", "key", "value"], [],
                      "no OSINT stored yet — build with OSINT enabled (the default)", 0)
    q = "SELECT section, key, value FROM osint_facts WHERE run_id=?"
    p: list = [row["id"]]
    if section:
        q += " AND section=? COLLATE NOCASE"
        p.append(section)
    rows = [{"section": r[0], "key": r[1], "value": r[2]}
            for r in conn.execute(q + " ORDER BY rowid", p)]
    return Result("facts", ["section", "key", "value"], rows,
                  f"OSINT run #{row['id']} · {row['host']} · {row['generated_at']}", len(rows))


def run_query(conn: sqlite3.Connection, text: str, limit: int = DEFAULT_LIMIT) -> Result:
    """Run one BQL statement. Raises BQLError on anything it cannot run."""
    text = (text or "").strip().rstrip(";").strip()
    if not text:
        raise BQLError("empty query — try `help`")
    first, _, rest = text.partition(" ")
    verb, rest = first.lower(), rest.strip()

    if verb == "help":
        return Result("text", note=HELP)
    if verb == "schema":
        rows = []
        for t in store.table_names(conn):
            cols = [c[1] for c in conn.execute(f"PRAGMA table_info({t})")]
            rows.append({"table": t, "columns": ", ".join(cols)})
        return Result("table", ["table", "columns"], rows, f"{len(rows)} tables", len(rows))
    if verb == "stats":
        s = store.summary(conn)
        return Result("table", ["metric", "value"],
                      [{"metric": k, "value": v} for k, v in s.items()], "graph.db", len(s))
    if verb == "unknowns":
        rows = [{"type": r["type"], "entity": r["entity"], "we_dont_know": r["we_dont_know"],
                 "next_step": r["next_step"]}
                for r in conn.execute("SELECT * FROM unknowns ORDER BY id")]
        return Result("table", ["type", "entity", "we_dont_know", "next_step"], rows,
                      f"{len(rows)} unknown(s)", len(rows))
    if verb == "osint":
        return _osint_result(conn, rest or None)
    if verb == "sql":
        try:
            rows = store.read_only_sql(conn, rest)
        except (ValueError, sqlite3.Error) as e:
            raise BQLError(f"sql: {e}")
        cols = list(rows[0].keys()) if rows else []
        return Result("table", cols, [dict(r) for r in rows[:limit]],
                      f"{len(rows)} row(s)", len(rows))
    if verb in ("reach", "blast", "upstream", "neighbors", "path"):
        if not rest:
            raise BQLError(f"{verb} needs a node")
        if verb == "path":
            m = re.split(r"\s+to\s+", rest, maxsplit=1, flags=re.I)
            if len(m) != 2:
                raise BQLError("usage: path <a> to <b>")
            a, b = resolve(conn, _unquote(m[0].strip())), resolve(conn, _unquote(m[1].strip()))
            return _paths_result(conn, _paths(conn, a, b, limit=1),
                                 f"{_label(conn, a)} → {_label(conn, b)}")
        words, depth = _depth_arg(rest.split())
        nid = resolve(conn, _unquote(" ".join(words)))
        if verb == "reach":
            return _paths_result(conn, _paths(conn, nid, None),
                                 f"how {_label(conn, nid)} is reached")
        if verb == "blast":
            return _walk(conn, nid, depth, "out")
        if verb == "upstream":
            return _walk(conn, nid, depth, "in")
        down, up = _walk(conn, nid, depth, "out"), _walk(conn, nid, depth, "in")
        rows = ([dict(r, direction="out") for r in down.rows]
                + [dict(r, direction="in") for r in up.rows])
        return Result("nodes", ["direction", "hops", "type", "label", "source"], rows,
                      f"{len(rows)} node(s) within {depth} hop(s) of {_label(conn, nid)}",
                      len(rows))
    return run_filter(conn, text, limit)


# ------------------------------------------------------------- rendering ----

def _cell(v) -> str:
    if isinstance(v, list):
        return ",".join(map(str, v[:4])) + ("…" if len(v) > 4 else "")
    return "" if v is None else str(v)


def render_text(res: Result, width: int = 44) -> str:
    if res.kind == "text":
        return res.note
    lines = []
    if res.rows:
        cols = res.columns
        cells = [[_cell(r.get(c)) for c in cols] for r in res.rows]
        widths = [min(max(len(c), *(len(row[i]) for row in cells)), width)
                  for i, c in enumerate(cols)]
        fmt = lambda row: "  ".join(
            (v if len(v) <= w else v[:w - 1] + "…").ljust(w) for v, w in zip(row, widths)
        ).rstrip()
        lines.append(fmt(cols))
        lines.append(fmt(["-" * w for w in widths]))
        lines.extend(fmt(row) for row in cells)
        lines.append("")
    lines.append(res.note)
    return "\n".join(lines)


def render_json(res: Result) -> str:
    return json.dumps(res.to_dict(), indent=2, default=str)
