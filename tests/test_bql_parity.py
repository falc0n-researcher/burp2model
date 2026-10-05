"""The report's JavaScript BQL engine must answer exactly like the SQLite one."""

import json
import os
import shutil
import subprocess

import pytest

from burp2model import bql, store
from burp2model.bql_js import BQL_JS
from burp2model.cli import main

HERE = os.path.dirname(__file__)
SAMPLE = os.path.join(HERE, "..", "samples", "burp-history-sample.xml")
OSINT = os.path.join(HERE, "..", "samples", "osint-sample.json")

pytestmark = pytest.mark.skipif(shutil.which("node") is None, reason="node not installed")

CORPUS = [
    "req.method:POST AND resp.code.gte:200",
    "req.method:post",
    "NOT req.method:GET AND req.host.cont:api",
    "req.path.like:/api/*",
    'req.path.regex:"^/api/(checkout|export)$"',
    "(req.method:POST OR req.method:GET) AND resp.code:404",
    "req.method:POST OR req.method:GET AND resp.code:404",
    '"login"',
    'resp.body.regex:"token" OR "login"',
    "resp.header.cont:set-cookie",
    'req.path.regex:"^/api/\\w+$"',
    'resp.body.regex:"\\d+\\.\\d+"',
    'req.path.cont:"a\\"b"',
    "req.header.cont:cookie limit 2",
    "resp.code.gt:399",
    "id:5",
    "node.type:endpoint AND node.state:STATIC_ONLY",
    "node.type:endpoint limit 3",
    "node.attr.method:POST AND node.type:endpoint",
    "node.type:subdomain",
    "node.type:subdomain AND node.attr.seen_in_capture:0",
    "node.layer:0",
    "node.layer.lte:1",
    "node.evidence:ev_3",
    "node.source:osint AND NOT node.type:ip",
    "node.role:admin",
    "edge.state:EXTERNAL",
    "edge.type:CALLS",
    "edge.src.type:host AND edge.dst.type:route",
    "edge.dst.label.cont:checkout",
    'reach "POST /api/checkout"',
    "reach host:shop.example.com",
    "blast host:shop.example.com depth 1",
    "blast host:shop.example.com depth 3",
    'upstream "POST /api/checkout"',
    'neighbors "POST /api/checkout" depth 1',
    'path host:shop.example.com to "POST /api/checkout"',
    "osint",
    "osint tls",
    "osint DNS",
    "unknowns",
    "stats",
    # errors must agree too
    "", "req.method:", "nosuch.field:x", "req.method:GET AND", "(req.method:GET",
    "req.method:GET AND node.type:endpoint", "resp.code:abc", "resp.code.cont:2",
    "req.path.regex:'('", "reach", "path a", "reach nonexistent-node-xyz", "reach /api",
    "node.evidence:zzz", "node.layer.regex:x",
]


@pytest.fixture(scope="module")
def engines(tmp_path_factory):
    out = tmp_path_factory.mktemp("o")
    os.makedirs(out / "shop")
    shutil.copy(OSINT, out / "shop" / "osint.json")
    assert main([SAMPLE, "-w", "shop", "--out", str(out)]) == 0
    path = str(out / "shop" / "graph.db")
    conn = bql.connect(path)
    db = store.export_for_report(conn)
    model = json.load(open(out / "shop" / "model.json"))
    db["evidence"] = {f"ev_{e['id']}": e for e in model["evidence"]}
    return conn, db


def _js(db, queries):
    script = BQL_JS + """
const fs=require('fs');const inp=JSON.parse(fs.readFileSync(0,'utf8'));
const db=inp.db;db.requests=BQL.requestsFrom(db.evidence);
const out=inp.queries.map(q=>{try{return{ok:BQL.run(db,q)};}catch(e){
  return{err:e instanceof BQL.BQLError?e.message:'CRASH '+e.message};}});
console.log(JSON.stringify(out));"""
    p = subprocess.run(["node", "-e", script], input=json.dumps({"db": db, "queries": queries}),
                       capture_output=True, text=True, timeout=60)
    assert p.returncode == 0, p.stderr
    return json.loads(p.stdout)


def _norm(res):
    """Order-insensitive view of a result (ties in SQL ordering are unspecified)."""
    rows = [json.dumps(r, sort_keys=True, default=str) for r in res["rows"]]
    return res["kind"], res["columns"], res["total"], sorted(rows), res["note"]


def test_js_engine_matches_python_engine(engines):
    conn, db = engines
    js = _js(db, CORPUS)
    mismatches = []
    for q, j in zip(CORPUS, js):
        try:
            py = bql.run_query(conn, q).to_dict()
            py_err = None
        except bql.BQLError as e:
            py, py_err = None, str(e)
        if py_err is not None:
            if "err" not in j:
                mismatches.append((q, "python errors, js ran", py_err))
            continue
        if "err" in j:
            mismatches.append((q, "js errors, python ran", j["err"]))
            continue
        if _norm(py) != _norm(j["ok"]):
            mismatches.append((q, _norm(py)[:3], _norm(j["ok"])[:3]))
    assert not mismatches, "\n".join(map(str, mismatches))
