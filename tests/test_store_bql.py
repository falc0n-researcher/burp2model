"""graph.db (the graph database) and BQL (its query language)."""

import json
import os
import shutil
import sqlite3

import pytest

from burp2model import bql, store
from burp2model.cli import main

HERE = os.path.dirname(__file__)
SAMPLE = os.path.join(HERE, "..", "samples", "burp-history-sample.xml")
OSINT = os.path.join(HERE, "..", "samples", "osint-sample.json")
PLANTED = ["s3cr3tSESSIONv4lue123456", "AKIAIOSFODNN7EXAMPLE",
           "user@shop.example.com", "eyJhbGciOiJIUzI1NiJ9"]


@pytest.fixture(scope="module")
def built(tmp_path_factory):
    out = tmp_path_factory.mktemp("o")
    os.makedirs(out / "shop")
    shutil.copy(OSINT, out / "shop" / "osint.json")
    assert main([SAMPLE, "-w", "shop", "--out", str(out)]) == 0
    return out / "shop"


@pytest.fixture()
def conn(built):
    c = bql.connect(str(built / "graph.db"))
    yield c
    c.close()


def test_db_written_with_all_layers(built):
    assert (built / "graph.db").exists()
    c = store.open_db(str(built / "graph.db"))
    s = store.summary(c)
    assert s["exchanges"] == 17 and s["nodes"] > 39 and s["external_nodes"] > 0
    assert s["osint_runs"] == 1 and s["builds"] == 1


def test_db_never_contains_a_planted_secret(built):
    raw = (built / "graph.db").read_bytes()
    for secret in PLANTED:
        assert secret.encode() not in raw, secret


def test_osint_edges_are_external_never_observed(conn):
    res = bql.run_query(conn, "edge.state:EXTERNAL limit 500")
    assert res.total > 10
    types = {r["type"] for r in res.rows}
    assert {"RESOLVES_TO", "PRESENTS_CERT", "SUBDOMAIN_OF"} <= types
    # no edge to an external node is ever OBSERVED or INFERRED
    bad = conn.execute("SELECT count(*) FROM edges e JOIN nodes n ON n.id=e.dst "
                       "WHERE n.source='osint' AND e.state!='EXTERNAL'").fetchone()[0]
    assert bad == 0


def test_request_filters(conn):
    r = bql.run_query(conn, "req.method:POST AND resp.code.gte:200")
    assert r.kind == "requests" and r.total == 4
    assert all(row["method"] == "POST" for row in r.rows)
    assert bql.run_query(conn, "req.method:post").total == 4          # case-insensitive
    assert bql.run_query(conn, "NOT req.method:GET AND req.host.cont:api").total >= 4
    assert bql.run_query(conn, '"login"').total >= 2                  # free text


def test_node_filters_and_attr(conn):
    r = bql.run_query(conn, "node.type:endpoint AND node.state:STATIC_ONLY")
    assert [x["label"] for x in r.rows] == ["* /api/admin/audit"]
    assert r.rows[0]["evidence"]                                      # cited
    r = bql.run_query(conn, "node.attr.method:POST AND node.type:endpoint")
    assert r.total >= 3


def test_regex_and_like(conn):
    assert bql.run_query(conn, 'req.path.like:"/api/*"').total >= 3
    assert bql.run_query(conn, 'req.path.regex:"^/api/(checkout|export)$"').total == 3


def test_precedence_and_parens(conn):
    a = bql.run_query(conn, "req.method:POST OR req.method:GET AND resp.code:404").total
    b = bql.run_query(conn, "(req.method:POST OR req.method:GET) AND resp.code:404").total
    assert a >= b


def test_injection_is_inert(conn):
    before = store.summary(conn)
    for evil in ("req.path:\"'; DROP TABLE nodes; --\"", "req.host.cont:\"%' OR '1'='1\""):
        r = bql.run_query(conn, evil)
        assert r.total == 0
    assert store.summary(conn) == before


def test_sql_is_read_only(conn):
    with pytest.raises(bql.BQLError):
        bql.run_query(conn, "sql DELETE FROM nodes")
    with pytest.raises(bql.BQLError):
        bql.run_query(conn, "sql SELECT 1; DROP TABLE nodes")
    assert bql.run_query(conn, "sql SELECT count(*) AS n FROM nodes").rows[0]["n"] > 0


@pytest.mark.parametrize("bad", [
    "", "req.method:", "nosuch.field:x", "req.method:GET AND", "(req.method:GET",
    "req.method:GET AND node.type:endpoint", "resp.code:abc", "resp.code.cont:2",
    "req.path.regex:'('", "reach", "path a", "reach nonexistent-node-xyz",
])
def test_bad_queries_raise_bqlerror(conn, bad):
    with pytest.raises(bql.BQLError):
        bql.run_query(conn, bad)


def test_graph_verbs(conn):
    reach = bql.run_query(conn, 'reach "POST /api/checkout"')
    assert reach.kind == "paths" and reach.total >= 2
    assert all(r["evidence"] for r in reach.rows if r["state"] == "OBSERVED")
    blast = bql.run_query(conn, "blast host:shop.example.com depth 2")
    assert blast.total > 5
    assert bql.run_query(conn, 'upstream "POST /api/checkout"').total >= 2
    p = bql.run_query(conn, 'path host:shop.example.com to "POST /api/checkout"')
    assert p.total == 1 and p.rows[-1]["to"] == "POST /api/checkout"
    assert bql.run_query(conn, 'neighbors "POST /api/checkout" depth 1').total >= 2


def test_ambiguous_node_reference_is_refused(conn):
    with pytest.raises(bql.BQLError, match="ambiguous"):
        bql.run_query(conn, "reach /api")


def test_osint_and_meta_verbs(conn):
    assert bql.run_query(conn, "osint tls").total >= 5
    assert bql.run_query(conn, "unknowns").total >= 1
    assert bql.run_query(conn, "stats").kind == "table"
    assert "nodes" in {r["table"] for r in bql.run_query(conn, "schema").rows}
    assert bql.run_query(conn, "help").kind == "text"


def test_q_cli_and_json(built, capsys):
    out = str(built.parent)
    assert main(["q", "shop", "req.method:POST", "--out", out, "--format", "json"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert data["kind"] == "requests" and data["total"] == 4
    assert main(["q", "shop", "req.method:", "--out", out]) == 2
    assert main(["q", "nope", "stats", "--out", out]) == 2


def test_rebuild_keeps_one_osint_run_and_grows_history(built):
    out = str(built.parent)
    assert main([SAMPLE, "-w", "shop", "--out", out]) == 0            # identical osint
    c = store.open_db(str(built / "graph.db"))
    s = store.summary(c)
    assert s["osint_runs"] == 1 and s["builds"] == 2
    snap = store.load_build(c)
    assert snap["app"] == "shop" and snap["nodes"]


def test_offline_build_without_osint_still_makes_db(tmp_path):
    out = str(tmp_path)
    assert main([SAMPLE, "-w", "x", "--out", out, "--no-osint"]) == 0
    c = store.open_db(os.path.join(out, "x", "graph.db"))
    assert store.summary(c)["external_nodes"] == 0
    assert bql.run_query(bql.connect(os.path.join(out, "x", "graph.db")),
                         "osint").total == 0


def test_newer_schema_refused(tmp_path):
    p = str(tmp_path / "graph.db")
    c = sqlite3.connect(p)
    c.executescript("CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT);"
                    "INSERT INTO meta VALUES ('schema','99');")
    c.commit()
    c.close()
    with pytest.raises(ValueError, match="newer"):
        store.open_db(p)


def test_changes_against_stored_build(built, capsys):
    out = str(built.parent)
    assert main(["changes", "shop", "--against-build", "previous", "--out", out]) == 0
    assert "No drift" in capsys.readouterr().out
    assert main(["changes", "shop", "--out", out]) == 2                     # needs a baseline
    assert main(["changes", "shop", "--against-build", "999", "--out", out]) == 2
    builds = bql.run_query(bql.connect(str(built / "graph.db")),
                           "sql SELECT id FROM builds ORDER BY id")
    assert len(builds.rows) >= 1


def test_osint_wildcard_san_and_error_page_headers(tmp_path):
    osint = {"host": "shop.example.com", "domain": "example.com", "generated_at": "2026-01-01T00:00:00Z",
             "tls": {"issuer": "Amazon", "subject_cn": "*.example.com", "san": ["*.example.com", "api.example.com"]},
             "http": {"status": 503, "security_headers_present": {}, "security_headers_missing": ["csp"]}}
    os.makedirs(tmp_path / "x")
    (tmp_path / "x" / "osint.json").write_text(json.dumps(osint))
    assert main([SAMPLE, "-w", "x", "--out", str(tmp_path), "--no-osint"]) == 0
    c = bql.connect(str(tmp_path / "x" / "graph.db"))
    assert bql.run_query(c, "node.type:wildcard_san").total == 1
    assert bql.run_query(c, "node.type:subdomain AND node.label.cont:*").total == 0
    assert bql.run_query(c, "node.type:security_headers").total == 0       # 503: not the app's headers


def test_regex_backslashes_reach_the_engine_untouched(conn):
    assert bql.run_query(conn, 'req.path.regex:"^/api/\\w+$"').total >= 1
    assert bql.run_query(conn, "req.path.regex:'^/api/\\w+$'").total >= 1
    assert bql.run_query(conn, 'req.path.cont:"no\\"such"').total == 0          # escaped quote
