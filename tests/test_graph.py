"""
Tests for the reasoning layer (graph.py): traversal, execution flows, trust
zones, communities, coupling, the LLM package and the GraphML/Cypher/JSON
exports. Every assertion is grounded in traffic the test builds itself.
"""

import json
import xml.etree.ElementTree as ET

import pytest

from burp2model import build, parse_items, context_package
from burp2model.graph import (
    ReasonGraph, reason_graph, to_graphml, to_cypher, to_graph_json,
)

from test_gaps import export, item


def _app(tmp_path):
    """A small app: two pages, a script, catalog + admin endpoints, a third party."""
    items = [
        item(host="www.shop.test", path="/"),
        item(host="www.shop.test", path="/dashboard",
             resp_headers=[("Set-Cookie", "sid=x; HttpOnly; Secure")]),
        item(host="www.shop.test", path="/app.js", mime="script",
             resp_ct="application/javascript",
             resp_body='fetch("/api/orders");fetch("/api/admin/users");'),
        item(host="api.shop.test", path="/api/orders", mime="JSON",
             resp_ct="application/json", resp_body="{}",
             req_headers=[("Authorization", "Bearer x"),
                          ("Referer", "https://www.shop.test/dashboard")]),
        item(method="POST", host="api.shop.test", path="/api/admin/users", mime="JSON",
             resp_ct="application/json", resp_body="{}",
             req_headers=[("Authorization", "Bearer x")]),
        item(host="cdn.analytics.test", path="/t.js", mime="script",
             resp_ct="application/javascript", resp_body="//tracker"),
    ]
    return build(list(parse_items(export(tmp_path, items))), name="shop",
                 scope=["shop.test"])


# ---------------------------------------------- reach / flows ----------------

def test_reach_traces_paths_back_to_an_entry(tmp_path):
    m = _app(tmp_path)
    rg = ReasonGraph(m)
    nid = next(nid for nid, n in m.nodes.items()
              if n.type == "endpoint" and "/api/orders" in n.attrs.get("path", ""))
    r = rg.reach(nid)
    assert r["paths"], "orders should be reachable from an entry point"
    entries = {p["entry"] for p in r["paths"]}
    # reached both directly from its host and, via the script reference, from the CDN/page
    assert any("api.shop.test" in e for e in entries)
    for p in r["paths"]:
        assert p["hops"], "each path lists its hops"
        for hop in p["hops"]:
            assert hop["evidence"], "every hop is cited"


def test_reach_marks_entry_nodes(tmp_path):
    m = _app(tmp_path)
    rg = ReasonGraph(m)
    host = next(nid for nid, n in m.nodes.items() if n.type == "host")
    assert rg.reach(host).get("entry") is True


# ---------------------------------------------- blast / touched_by -----------

def test_blast_lists_downstream(tmp_path):
    m = _app(tmp_path)
    rg = ReasonGraph(m)
    page = next(nid for nid, n in m.nodes.items()
                if n.type == "route" and n.label.endswith("/dashboard"))
    b = rg.blast(page, depth=3)
    assert b["total"] >= 1
    # a page reaches endpoints / a cookie downstream
    assert "downstream" in b


def test_touched_by_is_the_reverse(tmp_path):
    m = _app(tmp_path)
    rg = ReasonGraph(m)
    nid = next(nid for nid, n in m.nodes.items()
              if n.type == "endpoint" and "/api/orders" in n.attrs.get("path", ""))
    up = rg.touched_by(nid, depth=3)
    assert up["total"] >= 1


# ---------------------------------------------- trust zones ------------------

def test_trust_zones_group_by_auth(tmp_path):
    m = _app(tmp_path)
    z = ReasonGraph(m).trust_zones()
    assert z.get("credentialed"), "orders/admin carried a bearer token"
    assert z.get("privileged"), "/api/admin/users is privileged-looking"
    labels = {r["endpoint"] for r in z["privileged"]}
    assert any("admin" in l for l in labels)


# ---------------------------------------------- communities ------------------

def test_communities_are_deterministic_and_named(tmp_path):
    m = _app(tmp_path)
    a = ReasonGraph(m).communities()
    b = ReasonGraph(m).communities()
    assert [c["members"] for c in a] == [c["members"] for c in b], "stable"
    assert all("id" in c and "name" in c and c["size"] for c in a)
    # the third party clusters away from the first-party app
    tp_clusters = [c for c in a if any("analytics" in mlabel for mlabel in c["members"])]
    assert tp_clusters


def test_communities_do_not_collapse_into_one(tmp_path):
    m = _app(tmp_path)
    comms = ReasonGraph(m).communities()
    assert len(comms) >= 2, "connectors held out, so features separate"


# ---------------------------------------------- hubs / coupling --------------

def test_hubs_rank_by_connectivity(tmp_path):
    m = _app(tmp_path)
    hubs = ReasonGraph(m).hubs(5)
    assert hubs and hubs[0]["degree"] >= hubs[-1]["degree"]
    assert all(h["type"] not in ("parameter", "operation", "cookie") for h in hubs)


def test_coupling_finds_third_parties(tmp_path):
    m = _app(tmp_path)
    c = ReasonGraph(m).coupling()
    tps = {e["to"] for e in c["to_third_party"]}
    assert any("analytics" in t for t in tps)


# ---------------------------------------------- LLM package ------------------

def test_reason_graph_package_shape(tmp_path):
    m = _app(tmp_path)
    g = reason_graph(m)
    assert g["guide"] and g["nodes"] and g["adjacency"]
    assert set(g["reasoning"]) >= {
        "entry_points", "hubs", "communities", "trust_zones",
        "coupling", "execution_flows"}
    # adjacency only references known nodes
    for src, links in g["adjacency"].items():
        assert src in g["nodes"]
        for dst, etype, state in links:
            assert dst in g["nodes"]
            assert state in ("OBSERVED", "INFERRED")


def test_context_package_embeds_graph_and_resolves_its_evidence(tmp_path):
    m = _app(tmp_path)
    pkg = context_package(m)
    assert "graph" in pkg
    # every evidence id the graph cites resolves in the package evidence table
    ev_keys = set(pkg["evidence"])
    cited = []

    def walk(o):
        if isinstance(o, dict):
            for k, v in o.items():
                if k == "evidence" and isinstance(v, list):
                    cited.extend(i for i in v if isinstance(i, int))
                else:
                    walk(v)
        elif isinstance(o, list):
            for v in o:
                walk(v)
    walk(pkg["graph"])
    for i in cited:
        assert f"ev_{i}" in ev_keys, f"ev_{i} cited by graph but not resolved"


def test_context_package_graph_can_be_disabled(tmp_path):
    pkg = context_package(_app(tmp_path), graph=False)
    assert "graph" not in pkg


# ---------------------------------------------- exports ----------------------

def test_graphml_is_wellformed_and_complete(tmp_path):
    m = _app(tmp_path)
    xml = to_graphml(m)
    root = ET.fromstring(xml)                       # parses = well-formed
    ns = "{http://graphml.graphdrawing.org/xmlns}"
    graph = root.find(f"{ns}graph")
    assert len(graph.findall(f"{ns}node")) == len(m.nodes)


def test_cypher_has_a_statement_per_node_and_edge(tmp_path):
    m = _app(tmp_path)
    cy = to_cypher(m)
    assert cy.count("MERGE (n:") == len(m.nodes)
    valid_edges = [e for e in m.edges if e.src in m.nodes and e.dst in m.nodes]
    assert cy.count("]->(b)") == len(valid_edges)


def test_graph_json_is_node_link(tmp_path):
    m = _app(tmp_path)
    d = to_graph_json(m)
    assert d["directed"] and len(d["nodes"]) == len(m.nodes)
    ids = {n["id"] for n in d["nodes"]}
    for link in d["links"]:
        assert link["source"] in ids and link["target"] in ids


# ---------------------------------------------- CLI --------------------------

def test_cli_graph_exports_and_reasons(tmp_path, capsys):
    from burp2model.cli import main
    xml = export(tmp_path, [item(host="www.shop.test", path="/"),
                            item(host="api.shop.test", path="/api/x", mime="JSON",
                                 resp_ct="application/json", resp_body="{}")])
    out = tmp_path / "o"
    assert main([xml, "-w", "shop", "--out", str(out), "--scope", "shop.test"]) == 0
    # build wrote the graph exports
    assert (out / "shop" / "graph.graphml").exists()
    assert (out / "shop" / "graph.json").exists()
    capsys.readouterr()
    # graph overview
    assert main(["graph", "shop", "--out", str(out)]) == 0
    assert "graph reasoning" in capsys.readouterr().out
    # cypher export
    assert main(["graph", "shop", "--out", str(out), "--format", "cypher"]) == 0
    assert "MERGE" in capsys.readouterr().out
    # reach a node
    assert main(["graph", "shop", "--reach", "/api/x", "--out", str(out)]) == 0
    r = json.loads(capsys.readouterr().out)
    assert r["paths"]
