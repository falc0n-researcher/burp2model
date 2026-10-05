"""
Tests for what the Map draws: technology nodes from the capture, the
external-recon (OSINT) layer with its own edge state, and the bundled synthetic
recon sample that lets the demo show that layer offline.
"""

import json
import os
import shutil

from burp2model import build, parse_items
from burp2model.cli import main
from burp2model.graph import ReasonGraph
from burp2model.report import build_payload

from test_gaps import export, item

HERE = os.path.dirname(os.path.abspath(__file__))
SAMPLE_OSINT = os.path.join(HERE, "..", "samples", "osint-sample.json")


def _model(tmp_path):
    items = [
        item(host="www.shop.test", path="/",
             resp_headers=[("Server", "nginx"), ("X-Powered-By", "Express")]),
        item(host="api.shop.test", path="/api/x", mime="JSON",
             resp_ct="application/json", resp_body="{}",
             resp_headers=[("Server", "nginx")]),
    ]
    return build(list(parse_items(export(tmp_path, items))), name="shop",
                 scope=["shop.test"])


# ---------------------------------------------- technology nodes -------------

def test_tech_markers_become_nodes_with_runs_edges(tmp_path):
    m = _model(tmp_path)
    tech = {n.label: n for n in m.nodes.values() if n.type == "tech"}
    assert set(tech) == {"nginx", "Express"}
    runs = [(e.src, e.dst) for e in m.edges if e.type == "RUNS"]
    # nginx is advertised by both hosts, Express by one
    assert ("host:www.shop.test", "tech:nginx") in runs
    assert ("host:api.shop.test", "tech:nginx") in runs
    assert ("host:www.shop.test", "tech:Express") in runs
    assert all(e.state == "OBSERVED" for e in m.edges if e.type == "RUNS")
    assert m.counts()["tech"] == 2
    for n in tech.values():
        assert n.evidence, "a tech node cites the responses that advertised it"


def test_tech_nodes_are_leaves_for_reasoning(tmp_path):
    m = _model(tmp_path)
    rg = ReasonGraph(m)
    assert all(h["type"] != "tech" for h in rg.hubs())


# ---------------------------------------------- OSINT layer ------------------

def test_osint_layer_has_its_own_edge_state_and_rich_nodes(tmp_path):
    m = _model(tmp_path)
    with open(SAMPLE_OSINT, encoding="utf-8") as f:
        osint = json.load(f)
    p = build_payload(m, osint=osint)
    infra = {n["id"]: n for n in p["graph"]["nodes"] if n["type"] == "infra"}
    for nid in ("infra:tls", "infra:headers", "infra:registrar", "infra:ports",
                "infra:robots", "infra:subs", "infra:email", "infra:host", "infra:cname"):
        assert nid in infra, nid
    assert "5 missing" in infra["infra:headers"]["label"]
    assert all(n.get("detail") for n in infra.values())
    ext = [e for e in p["graph"]["edges"] if e["type"] == "OSINT"]
    assert ext and all(e["state"] == "EXTERNAL" for e in ext)
    node_ids = {n["id"] for n in p["graph"]["nodes"]}
    assert all(e["s"] in node_ids and e["d"] in node_ids for e in ext)
    # overview card data
    assert p["osint"]["headers_missing"] and p["osint"]["registrar"]
    assert p["osint"]["open_ports"] == [80, 443]


def test_sample_osint_is_synthetic_and_loads_end_to_end(tmp_path):
    with open(SAMPLE_OSINT, encoding="utf-8") as f:
        osint = json.load(f)
    assert "Synthetic" in osint["_note"]
    assert osint["host"].endswith("example.com")
    out = tmp_path / "o"
    (out / "shop").mkdir(parents=True)
    shutil.copy(SAMPLE_OSINT, out / "shop" / "osint.json")
    xml = export(tmp_path, [item(host="shop.example.com", path="/"),
                            item(host="api.example.com", path="/api/x", mime="JSON",
                                 resp_ct="application/json", resp_body="{}")])
    assert main([xml, "-w", "shop", "--out", str(out)]) == 0
    html = (out / "shop" / "report.html").read_text()
    assert "infra:headers" in html and '"EXTERNAL"' in html
    ctx = json.loads((out / "shop" / "context.json").read_text())
    assert ctx["osint"]["host"] == "shop.example.com"
