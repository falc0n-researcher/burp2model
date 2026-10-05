"""
Test suite for burp2model.

The most important test is redaction: no planted secret value may ever appear
in any derived artifact. If that ever fails, the tool is dangerous.
"""

import json
import os
import xml.dom.minidom

import pytest

from burp2model import parse_items, build, to_dict, query, context_package
from burp2model.redact import (
    redact_headers, redact_params, redact_body, shannon_entropy, fingerprint,
)
from burp2model.parse import template_path
from burp2model.model import cross_role
from burp2model.animate import render_svg

HERE = os.path.dirname(__file__)
SAMPLE = os.path.join(HERE, "..", "samples", "burp-history-sample.xml")

PLANTED = [
    "s3cr3tSESSIONv4lue123456",
    "AKIAIOSFODNN7EXAMPLE",
    "user@shop.example.com",
    "eyJhbGciOiJIUzI1NiJ9",
]


@pytest.fixture(scope="module")
def exchanges():
    return list(parse_items(SAMPLE))


@pytest.fixture(scope="module")
def model(exchanges):
    return build(exchanges, name="shop")


# ---- parsing ----

def test_parses_all_items(exchanges):
    assert len(exchanges) == 17


def test_decodes_method_and_host(exchanges):
    ex = next(e for e in exchanges if e.path == "/api/export")
    assert ex.method == "POST"
    assert ex.host == "api.example.com"
    assert ex.scheme == "https"


def test_malformed_items_do_not_crash(tmp_path):
    bad = tmp_path / "bad.xml"
    bad.write_text('<items><item><method>GET</method></item>'
                   '<item><host>x.test</host><path>/</path>'
                   '<method>GET</method><mimetype>HTML</mimetype></item></items>')
    exs = list(parse_items(str(bad)))
    # first item has no host -> skipped; second parses
    assert len(exs) == 1


# ---- redaction (the trust core) ----

def test_no_planted_secret_in_model(model, tmp_path):
    blob = json.dumps(to_dict(model))
    for secret in PLANTED:
        assert secret not in blob, f"LEAK: {secret} present in model"


def test_no_planted_secret_in_any_output(model, tmp_path):
    from burp2model.report import write_html_report
    from burp2model.animate import write_svg
    out = tmp_path / "shop"
    out.mkdir()
    (out / "model.json").write_text(json.dumps(to_dict(model)))
    (out / "context.json").write_text(json.dumps(context_package(model)))
    write_html_report(model, str(out / "report.html"))
    write_svg(model, str(out / "build.svg"))
    for f in out.iterdir():
        text = f.read_text()
        for secret in PLANTED:
            assert secret not in text, f"LEAK: {secret} in {f.name}"


def test_authorization_header_masked():
    headers = [("Authorization", "Bearer eyJhbGciOiJIUzI1NiJ9.payload.sig")]
    out, prints = redact_headers(headers)
    assert out[0][1] == "[REDACTED]"
    assert len(prints) == 1
    assert prints[0].length > 0


def test_param_name_masks_value():
    out, prints = redact_params([("password", "hunter2"), ("q", "shoes")])
    assert ("password", "[REDACTED]") in out
    assert ("q", "shoes") in out  # non-sensitive untouched


def test_param_name_kept_when_value_masked():
    out, _ = redact_params([("password", "hunter2")])
    # name survives, value dies
    assert out[0][0] == "password"
    assert out[0][1] == "[REDACTED]"


def test_body_email_and_key_masked():
    body = 'contact me at user@shop.example.com key sk-ABCDEFGHIJKLMNOPQRSTUVWX'
    masked, prints = redact_body(body)
    assert "user@shop.example.com" not in masked
    assert "sk-ABCDEFGHIJKLMNOPQRSTUVWX" not in masked
    assert any(p.kind == "email" for p in prints)


def test_fingerprint_has_no_value():
    fp = fingerprint("supersecret", kind="token")
    d = fp.as_dict()
    assert "supersecret" not in json.dumps(d)
    assert d["length"] == 11
    assert d["entropy"] > 0


def test_entropy_monotonic():
    assert shannon_entropy("aaaa") < shannon_entropy("abcd")


# ---- templating ----

@pytest.mark.parametrize("raw,expected", [
    ("/api/users/123", "/api/users/{id}"),
    ("/api/users/123?x=1", "/api/users/{id}"),
    ("/a/550e8400-e29b-41d4-a716-446655440000/b", "/a/{uuid}/b"),
    ("/static/app.js", "/static/app.js"),
    ("/", "/"),
])
def test_template_path(raw, expected):
    assert template_path(raw) == expected


# ---- model ----

def test_six_layers_present(model):
    layers = {n.layer for n in model.nodes.values()}
    # at least edge, route, code, api, trust
    assert {1, 2, 3, 4}.issubset(layers)


def test_reconcile_static_only(model):
    eps = {n.label: n.attrs.get("api_state") for n in model.nodes.values()
           if n.type == "endpoint"}
    # /api/admin/audit is referenced in JS, never requested
    audit = next((v for k, v in eps.items() if "audit" in k), None)
    assert audit == "STATIC_ONLY"


def test_reconcile_both(model):
    eps = {n.label: n.attrs.get("api_state") for n in model.nodes.values()
           if n.type == "endpoint"}
    # /api/orders and /api/me are referenced AND requested
    both = [v for k, v in eps.items() if "orders" in k or "/api/me" in k]
    assert "BOTH" in both


def test_evidence_on_every_node(model):
    for n in model.nodes.values():
        assert n.evidence, f"node {n.id} has no evidence"


def test_edges_labeled_observed_or_inferred(model):
    for e in model.edges:
        assert e.state in ("OBSERVED", "INFERRED")


def test_inferred_edges_are_references(model):
    for e in model.edges:
        if e.state == "INFERRED":
            assert e.type in ("REFERENCES",)


def test_unknowns_named(model):
    types = {u.type for u in model.unknowns}
    assert "API_PURPOSE_UNKNOWN" in types


def test_determinism(exchanges):
    a = to_dict(build(exchanges, name="shop"))
    b = to_dict(build(exchanges, name="shop"))
    # node/edge sets identical (order-independent)
    assert {n["id"] for n in a["nodes"]} == {n["id"] for n in b["nodes"]}
    assert a["counts"] == b["counts"]


# ---- query (no AI) ----

def test_query_code_vs_runtime(model):
    out = query(model, "code vs runtime")
    assert "STATIC_ONLY" in out
    assert "Model call: none" in out


def test_query_unknowns(model):
    out = query(model, "what is not known")
    assert "named unknowns" in out
    assert "Model call: none" in out


# ---- context package ----

def test_context_package_capped_and_honest(model):
    pkg = context_package(model)
    assert "rules" in pkg and len(pkg["rules"]) >= 4
    assert "coverage" in pkg
    assert pkg["token_estimate"] > 0
    # every referenced node exists in the model
    ids = {n.id for n in model.nodes.values()}
    for ep in pkg["endpoints"]:
        assert ep["id"] in ids


def test_context_rules_forbid_invention(model):
    pkg = context_package(model)
    joined = " ".join(pkg["rules"]).lower()
    assert "never" in joined
    assert "evidence" in joined


# ---- animation ----

def test_svg_is_well_formed(model):
    svg = render_svg(model)
    xml.dom.minidom.parseString(svg)  # raises on malformed
    assert "burp2model" in svg
    assert svg.strip().startswith("<svg")


def test_svg_shows_static_only_callout(model):
    svg = render_svg(model)
    assert "static-only" in svg


def test_not_xml_gets_export_instructions(tmp_path, capsys):
    from burp2model.cli import main
    bad = tmp_path / "bad.xml"
    bad.write_text("this is not xml")
    assert main([str(bad), "-w", "x", "--out", str(tmp_path / "o")]) == 2
    err = capsys.readouterr().err
    assert "Save items" in err
