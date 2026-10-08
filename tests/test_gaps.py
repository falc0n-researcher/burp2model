"""
Regression tests for the gaps found in the 0.1.0 review: path redaction,
report escaping, keyed fingerprints, full-body JS scanning, multi-host scope,
method-aware reconciliation, dropped request kinds, the trust layer, the
cross-role workflow, the context package and the query surface.

Every export here is synthetic and built in the test, so each case states
exactly the traffic it depends on.
"""

import base64
import hashlib
import json
import os
import re

import pytest

from burp2model import build, context_package, parse_items, query, to_dict, from_dict
from burp2model import parse as parse_mod
from burp2model.cli import main
from burp2model.model import cross_role
from burp2model.redact import (
    classify_segment, fingerprint, redact_body, redact_path, template_path,
)
from burp2model.report import write_html_report


# ------------------------------------------------------------ helpers --------

def _b64(s) -> str:
    if isinstance(s, str):
        s = s.encode()
    return base64.b64encode(s).decode()


def item(method="GET", host="www.shop.test", path="/", mime="HTML", status=200,
         req_headers=(), req_body="", resp_headers=(), resp_body="", resp_ct=None):
    req = f"{method} {path} HTTP/1.1\r\nHost: {host}\r\n"
    req += "".join(f"{k}: {v}\r\n" for k, v in req_headers) + "\r\n" + req_body
    resp = f"HTTP/1.1 {status} X\r\n"
    if resp_ct:
        resp += f"Content-Type: {resp_ct}\r\n"
    resp += "".join(f"{k}: {v}\r\n" for k, v in resp_headers) + "\r\n"
    resp_b = resp.encode() + (resp_body if isinstance(resp_body, bytes) else resp_body.encode())
    esc = path.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    return (f"<item><host>{host}</host><port>443</port><protocol>https</protocol>"
            f"<method>{method}</method><path>{esc}</path><status>{status}</status>"
            f"<mimetype>{mime}</mimetype><request base64=\"true\">{_b64(req)}</request>"
            f"<response base64=\"true\">{_b64(resp_b)}</response></item>")


def export(tmp_path, items, name="h.xml") -> str:
    p = tmp_path / name
    p.write_text("<?xml version=\"1.0\"?><items>" + "".join(items) + "</items>")
    return str(p)


def model_of(tmp_path, items, **kw):
    return build(list(parse_items(export(tmp_path, items))), name="t", **kw)


def endpoints(m):
    return {n.label: n for n in m.nodes.values() if n.type == "endpoint"}


def all_outputs_text(root) -> str:
    chunks = []
    for dirpath, _, files in os.walk(root):
        for fn in files:
            with open(os.path.join(dirpath, fn), encoding="utf-8", errors="replace") as f:
                chunks.append(f.read())
    return "\n".join(chunks)


# ------------------------------------------------ 1. redaction of paths ------

@pytest.mark.parametrize("seg,expected", [
    ("alice@corp.com", "{email}"),
    ("alice%40corp.com", "{email}"),
    ("Zx9kQ2pLm7Rt", "{token}"),
    ("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abcDEFghiJKL", "{jwt}"),
    ("AKIAIOSFODNN7EXAMPLE", "{aws_key}"),
    ("123", "{id}"),
    ("app.js", None),
    ("my-product-2024", None),
    ("ProductV2Details", None),
    ("orders", None),
    ("v2", None),
])
def test_classify_segment(seg, expected):
    assert classify_segment(seg) == expected


def test_redact_path_masks_segments_and_query():
    red, prints = redact_path("/reset/alice@corp.com/Zx9kQ2pLm7Rt?token=abc&q=shoes")
    assert "alice" not in red and "Zx9kQ2pLm7Rt" not in red and "abc" not in red
    assert "q=shoes" in red
    assert {p.kind for p in prints} >= {"path:email", "path:token", "token"}


def test_no_path_secret_in_any_cli_output(tmp_path):
    xml = export(tmp_path, [
        item(path="/"),
        item(host="api.shop.test", path="/api/reset/alice@corp.com/Zx9kQ2pLm7Rt?sig=S1gn4tur3Value",
             mime="JSON", resp_ct="application/json", resp_body="{}",
             req_headers=[("Referer", "https://www.shop.test/account/bob@corp.com?session=abc123xyz")]),
    ])
    out = tmp_path / "out"
    assert main([xml, "-w", "t", "--out", str(out)]) == 0
    blob = all_outputs_text(out)          # includes inputs/*.jsonl
    for secret in ("alice@corp.com", "Zx9kQ2pLm7Rt", "S1gn4tur3Value", "bob@corp.com", "abc123xyz"):
        assert secret not in blob, f"LEAK: {secret}"


# ---------------------------------------------- 2. report escaping ----------

def test_report_cannot_be_broken_out_of(tmp_path):
    m = model_of(tmp_path, [
        item(path="/"),
        item(path="/api/x</script><img src=x onerror=alert(1)>", mime="JSON", resp_body="{}"),
    ])
    out = tmp_path / "report.html"
    write_html_report(m, str(out))
    html = out.read_text()
    # the report's only real </script> is its own; the hostile path cannot add one
    assert html.count("</script>") == 1
    assert "<img src=x" not in html                      # never emitted as live HTML
    # the hostile string survives only as inert, angle-bracket-escaped JSON data
    assert "\\u003cimg src=x" in html
    assert "\\u003c/script" in html
    assert "Content-Security-Policy" in html


# ------------------------------------- 3. keyed fingerprints, card numbers ---

def test_fingerprint_is_keyed_not_plain_sha256():
    fp = fingerprint("alice@corp.com", kind="email")
    assert fp.hmac_12 != hashlib.sha256(b"alice@corp.com").hexdigest()[:12]


def test_card_requires_luhn():
    masked, _ = redact_body("ts=1727265600000 card=4111 1111 1111 1111")
    assert "1727265600000" in masked                      # a timestamp, not a card
    assert "4111 1111 1111 1111" not in masked


# ------------------------------------------- 4. JS extraction coverage -------

def test_js_scanned_past_old_20kb_cap(tmp_path):
    js = "var x=1;" * 5000 + 'fetch("/api/late/endpoint");'
    m = model_of(tmp_path, [item(path="/"), item(path="/app.js", mime="script", resp_body=js)])
    assert any("/api/late/endpoint" in lbl for lbl in endpoints(m))


def test_js_call_shapes(tmp_path):
    js = ('axios.post(`/api/users/${id}/delete`);'
          'fetch("https://api.shop.test/v2/orders", {method: "PUT"});'
          'xhr.open("DELETE", "/api/items/" + id);'
          'const u = "/api/search/";'
          '$.get(\'/rest/health\');')
    m = model_of(tmp_path, [item(path="/"), item(path="/app.js", mime="script", resp_body=js)])
    labels = set(endpoints(m))
    assert "POST /api/users/{param}/delete" in labels
    assert "PUT api.shop.test/v2/orders" in labels
    assert "DELETE /api/items/{param}" in labels
    assert "* /api/search/{param}" in labels
    assert "GET /rest/health" in labels


def test_html_form_and_inline_script(tmp_path):
    html = ('<form method="post" action="/account/delete"></form>'
            '<script>fetch("/api/inline")</script>')
    m = model_of(tmp_path, [item(path="/settings", resp_body=html, resp_ct="text/html")])
    labels = set(endpoints(m))
    assert "POST /account/delete" in labels
    assert "* /api/inline" in labels


def test_script_partially_scanned_is_an_unknown(tmp_path, monkeypatch):
    monkeypatch.setattr(parse_mod, "MAX_SCAN_BYTES", 1000)
    js = "x" * 2000 + 'fetch("/api/hidden")'
    m = model_of(tmp_path, [item(path="/"), item(path="/big.js", mime="script", resp_body=js)])
    assert "SCRIPT_PARTIALLY_SCANNED" in {u.type for u in m.unknowns}
    assert not any("hidden" in lbl for lbl in endpoints(m))


# ------------------------------------------- 5. scope + reconciliation -------

def test_subdomains_are_first_party(tmp_path):
    m = model_of(tmp_path, [
        item(path="/"), item(path="/a"),
        item(host="api.shop.test", path="/v2/orders", mime="JSON", resp_body="{}"),
        item(host="cdn.shop.test", path="/b.js", mime="script", resp_body=""),
        item(host="www.google-analytics.com", path="/collect", mime="", resp_body=""),
    ])
    types = {n.label: n.type for n in m.nodes.values() if n.type in ("host", "third_party")}
    assert types["api.shop.test"] == "host"
    assert types["cdn.shop.test"] == "host"
    assert types["www.google-analytics.com"] == "third_party"
    assert m.scope == ["shop.test"]


def test_explicit_scope(tmp_path):
    m = model_of(tmp_path, [item(path="/"), item(path="/p"),
                            item(host="api.other.test", path="/v1/x", mime="JSON")],
                 scope=["shop.test", "other.test"])
    assert "GET api.other.test/v1/x" in endpoints(m)


def test_cdn_bundle_reconciles_with_api_host(tmp_path):
    js = 'fetch("/api/orders");fetch("/api/users/" + id)'
    m = model_of(tmp_path, [
        item(path="/"), item(path="/p"),
        item(host="cdn.shop.test", path="/app.js", mime="script", resp_body=js),
        item(path="/api/orders", mime="JSON", resp_body="{}"),
        item(path="/api/users/42", mime="JSON", resp_body="{}"),
    ])
    eps = endpoints(m)
    assert eps["GET /api/orders"].attrs["api_state"] == "BOTH"
    assert eps["GET /api/users/{id}"].attrs["api_state"] == "BOTH"
    assert not [lbl for lbl, n in eps.items() if n.attrs["api_state"] == "STATIC_ONLY"]


def _extract_embedded(html: str) -> dict:
    """Pull the embedded model JSON out of a generated report.html."""
    m = re.search(r"const D = (\{.*?\});\n", html, re.S)
    assert m, "embedded model not found"
    raw = (m.group(1).replace("\\u003c", "<").replace("\\u003e", ">")
           .replace("\\u0026", "&").replace("\\u2028", " ").replace("\\u2029", " "))
    return json.loads(raw)


def test_report_is_self_contained_and_offline(tmp_path):
    m = model_of(tmp_path, [item(path="/"), item(path="/api/x", mime="JSON", resp_body="{}")])
    out = tmp_path / "r.html"
    write_html_report(m, str(out))
    html = out.read_text()
    assert "default-src 'none'" in html          # strict CSP
    assert "<script src=" not in html            # all JS inline
    assert '<link rel="stylesheet"' not in html  # no external CSS or fonts
    assert re.search(r'<link[^>]+href="(?!data:)', html) is None  # links only to data: URIs
    assert 'src="http' not in html and 'src="//' not in html
    assert 'fetch("http' not in html and "fetch('http" not in html


def test_embedded_model_round_trips(tmp_path):
    m = model_of(tmp_path, [
        item(path="/"), item(path="/app.js", mime="script", resp_body='fetch("/api/orders")'),
        item(path="/api/orders", mime="JSON", resp_body="{}"),
        item(path="/api/users/7", mime="JSON", resp_body="{}"),
    ])
    out = tmp_path / "r.html"
    write_html_report(m, str(out))
    D = _extract_embedded(out.read_text())
    assert D["schema"] >= 1 and D["tool"] == "burp2model"
    # every endpoint the page shows resolves to model endpoints of the same set
    model_eps = {n.label for n in m.nodes.values() if n.type == "endpoint"}
    assert {e["label"] for e in D["endpoints"]} == model_eps
    # every evidence id a node cites exists in the embedded evidence table
    ids = set(D["evidence"])
    for e in D["endpoints"]:
        for ev in e["evidence"]:
            assert f"ev_{ev}" in ids


def test_report_embeds_copyable_context_without_secrets(tmp_path):
    # the report's "Copy for AI" hands the context package to the user's own
    # model; it must be present, rules-first, and carry no secret value.
    from burp2model.report import build_payload
    m = build(list(parse_items(export(tmp_path, [
        item(path="/", req_headers=[("Cookie", "session=s3cr3tSESSIONv4lue123456")]),
        item(path="/api/me", mime="JSON", resp_body='{"email":"user@shop.example.com"}'),
    ]))), name="t")
    payload = build_payload(m)
    ctx = payload["context"]
    assert ctx["rules"] and ctx["token_estimate"] > 0
    blob = json.dumps(ctx)
    for secret in ("s3cr3tSESSIONv4lue123456", "user@shop.example.com"):
        assert secret not in blob
    out = tmp_path / "r.html"
    write_html_report(m, str(out))
    html = out.read_text()
    assert "Copy for AI" in html and 'id="copyai"' in html
    # the AI-off question view ships too, with its honesty line
    assert "function vAsk" in html and "No AI was called" in html


def test_evidence_panes_are_redacted(tmp_path):
    # the report stores a request/response view per evidence id; it must be
    # as redacted as everything else — names/shapes kept, values gone.
    xml = export(tmp_path, [
        item(path="/"),
        item(method="POST", path="/login", mime="", status=200,
             req_headers=[("Content-Type", "application/x-www-form-urlencoded"),
                          ("Authorization", "Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.sig"),
                          ("Referer", "https://x.test/reset?session=liveSECRET123&next=/home")],
             req_body="username=alice&password=hunter2SECRET",
             resp_body='{"token":"tok_liveSECRETvalue","ok":true}', resp_ct="application/json"),
    ])
    exs = list(parse_items(xml))
    ev = next(e.ev for e in exs if e.path == "/login")
    blob = json.dumps(ev)
    for secret in ("hunter2SECRET", "liveSECRET123", "tok_liveSECRETvalue", "eyJhbGciOiJIUzI1NiJ9"):
        assert secret not in blob, f"LEAK in evidence pane: {secret}"
    # structure survives: header/param names and the [REDACTED] markers are there
    assert "username" in blob and "password" in blob
    assert "[REDACTED]" in blob
    assert "POST /login" in ev["request"]["line"]


def test_method_from_one_call_does_not_bleed_to_another(tmp_path):
    # a later call's {method:"POST"} must not attach to an earlier fetch()
    js = ('fetch("/api/orders");'
          'await axios.post("/api/checkout", body);'
          'fetch("/api/events", {method: "POST"});')
    m = model_of(tmp_path, [
        item(path="/"), item(path="/app.js", mime="script", resp_body=js),
        item(path="/api/orders", mime="JSON", resp_body="{}"),
    ])
    eps = endpoints(m)
    assert eps["GET /api/orders"].attrs["api_state"] == "BOTH"   # not POST-shadowed
    assert "POST /api/orders" not in eps
    assert "POST /api/events" in eps                             # its own method kept


def test_method_mismatch_is_not_both(tmp_path):
    js = 'axios.post("/api/x")'
    m = model_of(tmp_path, [
        item(path="/"), item(path="/app.js", mime="script", resp_body=js),
        item(path="/api/x", mime="JSON", resp_body="{}"),
    ])
    eps = endpoints(m)
    assert eps["GET /api/x"].attrs["api_state"] == "RUNTIME_ONLY"
    assert eps["POST /api/x"].attrs["api_state"] == "STATIC_ONLY"


def test_vendor_script_relative_refs_ignored(tmp_path):
    js = 'fetch("/api/collect")'
    m = model_of(tmp_path, [item(path="/"), item(path="/p"),
                            item(host="cdn.vendor.test", path="/tag.js", mime="script", resp_body=js)])
    assert not endpoints(m)


# ------------------------------------- 6. request kinds that were dropped ----

def test_form_post_redirect_and_assets(tmp_path):
    m = model_of(tmp_path, [
        item(path="/"), item(path="/p2"),
        item(method="POST", path="/login", mime="", status=302,
             req_headers=[("Content-Type", "application/x-www-form-urlencoded")],
             req_body="user=a&password=hunter2", resp_headers=[("Location", "/")]),
        item(path="/logo.png", mime="PNG"),
        item(path="/site.css", mime="CSS"),
        item(method="OPTIONS", path="/api/x", mime="",
             req_headers=[("Access-Control-Request-Method", "POST")]),
    ])
    eps = endpoints(m)
    assert "POST /login" in eps
    assert m.stats["static_assets"] == 2
    assert m.stats["preflight"] == 1
    params = {n.label for n in m.nodes.values() if n.type == "parameter"}
    assert {"user", "password"} <= params
    assert "hunter2" not in json.dumps(to_dict(m))


def test_graphql_operations(tmp_path):
    body = json.dumps({"operationName": "GetUser", "query": "query GetUser { me { id } }"})
    m = model_of(tmp_path, [item(path="/"), item(method="POST", path="/graphql", mime="JSON",
                                                 req_headers=[("Content-Type", "application/json")],
                                                 req_body=body, resp_body="{}")])
    ops = {n.label for n in m.nodes.values() if n.type == "operation"}
    assert ops == {"GetUser"}


# ------------------------------------------- 7. graph connectivity + trust ---

def test_referer_and_host_edges(tmp_path):
    m = model_of(tmp_path, [
        item(path="/dashboard"),
        item(path="/api/me", mime="JSON", resp_body="{}",
             req_headers=[("Referer", "https://www.shop.test/dashboard")]),
    ])
    types = {(m.nodes[e.src].type, e.type, m.nodes[e.dst].type) for e in m.edges}
    assert ("route", "CALLS", "endpoint") in types
    assert ("host", "EXPOSES", "endpoint") in types
    ep = endpoints(m)["GET /api/me"]
    assert any(e.dst == ep.id for e in m.edges)


def test_trust_layer(tmp_path):
    m = model_of(tmp_path, [
        item(path="/", resp_headers=[("Set-Cookie", "sid=abc; Path=/; HttpOnly"),
                                     ("Server", "nginx/1.18.0")]),
        item(path="/p"),
        item(path="/api/me", mime="JSON", resp_body="{}",
             req_headers=[("Authorization", "Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.sigsigsig"),
                          ("Cookie", "sid=abc")]),
        item(path="/api/me", mime="JSON", resp_body="{}"),
    ])
    cookie = m.nodes["cookie:sid"]
    assert cookie.attrs["httponly"] is True and cookie.attrs["secure"] is False
    assert {n.id for n in m.nodes.values() if n.type == "auth"} == {"auth:bearer", "auth:cookie:sid"}
    ep = endpoints(m)["GET /api/me"]
    assert ep.attrs["anonymous_requests"] == 1 and ep.attrs["credentials"]
    host = m.nodes["host:www.shop.test"]
    assert host.attrs["tech"]["server"] == "nginx/1.18.0"


def test_secrets_deduplicated_with_evidence(tmp_path):
    hdr = [("Cookie", "session=s3cr3tSESSIONv4lue123456")]
    m = model_of(tmp_path, [item(path="/", req_headers=hdr), item(path="/a", req_headers=hdr),
                            item(path="/b", req_headers=hdr)])
    assert len(m.secrets) == 1
    s = m.secrets[0]
    assert s["count"] == 3 and s["evidence"] == [1, 2, 3]
    assert "sha256_12" not in s and "hmac_12" in s


def test_statuses_and_error_only_unknown(tmp_path):
    m = model_of(tmp_path, [item(path="/"), item(path="/p"),
                            item(path="/api/a", mime="JSON", status=403),
                            item(path="/api/a", mime="JSON", status=500)])
    ep = endpoints(m)["GET /api/a"]
    assert ep.attrs["statuses"] == [403, 500]
    assert "ENDPOINT_ONLY_ERRORED" in {u.type for u in m.unknowns}


# ------------------------------------------------ 8. parser robustness -------

def test_skipped_items_counted(tmp_path):
    xml = export(tmp_path, [item(path="/"), "<item><method>GET</method></item>",
                            "<item><host>x.test</host><port>abc</port><path>/</path></item>"])
    stats = {}
    exs = list(parse_items(xml, stats=stats))
    assert stats == {"items": 3, "parsed": 2, "skipped": 1}
    assert [e.item for e in exs] == [0, 2]


def test_entity_declarations_refused(tmp_path):
    p = tmp_path / "evil.xml"
    p.write_text('<?xml version="1.0"?><!DOCTYPE items [<!ENTITY a "aaaa">]><items>&a;</items>')
    with pytest.raises(ValueError):
        list(parse_items(str(p)))


def test_record_round_trip(tmp_path):
    exs = list(parse_items(export(tmp_path, [
        item(path="/"), item(path="/app.js", mime="script", resp_body='fetch("/api/q")')])))
    back = [parse_mod.Exchange.from_record(json.loads(json.dumps(e.to_record()))) for e in exs]
    assert to_dict(build(exs, "t"))["counts"] == to_dict(build(back, "t"))["counts"]


# ------------------------------------------------------ 9. cross-role --------

def _role_exports(tmp_path):
    user = export(tmp_path, [
        item(path="/"),
        item(path="/api/me", mime="JSON", resp_body="{}"),
        item(path="/api/admin/users", mime="JSON", status=200, resp_body="{}"),
    ], "user.xml")
    admin = export(tmp_path, [
        item(path="/"),
        item(path="/api/me", mime="JSON", resp_body="{}"),
        item(path="/api/admin/users", mime="JSON", resp_body="{}"),
        item(method="DELETE", path="/api/users/7", mime="JSON", resp_body="{}"),
    ], "admin.xml")
    return user, admin


def test_role_builds_merge_and_cross_role_works(tmp_path, capsys):
    user, admin = _role_exports(tmp_path)
    out = str(tmp_path / "out")
    assert main([user, "-w", "t", "--role", "user", "--out", out]) == 0
    assert main([admin, "-w", "t", "--role", "admin", "--out", out]) == 0
    data = json.load(open(os.path.join(out, "t", "model.json")))
    assert data["roles"] == ["admin", "user"]
    ids = [e["id"] for e in data["evidence"]]
    assert ids == list(range(1, len(ids) + 1))              # unique across merged inputs

    m = from_dict(data)
    r = cross_role(m, "user", "admin")
    assert [e["endpoint"] for e in r["high_only"]] == ["DELETE /api/users/{id}"]
    assert [e["endpoint"] for e in r["low_reached_privileged"]] == ["GET /api/admin/users"]
    assert r["low_reached_privileged"][0]["statuses"] == {"user": [200], "admin": [200]}

    capsys.readouterr()
    assert main(["cross-role", "t", "--low", "user", "--high", "admin", "--out", out]) == 0
    printed = capsys.readouterr().out
    assert "DELETE /api/users/{id}" in printed and "GET /api/admin/users" in printed


def test_rebuilding_a_role_replaces_it_and_plain_build_starts_over(tmp_path):
    user, admin = _role_exports(tmp_path)
    out = str(tmp_path / "out")
    main([user, "-w", "t", "--role", "user", "--out", out])
    main([user, "-w", "t", "--role", "user", "--out", out])
    data = json.load(open(os.path.join(out, "t", "model.json")))
    assert data["stats"]["parsed"] == 3                # not doubled
    main([admin, "-w", "t", "--out", out])
    data = json.load(open(os.path.join(out, "t", "model.json")))
    assert data["roles"] == []


def test_cross_role_missing_role_fails_clearly(tmp_path, capsys):
    user, _ = _role_exports(tmp_path)
    out = str(tmp_path / "out")
    main([user, "-w", "t", "--role", "user", "--out", out])
    assert main(["cross-role", "t", "--low", "user", "--high", "admin", "--out", out]) == 2
    assert "admin" in capsys.readouterr().err


def test_webapp_name_cannot_escape_out_dir(tmp_path):
    xml = export(tmp_path, [item(path="/")])
    with pytest.raises(SystemExit):
        main([xml, "-w", "../../escape", "--out", str(tmp_path / "out")])


# ------------------------------------------------- 10. context package -------

def _busy_model(tmp_path):
    js = 'fetch("/api/secret/thing")'
    items = [item(path="/"), item(path="/app.js", mime="script", resp_body=js)]
    items += [item(path=f"/api/list{i}", mime="JSON", resp_body="{}") for i in range(10)]
    return model_of(tmp_path, items)


def test_context_attention_puts_static_only_first_and_survives_cap(tmp_path):
    pkg = context_package(_busy_model(tmp_path), cap=3)
    assert pkg["endpoints"][0]["api_state"] == "STATIC_ONLY"
    assert pkg["coverage"]["endpoints"] == "3/11 (capped)"


def test_context_evidence_table_resolves_every_cited_id(tmp_path):
    pkg = context_package(_busy_model(tmp_path))
    blob = json.dumps({k: v for k, v in pkg.items() if k != "evidence"})
    import re
    cited = set(re.findall(r"ev_\d+", blob))
    assert cited and cited <= set(pkg["evidence"])
    for ev in pkg["evidence"].values():
        assert {"method", "host", "path", "status"} <= set(ev)


def test_context_lenses(tmp_path):
    m = _busy_model(tmp_path)
    assert context_package(m, lens="auth")["endpoints"] == []
    assert len(context_package(m, lens="all")["endpoints"]) == 11
    with pytest.raises(ValueError):
        context_package(m, lens="nope")


# ---------------------------------------------------------- 11. query --------

def test_query_endpoint_provenance(tmp_path):
    m = _busy_model(tmp_path)
    out = query(m, "endpoint /api/secret/thing")
    assert "STATIC_ONLY" in out and "references" in out and "app.js" in out


def test_query_help_and_topics(tmp_path):
    m = _busy_model(tmp_path)
    assert "code vs runtime" in query(m, "help")
    for q in ("parameters", "secrets", "auth", "privileged", "errors", "third parties"):
        assert "Model call: none" in query(m, q)


def test_query_spec_intents_cited_and_ai_off(tmp_path):
    m = _busy_model(tmp_path)
    for q in ("list-apis", "reconcile", "list-routes", "provenance /api/secret/thing",
              "third-parties", "auth-surface", "unknowns",
              "entity-evidence /api/secret/thing", "route-apis /"):
        out = query(m, q)
        assert "Model call: none" in out, q
        assert "cannot answer" not in out, q
    assert "ev_" in query(m, "list-apis")
    assert "ev_" in query(m, "entity-evidence /api/secret/thing")


def test_query_unanswerable_is_refused_not_guessed(tmp_path):
    m = _busy_model(tmp_path)
    out = query(m, "who loves pizza")
    assert "cannot answer" in out and "model shape" not in out
    assert "Model call: none" in out
