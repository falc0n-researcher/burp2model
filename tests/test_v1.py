"""
Regression tests for the gaps closed in the 1.0.0 review: pane redaction of
prefixed/camelCase names, fragment tokens, matrix path parameters, chunked
bodies, scope normalisation, IPv6 hosts, primary-host selection under --scope,
cookie SameSite weakening, schema versioning, cross-role evidence roles and
the unknown cap ordering.
"""

import json

import pytest

from burp2model import build, context_package, parse_items, from_dict, to_dict
from burp2model.cli import main, _scope
from burp2model.model import MODEL_SCHEMA_VERSION, cross_role, in_scope
from burp2model.parse import _dechunk
from burp2model.redact import redact_named, redact_path, template_path

from test_gaps import endpoints, export, item, model_of


# ---------------------------------------------- pane (ev) redaction ----------

@pytest.mark.parametrize("text,leaks", [
    ("old_password=hunter1&new_password=hunter2", ["hunter1", "hunter2"]),
    ('{"access_token":"opaqueValue12","newPassword":"hunter2"}', ["opaqueValue12", "hunter2"]),
    ('{"accessToken":"opaqueValue12"}', ["opaqueValue12"]),
    ("Location: /cb#access_token=opaqueXYZ", ["opaqueXYZ"]),
    ("user[password]=x123secret", ["x123secret"]),
    ("resetToken=abcOpaque99&keep=this", ["abcOpaque99"]),
])
def test_redact_named_catches_prefixed_and_camelcase_names(text, leaks):
    out = redact_named(text)
    for v in leaks:
        assert v not in out, out
    assert "[REDACTED]" in out


def test_redact_named_keeps_benign_pairs():
    out = redact_named("q=shoes&page=2&zipcode=90210")
    assert out == "q=shoes&page=2&zipcode=90210"


def test_pane_bodies_are_masked_end_to_end(tmp_path):
    xml = export(tmp_path, [item(
        method="POST", path="/account/password", mime="JSON",
        req_headers=[("Content-Type", "application/x-www-form-urlencoded")],
        req_body="old_password=hunter1&new_password=hunter2",
        resp_ct="application/json",
        resp_body='{"access_token":"opaqueValue12"}')])
    ex = list(parse_items(xml))[0]
    blob = json.dumps(ex.ev)
    for v in ("hunter1", "hunter2", "opaqueValue12"):
        assert v not in blob


# ---------------------------------------------- matrix path params ----------

def test_matrix_jsessionid_never_survives():
    assert template_path("/app;jsessionid=1A2B3C4D5E6F/cart") == "/app;jsessionid={value}/cart"
    red, prints = redact_path("/app;jsessionid=1A2B3C4D5E6F/cart?x=1")
    assert "1A2B3C4D5E6F" not in red
    assert any(p.kind == "path:jsessionid" for p in prints)


# ---------------------------------------------- chunked bodies --------------

def test_dechunk_reassembles():
    body = b"5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n"
    assert _dechunk(body) == b"hello world"


def test_dechunk_bad_input_returns_original():
    assert _dechunk(b"not chunked at all") == b"not chunked at all"


def test_chunked_json_body_params_extracted(tmp_path):
    chunked = b'1c\r\n{"user_name":"a","pin":"12"}\r\n0\r\n\r\n'
    # 0x1c == 28 == len of the JSON above
    xml = export(tmp_path, [item(
        method="POST", path="/api/verify", mime="JSON",
        req_headers=[("Content-Type", "application/json"),
                     ("Transfer-Encoding", "chunked")],
        req_body=chunked.decode("latin-1"),
        resp_ct="application/json", resp_body="{}")])
    ex = list(parse_items(xml))[0]
    names = [n for n, _ in ex.body_params]
    assert "$.user_name" in names and "$.pin" in names


# ---------------------------------------------- scope handling --------------

def test_scope_normalisation():
    class A:
        scope = ["https://shop.com:443/x, api.shop.com", "*.cdn.net"]
    assert _scope(A) == ["shop.com", "api.shop.com", "*.cdn.net"]


def test_in_scope_ipv6_and_ports():
    assert in_scope("[::1]:8080", ["::1"])
    assert in_scope("shop.com:8443", ["shop.com"])
    assert not in_scope("evilshop.com", ["shop.com"])


def test_primary_host_respects_scope(tmp_path):
    # the CDN is busier, but --scope names shop.test, so shop.test is primary
    items = [item(host="cdn.other.test", path=f"/a{i}.js", mime="script",
                  resp_ct="application/javascript") for i in range(5)]
    items.append(item(host="www.shop.test", path="/api/x", mime="JSON",
                      resp_ct="application/json", resp_body="{}"))
    m = model_of(tmp_path, items, scope=["shop.test"])
    labels = endpoints(m)
    assert all("cdn.other.test" not in lbl or "GET" in lbl for lbl in labels)
    host_nodes = [n for n in m.nodes.values() if n.type == "host"]
    assert [n.label for n in host_nodes] == ["www.shop.test"]


def test_all_out_of_scope_warns(tmp_path, capsys):
    xml = export(tmp_path, [item(host="www.shop.test", path="/")])
    assert main([xml, "-w", "t", "--out", str(tmp_path / "o"),
                 "--scope", "unrelated.example"]) == 0
    assert "no captured host matched the scope" in capsys.readouterr().err


# ---------------------------------------------- cookies ---------------------

def test_cookie_samesite_keeps_weakest(tmp_path):
    m = model_of(tmp_path, [
        item(path="/a", resp_headers=[("Set-Cookie", "sid=1; HttpOnly; Secure; SameSite=Strict")]),
        item(path="/b", resp_headers=[("Set-Cookie", "sid=2; HttpOnly; Secure; SameSite=Lax")]),
    ])
    cookie = next(n for n in m.nodes.values() if n.type == "cookie")
    assert (cookie.attrs["samesite"] or "").lower() == "lax"


# ---------------------------------------------- schema versioning -----------

def test_model_json_carries_tool_and_schema(tmp_path):
    d = to_dict(model_of(tmp_path, [item()]))
    assert d["tool"] == "burp2model" and d["schema"] == MODEL_SCHEMA_VERSION
    assert d["version"]
    # round-trips
    assert from_dict(d).name == "t"


def test_from_dict_rejects_newer_schema(tmp_path):
    d = to_dict(model_of(tmp_path, [item()]))
    d["schema"] = MODEL_SCHEMA_VERSION + 1
    with pytest.raises(ValueError, match="newer"):
        from_dict(d)


def test_from_dict_rejects_garbage():
    with pytest.raises(ValueError):
        from_dict({"nonsense": True})


def test_context_carries_tool_version(tmp_path):
    pkg = context_package(model_of(tmp_path, [item()]))
    assert pkg["tool"] == "burp2model" and pkg["version"]


# ---------------------------------------------- cross-role evidence ---------

def _role_export(tmp_path, role, paths, name):
    xml = export(tmp_path, [item(method="GET", path=p, mime="JSON",
                                 resp_ct="application/json", resp_body="{}",
                                 req_headers=[("Authorization", "Bearer x")])
                            for p in paths], name=name)
    return list(parse_items(xml, role=role))


def test_cross_role_cites_the_right_roles_evidence(tmp_path):
    low = _role_export(tmp_path, "user", ["/api/admin/panel"], "u.xml")
    high = _role_export(tmp_path, "admin", ["/api/admin/panel", "/api/admin/only"], "a.xml")
    exchanges = low + high
    for i, ex in enumerate(exchanges):
        ex.index = i
    m = build(exchanges, name="t")
    ev_role = {e["id"]: e.get("role") for e in m.evidence_log}
    res = cross_role(m, "user", "admin")
    for entry in res["low_reached_privileged"]:
        assert any(ev_role[i] == "user" for i in entry["evidence"])
    for entry in res["high_only"]:
        assert all(ev_role[i] == "admin" for i in entry["evidence"])


# ---------------------------------------------- unknown cap ordering --------

def test_unknown_cap_keeps_specific_unknowns_first(tmp_path):
    items = [item(method="GET", path=f"/api/r{i}", mime="JSON",
                  resp_ct="application/json", resp_body="{}",
                  req_headers=[("Authorization", "Bearer x")]) for i in range(60)]
    xml = export(tmp_path, items)
    m = build(list(parse_items(xml, role="user")), name="t")
    m.unknowns.append(type(m.unknowns[0])(
        "CAPTURE_ITEMS_SKIPPED", "app:t", ["x"], "y", "z"))
    pkg = context_package(m, cap=40)
    types = [u["type"] for u in pkg["unknowns"]]
    assert "CAPTURE_ITEMS_SKIPPED" in types


# ---------------------------------------------- CLI -------------------------

def test_unknown_command_is_a_clear_error(capsys):
    assert main(["qeury", "shop", "x"]) == 2
    assert "not a command" in capsys.readouterr().err


def test_python_dash_m_entrypoint():
    import burp2model.__main__  # noqa: F401  (import must not run main)


def test_osint_requires_consent(tmp_path, capsys, monkeypatch):
    monkeypatch.delenv("BURP2MODEL_OSINT_CONSENT", raising=False)
    assert main(["osint", "example.com"]) == 2
    err = capsys.readouterr().err
    assert "authorized" in err and "--yes" in err


def test_osint_rejects_ip_literal(capsys):
    assert main(["osint", "10.0.0.1", "--yes"]) == 2
    assert "IP address" in capsys.readouterr().err


def test_empty_export_is_a_clean_error(tmp_path, capsys):
    p = tmp_path / "empty.xml"
    p.write_text('<?xml version="1.0"?><items></items>')
    assert main([str(p), "-w", "t", "--out", str(tmp_path / "o")]) == 2
    assert "no <item> elements" in capsys.readouterr().err


def test_corrupt_model_json_is_a_clean_error(tmp_path, capsys):
    out = tmp_path / "o" / "t"
    out.mkdir(parents=True)
    (out / "model.json").write_text("{not json")
    assert main(["query", "t", "help", "--out", str(tmp_path / "o")]) == 2
    assert "could not load" in capsys.readouterr().err


def test_gzip_response_is_decoded_and_secret_never_written(tmp_path, monkeypatch):
    import gzip
    from test_gaps import all_outputs_text
    monkeypatch.setenv("BURP2MODEL_FP_KEY", "ci")
    monkeypatch.setenv("BURP2MODEL_OFFLINE", "1")
    body = gzip.compress(b'{"access_token":"gzSECRETvalue123456","note":"hello-gzip"}')
    xml = export(tmp_path, [item(
        path="/api/session", resp_ct="application/json",
        resp_headers=[("Content-Encoding", "gzip")], resp_body=body)])
    ex = list(parse_items(xml))[0]
    assert "hello-gzip" in ex.resp_body          # gzip was decoded
    out = tmp_path / "out"
    assert main([xml, "-w", "gz", "--out", str(out)]) == 0
    text = all_outputs_text(out)
    assert "gzSECRETvalue123456" not in text
    assert "hello-gzip" in text or "access_token" in text


# ---------------------------------------------- source maps and workers -----

def _script_item(path, body, **kw):
    return item(path=path, mime="script", resp_ct="application/javascript", resp_body=body, **kw)


def test_source_map_and_workers_become_layer_3_facts(tmp_path):
    app = ('navigator.serviceWorker.register("/sw.js");'
           'const w = new Worker("/static/worker.js");'
           '//# sourceMappingURL=app.js.map')
    m = model_of(tmp_path, [
        item(path="/", resp_ct="text/html", resp_body='<script src="/static/app.js"></script>'),
        _script_item("/static/app.js", app),
        _script_item("/static/worker.js", "importScripts('/static/lib.js');"),
    ])
    scripts = {n.id: n for n in m.nodes.values() if n.type == "script"}
    sw = [n for n in scripts.values() if n.label == "sw.js"]
    assert sw and sw[0].attrs["worker"] == "service_worker"
    wk = [n for n in scripts.values() if n.label == "worker.js"][0]
    assert wk.attrs["worker"] == "worker"
    assert any(e.type == "SPAWNS" and e.state == "INFERRED" and e.dst == wk.id for e in m.edges)
    app_node = [n for n in scripts.values() if n.label == "app.js"][0]
    assert app_node.attrs["sourcemap"] == {"host": "www.shop.test", "path": "/static/app.js.map",
                                           "captured": False}
    assert any(u.type == "SOURCE_MAP_NOT_CAPTURED" for u in m.unknowns)


def test_captured_source_map_is_not_an_unknown(tmp_path):
    m = model_of(tmp_path, [
        item(path="/", resp_ct="text/html", resp_body="x"),
        _script_item("/static/app.js", "//# sourceMappingURL=app.js.map"),
        item(path="/static/app.js.map", mime="text", resp_ct="application/json", resp_body="{}"),
    ])
    app_node = [n for n in m.nodes.values() if n.type == "script"][0]
    assert app_node.attrs["sourcemap"]["captured"] is True
    assert not any(u.type == "SOURCE_MAP_NOT_CAPTURED" for u in m.unknowns)


def test_data_uri_source_map_ignored():
    from burp2model.extract import extract_script_assets
    assert extract_script_assets("//# sourceMappingURL=data:application/json;base64,e30=",
                                 "a.test", "/app.js") == set()


def test_same_export_builds_byte_identical_output(tmp_path, monkeypatch):
    import os, time
    monkeypatch.setenv("BURP2MODEL_FP_KEY", "ci")
    monkeypatch.setenv("BURP2MODEL_OFFLINE", "1")
    monkeypatch.setenv("SOURCE_DATE_EPOCH", "0")
    xml = export(tmp_path, [item(path="/", resp_ct="text/html", resp_body="hi"),
                            item(path="/api/x", mime="JSON", resp_ct="application/json", resp_body="{}")])
    for name in ("a", "b"):
        assert main([xml, "-w", "app", "--out", str(tmp_path / name)]) == 0
        time.sleep(1.1)

    def snapshot(root):
        return {os.path.relpath(os.path.join(d, f), root): open(os.path.join(d, f), "rb").read()
                for d, _, fs in os.walk(root) for f in fs}
    assert snapshot(tmp_path / "a") == snapshot(tmp_path / "b")
