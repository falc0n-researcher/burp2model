"""Credential fields found on a real Juice Shop capture that the first pass missed."""

from burp2model.redact import redact_named, redact_params, redact_path


def test_change_password_query_is_masked_by_group():
    red, prints = redact_path("/rest/user/change-password?current=Sup3r-Pa55%21&new=N3w-Pa55%21&repeat=N3w-Pa55%21")
    assert "Pa55" not in red
    assert red.startswith("/rest/user/change-password?")
    assert len(prints) == 3


def test_change_password_json_body_is_masked():
    out = redact_named('{"email":"a@b.co","answer":"Marlowe","new":"Th1rd-Pa55","repeat":"Th1rd-Pa55"}')
    assert "Th1rd" not in out and "Marlowe" not in out


def test_security_answer_is_a_credential():
    out = redact_named('{"securityAnswer":"Marlowe","securityQuestion":{"id":1}}')
    assert "Marlowe" not in out and '"id":1' in out
    red, _ = redact_params([("securityAnswer", "Marlowe")])
    assert red == [("securityAnswer", "[REDACTED]")]


def test_old_and_confirm_pair_also_masked():
    red, _ = redact_params([("old", "hunter1"), ("confirm", "hunter2"), ("page", "2")])
    assert red == [("old", "[REDACTED]"), ("confirm", "[REDACTED]"), ("page", "2")]


def test_lone_generic_names_are_not_over_masked():
    # one of them on its own is ordinary (`?new=true`, `current=page`)
    assert redact_named("GET /items?new=true&sort=asc") == "GET /items?new=true&sort=asc"
    red, _ = redact_params([("current", "3"), ("limit", "10")])
    assert red == [("current", "3"), ("limit", "10")]


# ---- templating of ids seen on a real Juice Shop capture ----

def test_hex_dash_order_ids_and_coupon_codes_template():
    from burp2model.redact import template_path
    assert template_path("/rest/track-order/5267-f73dcd000abcc353") == "/rest/track-order/{id}"
    assert template_path("/rest/track-order/e21f-1ac15523d21b03f5") == "/rest/track-order/{id}"
    assert template_path("/rest/basket/6/coupon/WMNSDY2019") == "/rest/basket/{id}/coupon/{code}"
    # ordinary route names are untouched
    for p in ("/api/v2/users", "/oauth2/authorize", "/rest/user/whoami", "/ftp/legal.md"):
        assert template_path(p) == p


def test_unresolvable_code_base_is_not_invented_as_an_endpoint():
    from burp2model.extract import extract_js_refs
    refs = extract_js_refs('a.http.get(`${this.host}/${id}/reviews`); a.http.get(`${this.h}/api/Users/${id}`)')
    paths = {r[2] for r in refs}
    assert "/{param}/reviews" not in paths
    assert "/api/Users/{id}" in paths or "/api/Users/{param}" in paths


def test_changes_does_not_report_a_walked_code_reference_as_gone():
    from burp2model.changes import diff_models
    from burp2model.model import Model
    old, new = Model("a"), Model("a")
    old.add_node("endpoint:*:h:/api/x", "endpoint", 4, "* /api/x", method=None, host="h",
                 path="/api/x", method_known=False, api_state="STATIC_ONLY")
    new.add_node("endpoint:GET:h:/api/x", "endpoint", 4, "GET /api/x", method="GET", host="h",
                 path="/api/x", method_known=True, api_state="BOTH")
    d = diff_models(old, new)
    assert d["totals"]["gone"] == 0
    assert any("gap closed" in x["why"] for a in d["areas"] for x in a["appeared"])


def test_error_constants_under_a_code_key_survive_but_real_codes_do_not():
    assert '"SQLITE_ERROR"' in redact_named('{"code":"SQLITE_ERROR","errno":1}')
    assert "ERR_BAD_REQUEST" in redact_named("?code=ERR_BAD_REQUEST")
    assert "a1B2c3D4" not in redact_named('{"code":"a1B2c3D4"}')          # an auth code
    assert "482913" not in redact_named("code=482913")                    # an otp


# ---- found crawling DVWA and Mutillidae ----

def test_html_hidden_fields_with_secret_names_are_masked():
    html = ("<input type='hidden' name='user_token' value='84049048436996a5593d5cc8ba7d4726' />"
            '<input name="csrfmiddlewaretoken" type="hidden" value="Zx9kQ2pLm7RtAbCdEf12">'
            '<input type="text" name="q" value="shoes"><input name=authenticity_token value=abcDEF123456789xyz>')
    out = redact_named(html)
    assert "84049048436996a5593d5cc8ba7d4726" not in out and "Zx9kQ2pLm7RtAbCdEf12" not in out
    assert "abcDEF123456789xyz" not in out and 'value="shoes"' in out


def test_header_lines_echoed_in_a_page_body_are_masked():
    body = "<pre>GET /x HTTP/1.1\r\nCookie: showhints=0; PHPSESSID=fik978dbhcujcgdjfc2lg249r4\r\nAuthorization: Bearer abc.def\r\nAccept: */*</pre>"
    out = redact_named(body)
    assert "fik978dbhcujcgdjfc2lg249r4" not in out and "abc.def" not in out and "Accept: */*" in out


def test_session_and_nonce_style_names_are_credentials():
    for name in ("PHPSESSID", "ASP.NET_SessionId", "_wpnonce", "__VIEWSTATE", "XSRF-TOKEN", "csrf"):
        out = redact_named(f"{name}=abcdefgh12345678")
        assert "abcdefgh12345678" not in out, name
