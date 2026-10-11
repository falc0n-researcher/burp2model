"""Secrets in the shapes real apps use, not only the ones the audit plants.

Each case is text as it appears in a captured request or response; the value after "secret" must never survive
the redaction that runs on everything stored. Found by running two real exports: a token in an HTML attribute got
through, and the shapes below were the other places a secret hides.
"""

import pytest

from burp2model.redact import redact_named, redact_value_patterns

SECRET = "hunter2hunter2"
TOKEN = "abc123DEF456ghi789"

CASES = {
    "multipart field": (f'--b\r\nContent-Disposition: form-data; name="password"\r\n\r\n{SECRET}\r\n--b--', SECRET),
    "multipart with a content type": (f'--b\r\nContent-Disposition: form-data; name="api_key"\r\nContent-Type: text/plain\r\n\r\n{TOKEN}\r\n--b--', TOKEN),
    "xml element": (f"<login><user>a</user><password>{SECRET}</password></login>", SECRET),
    "xml token": (f"<token>{TOKEN}</token>", TOKEN),
    "js const": (f'const apiKey = "{TOKEN}";', TOKEN),
    "js var single quotes": (f"var token='{TOKEN}';", TOKEN),
    "js object, unquoted key": (f'{{token:"{TOKEN}",id:1}}', TOKEN),
    "js header object": (f'fetch(u,{{headers:{{Authorization:"Bearer {TOKEN}"}}}})', TOKEN),
    "json with a cookie": (f'{{"cookie":"sid={TOKEN}"}}', TOKEN),
    "json single quotes": (f"{{'password':'{SECRET}'}}", SECRET),
    "json array of secrets": (f'{{"tokens":["{TOKEN}","{TOKEN}x"]}}', TOKEN),
    "json inside a form field": (f"data=%7B%22password%22%3A%22{SECRET}%22%7D", SECRET),
    "yaml line": (f"password: {SECRET}\nname: shop", SECRET),
    "ini line": (f"api_key={TOKEN}", TOKEN),
    "client secret": (f'client_secret: "{TOKEN}"', TOKEN),
    "graphql variables": (f'{{"variables":{{"password":"{SECRET}"}}}}', SECRET),
    "html data attribute": (f'<div data-auth-token="{TOKEN}"></div>', TOKEN),
    "hidden input": (f'<input type="hidden" name="csrf_token" value="{TOKEN}">', TOKEN),
    "meta csrf": (f'<meta name="csrf-token" content="{TOKEN}">', TOKEN),
    "echoed header": (f"Authorization: Bearer {TOKEN}", TOKEN),
    "api key header": (f"X-Api-Key: {TOKEN}", TOKEN),
    "set-cookie in a body": (f"Set-Cookie: session={TOKEN}; Path=/", TOKEN),
    "token in a query string": (f'"/cb?access_token={TOKEN}&x=1"', TOKEN),
    "jwt in code": ('var t="eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.c2lnbmF0dXJlc2lnbmF0dXJl";', "eyJhbGciOiJIUzI1NiJ9"),
    "aws key": ("key AKIAIOSFODNN7EXAMPLE here", "AKIAIOSFODNN7EXAMPLE"),
    "github token": ("ghp_" + "a" * 36, "a" * 36),
    "stripe secret key": ("sk_live_abcdefghijklmnop1234", "abcdefghijklmnop1234"),
    "email": ("contact alice@corp.example now", "alice@corp.example"),
}

# text that merely sits near words like these must read the same afterwards
BENIGN = [
    "<title>Hello</title>",
    '{"id":5,"name":"shirt","price":12}',
    "color: red;\nfont-size: 12px",
    '<a class="x">Sign in</a>',
    '{"status":"ok","code":"ERR_NOT_FOUND"}',
    "fetch(\"/api/orders\").then(r=>r.json())",
]


@pytest.mark.parametrize("name", sorted(CASES))
def test_the_secret_never_survives(name, monkeypatch):
    monkeypatch.setenv("BURP2MODEL_FP_KEY", "ci")
    text, secret = CASES[name]
    out = redact_named(redact_value_patterns(text)[0])
    assert secret not in out, out


@pytest.mark.parametrize("text", BENIGN)
def test_ordinary_text_is_left_alone(text, monkeypatch):
    monkeypatch.setenv("BURP2MODEL_FP_KEY", "ci")
    assert redact_named(redact_value_patterns(text)[0]) == text
