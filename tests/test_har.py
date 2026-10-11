"""A HAR file (browser DevTools, Hetty, mitmproxy, ZAP ...) builds the same kind of model as a Burp export."""

import base64
import json
import os

import pytest

from burp2model import from_dict, parse_items
from burp2model.cli import main

JWT = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.c2lnbmF0dXJlLXNpZ25hdHVyZQ"


def h(**kw):
    return [{"name": k.replace("_", "-"), "value": v} for k, v in kw.items()]


def entry(method, url, status, rq_headers=None, rs_headers=None, body=None, text=None, mime="application/json",
          rs_encoding=None, params=None):
    e = {"startedDateTime": "2026-10-12T10:00:00Z",
         "request": {"method": method, "url": url, "httpVersion": "HTTP/2.0", "headers": rq_headers or [], "queryString": []},
         "response": {"status": status, "statusText": "OK", "headers": rs_headers or [],
                      "content": {"mimeType": mime, "text": text, **({"encoding": rs_encoding} if rs_encoding else {})}}}
    if body is not None:
        e["request"]["postData"] = {"mimeType": "application/json", "text": body}
    if params is not None:
        e["request"]["postData"] = {"mimeType": "application/x-www-form-urlencoded", "params": params}
    return e


def har(tmp_path, entries, name="session.har"):
    p = tmp_path / name
    p.write_text(json.dumps({"log": {"version": "1.2", "creator": {"name": "test"}, "entries": entries}}))
    return str(p)


SHOP = [
    entry("GET", "https://shop.test/", 200, rs_headers=h(Server="nginx/1.24.0", Content_Type="text/html",
                                                          Content_Encoding="gzip", Set_Cookie="sid=SECRETCOOKIEVALUE123456; HttpOnly; Secure"),
          text='<html><script src="/app.js"></script></html>', mime="text/html; charset=utf-8"),
    entry("GET", "https://shop.test/app.js", 200, rs_headers=h(Content_Type="application/javascript"),
          text='fetch("/api/orders");fetch("/api/hidden/audit")', mime="application/javascript"),
    entry("POST", "https://shop.test/api/orders?page=2", 201,
          rq_headers=[{"name": ":authority", "value": "shop.test"}] + h(Authorization="Bearer " + JWT, Cookie="sid=SECRETCOOKIEVALUE123456",
                                                                       Content_Type="application/json"),
          body='{"item": 7, "email": "alice@corp.example"}', text='{"id": 9}'),
    entry("POST", "https://shop.test/login", 200, params=[{"name": "user", "value": "alice"}, {"name": "password", "value": "hunter2hunter2"}],
          text='{"ok": true}'),
    entry("GET", "https://shop.test/logo.png", 200, text=base64.b64encode(b"\x89PNG....").decode(), rs_encoding="base64", mime="image/png"),
    {"request": {"method": "GET", "url": "https://shop.test/never-answered", "headers": []}, "response": {"status": 0}},
]


def test_a_har_builds_the_same_kind_of_model(tmp_path, monkeypatch):
    monkeypatch.setenv("BURP2MODEL_FP_KEY", "ci")
    monkeypatch.setenv("BURP2MODEL_OFFLINE", "1")
    out = tmp_path / "o"
    assert main([har(tmp_path, SHOP), "-w", "shop", "--out", str(out)]) == 0
    m = from_dict(json.load(open(out / "shop" / "model.json")))
    labels = {n.label for n in m.nodes.values()}
    assert {"POST /api/orders", "/", "app.js"} <= labels
    assert "* /api/hidden/audit" in labels                              # named in the script, never called
    assert m.nodes["endpoint:POST:shop.test:/api/orders"].attrs["credentials"]
    assert m.stats["items"] == 6 and m.stats["parsed"] == 5 and m.stats["skipped"] == 1   # the unanswered request is skipped


def test_no_secret_value_survives_a_har(tmp_path, monkeypatch):
    monkeypatch.setenv("BURP2MODEL_FP_KEY", "ci")
    monkeypatch.setenv("BURP2MODEL_OFFLINE", "1")
    out = tmp_path / "o"
    assert main([har(tmp_path, SHOP), "-w", "shop", "--out", str(out)]) == 0
    for root, _, files in os.walk(out):
        for f in files:
            if f.endswith(".db"):
                continue
            body = open(os.path.join(root, f), encoding="utf-8", errors="replace").read()
            for secret in (JWT, "SECRETCOOKIEVALUE123456", "hunter2hunter2", "alice@corp.example"):
                assert secret not in body, (f, secret)


def test_a_har_is_read_whatever_it_is_named(tmp_path):
    p = har(tmp_path, SHOP[:2], name="capture.json")
    assert len(list(parse_items(p))) == 2


def test_decoded_bodies_are_not_flagged_as_unreadable(tmp_path):
    """A HAR keeps the Content-Encoding header but not the compression; the page must still be scanned."""
    ex = list(parse_items(har(tmp_path, SHOP[:1])))[0]
    assert not ex.scan_truncated and ex.status == 200


def test_a_bad_har_says_so(tmp_path, capsys):
    p = tmp_path / "x.har"
    p.write_text("not json")
    assert main([str(p), "-w", "shop", "--out", str(tmp_path / "o")]) == 2
    assert "HAR" in capsys.readouterr().err
    assert not (tmp_path / "o" / "shop").exists()


def test_watch_picks_up_har_files(tmp_path, monkeypatch):
    monkeypatch.setenv("BURP2MODEL_FP_KEY", "ci")
    monkeypatch.setenv("BURP2MODEL_OFFLINE", "1")
    folder = tmp_path / "in"
    folder.mkdir()
    (folder / "a.har").write_text(open(har(tmp_path, SHOP[:3])).read())
    assert main(["watch", str(folder), "-w", "shop", "--out", str(tmp_path / "o"), "--once"]) == 0
    assert (tmp_path / "o" / "shop" / "graph.db").exists()
