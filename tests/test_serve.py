"""The local endpoint the Burp extension talks to."""

import http.client
import json
import os
import socket
import threading

import pytest

from burp2model import serve, store

SAMPLE = os.path.join(os.path.dirname(__file__), "..", "samples", "burp-history-sample.xml")


@pytest.fixture
def server(tmp_path, monkeypatch):
    monkeypatch.setenv("BURP2MODEL_FP_KEY", "ci")
    monkeypatch.setenv("BURP2MODEL_OFFLINE", "1")
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    srv = serve.make_server("shop", str(tmp_path / "out"), "sekret", port)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    yield port, tmp_path / "out"
    srv.shutdown()
    srv.server_close()


def call(port, method, path, body=None, token="sekret", host=None):
    c = http.client.HTTPConnection("127.0.0.1", port, timeout=30)
    headers = {"X-B2M-Token": token}
    if host:
        headers["Host"] = host
    c.request(method, path, body=body, headers=headers)
    r = c.getresponse()
    data = json.loads(r.read() or b"{}")
    c.close()
    return r.status, data


def test_a_selection_becomes_a_build_and_a_report(server):
    port, out = server
    xml = open(SAMPLE, "rb").read()
    code, data = call(port, "POST", "/ingest?label=first", xml)
    assert code == 200 and data["ok"] and os.path.exists(data["report"])
    code, data = call(port, "POST", "/ingest?label=second", xml)
    assert code == 200
    conn = store.open_db(str(out / "shop" / "graph.db"))
    assert [b["label"] for b in store.list_builds(conn)] == ["first", "second"]
    conn.close()


def test_health_needs_the_token(server):
    port, _ = server
    assert call(port, "GET", "/health")[0] == 200
    assert call(port, "GET", "/health", token="nope")[0] == 401
    assert call(port, "POST", "/ingest", b"<x/>", token="")[0] == 401


def test_a_web_page_cannot_reach_it_by_another_host_name(server):
    port, _ = server
    assert call(port, "GET", "/health", host="evil.example")[0] == 403


def test_bad_bodies_are_refused(server):
    port, out = server
    code, data = call(port, "POST", "/ingest", b"not xml at all")
    assert code == 422 and "error" in data
    assert call(port, "POST", "/nope", b"x")[0] == 404
    assert not (out / "shop").exists()          # a failed selection leaves nothing behind


def test_the_extensions_xml_shape_builds(server):
    """The Java side writes this exact shape: no DOCTYPE, no mimetype, no response on a dropped request."""
    import base64
    b = lambda s: base64.b64encode(s.encode()).decode()          # noqa: E731
    xml = ("<?xml version=\"1.0\"?>\n<items>\n"
           "<item><url>https://shop.test/api/me</url><host>shop.test</host><port>443</port>"
           "<protocol>https</protocol><method>GET</method><path>/api/me</path><status>200</status>"
           f"<request base64=\"true\">{b('GET /api/me HTTP/1.1' + chr(13) + chr(10) + 'Host: shop.test' + chr(13) + chr(10) * 2)}</request>"
           f"<response base64=\"true\">{b('HTTP/1.1 200 OK' + chr(13) + chr(10) + 'Content-Type: application/json' + chr(13) + chr(10) * 2 + '{}')}</response>"
           "</item>\n"
           "<item><url>https://shop.test/x</url><host>shop.test</host><port>443</port><protocol>https</protocol>"
           "<method>GET</method><path>/x</path>"
           f"<request base64=\"true\">{b('GET /x HTTP/1.1' + chr(13) + chr(10) + 'Host: shop.test' + chr(13) + chr(10) * 2)}</request>"
           "</item>\n</items>\n").encode()
    port, out = server
    code, data = call(port, "POST", "/ingest?role=admin", xml)
    assert code == 200, data
    conn = store.open_db(str(out / "shop" / "graph.db"))
    assert conn.execute("SELECT count(*) FROM nodes WHERE type='endpoint'").fetchone()[0] >= 1
    conn.close()
