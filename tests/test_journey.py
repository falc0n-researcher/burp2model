"""Scripted journeys: login/register/fill/click flows the autonomous crawl cannot invent."""

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from burp2model import bql
from burp2model import journey as jy
from burp2model.browser import find_chrome
from burp2model.cli import main
from burp2model.crawl import CrawlConfig, make_crawler

needs_chrome = pytest.mark.skipif(find_chrome() is None, reason="no Chrome/Chromium installed")

HOME = """<!doctype html><html><body>
<input id="name" name="name"><button id="save">Save</button>
<button id="del">Delete draft</button>
<script>
const api = (u, o) => fetch(u, o).then(r => r.text());
api('/api/boot', {headers: {Authorization: 'Bearer ' + (localStorage.getItem('token') || 'none')}});
document.getElementById('save').onclick = () => api('/api/save', {method: 'POST', body: document.getElementById('name').value});
document.getElementById('del').onclick = () => api('/api/delete-draft', {method: 'DELETE'});
</script></body></html>"""


class App(BaseHTTPRequestHandler):
    log = []
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    def _send(self, body, ctype="application/json", status=200):
        data = body.encode()
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _rec(self):
        n = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(n) if n else b""
        App.log.append({"m": self.command, "p": self.path, "auth": self.headers.get("Authorization"),
                        "body": body.decode("utf-8", "replace")})
        return body

    def do_GET(self):
        self._rec()
        if self.path == "/":
            self._send(HOME, "text/html")
        else:
            self._send(json.dumps({"ok": True}))

    def do_POST(self):
        body = self._rec()
        if self.path == "/api/login":
            self._send(json.dumps({"auth": {"token": "tok-JOURNEY-abcdef123456", "uid": 7}}))
        elif self.path == "/api/register":
            self._send(json.dumps({"id": 7}), status=201)
        elif self.path == "/api/fail":
            self._send(json.dumps({"error": "no"}), status=500)
        else:
            self._send(json.dumps({"ok": True, "echo": body.decode()[:40]}))

    do_PUT = do_DELETE = do_POST


@pytest.fixture()
def base():
    App.log = []
    srv = ThreadingHTTPServer(("127.0.0.1", 0), App)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_address[1]}"
    srv.shutdown()


def write(tmp_path, steps, **top):
    p = tmp_path / "j.json"
    p.write_text(json.dumps({"name": "t", "steps": steps, **top}))
    return str(p)


# ------------------------------------------------------------------ the file ----

def test_a_bad_journey_is_rejected_before_anything_is_sent(tmp_path):
    bad = {"nonsense": "x"}
    for content, why in (("not json", "not valid JSON"), ("{}", "non-empty"), (json.dumps({"steps": [bad]}), "exactly one"),
                         (json.dumps({"steps": [{"goto": "/", "click": "#a"}]}), "exactly one"),
                         (json.dumps({"steps": [{"fill": {"value": "x"}}]}), "fill takes"),
                         (json.dumps({"steps": [{"request": {"method": "GET"}}]}), "request takes")):
        p = tmp_path / "bad.json"
        p.write_text(content)
        with pytest.raises(jy.JourneyError, match=why):
            jy.load(str(p))


def test_variables_env_and_missing_ones(monkeypatch):
    monkeypatch.setenv("B2M_PW", "s3cret")
    out = jy.substitute({"a": ["${x}", {"b": "p=${env:B2M_PW}"}], "n": 3}, {"x": "1"})
    assert out == {"a": ["1", {"b": "p=s3cret"}], "n": 3}
    with pytest.raises(jy.JourneyError, match="not defined"):
        jy.substitute("${nope}", {})
    monkeypatch.delenv("B2M_PW")
    with pytest.raises(jy.JourneyError, match="is not set"):
        jy.substitute("${env:B2M_PW}", {})
    assert jy.dig({"a": {"b": [{"c": 5}]}}, "a.b.0.c") == 5 and jy.dig({}, "a.b") is None


# ------------------------------------------------------------- static engine ----

def test_static_journey_logs_in_extracts_and_carries_the_token(base, tmp_path, capsys):
    path = write(tmp_path, [
        {"request": {"method": "POST", "path": "/api/register", "json": {"email": "${email}"}, "expect": 201}},
        {"request": {"method": "POST", "path": "/api/login", "json": {"email": "${email}"},
                     "extract": {"token": "auth.token", "uid": "auth.uid"}}},
        {"set_header": {"Authorization": "Bearer ${token}"}},
        {"request": {"method": "POST", "path": "/api/cart", "json": {"u": "${uid}"}}},
    ], vars={"email": "j@b2m.test"})
    cfg = CrawlConfig(start=base + "/", delay=0, progress=False, browser="off", journeys=[jy.load(path)],
                      journey_only=True)
    res = make_crawler(cfg).run()
    assert [e["p"] for e in App.log] == ["/api/register", "/api/login", "/api/cart"]
    assert App.log[2]["auth"] == "Bearer tok-JOURNEY-abcdef123456" and '"u": 7' in App.log[2]["body"]
    assert res.stats["journey_failed"] == 0 and res.stats["journey_steps"] == 4


def test_failures_are_reported_and_the_journey_carries_on_unless_required(base, tmp_path, capsys):
    path = write(tmp_path, [
        {"request": {"method": "POST", "path": "/api/fail", "expect": 200}},
        {"click": "#nothing"},
        {"goto": "/after"},
        {"request": {"method": "POST", "path": "/api/fail", "expect": 200}, "required": True},
        {"goto": "/never"},
    ])
    cfg = CrawlConfig(start=base + "/", delay=0, progress=False, browser="off", journeys=[jy.load(path)],
                      journey_only=True)
    res = make_crawler(cfg).run()
    err = capsys.readouterr().err
    assert "answered 500, expected 200" in err and "needs a browser" in err
    paths = [e["p"] for e in App.log]
    assert "/after" in paths and "/never" not in paths
    assert res.stats["journey_failed"] == 3


def test_a_journey_cannot_leave_scope_or_break_read_only(base, tmp_path, capsys):
    path = write(tmp_path, [{"request": {"method": "GET", "url": "http://other.invalid/x"}},
                            {"request": {"method": "POST", "path": "/api/save"}}])
    cfg = CrawlConfig(start=base + "/", delay=0, progress=False, browser="off", journeys=[jy.load(path)],
                      journey_only=True, read_only=True)
    make_crawler(cfg).run()
    err = capsys.readouterr().err
    assert "outside the crawl scope" in err and "--read-only" in err and App.log == []


def test_cli_validates_journeys_and_takes_vars_and_env(base, tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("B2M_JPW", "pw-from-env-1")
    path = write(tmp_path, [{"request": {"method": "POST", "path": "/api/login",
                                         "json": {"email": "${who}", "password": "${env:B2M_JPW}"}}}])
    out = str(tmp_path / "o")
    common = ["--yes", "--delay", "0", "--browser", "off", "--no-osint", "--out", out, "-w", "app"]
    assert main(["crawl", base + "/", "--journey", path, "--var", "who=a@b2m.test"] + common) == 0
    login = next(e for e in App.log if e["p"] == "/api/login")
    assert "pw-from-env-1" in login["body"] and "a@b2m.test" in login["body"]
    for f in (tmp_path / "o" / "app").rglob("*"):                      # masked in every output
        if f.is_file():
            assert b"pw-from-env-1" not in f.read_bytes(), f.name
    assert main(["crawl", base + "/", "--journey", str(tmp_path / "missing.json")] + common) == 2
    assert main(["crawl", base + "/", "--journey-only"] + common) == 2
    assert main(["crawl", base + "/", "--journey", path, "--var", "bad"] + common) == 2
    assert "journey" in capsys.readouterr().err


def test_example_journey_in_samples_is_valid():
    j = jy.load("samples/journeys/juiceshop-customer.json")
    assert len(j.steps) >= 10 and j.steps[0]["required"]


# ------------------------------------------------------------ browser engine ----

@needs_chrome
def test_browser_journey_fills_clicks_and_may_press_a_destructive_looking_button(base, tmp_path):
    path = write(tmp_path, [
        {"goto": "/"},
        {"fill": {"selector": "#name", "value": "from-journey"}},
        {"click": {"text": "Save"}},
        {"click": {"text": "Delete draft"}},        # deliberate: the autonomous crawl would never press it
        {"wait_idle": True},
    ])
    cfg = CrawlConfig(start=base + "/", delay=0, progress=False, browser="on", journeys=[jy.load(path)],
                      journey_only=True, max_seconds=60)
    res = make_crawler(cfg).run()
    got = {(e["m"], e["p"]): e for e in App.log}
    assert got[("POST", "/api/save")]["body"] == "from-journey"
    assert ("DELETE", "/api/delete-draft") in got
    assert res.stats["journey_failed"] == 0


@needs_chrome
def test_browser_journey_request_carries_the_session_into_the_crawl_that_follows(base, tmp_path):
    path = write(tmp_path, [
        {"request": {"method": "POST", "path": "/api/login", "json": {"e": "x"}, "extract": {"token": "auth.token"}}},
        {"set_storage": {"token": "${token}"}},
    ])
    cfg = CrawlConfig(start=base + "/", delay=0, progress=False, browser="on", journeys=[jy.load(path)],
                      max_seconds=60, max_clicks=0)
    res = make_crawler(cfg).run()
    boots = [e["auth"] for e in App.log if e["p"] == "/api/boot"]
    assert "Bearer tok-JOURNEY-abcdef123456" in boots       # the autonomous crawl loaded the app logged in
    assert res.stats["journey_failed"] == 0 and res.items


@needs_chrome
def test_browser_journey_failures_name_the_step(base, tmp_path, capsys):
    path = write(tmp_path, [{"click": "#missing"}, {"fill": {"selector": "#missing", "value": "x"}},
                            {"wait_for": {"selector": "#missing", "timeout": 0.5}}])
    cfg = CrawlConfig(start=base + "/", delay=0, progress=False, browser="on", journeys=[jy.load(path)],
                      journey_only=True, max_seconds=60)
    res = make_crawler(cfg).run()
    err = capsys.readouterr().err
    assert res.stats["journey_failed"] == 3
    assert "step 1 (click)" in err and "step 2 (fill)" in err and "timed out waiting" in err


def test_assert_step_validates_and_static_says_it_needs_a_browser(base, tmp_path, capsys):
    p = tmp_path / "bad.json"
    p.write_text(json.dumps({"steps": [{"assert": {}}]}))
    with pytest.raises(jy.JourneyError, match="assert takes"):
        jy.load(str(p))
    path = write(tmp_path, [{"assert": {"text": "x"}}])
    make_crawler(CrawlConfig(start=base + "/", delay=0, progress=False, browser="off",
                             journeys=[jy.load(path)], journey_only=True)).run()
    assert "needs a browser" in capsys.readouterr().err


@needs_chrome
def test_browser_assert_catches_a_login_that_did_not_log_in(base, tmp_path, capsys):
    path = write(tmp_path, [{"goto": "/"}, {"assert": {"url_contains": "/welcome"}, "required": True},
                            {"goto": "/never"}])
    cfg = CrawlConfig(start=base + "/", delay=0, progress=False, browser="on", journeys=[jy.load(path)],
                      journey_only=True, max_seconds=60)
    res = make_crawler(cfg).run()
    assert "expected the URL to contain '/welcome'" in capsys.readouterr().err
    assert res.stats["journey_failed"] == 1 and "/never" not in [e["p"] for e in App.log]
