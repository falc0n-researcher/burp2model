"""The JavaScript-enabled crawl: a real Chrome driven over DevTools, against a small SPA."""

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from burp2model import bql
from burp2model.browser import find_chrome
from burp2model.cli import main
from burp2model.crawl import CrawlConfig, make_crawler

pytestmark = pytest.mark.skipif(find_chrome() is None, reason="no Chrome/Chromium installed")

HOME = """<!doctype html><html><head><title>spa</title></head><body>
<button id="menu">Menu</button><div id="nav"></div><div id="view"></div>
<button id="more">Load more</button>
<button id="out">Log out</button><button id="del">Delete account</button>
<button id="reset">Reset</button>
<form id="sub"><input name="email" type="email"><button type="submit">Subscribe</button></form>
<form id="pw"><input name="u"><input name="p" type="password"><button type="submit">Sign in</button></form>
<script src="/app.js"></script></body></html>"""

APP_JS = """
const api = (u, o) => fetch(u, o).then(r => r.text());
const routes = [{path:`secret-page`}, {path:`about`}];
function render() {
  const h = location.hash.replace('#/', '');
  if (h === 'about') api('/api/about');
  if (h === 'secret-page') api('/api/secret');
  document.getElementById('view').textContent = h || 'home';
}
window.addEventListener('hashchange', render);
api('/api/items', {headers: {'X-Seen-Auth': localStorage.getItem('token') || ''}});
if (localStorage.getItem('token')) api('/api/items?authed=1', {headers: {Authorization: 'Bearer ' + localStorage.getItem('token')}});
api('http://localhost:%PORT%/third-party');
document.getElementById('menu').onclick = () => { document.getElementById('nav').innerHTML = '<a href="#/about">About</a>'; };
document.getElementById('more').onclick = () => api('/api/more');
document.getElementById('out').onclick = () => api('/api/logout', {method: 'POST'});
document.getElementById('del').onclick = () => api('/api/delete', {method: 'DELETE'});
document.getElementById('reset').onclick = () => { if (confirm('really?')) api('/api/reset', {method: 'POST'}); };
document.getElementById('sub').onsubmit = e => { e.preventDefault(); api('/api/subscribe', {method: 'POST', body: new FormData(e.target)}); };
document.getElementById('pw').onsubmit = e => { e.preventDefault(); api('/api/signin', {method: 'POST', body: '{}'}); };
render();
"""


class App(BaseHTTPRequestHandler):
    log = []
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    def _send(self, body, ctype="text/html", status=200):
        data = body.encode()
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _rec(self):
        n = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(n) if n else b""
        App.log.append({"m": self.command, "p": self.path, "host": self.headers.get("Host", ""),
                        "auth": self.headers.get("Authorization"), "body": body})

    def do_GET(self):
        self._rec()
        if self.path == "/":
            self._send(HOME)
        elif self.path == "/app.js":
            self._send(APP_JS.replace("%PORT%", str(self.server.server_address[1])), "application/javascript")
        elif self.path.startswith("/api/"):
            self._send(json.dumps({"ok": True}), "application/json")
        else:
            self._send("nope", status=404)

    def do_POST(self):
        self._rec()
        self._send(json.dumps({"ok": True}), "application/json")

    do_DELETE = do_PUT = do_POST


@pytest.fixture(scope="module")
def base():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), App)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_address[1]}"
    srv.shutdown()


def crawl(base, **kw):
    App.log = []
    cfg = CrawlConfig(start=base + "/", progress=False, max_seconds=90, delay=0, **kw)
    crawler = make_crawler(cfg)
    assert getattr(crawler, "chrome", None), "browser mode was not selected"
    return crawler.run()


def seen(method=None):
    return {(e["m"], e["p"].split("?")[0]) for e in App.log if method in (None, e["m"])}


@pytest.fixture(scope="module")
def full(base):
    res = crawl(base, browser="on")
    return res, list(App.log)


def test_runs_the_app_and_records_its_real_xhr_traffic(full):
    res, log = full
    got = {(e["m"], e["p"].split("?")[0]) for e in log}
    assert ("GET", "/api/items") in got                              # fired by JavaScript on load
    assert res.stats["browser"] and res.stats["js_probes"] >= 1


def test_the_start_page_is_captured_as_a_small_jpeg_when_asked(base):
    res = crawl(base, browser="on", screenshot=True, no_interact=True, max_requests=30)
    assert res.screenshot and res.screenshot[:3] == b"\xff\xd8\xff" and len(res.screenshot) < 600_000
    assert crawl(base, browser="on", no_interact=True, max_requests=30).screenshot is None


def test_clicks_reveal_menus_routes_and_buttons(full):
    _, log = full
    got = {(e["m"], e["p"].split("?")[0]) for e in log}
    assert ("GET", "/api/about") in got        # a link that only exists after clicking "Menu"
    assert ("GET", "/api/more") in got         # a button handler
    assert ("GET", "/api/secret") in got       # a route named only in the bundle


def test_fills_and_submits_safe_forms_but_never_a_password_form(full):
    _, log = full
    got = {(e["m"], e["p"].split("?")[0]) for e in log}
    assert ("POST", "/api/subscribe") in got
    assert ("POST", "/api/signin") not in got
    sub = next(e for e in log if e["p"] == "/api/subscribe")
    assert b"test@example.invalid" in sub["body"]


def test_never_clicks_destructive_controls_and_dismisses_dialogs(full):
    res, log = full
    got = {(e["m"], e["p"].split("?")[0]) for e in log}
    assert ("POST", "/api/logout") not in got and ("DELETE", "/api/delete") not in got
    assert ("POST", "/api/reset") not in got                       # confirm() answered "cancel"
    assert res.stats["dialogs_dismissed"] >= 1


def test_blocks_out_of_scope_requests_before_they_are_sent(full):
    res, log = full
    assert not [e for e in log if e["host"].startswith("localhost")]
    assert res.stats["blocked_scope"] >= 1


def test_read_only_blocks_every_non_get(base):
    res = crawl(base, browser="on", read_only=True)
    assert not [m for m, _ in seen() if m != "GET"]
    assert res.stats["blocked_method"] >= 1


def test_login_token_reaches_the_app_through_local_storage(base):
    crawl(base, browser="on", local_storage={"token": "tok-abc123"})
    authed = [e for e in App.log if e["p"].startswith("/api/items?authed=1")]
    assert authed and authed[0]["auth"] == "Bearer tok-abc123"


def test_browser_crawl_builds_the_model_and_masks_the_token(base, tmp_path):
    out = tmp_path / "o"
    rc = main(["crawl", base + "/", "-w", "app", "--yes", "--out", str(out), "--browser", "on",
               "--max-seconds", "90", "--local-storage", "token=tok-abc123"])
    assert rc == 0
    d = out / "app"
    c = bql.connect(str(d / "graph.db"))
    assert bql.run_query(c, "node.type:endpoint AND node.label.cont:/api/items").total >= 1
    assert bql.run_query(c, "node.type:endpoint AND node.label.cont:/api/secret").total >= 1
    for f in d.rglob("*"):
        if f.is_file():
            assert b"tok-abc123" not in f.read_bytes(), f.name


def test_browser_off_and_missing_chrome_fall_back_to_the_static_crawler(base, monkeypatch):
    cfg = CrawlConfig(start=base + "/", progress=False, browser="off")
    assert not getattr(make_crawler(cfg), "chrome", None)
    monkeypatch.setattr("burp2model.browser.find_chrome", lambda explicit=None: None)
    assert not getattr(make_crawler(CrawlConfig(start=base + "/", browser="auto")), "chrome", None)
    with pytest.raises(ValueError):
        make_crawler(CrawlConfig(start=base + "/", browser="on"))


def test_asset_cap_leaves_budget_for_pages_on_an_image_heavy_site(base, monkeypatch):
    # reuse the fixture app's /app.js image-less page but exercise the cap mechanism directly
    cfg = CrawlConfig(start=base + "/", progress=False, max_seconds=60, browser="on", max_assets=0)
    c = make_crawler(cfg)
    assert c._allow(base + "/img.png", "GET", "Image")        # max_assets=0 means no cap
    cfg2 = CrawlConfig(start=base + "/", progress=False, max_seconds=60, browser="on", max_assets=2)
    c2 = make_crawler(cfg2)
    assert c2._allow(base + "/a.png", "GET", "Image")
    assert c2._allow(base + "/b.png", "GET", "Image")
    assert not c2._allow(base + "/c.png", "GET", "Image")      # third image: over the cap
    assert c2.stats["blocked_asset_cap"] == 1
    assert c2._allow(base + "/x.js", "GET", "Script")           # non-asset types are never capped
