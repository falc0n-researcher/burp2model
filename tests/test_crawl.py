"""The crawler, against a small local app that logs everything it is asked."""

import json
import os
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from burp2model import bql, parse_items
from burp2model.cli import main
from burp2model.crawl import CrawlConfig, Crawler

PAGES = "".join(f'<a href="/products?page={i}">{i}</a>' for i in range(1, 9))
ITEMS = "".join(f'<a href="/item/{i}">i{i}</a>' for i in range(1, 13))
HTML_HOME = ("""<!doctype html><html><head><title>Shop</title>
<link rel="stylesheet" href="/s.css"><script src="/app.js"></script></head><body>
<a href="/about">about</a> <a href="/redirect">go</a> <a href="/logout">log out</a>
<a href="/delete-everything">delete</a> <a href="http://other.invalid/x">elsewhere</a>
<a href="http://localhost:{port}/other-origin">same server, other hostname</a>
<a href="mailto:a@b.co">mail</a> <a href="javascript:void(0)">js</a>""" + PAGES + ITEMS + """
<iframe src="/frame"></iframe><img src="/logo.png">
<form action="/search" method="get"><input name="q"><input type="submit"></form>
<form action="/contact" method="post"><input name="name"><input name="msg"></form>
<form action="/signin" method="post"><input name="user"><input type="password" name="pw"></form>
</body></html>""")

APP_JS = """
fetch('/api/items'); fetch('/api/orders/' + id); axios.post('/api/create', {});
const A = '/api/admin/stats'; fetch(`${base}/${id}/reviews`); fetch('/api/whoami');
"""
TOKEN = "Bearer tok-SECRET-abcdefghijklmnop"


class App(BaseHTTPRequestHandler):
    log = []
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    def _send(self, status, body, ctype="text/html", extra=()):
        data = body.encode() if isinstance(body, str) else body
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        for k, v in extra:
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(data)

    def _record(self, body=b""):
        App.log.append({"method": self.command, "path": self.path, "host": self.headers.get("Host", ""),
                        "referer": self.headers.get("Referer"), "cookie": self.headers.get("Cookie"),
                        "auth": self.headers.get("Authorization"), "ua": self.headers.get("User-Agent"),
                        "body": body.decode("utf-8", "replace")})

    def do_GET(self):
        self._record()
        p = self.path.split("?")[0]
        port = self.server.server_address[1]
        authed = self.headers.get("Authorization") == TOKEN
        if p == "/":
            self._send(200, HTML_HOME.replace("{port}", str(port)),
                       extra=[("Set-Cookie", "sid=COOKIEVALUE1234567890; Path=/; HttpOnly")])
        elif p == "/app.js":
            self._send(200, APP_JS, "application/javascript")
        elif p == "/s.css":
            self._send(200, "body{}", "text/css")
        elif p == "/logo.png":
            self._send(200, b"\x89PNG\r\n", "image/png")
        elif p == "/about":
            self._send(200, '<a href="/team">team</a>')
        elif p == "/redirect":
            self._send(302, "", extra=[("Location", "/landing")])
        elif p == "/robots.txt":
            self._send(200, "User-agent: *\nDisallow: /private/\nSitemap: /sitemap.xml\n", "text/plain")
        elif p == "/sitemap.xml":
            self._send(200, "<urlset><url><loc>/hidden-page</loc></url><url><loc>/private/x</loc></url></urlset>",
                       "application/xml")
        elif p in ("/api/whoami", "/api/admin/stats"):
            self._send(200 if authed else 401, json.dumps({"ok": authed}), "application/json")
        elif p == "/api/items":
            self._send(200, json.dumps([{"id": 1}]), "application/json")
        elif p.startswith(("/products", "/item", "/team", "/frame", "/hidden-page", "/search", "/private", "/landing")):
            self._send(200, "<p>page</p>")
        else:
            self._send(404, "<p>nope</p>")

    def do_POST(self):
        n = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(n) if n else b""
        self._record(body)
        if self.path == "/login":
            self._send(200, json.dumps({"authentication": {"token": TOKEN.split()[1]}}), "application/json")
        else:
            self._send(200, "ok")


@pytest.fixture()
def server():
    App.log = []
    srv = ThreadingHTTPServer(("127.0.0.1", 0), App)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_address[1]}"
    srv.shutdown()


def paths(method=None):
    return [(e["method"], e["path"]) for e in App.log if method in (None, e["method"])]


def run(url, **kw):
    return Crawler(CrawlConfig(start=url + "/", delay=0, progress=False, **kw)).run()


def test_follows_links_frames_forms_assets_sitemap_and_redirects(server):
    res = run(server)
    got = {p.split("?")[0] for _, p in paths()}
    assert {"/", "/about", "/team", "/frame", "/s.css", "/app.js", "/logo.png", "/redirect",
            "/search", "/hidden-page", "/robots.txt", "/sitemap.xml", "/landing"} <= got
    assert res.stats["redirects"] >= 1 and res.stats["forms_found"] == 3
    assert any(p.startswith("/search?q=") for _, p in paths("GET"))      # a GET form, benign value


def test_requests_what_the_bundle_names_but_never_a_non_get(server):
    res = run(server)
    got = paths()
    assert ("GET", "/api/items") in got and ("GET", "/api/whoami") in got
    assert not [m for m, p in got if p.startswith("/api/create")]              # axios.post: named, not sent
    assert res.stats["js_refs_not_requested"] >= 1
    assert not [p for _, p in got if "{" in p or "reviews" in p]               # unresolved base: not guessed


def test_never_sends_anything_but_get_by_default(server):
    run(server)
    assert {m for m, _ in paths()} == {"GET"}


def test_stays_in_scope_and_skips_unsafe_links(server):
    res = run(server)
    assert not [e for e in App.log if e["host"].startswith("localhost")]       # same server, other hostname
    got = {p for _, p in paths()}
    assert "/logout" not in got and "/delete-everything" not in got
    assert res.stats["skipped_out_of_scope"] >= 2 and res.stats["skipped_unsafe"] >= 2


def test_caps_variants_of_one_path_and_one_template(server):
    run(server, per_path_query_cap=5, per_template_cap=8)
    assert len([p for _, p in paths() if p.startswith("/products?")]) <= 5
    assert len([p for _, p in paths() if p.startswith("/item/")]) <= 8


def test_budget_and_depth_are_respected(server):
    res = run(server, max_requests=6)
    assert res.stats["requests"] == 6 and len(App.log) == 6
    App.log.clear()
    run(server, max_depth=0)
    assert "/team" not in {p for _, p in paths()}                              # two links deep


def test_sends_referer_cookies_and_its_own_user_agent(server):
    run(server)
    about = next(e for e in App.log if e["path"] == "/about")
    assert about["referer"].endswith("/") and "burp2model-crawler" in about["ua"]
    assert about["cookie"] and "sid=COOKIEVALUE1234567890" in about["cookie"]


def test_robots_are_optional(server):
    run(server)
    assert "/private/x" in {p for _, p in paths()}
    App.log.clear()
    run(server, respect_robots=True)
    assert "/private/x" not in {p for _, p in paths()}


def test_login_once_then_carry_the_token(server):
    res = run(server, auth_login=server + "/login", auth_body='{"email":"a","password":"b"}',
              auth_token="authentication.token")
    assert paths("POST") == [("POST", "/login")]
    who = next(e for e in App.log if e["path"] == "/api/whoami")
    assert who["auth"] == TOKEN and res.items


def test_submit_forms_is_opt_in_and_never_posts_a_password_form(server):
    run(server)
    assert not paths("POST")
    App.log.clear()
    res = run(server, submit_forms=True)
    posts = paths("POST")
    assert ("POST", "/contact") in posts and ("POST", "/signin") not in posts
    assert next(e for e in App.log if e["path"] == "/contact")["body"] == "name=test&msg=test"
    assert any("password field" in f.get("note", "") for f in res.forms)


def test_consent_is_required_and_nothing_is_sent_without_it(server, tmp_path, capsys):
    assert main(["crawl", server + "/", "-w", "t", "--out", str(tmp_path)]) == 2
    assert "authorized" in capsys.readouterr().err and App.log == []


def test_bad_input_is_a_clean_error_not_a_traceback(tmp_path, capsys):
    assert main(["crawl", "ftp://x/", "--yes", "--out", str(tmp_path)]) == 2
    assert main(["crawl", "http://127.0.0.1:9/", "--yes", "--header", "nonsense", "--out", str(tmp_path)]) == 2
    assert main(["crawl", "http://127.0.0.1:1/", "--yes", "--out", str(tmp_path), "--delay", "0",
                 "--browser", "off"]) == 2                    # nothing listening
    assert "nothing was fetched" in capsys.readouterr().err


def test_crawl_builds_the_same_outputs_as_a_burp_export_and_masks_everything(server, tmp_path):
    out = tmp_path / "o"
    rc = main(["crawl", server + "/", "-w", "app", "--yes", "--delay", "0", "--out", str(out), "--browser", "off",
               "--browser", "off", "--role", "user", "--auth-login", server + "/login",
               "--auth-body", '{"email":"a@b.co","password":"hunter2hunter2"}',
               "--auth-token", "authentication.token", "--save-xml", str(tmp_path / "crawl.xml")])
    assert rc == 0
    d = out / "app"
    for f in ("graph.db", "model.json", "report.html", "context.json", "graph.json", "graph.graphml"):
        assert (d / f).exists(), f
    for secret in ("tok-SECRET-abcdefghijklmnop", "COOKIEVALUE1234567890", "hunter2hunter2", "a@b.co"):
        for f in d.rglob("*"):
            if f.is_file():
                assert secret.encode() not in f.read_bytes(), (secret, f.name)
    c = bql.connect(str(d / "graph.db"))
    assert bql.run_query(c, "node.type:endpoint AND node.label.cont:/api/items").total >= 1
    assert bql.run_query(c, "role:user").total >= 10
    assert bql.run_query(c, "req.header.cont:Referer").total >= 1
    # the optional Burp-format file round-trips through the normal parser
    assert len(list(parse_items(str(tmp_path / "crawl.xml")))) >= 10


def test_crawl_roles_merge_like_burp_role_builds(server, tmp_path):
    out = str(tmp_path / "o")
    base = ["--yes", "--delay", "0", "--out", out, "--browser", "off", "-w", "app"]
    assert main(["crawl", server + "/", "--role", "anon"] + base) == 0
    assert main(["crawl", server + "/", "--browser", "off", "--role", "user", "--auth-login", server + "/login",
                 "--auth-body", "{}", "--auth-token", "authentication.token"] + base) == 0
    c = bql.connect(os.path.join(out, "app", "graph.db"))
    roles = {r["role"] for r in bql.run_query(c, "sql SELECT DISTINCT role FROM exchanges").rows}
    assert {"anon", "user"} <= roles
