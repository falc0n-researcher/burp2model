"""
A crawler, so the model can be built straight from a running web app with no
proxy and no Burp export.

It does what a browser-driven spider does, with the standard library:

  * follows links, frames, redirects and GET forms, sending a Referer like a
    browser so page -> request edges (CALLS / NAVIGATES_TO) appear in the model;
  * fetches the scripts and styles a page pulls in, then reads the endpoints the
    JavaScript names and requests the concrete GET ones (the paths a single-page
    app only reveals in its bundle);
  * keeps cookies, takes extra headers, and can log in once and carry the token,
    so authenticated surface is reachable (one crawl per role, like `--role`);
  * records every request and response as a Burp-style <item>, in memory. They go
    through exactly the same parser and redaction as a Burp export, so nothing raw
    is ever written by the crawl itself.

What it deliberately does not do: it never leaves the scope you give it, never
sends anything but GET unless you pass --submit-forms (and then never to a form
with a password field), skips links that look destructive (logout, delete, ...),
rate-limits itself, caps requests, depth, body size and variants of one template,
and does not run until you confirm you are authorised to test the target.

It does not execute JavaScript. A page that builds its links in the browser is
covered through the endpoints its bundle names, not by clicking.
"""

from __future__ import annotations

import base64
import gzip
import http.client
import json
import re
import ssl
import sys
import threading
import time
import urllib.parse
import zlib
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from html.parser import HTMLParser
from xml.etree.ElementTree import Element, SubElement

from . import __version__
from .domains import registrable_domain
from .extract import extract_js_refs
from .redact import route_template, template_path

_UNSAFE = re.compile(
    r"(?i)(log-?out|sign-?out|log-?off|delete|remove|destroy|unsubscribe|deactivate|"
    r"erase|erasure|reset-?db|shutdown|drop|purge|wipe|truncate|factory-?reset|"
    r"set-?up|install|init-?db|create-?db|database-?reset)")
_STATIC_ASSET = re.compile(r"(?i)\.(?:png|jpe?g|gif|svg|ico|webp|avif|bmp|woff2?|ttf|otf|eot|mp4|webm|mp3|wav|pdf|zip)$")
_REASONS = {200: "OK", 201: "Created", 204: "No Content", 301: "Moved Permanently", 302: "Found",
            303: "See Other", 304: "Not Modified", 307: "Temporary Redirect", 308: "Permanent Redirect",
            400: "Bad Request", 401: "Unauthorized", 403: "Forbidden", 404: "Not Found",
            405: "Method Not Allowed", 429: "Too Many Requests", 500: "Internal Server Error",
            502: "Bad Gateway", 503: "Service Unavailable"}
_PAGE_TAGS = {"a": "href", "area": "href", "iframe": "src", "frame": "src"}
_ASSET_TAGS = {"script": "src", "link": "href", "img": "src", "source": "src", "video": "src",
               "audio": "src", "embed": "src", "track": "src"}


@dataclass
class CrawlConfig:
    start: str
    scope: list[str] = field(default_factory=list)       # extra hosts / host:port
    include_subdomains: bool = False
    max_requests: int = 3000           # 0 = no limit
    max_depth: int = 12
    max_assets: int = 2000
    max_seconds: float = 0             # wall-clock limit for the whole crawl; 0 = none
    delay: float = 0.1
    timeout: float = 10.0
    threads: int = 1
    headers: dict = field(default_factory=dict)
    cookies: dict = field(default_factory=dict)
    probe_js: bool = True
    submit_forms: bool = False
    respect_robots: bool = False
    insecure: bool = False
    user_agent: str = f"burp2model-crawler/{__version__}"
    per_template_cap: int = 25         # variants of /items/{id}
    per_path_query_cap: int = 15       # variants of /search?q=...
    max_body: int = 5 * 1024 * 1024
    auth_login: str | None = None      # URL to POST credentials to
    auth_body: str | None = None       # JSON body for it
    auth_token: str | None = None      # dotted path to the token in the JSON reply
    auth_header: str = "Authorization"
    auth_scheme: str = "Bearer"
    progress: bool = True
    # browser mode (a real Chrome driven over DevTools; see browser.py)
    browser: str = "auto"              # auto | on | off
    chrome: str | None = None
    max_clicks: int = 25               # per page state
    no_interact: bool = False          # load pages, do not click or fill
    no_forms: bool = False             # fill fields but do not submit forms
    read_only: bool = False            # block every non-GET the browser would send
    headful: bool = False
    auth_storage: str | None = None    # put the login token in localStorage[KEY] and cookie KEY
    local_storage: dict = field(default_factory=dict)
    # scripted journeys (see journey.py)
    journeys: list = field(default_factory=list)
    journey_vars: dict = field(default_factory=dict)
    journey_only: bool = False


@dataclass
class Task:
    method: str
    url: str
    depth: int
    referer: str | None
    kind: str                       # seed | page | asset | js | form | redirect | sitemap
    body: bytes | None = None
    ctype: str | None = None
    hops: int = 0


@dataclass
class CrawlResult:
    items: list
    stats: dict
    forms: list
    scope: list[str]


class _Page(HTMLParser):
    """Links, frames, assets and forms out of an HTML document."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.base: str | None = None
        self.pages: list[str] = []
        self.assets: list[str] = []
        self.forms: list[dict] = []
        self._form: dict | None = None

    def handle_starttag(self, tag, attrs):
        a = {k: (v or "") for k, v in attrs}
        if tag == "base" and a.get("href"):
            self.base = a["href"]
        elif tag in _PAGE_TAGS and a.get(_PAGE_TAGS[tag]):
            self.pages.append(a[_PAGE_TAGS[tag]])
        elif tag in _ASSET_TAGS and a.get(_ASSET_TAGS[tag]):
            if tag == "link" and a.get("rel", "").lower() not in ("stylesheet", "icon", "shortcut icon",
                                                                  "manifest", "modulepreload", "preload"):
                return
            self.assets.append(a[_ASSET_TAGS[tag]])
        elif tag == "meta" and a.get("http-equiv", "").lower() == "refresh":
            m = re.search(r"url\s*=\s*['\"]?([^'\";]+)", a.get("content", ""), re.I)
            if m:
                self.pages.append(m.group(1).strip())
        elif tag == "form":
            self._form = {"action": a.get("action", ""), "method": (a.get("method") or "GET").upper(),
                          "inputs": []}
            self.forms.append(self._form)
        elif tag in ("input", "select", "textarea", "button") and self._form is not None and a.get("name"):
            self._form["inputs"].append((a["name"], (a.get("type") or tag).lower(), a.get("value", "")))

    def handle_endtag(self, tag):
        if tag == "form":
            self._form = None


def _burp_mime(ct: str) -> str:
    ct = (ct or "").split(";")[0].strip().lower()
    return {"text/html": "HTML", "application/json": "JSON", "text/css": "CSS",
            "application/javascript": "script", "text/javascript": "script", "image/png": "PNG",
            "image/jpeg": "JPEG", "image/svg+xml": "XML", "application/xml": "XML", "text/xml": "XML",
            "text/plain": "text", "application/pdf": "PDF"}.get(ct, "text" if ct.startswith("text/") else "")


def _decode(headers: dict, body: bytes) -> bytes:
    enc = headers.get("content-encoding", "").lower()
    try:
        if "gzip" in enc:
            return gzip.decompress(body)
        if "deflate" in enc:
            try:
                return zlib.decompress(body)
            except zlib.error:
                return zlib.decompress(body, -zlib.MAX_WBITS)
    except (OSError, zlib.error, EOFError):
        pass
    return body


class Crawler:
    def __init__(self, cfg: CrawlConfig):
        u = urllib.parse.urlsplit(cfg.start)
        if u.scheme not in ("http", "https") or not u.hostname:
            raise ValueError(f"not an http(s) URL: {cfg.start!r}")
        self.cfg = cfg
        self.start = u
        self.scope = self._build_scope(u, cfg)
        self.jar: dict[str, dict[str, str]] = {}
        if cfg.cookies:
            self.jar[u.hostname.lower()] = dict(cfg.cookies)
        self.headers = dict(cfg.headers)
        self.items: list[Element] = []
        self.seen: set = set()
        self.template_count: dict = {}
        self.query_count: dict = {}
        self.forms: list[dict] = []
        self.stats = {"requests": 0, "pages": 0, "assets": 0, "js_probes": 0, "redirects": 0,
                      "errors": 0, "skipped_out_of_scope": 0, "skipped_unsafe": 0,
                      "skipped_duplicate": 0, "skipped_cap": 0, "forms_found": 0,
                      "forms_submitted": 0, "js_refs_not_requested": 0, "robots_skipped": 0}
        self._rl = threading.Lock()
        self._last = 0.0
        self._disallow: list[str] = []
        self._ctx = ssl._create_unverified_context() if cfg.insecure else ssl.create_default_context()
        self.stats.update({"journey_steps": 0, "journey_failed": 0})
        self.journey_log: list[str] = []

    # ---------------------------------------------------------------- scope --
    @staticmethod
    def _build_scope(u, cfg) -> list[str]:
        port = u.port or (443 if u.scheme == "https" else 80)
        scope = [f"{u.hostname.lower()}:{port}"]
        for s in cfg.scope:
            s = s.strip().lower()
            if s:
                scope.append(s)
        if cfg.include_subdomains:
            scope.append("*." + registrable_domain(u.hostname.lower()))
        return scope

    def in_scope(self, url: str) -> bool:
        u = urllib.parse.urlsplit(url)
        if u.scheme not in ("http", "https") or not u.hostname:
            return False
        host = u.hostname.lower()
        port = u.port or (443 if u.scheme == "https" else 80)
        for s in self.scope:
            if s.startswith("*."):
                if host == s[2:] or host.endswith(s[1:]):
                    return True
            elif ":" in s and not s.endswith("]"):
                sh, _, sp = s.rpartition(":")
                if host == sh and str(port) == sp:
                    return True
            elif host == s:
                return True
        return False

    # ----------------------------------------------------------------- fetch --
    def _wait(self) -> None:
        with self._rl:
            gap = self._last + self.cfg.delay - time.monotonic()
            if gap > 0:
                time.sleep(gap)
            self._last = time.monotonic()

    def _cookie_header(self, host: str) -> str:
        return "; ".join(f"{k}={v}" for k, v in self.jar.get(host, {}).items())

    def _store_cookies(self, host: str, resp_headers: list) -> None:
        for k, v in resp_headers:
            if k.lower() != "set-cookie":
                continue
            pair = v.split(";", 1)[0]
            name, eq, val = pair.partition("=")
            if not eq or not name.strip():
                continue
            attrs = v.lower()
            jar = self.jar.setdefault(host, {})
            if not val.strip() or "max-age=0" in attrs:
                jar.pop(name.strip(), None)
            else:
                jar[name.strip()] = val.strip()

    def fetch(self, task: Task):
        """One request. Returns (Element, status, resp_headers dict, decoded body bytes) or None."""
        u = urllib.parse.urlsplit(task.url)
        host = u.hostname.lower()
        port = u.port or (443 if u.scheme == "https" else 80)
        path = (u.path or "/") + ("?" + u.query if u.query else "")
        hdr = {"Host": u.netloc, "User-Agent": self.cfg.user_agent,
               "Accept": "text/html,application/xhtml+xml,application/json;q=0.9,*/*;q=0.8",
               "Accept-Language": "en-US,en;q=0.9", "Accept-Encoding": "gzip, deflate",
               "Connection": "close"}
        if task.referer:
            hdr["Referer"] = task.referer
        hdr.update(self.headers)
        ck = self._cookie_header(host)
        if ck:
            hdr["Cookie"] = ck
        if task.body is not None:
            hdr["Content-Type"] = task.ctype or "application/x-www-form-urlencoded"
            hdr["Content-Length"] = str(len(task.body))
        raw_req = (f"{task.method} {path} HTTP/1.1\r\n"
                   + "".join(f"{k}: {v}\r\n" for k, v in hdr.items()) + "\r\n").encode("latin-1", "replace")
        raw_req += task.body or b""
        self._wait()
        try:
            cls = http.client.HTTPSConnection if u.scheme == "https" else http.client.HTTPConnection
            kw = {"timeout": self.cfg.timeout}
            if u.scheme == "https":
                kw["context"] = self._ctx
            conn = cls(u.hostname, port, **kw)
            conn.request(task.method, path, body=task.body,
                         headers={k: v for k, v in hdr.items() if k != "Host"} | {"Host": u.netloc})
            resp = conn.getresponse()
            data = resp.read(self.cfg.max_body + 1)
            truncated = len(data) > self.cfg.max_body
            data = data[: self.cfg.max_body]
            rheaders = resp.getheaders()
            status = resp.status
            conn.close()
        except (OSError, http.client.HTTPException, ssl.SSLError):
            self.stats["errors"] += 1
            return None
        self._store_cookies(host, rheaders)
        kept = [(k, v) for k, v in rheaders if k.lower() not in ("transfer-encoding", "content-length")]
        kept.append(("Content-Length", str(len(data))))
        head = (f"HTTP/1.1 {status} {_REASONS.get(status, resp.reason)}\r\n"
                + "".join(f"{k}: {v}\r\n" for k, v in kept) + "\r\n")
        raw_resp = head.encode("latin-1", "replace") + data
        low = {k.lower(): v for k, v in rheaders}
        item = Element("item")
        for tag, val in (("method", task.method), ("host", host), ("port", str(port)),
                         ("protocol", u.scheme), ("path", path), ("status", str(status)),
                         ("mimetype", _burp_mime(low.get("content-type", "")))):
            SubElement(item, tag).text = val
        rq = SubElement(item, "request", {"base64": "true"})
        rq.text = base64.b64encode(raw_req).decode()
        rs = SubElement(item, "response", {"base64": "true"})
        rs.text = base64.b64encode(raw_resp).decode()
        if truncated:
            SubElement(item, "comment").text = "body truncated by burp2model crawler"
        return item, status, low, _decode(low, data)

    # ------------------------------------------------------------- planning --
    def _normalise(self, base: str, link: str) -> str | None:
        link = (link or "").strip()
        if not link or link.startswith(("#", "javascript:", "mailto:", "tel:", "data:", "blob:")):
            return None
        url = urllib.parse.urljoin(base, link)
        url, _ = urllib.parse.urldefrag(url)
        return url if url.startswith(("http://", "https://")) else None

    def _admit(self, method: str, url: str, kind: str) -> bool:
        """Scope, safety, duplicate and variant caps. Counts why a URL was dropped."""
        if not self.in_scope(url):
            self.stats["skipped_out_of_scope"] += 1
            return False
        u = urllib.parse.urlsplit(url)
        if _UNSAFE.search(u.path) or _UNSAFE.search(u.query):
            self.stats["skipped_unsafe"] += 1
            return False
        if self.cfg.respect_robots and any(u.path.startswith(d) for d in self._disallow if d):
            self.stats["robots_skipped"] += 1
            return False
        key = (method, u.scheme, u.netloc.lower(), u.path, u.query)
        if key in self.seen:
            self.stats["skipped_duplicate"] += 1
            return False
        tkey = (method, u.netloc.lower(), route_template(u.path + ("?" + u.query if u.query else ""),
                                                         template_path(u.path)))
        qkey = (method, u.netloc.lower(), u.path)
        if self.template_count.get(tkey, 0) >= self.cfg.per_template_cap or \
                (u.query and self.query_count.get(qkey, 0) >= self.cfg.per_path_query_cap):
            self.stats["skipped_cap"] += 1
            return False
        self.seen.add(key)
        self.template_count[tkey] = self.template_count.get(tkey, 0) + 1
        if u.query:
            self.query_count[qkey] = self.query_count.get(qkey, 0) + 1
        return True

    def _sample(self, inputs) -> list[tuple[str, str]]:
        out = []
        for name, typ, value in inputs:
            if typ in ("submit", "button", "image", "reset", "file"):
                continue
            if typ in ("checkbox", "radio") and not value:
                continue
            out.append((name, value or {"number": "1", "email": "test@example.invalid"}.get(typ, "test")))
        return out

    def _discover(self, task: Task, status: int, low: dict, body: bytes) -> list[Task]:
        ct = low.get("content-type", "").lower()
        new: list[Task] = []
        text = body.decode("utf-8", "replace") if body else ""
        base = task.url
        is_html = "html" in ct
        is_js = "javascript" in ct or task.url.split("?")[0].endswith((".js", ".mjs"))

        if 300 <= status < 400 and low.get("location"):
            dest = self._normalise(task.url, low["location"])
            if dest and task.hops < 5 and self._admit("GET", dest, "redirect"):
                self.stats["redirects"] += 1
                new.append(Task("GET", dest, task.depth, task.referer, "redirect", hops=task.hops + 1))
            return new
        if not (200 <= status < 300) or not text:
            return new

        if is_html:
            page = _Page()
            try:
                page.feed(text)
            except Exception:
                pass
            if page.base:
                base = urllib.parse.urljoin(task.url, page.base)
            if task.depth < self.cfg.max_depth:
                for link in page.pages:
                    dest = self._normalise(base, link)
                    if dest and self._admit("GET", dest, "page"):
                        new.append(Task("GET", dest, task.depth + 1, task.url, "page"))
            for link in page.assets:
                dest = self._normalise(base, link)
                if dest and (self.stats["assets"] + sum(1 for t in new if t.kind == "asset")
                             < self.cfg.max_assets) and self._admit("GET", dest, "asset"):
                    new.append(Task("GET", dest, task.depth, task.url, "asset"))
            for form in page.forms:
                self._handle_form(task, base, form, new)
        if (is_html or is_js) and self.cfg.probe_js:
            self._probe_refs(task, text, new)
        if task.kind == "sitemap" or task.url.endswith("sitemap.xml"):
            for loc in re.findall(r"<loc>\s*([^<\s]+)\s*</loc>", text):
                dest = self._normalise(task.url, loc)
                if dest and self._admit("GET", dest, "sitemap"):
                    new.append(Task("GET", dest, task.depth + 1, task.url, "sitemap"))
        return new

    def _handle_form(self, task: Task, base: str, form: dict, new: list) -> None:
        self.stats["forms_found"] += 1
        action = self._normalise(base, form["action"]) or base
        has_password = any(t == "password" for _, t, _ in form["inputs"])
        rec = {"page": task.url, "action": urllib.parse.urlsplit(action).path or "/",
               "method": form["method"], "fields": [n for n, t, _ in form["inputs"]
                                                     if t not in ("submit", "button", "image", "reset")]}
        if has_password:
            rec["note"] = "password field — never submitted"
        self.forms.append(rec)
        data = urllib.parse.urlencode(self._sample(form["inputs"]))
        if form["method"] == "GET":
            sep = "&" if "?" in action else "?"
            dest = action.split("#")[0] + (sep + data if data else "")
            if not has_password and task.depth < self.cfg.max_depth and self._admit("GET", dest, "form"):
                new.append(Task("GET", dest, task.depth + 1, task.url, "form"))
        elif self.cfg.submit_forms and not has_password and self.in_scope(action) \
                and not _UNSAFE.search(action):
            key = ("POST", action, data)
            if key not in self.seen and self.stats["forms_submitted"] < 25:
                self.seen.add(key)
                self.stats["forms_submitted"] += 1
                new.append(Task("POST", action, task.depth + 1, task.url, "form", data.encode(),
                                "application/x-www-form-urlencoded"))

    def _probe_refs(self, task: Task, text: str, new: list) -> None:
        """Request the concrete GET endpoints a script or page names."""
        try:
            refs = extract_js_refs(text)
        except Exception:
            return
        for method, host, path, _kind in sorted(refs, key=lambda r: (r[2], r[0] or "")):
            if "{" in path or _STATIC_ASSET.search(path):
                continue
            if method not in (None, "GET"):
                self.stats["js_refs_not_requested"] += 1        # named, but not a GET: not sent
                continue
            if host:
                dest = f"{urllib.parse.urlsplit(task.url).scheme}://{host}{path}"
            else:
                u = urllib.parse.urlsplit(self.cfg.start)
                dest = f"{u.scheme}://{u.netloc}{path}"
            if self._admit("GET", dest, "js"):
                new.append(Task("GET", dest, task.depth + 1, self.cfg.start, "js"))

    # --------------------------------------------------------------- login ---
    def _login(self) -> bool:
        cfg = self.cfg
        url = self._normalise(cfg.start, cfg.auth_login)
        if not url or not self.in_scope(url):
            print(f"crawl: --auth-login {cfg.auth_login!r} is outside the crawl scope", file=sys.stderr)
            return False
        task = Task("POST", url, 0, cfg.start, "seed", (cfg.auth_body or "{}").encode(), "application/json")
        self.seen.add(("POST", urllib.parse.urlsplit(url).scheme, urllib.parse.urlsplit(url).netloc.lower(),
                       urllib.parse.urlsplit(url).path, urllib.parse.urlsplit(url).query))
        got = self.fetch(task)
        if got is None:
            print("crawl: login request failed", file=sys.stderr)
            return False
        item, status, low, body = got
        self.items.append(item)
        self.stats["requests"] += 1
        if cfg.auth_token:
            try:
                node = json.loads(body.decode("utf-8", "replace"))
                for part in cfg.auth_token.split("."):
                    node = node[int(part)] if isinstance(node, list) else node[part]
                self.headers[cfg.auth_header] = (f"{cfg.auth_scheme} {node}" if cfg.auth_scheme else str(node))
            except (ValueError, KeyError, IndexError, TypeError):
                print(f"crawl: login answered {status} but no token at {cfg.auth_token!r}; "
                      "crawling without it", file=sys.stderr)
                return False
        elif not (200 <= status < 300):
            print(f"crawl: login answered {status}; crawling without it", file=sys.stderr)
            return False
        return True

    # ----------------------------------------------------------------- run ---
    # ----------------------------------------------------------- journeys ---
    def _journey_note(self, j, n: int, kind: str, msg: str) -> None:
        line = f"journey {j.name!r} step {n} ({kind}): {msg}"
        self.journey_log.append(line)
        self.stats["journey_failed"] += 1
        print(f"crawl: {line}", file=sys.stderr)

    def _run_journeys_static(self) -> None:
        """goto / request / set_header / set_cookie over plain HTTP; the rest need a browser."""
        from . import journey as jy
        origin = f"{self.start.scheme}://{self.start.netloc}"
        for j in self.cfg.journeys:
            variables = {}
            try:
                for k, v in j.vars.items():
                    variables[k] = jy.substitute(v, {**variables, **self.cfg.journey_vars})
                variables.update(self.cfg.journey_vars)
            except jy.JourneyError as e:
                self._journey_note(j, 0, "vars", str(e))
                continue
            for n, step in enumerate(j.steps, 1):
                kind = next(k for k in step if k in jy.STEPS)
                self.stats["journey_steps"] += 1
                try:
                    if kind in jy.BROWSER_ONLY:
                        raise jy.JourneyError("needs a browser (--browser on); the static crawler cannot click or fill")
                    arg = jy.substitute(step[kind], variables)
                    if kind == "goto":
                        url = urllib.parse.urljoin(origin + "/", arg)
                        self._journey_fetch("GET", url, None, None, variables, {})
                    elif kind == "request":
                        self._journey_request(arg, origin, variables)
                    elif kind == "set_header":
                        self.headers.update({k: str(v) for k, v in arg.items()})
                    elif kind == "set_cookie":
                        self.jar.setdefault(self.start.hostname.lower(), {}).update(
                            {k: str(v) for k, v in arg.items()})
                    elif kind in ("wait",):
                        time.sleep(float(arg))
                except jy.JourneyError as e:
                    self._journey_note(j, n, kind, str(e))
                    if step.get("required"):
                        break

    def _journey_fetch(self, method, url, body, ctype, variables, extract, expect=None, headers=None):
        from . import journey as jy
        if not self.in_scope(url):
            raise jy.JourneyError(f"{url} is outside the crawl scope")
        if self.cfg.read_only and method.upper() not in ("GET", "HEAD", "OPTIONS"):
            raise jy.JourneyError(f"{method} blocked by --read-only")
        saved = dict(self.headers)
        self.headers.update(headers or {})
        try:
            got = self.fetch(Task(method.upper(), url, 0, self.cfg.start, "journey", body, ctype))
        finally:
            self.headers.clear()
            self.headers.update(saved)
        if got is None:
            raise jy.JourneyError(f"{method} {url} failed (no response)")
        item, status, low, text = got
        self.items.append(item)
        self.stats["requests"] += 1
        if expect is not None and status not in ([expect] if isinstance(expect, int) else expect):
            raise jy.JourneyError(f"{method} {url} answered {status}, expected {expect}")
        if extract:
            try:
                data = json.loads(text.decode("utf-8", "replace"))
            except ValueError:
                data = None
            for name, path in extract.items():
                val = jy.dig(data, path) if isinstance(path, str) else None
                if val is None:
                    raise jy.JourneyError(f"could not extract {name!r} from {path!r} in the response")
                variables[name] = val

    def _journey_request(self, spec: dict, origin: str, variables: dict) -> None:
        from . import journey as jy
        url = spec.get("url") or urllib.parse.urljoin(origin + "/", spec["path"])
        body, ctype = None, None
        if "json" in spec:
            body, ctype = json.dumps(spec["json"]).encode(), "application/json"
        elif "form" in spec:
            body, ctype = urllib.parse.urlencode(spec["form"]).encode(), "application/x-www-form-urlencoded"
        elif "body" in spec:
            body, ctype = str(spec["body"]).encode(), spec.get("content_type")
        self._journey_fetch(spec.get("method", "GET"), url, body, ctype, variables,
                            spec.get("extract") or {}, spec.get("expect"), spec.get("headers"))

    def run(self) -> CrawlResult:
        cfg = self.cfg
        if cfg.auth_login:
            self._login()
        if cfg.journeys:
            self._run_journeys_static()
            if cfg.journey_only:
                return CrawlResult(self.items, self.stats, self.forms, self.scope)
        start_url = urllib.parse.urldefrag(cfg.start)[0]
        origin = f"{self.start.scheme}://{self.start.netloc}"
        frontier = [Task("GET", start_url, 0, None, "seed")]
        self._admit("GET", start_url, "seed")
        for extra, kind in (("/robots.txt", "seed"), ("/sitemap.xml", "sitemap")):
            if self._admit("GET", origin + extra, kind):
                frontier.append(Task("GET", origin + extra, 0, None, kind))

        with ThreadPoolExecutor(max_workers=max(1, min(cfg.threads, 8))) as pool:
            while frontier and (not cfg.max_requests or self.stats["requests"] < cfg.max_requests):
                room = (cfg.max_requests - self.stats["requests"]) if cfg.max_requests else len(frontier)
                batch, frontier = frontier[:room], frontier[room:]
                nxt: list[Task] = list(frontier)
                for task, got in zip(batch, pool.map(self.fetch, batch)):
                    if got is None:
                        continue
                    item, status, low, body = got
                    self.items.append(item)
                    self.stats["requests"] += 1
                    key = {"asset": "assets", "js": "js_probes"}.get(task.kind, "pages")
                    self.stats[key] += 1
                    if task.url.endswith("/robots.txt") and 200 <= status < 300:
                        self._disallow = [m.strip() for m in re.findall(
                            r"(?im)^disallow:\s*(\S*)", body.decode("utf-8", "replace"))]
                        for sm in re.findall(r"(?im)^sitemap:\s*(\S+)", body.decode("utf-8", "replace")):
                            if self._admit("GET", sm, "sitemap"):
                                nxt.append(Task("GET", sm, 0, task.url, "sitemap"))
                    nxt.extend(self._discover(task, status, low, body))
                    if cfg.progress and self.stats["requests"] % 25 == 0:
                        print(f"crawl: {self.stats['requests']} requests, {len(nxt)} queued",
                              file=sys.stderr)
                frontier = nxt
        if frontier:
            self.stats["skipped_cap"] += len(frontier)
        return CrawlResult(self.items, self.stats, self.forms, self.scope)


def to_burp_xml(items: list) -> str:
    """Burp 'Save items' XML for the crawl, so it can be opened in Burp too.

    This holds the raw requests and responses, secrets included, exactly like a
    real Burp export. burp2model's own outputs never do.
    """
    from xml.etree.ElementTree import tostring
    out = ['<?xml version="1.0"?>', f'<items burpVersion="burp2model-crawler-{__version__}">']
    for it in items:
        out.append(tostring(it, encoding="unicode"))
    out.append("</items>")
    return "\n".join(out) + "\n"


def make_crawler(cfg: CrawlConfig):
    """The browser crawler when a Chrome is available (and not turned off), else the static one."""
    if cfg.browser != "off":
        from .browser import BrowserCrawler, find_chrome
        chrome = find_chrome(cfg.chrome)
        if chrome:
            return BrowserCrawler(cfg, chrome)
        if cfg.browser == "on":
            raise ValueError("no Chrome/Chromium found for --browser on (install one, or pass --chrome PATH)")
        print("crawl: no Chrome/Chromium found; using the static crawler (no JavaScript). "
              "Install one, or pass --chrome PATH, for a JavaScript-enabled crawl.", file=sys.stderr)
    return Crawler(cfg)
