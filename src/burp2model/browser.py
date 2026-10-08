"""
A JavaScript-enabled crawl: drive a real Chrome/Chromium over the DevTools
Protocol and record what it does, the way Burp's browser-powered crawler does.

There is no dependency to install. The WebSocket client and the DevTools client
below are a few hundred lines of standard library; the only requirement is a
Chrome or Chromium on the machine (found automatically, or `--chrome PATH`).

Why a browser: a single-page app builds its links and calls its API in
JavaScript, so a fetch-and-parse crawler sees an empty shell. A browser runs the
app, so the crawl records the real XHR/fetch traffic, with real bodies, headers
and cookies, and can click through routes, menus, tabs and forms to reach more.

What is recorded: every in-scope request the page makes, with its response, as
a Burp-style item. It goes through the same parser and redaction as a Burp
export, in memory; nothing raw is written by the crawl.

Guard rails (the browser is told, not trusted):
  * Fetch interception blocks every request outside the scope before it is sent,
    and every URL that looks destructive (logout, delete, ...); with --read-only
    it blocks every non-GET as well;
  * dialogs are dismissed (a confirm() is answered "cancel"), downloads are denied;
  * elements whose label looks destructive are never clicked, and a form with a
    password field is never submitted;
  * a request budget, a click budget per page, and an overall time limit.
"""

from __future__ import annotations

import base64
import json
import os
import re
import select
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import time
import urllib.parse
from collections import deque
from xml.etree.ElementTree import Element, SubElement

from .crawl import _UNSAFE, CrawlConfig, CrawlResult, Crawler, Task, _burp_mime, _decode
from .redact import route_template, template_path

_CANDIDATES = [
    "google-chrome", "google-chrome-stable", "chromium", "chromium-browser", "chrome",
    "microsoft-edge", "microsoft-edge-stable", "brave-browser",
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
    "/Applications/Chromium.app/Contents/MacOS/Chromium",
    "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
    "/Applications/Brave Browser.app/Contents/MacOS/Brave Browser",
    r"C:\Program Files\Google\Chrome\Application\chrome.exe",
    r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
]


def find_chrome(explicit: str | None = None) -> str | None:
    for c in ([explicit] if explicit else []) + [os.environ.get("BURP2MODEL_CHROME")] + _CANDIDATES:
        if not c:
            continue
        found = shutil.which(c) or (c if os.path.isfile(c) and os.access(c, os.X_OK) else None)
        if found:
            return found
    return None


# ------------------------------------------------------------- WebSocket -----

def launch_chrome(chrome: str, tmp: str, extra: list[str] | None = None, headless: bool = True,
                  attempts: int = 3):
    """Start Chrome with DevTools on a free port; return (process, websocket url).

    A cold Chrome on a busy CI runner sometimes exits or never opens its port, so a failed start is
    retried before giving up."""
    args = [chrome, "--no-first-run", "--no-default-browser-check", "--disable-gpu",
            "--disable-extensions", "--disable-background-networking", "--disable-sync", "--mute-audio",
            "--disable-dev-shm-usage", "--hide-scrollbars", "--remote-debugging-port=0",
            f"--user-data-dir={tmp}", "--disable-features=Translate,MediaRouter", "--disable-component-update"]
    if headless:
        args.insert(1, "--headless=new")
    if (hasattr(os, "geteuid") and os.geteuid() == 0) or os.environ.get("BURP2MODEL_CHROME_NO_SANDBOX") == "1":
        args.append("--no-sandbox")        # containers and CI runners that cannot create a sandbox
    args += extra or []
    args.append("about:blank")
    port_file = os.path.join(tmp, "DevToolsActivePort")
    last = "the browser did not open its DevTools port"
    for _ in range(attempts):
        if os.path.exists(port_file):
            os.remove(port_file)
        proc = subprocess.Popen(args, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        for _ in range(200):
            if os.path.exists(port_file):
                lines = open(port_file).read().split("\n")
                if len(lines) >= 2 and lines[1]:
                    return proc, f"ws://127.0.0.1:{lines[0].strip()}{lines[1].strip()}"
            if proc.poll() is not None:
                last = "the browser exited during start-up"
                break
            time.sleep(0.1)
        if proc.poll() is None:
            proc.kill()
        try:
            proc.wait(5)
        except subprocess.TimeoutExpired:
            pass
    raise RuntimeError(last)


class WebSocket:
    """A minimal RFC 6455 client: text frames, fragments, ping/pong, close."""

    def __init__(self, url: str, timeout: float = 15.0):
        u = urllib.parse.urlsplit(url)
        self.sock = socket.create_connection((u.hostname, u.port), timeout=timeout)
        key = base64.b64encode(os.urandom(16)).decode()
        path = (u.path or "/") + ("?" + u.query if u.query else "")
        self.sock.sendall((f"GET {path} HTTP/1.1\r\nHost: {u.hostname}:{u.port}\r\n"
                           f"Upgrade: websocket\r\nConnection: Upgrade\r\n"
                           f"Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n").encode())
        head = b""
        while b"\r\n\r\n" not in head:
            chunk = self.sock.recv(4096)
            if not chunk:
                raise ConnectionError("DevTools closed the connection during the handshake")
            head += chunk
        head, _, rest = head.partition(b"\r\n\r\n")
        if b" 101 " not in head.split(b"\r\n", 1)[0]:
            raise ConnectionError("DevTools refused the WebSocket upgrade: " + head[:80].decode("latin-1"))
        self.buf = rest
        self.closed = False

    def send(self, text: str) -> None:
        data = text.encode()
        n = len(data)
        head = bytes([0x81])
        if n < 126:
            head += bytes([0x80 | n])
        elif n < 65536:
            head += bytes([0x80 | 126]) + struct.pack(">H", n)
        else:
            head += bytes([0x80 | 127]) + struct.pack(">Q", n)
        mask = os.urandom(4)
        self.sock.sendall(head + mask + bytes(b ^ mask[i % 4] for i, b in enumerate(data)))

    def _need(self, n: int, deadline: float | None) -> bytes | None:
        while len(self.buf) < n:
            if deadline is not None:
                left = deadline - time.monotonic()
                if left <= 0 or not select.select([self.sock], [], [], left)[0]:
                    return None
            chunk = self.sock.recv(1 << 20)
            if not chunk:
                self.closed = True
                raise ConnectionError("DevTools connection closed")
            self.buf += chunk
        out, self.buf = self.buf[:n], self.buf[n:]
        return out

    def recv(self, timeout: float | None) -> str | None:
        """The next text message, or None if none arrives within `timeout`."""
        deadline = None if timeout is None else time.monotonic() + timeout
        parts: list[bytes] = []
        while True:
            h = self._need(2, deadline)
            if h is None:
                return None
            fin, op, n = h[0] & 0x80, h[0] & 0x0F, h[1] & 0x7F
            if n == 126:
                n = struct.unpack(">H", self._need(2, None))[0]
            elif n == 127:
                n = struct.unpack(">Q", self._need(8, None))[0]
            payload = self._need(n, None) if n else b""
            if op == 8:
                self.closed = True
                raise ConnectionError("DevTools closed the WebSocket")
            if op == 9:
                self.sock.sendall(bytes([0x8A, 0x80]) + os.urandom(4))   # empty masked pong
                continue
            if op == 10:
                continue
            parts.append(payload)
            if fin:
                return b"".join(parts).decode("utf-8", "replace")

    def close(self) -> None:
        try:
            self.sock.close()
        except OSError:
            pass


class CDP:
    """Commands and events over one DevTools WebSocket."""

    def __init__(self, ws: WebSocket):
        self.ws = ws
        self.n = 0
        self.events: deque = deque()
        # events that must be answered at once, even while another command is waiting
        # (a paused request blocks the navigation that is waiting for it)
        self.urgent = None
        self.answers: dict = {}

    def call(self, method: str, params: dict | None = None, session: str | None = None,
             timeout: float = 20.0):
        self.n += 1
        my_id = self.n          # urgent events answered while waiting issue commands of their own
        msg = {"id": my_id, "method": method, "params": params or {}}
        if session:
            msg["sessionId"] = session
        self.ws.send(json.dumps(msg))
        end = time.monotonic() + timeout
        while True:
            m = self.answers.pop(my_id, None)
            if m is None:
                raw = self.ws.recv(max(0.05, end - time.monotonic()))
                if raw is None:
                    raise TimeoutError(f"DevTools did not answer {method}")
                m = json.loads(raw)
                if "id" in m and m["id"] != my_id:
                    # the answer to a command waiting further up the stack (an urgent event
                    # handler issued its own command meanwhile): keep it for its owner
                    self.answers[m["id"]] = m
                    continue
            if m.get("id") == my_id:
                if "error" in m:
                    raise RuntimeError(f"{method}: {m['error'].get('message')}")
                return m.get("result", {})
            if "method" in m:
                if self.urgent and m["method"] in ("Fetch.requestPaused", "Page.javascriptDialogOpening"):
                    self.urgent(m)
                else:
                    self.events.append(m)

    def next_event(self, timeout: float):
        if self.events:
            return self.events.popleft()
        raw = self.ws.recv(timeout)
        if raw is None:
            return None
        m = json.loads(raw)
        return m if "method" in m else self.next_event(0)


# ---------------------------------------------------- in-page helper scripts --

_SAFE_JS = r"""
(() => {
  const bad = /(log-?\s?out|sign-?\s?out|log-?\s?off|delete|remove|destroy|unsubscribe|deactivate|erase|erasure|reset[ /-]*(database|db)|create[ /]+reset|shutdown|purge|wipe|truncate|factory reset|set-?up|install|clear (all|cart|history))/i;
  const vis = e => { const r = e.getBoundingClientRect(); const s = getComputedStyle(e);
    return r.width > 1 && r.height > 1 && s.visibility !== 'hidden' && s.display !== 'none'; };
  const label = e => ((e.innerText || e.value || e.getAttribute('aria-label') || e.title || '') + '').trim().replace(/\s+/g,' ').slice(0, 60);
  window.__b2m = { bad, vis, label };
  return true;
})()
"""

_HARVEST_JS = r"""
(() => {
  const abs = x => { try { return new URL(x, document.baseURI).href; } catch (e) { return null; } };
  const links = [];
  document.querySelectorAll('a[href],area[href],iframe[src],frame[src]').forEach(e => {
    const v = abs(e.getAttribute('href') || e.getAttribute('src')); if (v) links.push(v); });
  document.querySelectorAll('[routerlink],[ng-reflect-router-link],[data-href],[to]').forEach(e => {
    const v = e.getAttribute('routerlink') || e.getAttribute('ng-reflect-router-link') || e.getAttribute('data-href');
    if (v && v.startsWith('/')) links.push({route: v}); });
  const forms = Array.from(document.forms).map((f, i) => ({
    index: i, action: abs(f.getAttribute('action') || '') || location.href, method: (f.method || 'get').toUpperCase(),
    password: !!f.querySelector('input[type=password]'),
    fields: Array.from(f.elements).filter(x => x.name).map(x => x.name) }));
  return { href: location.href, title: document.title, links, forms,
           hashRouting: location.hash.startsWith('#/') || links.some(l => typeof l === 'string' && l.includes('#/')) };
})()
"""

_CLICKABLES_JS = r"""
(() => {
  if (!window.__b2m) return [];
  const { bad, vis, label } = window.__b2m;
  const sel = 'button,[role=button],[role=menuitem],[role=tab],[role=link],[role=option],[routerlink],[onclick],summary,' +
              'a:not([href]),a[href="#"],a[href^="javascript:"],[class*=menu-item],[class*=nav-item],[class*=tab],mat-select,[aria-haspopup],[data-toggle],[data-bs-toggle]';
  const out = [];
  window.__b2m_c = Array.from(document.querySelectorAll(sel)).filter(vis);
  window.__b2m_c.forEach((e, i) => {
    const t = label(e);
    if (bad.test(t) || bad.test(e.className || '') || bad.test(e.id || '')) return;
    if (e.closest('form') && e.closest('form').querySelector('input[type=password]')) return;
    if (e.disabled || e.getAttribute('aria-disabled') === 'true') return;
    const r = e.getBoundingClientRect();
    out.push({ i, sig: e.tagName + '|' + t + '|' + (e.getAttribute('routerlink') || e.getAttribute('href') || '') +
                         '|' + Math.round(r.x / 40) + ',' + Math.round(r.y / 40) });
  });
  return out;
})()
"""


def _click_js(i: int) -> str:
    return ("(() => { const e = (window.__b2m_c || [])[%d]; if (!e) return false; "
            "try { e.scrollIntoView({block:'center'}); e.click(); return true; } catch (x) { return false; } })()" % i)


_FILL_JS = r"""
(() => {
  const filled = [];
  const val = t => ({email:'test@example.invalid', number:'1', tel:'5550100', url:'https://example.invalid/',
                     date:'2030-01-01', search:'a', text:'test'})[t] || 'test';
  const set = (e, v) => { const d = Object.getOwnPropertyDescriptor(Object.getPrototypeOf(e), 'value');
    d && d.set ? d.set.call(e, v) : (e.value = v);
    e.dispatchEvent(new Event('input', {bubbles:true})); e.dispatchEvent(new Event('change', {bubbles:true})); };
  document.querySelectorAll('input:not([type=hidden]):not([type=password]):not([type=file]):not([type=checkbox]):not([type=radio]):not([type=submit]):not([type=button]),textarea').forEach(e => {
    if (e.value || e.disabled || e.readOnly) return;
    const r = e.getBoundingClientRect(); if (r.width < 2 || r.height < 2) return;
    if (e.closest('form') && e.closest('form').querySelector('input[type=password]')) return;
    set(e, val((e.type || 'text').toLowerCase())); filled.push(e.name || e.id || e.type); });
  return filled;
})()
"""

_SUBMIT_JS = r"""
(() => {
  const forms = Array.from(document.forms).filter(f => !f.querySelector('input[type=password]'));
  const bad = window.__b2m ? window.__b2m.bad : /$^/;
  let n = 0;
  forms.forEach(f => {
    const txt = (f.innerText || '') + ' ' + (f.action || '');
    if (bad.test(txt)) return;
    try { f.requestSubmit ? f.requestSubmit() : f.submit(); n++; } catch (e) {}
  });
  return n;
})()
"""

_ENTER_JS = r"""
(() => { const e = document.querySelector('input[type=search],input[type=text]:not([form])');
  if (!e || !e.value) return false;
  ['keydown','keypress','keyup'].forEach(t => e.dispatchEvent(new KeyboardEvent(t, {key:'Enter', code:'Enter', keyCode:13, which:13, bubbles:true})));
  return true; })()
"""

_SCROLL_JS = "(() => { window.scrollTo(0, document.body.scrollHeight); return document.body.scrollHeight; })()"


# chatty background channels (long-polling, event streams, dev servers) that never "finish"
_BACKGROUND = re.compile(r"socket\.io|sockjs|transport=(?:polling|websocket)|/signalr|/hub(?:/|\?|$)|"
                         r"__webpack_hmr|livereload|/sse\b|/events?(?:\?|$)", re.I)


class _Rec:
    """One request as the browser made it, assembled from several DevTools events."""
    __slots__ = ("id", "req", "extra_req", "resp", "extra_resp", "body", "b64", "rtype", "done", "failed",
                 "post", "redirect")

    def __init__(self, rid):
        self.id, self.req, self.extra_req, self.resp, self.extra_resp = rid, None, None, None, None
        self.body, self.b64, self.rtype, self.done, self.failed, self.post, self.redirect = b"", False, "", False, False, None, False


class BrowserCrawler(Crawler):
    """Crawl with a real browser; fall back to nothing silently (see make_crawler)."""

    def __init__(self, cfg: CrawlConfig, chrome: str):
        super().__init__(cfg)
        self.chrome = chrome
        self.proc = None
        self.tmp = None
        self.cdp: CDP | None = None
        self.session: str | None = None
        self.recs: dict[str, _Rec] = {}
        self.inflight: set[str] = set()
        self.started: dict[str, float] = {}
        self.last_net = time.monotonic()
        self.finalised: list[_Rec] = []
        self._heavy_assets = 0
        self.stats.update({"browser": True, "clicks": 0, "forms_submitted": 0, "states": 0,
                           "blocked_scope": 0, "blocked_unsafe": 0, "blocked_method": 0, "dialogs_dismissed": 0,
                           "blocked_asset_cap": 0})
        self._deadline = time.monotonic() + (cfg.max_seconds if cfg.max_seconds else 10 ** 9)
        self._journey_active = False                     # a scripted step is deliberate: no "looks destructive" filter
        self._scripts: list[tuple[str, str]] = []        # (url, text) of JS/HTML bodies, for the static pass

    # ------------------------------------------------------------ lifecycle --
    def _launch(self) -> None:
        self.tmp = tempfile.mkdtemp(prefix="b2m-chrome-")
        extra = ["--window-size=1366,900", "--disable-popup-blocking"]
        if self.cfg.insecure:
            extra.append("--ignore-certificate-errors")
        self.proc, url = launch_chrome(self.chrome, self.tmp, extra, headless=not self.cfg.headful)
        self.cdp = CDP(WebSocket(url))
        self.cdp.urgent = self._handle

    def _close(self) -> None:
        try:
            if self.cdp:
                self.cdp.ws.close()
        except Exception:
            pass
        if self.proc and self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(5)
            except subprocess.TimeoutExpired:
                self.proc.kill()
        if self.tmp:
            shutil.rmtree(self.tmp, ignore_errors=True)

    def _page(self, method: str, params: dict | None = None, timeout: float = 20.0):
        return self.cdp.call(method, params, self.session, timeout)

    def _eval(self, expr: str, timeout: float = 15.0):
        try:
            r = self._page("Runtime.evaluate", {"expression": expr, "returnByValue": True,
                                                "awaitPromise": True}, timeout)
        except (RuntimeError, TimeoutError):
            return None
        return (r.get("result") or {}).get("value")

    def _setup(self) -> None:
        c = self.cdp
        try:
            c.call("Browser.setDownloadBehavior", {"behavior": "deny"})
        except RuntimeError:
            pass
        tid = c.call("Target.createTarget", {"url": "about:blank"})["targetId"]
        self.session = c.call("Target.attachToTarget", {"targetId": tid, "flatten": True})["sessionId"]
        for dom in ("Page", "Network", "Runtime"):
            self._page(f"{dom}.enable")
        self._page("Network.setCacheDisabled", {"cacheDisabled": True})
        self._page("Fetch.enable", {"patterns": [{"urlPattern": "*"}]})
        if self.headers:
            self._page("Network.setExtraHTTPHeaders", {"headers": self.headers})
        origin = f"{self.start.scheme}://{self.start.netloc}"
        for k, v in (self.cfg.cookies or {}).items():
            self._page("Network.setCookie", {"name": k, "value": v, "url": origin})
        inject = {}
        inject.update(self.cfg.local_storage or {})
        if self.cfg.auth_storage and self.headers.get(self.cfg.auth_header):
            tok = self.headers[self.cfg.auth_header].split(" ", 1)[-1]
            inject[self.cfg.auth_storage] = tok
            self._page("Network.setCookie", {"name": self.cfg.auth_storage, "value": tok, "url": origin})
        if inject:
            js = "try{" + ";".join(f"localStorage.setItem({json.dumps(k)},{json.dumps(v)})"
                                   for k, v in inject.items()) + "}catch(e){}"
            self._page("Page.addScriptToEvaluateOnNewDocument", {"source": js})

    # --------------------------------------------------------------- events --
    # Image/Media/Font never carry an endpoint or app logic, so once the budget for them
    # is spent the browser is left to render without them rather than starving the page
    # and API requests that the model is actually built from.
    _HEAVY_ASSET_TYPES = frozenset({"Image", "Media", "Font"})

    def _allow(self, url: str, method: str, resource_type: str = "") -> bool:
        if not self.in_scope(url):
            self.stats["blocked_scope"] += 1
            return False
        u = urllib.parse.urlsplit(url)
        if not self._journey_active and (_UNSAFE.search(u.path) or _UNSAFE.search(u.query)):
            self.stats["blocked_unsafe"] += 1
            return False
        if self.cfg.read_only and method.upper() not in ("GET", "HEAD", "OPTIONS"):
            self.stats["blocked_method"] += 1
            return False
        if resource_type in self._HEAVY_ASSET_TYPES and self.cfg.max_assets:
            if self._heavy_assets >= self.cfg.max_assets:
                self.stats["blocked_asset_cap"] += 1
                return False
            self._heavy_assets += 1
        return True

    def _handle(self, ev: dict) -> None:
        m, p = ev["method"], ev.get("params", {})
        sid = ev.get("sessionId")
        if sid and sid != self.session:
            return
        if m == "Fetch.requestPaused":
            req = p["request"]
            try:
                if self._allow(req["url"], req["method"], p.get("resourceType", "")):
                    self._page("Fetch.continueRequest", {"requestId": p["requestId"]}, 5)
                else:
                    self._page("Fetch.failRequest", {"requestId": p["requestId"],
                                                     "errorReason": "BlockedByClient"}, 5)
            except (RuntimeError, TimeoutError):
                pass
        elif m == "Page.javascriptDialogOpening":
            self.stats["dialogs_dismissed"] += 1
            try:
                self._page("Page.handleJavaScriptDialog",
                           {"accept": p.get("type") == "alert"}, 5)
            except (RuntimeError, TimeoutError):
                pass
        elif m == "Network.requestWillBeSent":
            rid = p["requestId"]
            if p.get("redirectResponse") and rid in self.recs:
                old = self.recs[rid]
                old.resp, old.done, old.redirect = p["redirectResponse"], True, True
                self.finalised.append(old)
                self.inflight.discard(rid)
            rec = _Rec(rid)
            rec.req, rec.rtype = p["request"], p.get("type", "")
            rec.post = rec.req.get("postData")
            self.recs[rid] = rec
            if not _BACKGROUND.search(rec.req.get("url", "")):
                self.inflight.add(rid)
                self.started[rid] = time.monotonic()
                self.last_net = time.monotonic()
        elif m == "Network.requestWillBeSentExtraInfo":
            if p["requestId"] in self.recs:
                self.recs[p["requestId"]].extra_req = p.get("headers")
        elif m == "Network.responseReceived":
            if p["requestId"] in self.recs:
                self.recs[p["requestId"]].resp = p["response"]
        elif m == "Network.responseReceivedExtraInfo":
            if p["requestId"] in self.recs:
                self.recs[p["requestId"]].extra_resp = p.get("headers")
        elif m == "Network.loadingFinished":
            rid = p["requestId"]
            rec = self.recs.get(rid)
            self.inflight.discard(rid)
            if rec and not _BACKGROUND.search((rec.req or {}).get("url", "")):
                self.last_net = time.monotonic()
            if rec and rec.resp:
                self._fetch_body(rec)
                rec.done = True
                self.finalised.append(rec)
        elif m == "Network.loadingFailed":
            self.inflight.discard(p["requestId"])
            self.last_net = time.monotonic()
            rec = self.recs.get(p["requestId"])
            if rec:
                rec.failed = True

    def _fetch_body(self, rec: _Rec) -> None:
        if rec.rtype in ("Image", "Font", "Media") or not rec.resp:
            return
        try:
            r = self._page("Network.getResponseBody", {"requestId": rec.id}, 15)
            body = r.get("body", "")
            rec.body = base64.b64decode(body) if r.get("base64Encoded") else body.encode("utf-8", "replace")
            rec.body = rec.body[: self.cfg.max_body]
        except (RuntimeError, TimeoutError, ValueError):
            pass
        if rec.req and rec.req.get("hasPostData") and rec.post is None:
            try:
                rec.post = self._page("Network.getRequestPostData", {"requestId": rec.id}, 5).get("postData")
            except (RuntimeError, TimeoutError):
                pass

    def _pump(self, seconds: float) -> None:
        end = time.monotonic() + seconds
        while time.monotonic() < end:
            ev = self.cdp.next_event(max(0.01, end - time.monotonic()))
            if ev is None:
                return
            self._handle(ev)

    def _settle(self, quiet: float = 0.6, limit: float = 12.0) -> None:
        """Wait for the network to go quiet (nothing in flight for `quiet` seconds)."""
        end = time.monotonic() + limit
        self.last_net = time.monotonic()
        while time.monotonic() < min(end, self._deadline):
            self._pump(0.1)
            now = time.monotonic()
            # a request still open after 2.5 s is a long-poll or an event stream
            # (socket.io, SSE); it must not keep the page "busy" forever
            young = [r for r in self.inflight if now - self.started.get(r, now) < 2.5]
            if not young and now - self.last_net >= quiet:
                return

    # ------------------------------------------------------------- recording --
    def _to_item(self, rec: _Rec) -> Element | None:
        req, resp = rec.req, rec.resp
        if not req or not resp:
            return None
        u = urllib.parse.urlsplit(req["url"])
        if u.scheme not in ("http", "https") or not self.in_scope(req["url"]):
            return None
        port = u.port or (443 if u.scheme == "https" else 80)
        path = (u.path or "/") + ("?" + u.query if u.query else "")
        rq = dict(req.get("headers") or {})
        rq.update(rec.extra_req or {})
        rq = {k: v for k, v in rq.items() if not k.startswith(":")}
        if not any(k.lower() == "host" for k in rq):
            rq = {"Host": u.netloc, **rq}
        post = (rec.post or "").encode("utf-8", "replace") if rec.post else b""
        if post and not any(k.lower() == "content-length" for k in rq):
            rq["Content-Length"] = str(len(post))
        raw_req = (f"{req['method']} {path} HTTP/1.1\r\n" + "".join(f"{k}: {v}\r\n" for k, v in rq.items())
                   + "\r\n").encode("latin-1", "replace") + post
        status = int(resp.get("status") or 0)
        rh: list[tuple[str, str]] = []
        for k, v in {**(resp.get("headers") or {}), **(rec.extra_resp or {})}.items():
            if k.startswith(":") or k.lower() in ("content-encoding", "transfer-encoding", "content-length"):
                continue
            for line in str(v).split("\n"):
                rh.append((k, line))
        # DevTools hands back the body already decoded, so the encoding header is dropped
        rh.append(("Content-Length", str(len(rec.body))))
        head = f"HTTP/1.1 {status} {resp.get('statusText') or ''}\r\n" + "".join(f"{k}: {v}\r\n" for k, v in rh) + "\r\n"
        raw_resp = head.encode("latin-1", "replace") + rec.body
        item = Element("item")
        low = {k.lower(): v for k, v in (resp.get("headers") or {}).items()}
        for tag, val in (("method", req["method"]), ("host", u.hostname.lower()), ("port", str(port)),
                         ("protocol", u.scheme), ("path", path), ("status", str(status)),
                         ("mimetype", _burp_mime(low.get("content-type", resp.get("mimeType", ""))))):
            SubElement(item, tag).text = val
        SubElement(item, "request", {"base64": "true"}).text = base64.b64encode(raw_req).decode()
        SubElement(item, "response", {"base64": "true"}).text = base64.b64encode(raw_resp).decode()
        ct = low.get("content-type", resp.get("mimeType", "")).lower()
        if rec.body and ("javascript" in ct or "html" in ct) and len(self._scripts) < 400:
            self._scripts.append((req["url"], rec.body.decode("utf-8", "replace")))
        return item

    def _drain(self) -> None:
        while self.finalised:
            rec = self.finalised.pop(0)
            item = self._to_item(rec)
            if item is None:
                continue
            self.items.append(item)
            self.stats["requests"] += 1
            if rec.rtype in ("Document",):
                self.stats["pages"] += 1
            elif rec.rtype in ("XHR", "Fetch"):
                self.stats["js_probes"] += 1
            else:
                self.stats["assets"] += 1

    def _budget_left(self) -> bool:
        if time.monotonic() > self._deadline:
            return False
        return not self.cfg.max_requests or self.stats["requests"] < self.cfg.max_requests

    # -------------------------------------------------------------- crawling --
    def _state_url(self) -> str:
        return self._eval("location.href") or ""

    def _navigate(self, url: str) -> bool:
        try:
            self._page("Page.navigate", {"url": url}, 25)
        except (RuntimeError, TimeoutError):
            return False
        self._pump(0.2)
        self._settle()
        self._drain()
        self._eval(_SAFE_JS)
        return True

    @staticmethod
    def _key(url: str) -> str:
        """Canonical state key: the fragment only counts for hash routes (#/ and #!)."""
        base, _, frag = url.partition("#")
        return base + ("#" + frag if frag.startswith(("/", "!")) else "")

    def _enqueue(self, url: str, depth: int, referer: str, queue: deque, kind="page") -> None:
        url = url.split("#")[0] + ("#" + url.partition("#")[2] if url.partition("#")[2].startswith(("/", "!")) else "")
        if not url.startswith(("http://", "https://")) or not self.in_scope(url):
            return
        if _UNSAFE.search(urllib.parse.urlsplit(url).path):
            return
        key = self._key(url)
        if ("GET", key) in self.seen:
            return
        self.seen.add(("GET", key))
        frag = url.partition("#")[2]
        us = urllib.parse.urlsplit(url)
        t = (us.netloc, route_template(us.path + ("?" + us.query if us.query else ""), template_path(us.path)),
             template_path("/" + frag.lstrip("/!")) if frag.startswith(("/", "!")) else "")
        if self.template_count.get(t, 0) >= self.cfg.per_template_cap:
            self.stats["skipped_cap"] += 1
            return
        self.template_count[t] = self.template_count.get(t, 0) + 1
        queue.append((url, depth))

    def _harvest(self, depth: int, queue: deque, page_url: str) -> dict:
        h = self._eval(_HARVEST_JS) or {}
        base = h.get("href", page_url)
        for link in h.get("links", []):
            if isinstance(link, dict):                       # [routerLink] -> a route on this app
                route = link["route"]
                origin = f"{self.start.scheme}://{self.start.netloc}"
                dest = f"{origin}/#{route}" if h.get("hashRouting") else origin + route
                self._enqueue(dest, depth + 1, base, queue)
            elif isinstance(link, str):
                self._enqueue(link, depth + 1, base, queue)
        for f in h.get("forms", []):
            self.stats["forms_found"] += 1
            self.forms.append({"page": base, "action": urllib.parse.urlsplit(f["action"]).path or "/",
                               "method": f["method"], "fields": f["fields"],
                               **({"note": "password field — never submitted"} if f["password"] else {})})
        return h

    def _interact(self, url: str, depth: int, queue: deque) -> None:
        """Click what a user would, fill and submit forms, scroll; follow what changes."""
        cfg = self.cfg
        if cfg.no_interact:
            return
        clicked: set = set()
        clicks = 0
        # fill empty fields first, so a click on a form's own submit button sends real values
        filled = self._eval(_FILL_JS) or []
        self._eval(_SCROLL_JS)
        self._settle(0.4, 5)
        while clicks < cfg.max_clicks and self._budget_left():
            cands = self._eval(_CLICKABLES_JS) or []
            nxt = next((c for c in cands if c["sig"] not in clicked), None)
            if nxt is None:
                break
            clicked.add(nxt["sig"])
            clicks += 1
            self.stats["clicks"] += 1
            self._eval(_click_js(nxt["i"]))
            self._pump(0.15)
            self._settle(0.5, 8)
            self._drain()
            now = self._state_url()
            if now and self._key(now) != self._key(url):
                self._enqueue(now, depth + 1, url, queue)
                if not self._navigate(url):
                    return
                if self._key(self._state_url()) != self._key(url):
                    return
            else:
                self._harvest(depth, queue, url)          # a menu may have revealed new links
                try:                                         # close a menu or dialog it opened
                    self._page("Input.dispatchKeyEvent", {"type": "keyDown", "key": "Escape", "code": "Escape",
                                                          "windowsVirtualKeyCode": 27}, 3)
                    self._page("Input.dispatchKeyEvent", {"type": "keyUp", "key": "Escape", "code": "Escape",
                                                          "windowsVirtualKeyCode": 27}, 3)
                except (RuntimeError, TimeoutError):
                    pass
        # press Enter in a search box, submit the forms that are safe to submit
        filled = (self._eval(_FILL_JS) or []) or filled
        if filled:
            self._settle(0.3, 4)
            if self._eval(_ENTER_JS):
                self._settle(0.5, 6)
                self._drain()
            if not cfg.no_forms:
                submitted = self._eval(_SUBMIT_JS) or 0
                self.stats["forms_submitted"] += int(submitted)
                if submitted:
                    self._settle(0.6, 8)
                    self._drain()
                    now = self._state_url()
                    if now and self._key(now) != self._key(url):
                        self._enqueue(now, depth + 1, url, queue)
                        self._navigate(url)

    def _route_seeds(self, queue: deque, depth: int) -> None:
        """Router paths written into a bundle (`path:"basket"`), for hash- and history-routed SPAs."""
        origin = f"{self.start.scheme}://{self.start.netloc}"
        hash_mode = "#/" in (self._state_url() or "") or self.cfg.start.find("#/") != -1
        paths: set[str] = set()
        for _, text in self._scripts:
            if len(text) < 2000:
                continue
            Q = """["'`]"""
            for m in re.finditer(r"path\s*:\s*" + Q + r"([A-Za-z0-9_\-/]{1,40})" + Q, text):
                p = m.group(1).strip("/")
                if p and not _UNSAFE.search(p):
                    paths.add(p)
            # one level of nesting: {path:`account`, ..., children:[{path:`orders`}, ...]}
            for m in re.finditer(r"path\s*:\s*" + Q + r"([A-Za-z0-9_\-/]{1,40})" + Q
                                 + r"[^\[\]{}]{0,80}children\s*:\s*\[", text):
                for c in re.finditer(r"path\s*:\s*" + Q + r"([A-Za-z0-9_\-/]{1,40})" + Q,
                                     text[m.end(): m.end() + 900].split("]}")[0]):
                    child = c.group(1).strip("/")
                    if child and not _UNSAFE.search(child):
                        paths.add(f"{m.group(1).strip('/')}/{child}")
        for p in sorted(paths)[:200]:
            self._enqueue(f"{origin}/#/{p}" if hash_mode else f"{origin}/{p}", depth, origin + "/", queue, "route")

    def run(self) -> CrawlResult:
        cfg = self.cfg
        try:
            if cfg.auth_login:
                self._login()                  # plain HTTP, once; the token is then given to the browser
            self._launch()
            self._setup()
            if cfg.journeys:
                self._run_journeys()
                if cfg.journey_only:
                    self._settle(0.3, 3)
                    self._drain()
                    self._sync_cookies()
                    return CrawlResult(self.items, self.stats, self.forms, self.scope)
            queue: deque = deque()
            start = cfg.start
            self.seen.add(("GET", self._key(start)))
            queue.append((start, 0))
            routes_done = False
            todo: deque = deque()                # states visited, not yet clicked through
            # Breadth first: reach every page state before spending clicks inside any of them,
            # so a time or request budget runs out on depth, not on breadth.
            while self._budget_left() and (queue or todo):
                if queue:
                    url, depth = queue.popleft()
                    if depth > cfg.max_depth:
                        self.stats["skipped_cap"] += 1
                        continue
                    if not self._navigate(url):
                        self.stats["errors"] += 1
                        continue
                    self.stats["states"] += 1
                    if cfg.progress:
                        print(f"crawl: [{self.stats['requests']} req] {url}", file=sys.stderr)
                    self._harvest(depth, queue, url)
                    todo.append((url, depth))
                    if not routes_done:
                        self._route_seeds(queue, depth + 1)
                        routes_done = True
                else:
                    url, depth = todo.popleft()
                    if self._key(self._state_url()) != self._key(url) and not self._navigate(url):
                        continue
                    self._interact(url, depth, queue)
            self._settle(0.3, 3)
            self._drain()
            self._sync_cookies()
        finally:
            self._close()
        self._static_pass()
        return CrawlResult(self.items, self.stats, self.forms, self.scope)

    # ------------------------------------------------------------ journeys ---
    _KEYS = {"Enter": (13, "\r"), "Tab": (9, ""), "Escape": (27, ""), "ArrowDown": (40, ""),
             "ArrowUp": (38, ""), "Space": (32, " "), "Backspace": (8, "")}

    def _run_journeys(self) -> None:
        from . import journey as jy
        self._journey_active = True
        try:
            for j in self.cfg.journeys:
                variables: dict = {}
                try:
                    for k, v in j.vars.items():
                        variables[k] = jy.substitute(v, {**variables, **self.cfg.journey_vars})
                    variables.update(self.cfg.journey_vars)
                except jy.JourneyError as e:
                    self._journey_note(j, 0, "vars", str(e))
                    continue
                if self.cfg.progress:
                    print(f"crawl: journey {j.name!r} ({len(j.steps)} steps)", file=sys.stderr)
                for n, step in enumerate(j.steps, 1):
                    kind = next(k for k in step if k in jy.STEPS)
                    self.stats["journey_steps"] += 1
                    try:
                        self._step(kind, jy.substitute(step[kind], variables), variables)
                        self._pump(0.1)
                        self._drain()
                    except (jy.JourneyError, RuntimeError, TimeoutError) as e:
                        self._journey_note(j, n, kind, str(e))
                        if step.get("required"):
                            print(f"crawl: journey {j.name!r} aborted at step {n} (required)", file=sys.stderr)
                            break
        finally:
            self._journey_active = False

    def _ensure_origin(self) -> None:
        origin = f"{self.start.scheme}://{self.start.netloc}"
        if (self._eval("location.origin") or "") != origin:
            self._navigate(origin + "/")

    def _step(self, kind: str, arg, variables: dict) -> None:
        from . import journey as jy
        origin = f"{self.start.scheme}://{self.start.netloc}"
        if kind == "goto":
            url = urllib.parse.urljoin(origin + "/", arg)
            if not self.in_scope(url):
                raise jy.JourneyError(f"{url} is outside the crawl scope")
            if not self._navigate(url):
                raise jy.JourneyError(f"could not load {url}")
        elif kind == "click":
            sel, text = (arg, "") if isinstance(arg, str) else (arg.get("selector", ""), arg.get("text", ""))
            self._eval(_SAFE_JS)
            ok = self._eval(
                "((sel, text) => { const vis = window.__b2m ? window.__b2m.vis : () => true;"
                " const label = window.__b2m ? window.__b2m.label : e => (e.innerText || '');"
                " let els = Array.from(document.querySelectorAll(sel || 'button,a,[role=button],[role=tab],[role=menuitem],"
                "input[type=submit],summary,[routerlink],[onclick]')).filter(vis);"
                " if (text) els = els.filter(e => (label(e) || '').toLowerCase().includes(text.toLowerCase()));"
                " const e = els[0]; if (!e) return false; e.scrollIntoView({block:'center'}); e.click(); return true; })(%s, %s)"
                % (json.dumps(sel), json.dumps(text)))
            if not ok:
                raise jy.JourneyError(f"nothing to click for {arg!r}")
            self._pump(0.15)
            self._settle(0.5, 8)
        elif kind == "fill":
            sel = arg.get("selector") or f"[name={json.dumps(arg['name'])}]"
            ok = self._eval(
                "((sel, v) => { const e = document.querySelector(sel); if (!e) return false; e.focus();"
                " const d = Object.getOwnPropertyDescriptor(Object.getPrototypeOf(e), 'value');"
                " d && d.set ? d.set.call(e, v) : (e.value = v);"
                " e.dispatchEvent(new Event('input', {bubbles:true})); e.dispatchEvent(new Event('change', {bubbles:true}));"
                " return true; })(%s, %s)" % (json.dumps(sel), json.dumps(str(arg["value"]))))
            if not ok:
                raise jy.JourneyError(f"no field matches {sel!r}")
        elif kind == "press":
            code, ch = self._KEYS.get(str(arg), (0, str(arg) if len(str(arg)) == 1 else ""))
            for t in ("keyDown", "keyUp"):
                self._page("Input.dispatchKeyEvent", {"type": t, "key": str(arg), "code": str(arg),
                                                      "windowsVirtualKeyCode": code,
                                                      **({"text": ch} if ch and t == "keyDown" else {})}, 5)
            self._pump(0.15)
            self._settle(0.5, 8)
        elif kind == "wait":
            self._pump(float(arg))
        elif kind == "wait_for":
            sel, text, timeout = (arg, "", 10.0) if isinstance(arg, str) else (
                arg.get("selector", ""), arg.get("text", ""), float(arg.get("timeout", 10)))
            end = time.monotonic() + timeout
            while time.monotonic() < end:
                if self._eval("((s, t) => { const q = s ? document.querySelector(s) : document.body;"
                              " return !!q && (!t || (q.innerText || '').includes(t)); })(%s, %s)"
                              % (json.dumps(sel), json.dumps(text))):
                    return
                self._pump(0.2)
            raise jy.JourneyError(f"timed out waiting for {arg!r}")
        elif kind == "wait_idle":
            self._settle(0.6, 12)
        elif kind == "assert":
            state = self._eval("({url: location.href, text: (document.body ? document.body.innerText : ''), "
                               "has: %s})" % (("!!document.querySelector(%s)" % json.dumps(arg["selector"]))
                                              if arg.get("selector") else "true")) or {}
            if arg.get("url_contains") and arg["url_contains"] not in state.get("url", ""):
                raise jy.JourneyError(f"expected the URL to contain {arg['url_contains']!r}, got {state.get('url')!r}")
            if arg.get("text") and arg["text"] not in state.get("text", ""):
                raise jy.JourneyError(f"expected the page to contain {arg['text']!r}")
            if arg.get("not_text") and arg["not_text"] in state.get("text", ""):
                raise jy.JourneyError(f"the page contains {arg['not_text']!r}")
            if not state.get("has", True):
                raise jy.JourneyError(f"no element matches {arg['selector']!r}")
        elif kind == "scroll":
            self._eval(_SCROLL_JS)
            self._settle(0.4, 5)
        elif kind == "set_header":
            self.headers.update({k: str(v) for k, v in arg.items()})
            self._page("Network.setExtraHTTPHeaders", {"headers": self.headers})
        elif kind == "set_cookie":
            for k, v in arg.items():
                self._page("Network.setCookie", {"name": k, "value": str(v), "url": origin})
        elif kind == "set_storage":
            self._ensure_origin()
            js = ";".join(f"localStorage.setItem({json.dumps(k)},{json.dumps(str(v))})" for k, v in arg.items())
            self._eval(js)
            self._page("Page.addScriptToEvaluateOnNewDocument", {"source": "try{" + js + "}catch(e){}"})
        elif kind == "request":
            self._request_step(arg, origin, variables)

    def _request_step(self, spec: dict, origin: str, variables: dict) -> None:
        """An HTTP request made from inside the page, so it carries the session and is recorded."""
        from . import journey as jy
        url = spec.get("url") or urllib.parse.urljoin(origin + "/", spec["path"])
        if not self.in_scope(url):
            raise jy.JourneyError(f"{url} is outside the crawl scope")
        method = spec.get("method", "GET").upper()
        headers = dict(spec.get("headers") or {})
        body = None
        if "json" in spec:
            body = json.dumps(spec["json"])
            headers.setdefault("Content-Type", "application/json")
        elif "form" in spec:
            body = urllib.parse.urlencode(spec["form"])
            headers.setdefault("Content-Type", "application/x-www-form-urlencoded")
        elif "body" in spec:
            body = str(spec["body"])
        self._ensure_origin()
        res = self._eval(
            "(async (u, m, h, b) => { try { const r = await fetch(u, {method: m, headers: h, body: b, credentials: 'include'});"
            " const t = await r.text(); return {status: r.status, text: t.slice(0, 2000000)}; }"
            " catch (e) { return {status: 0, error: String(e)}; } })(%s, %s, %s, %s)"
            % (json.dumps(url), json.dumps(method), json.dumps(headers), json.dumps(body)), 40)
        if not isinstance(res, dict) or not res.get("status"):
            why = (res or {}).get("error", "no response") if isinstance(res, dict) else "no response"
            raise jy.JourneyError(f"{method} {url} was not sent or failed ({why}; blocked by scope or --read-only?)")
        expect = spec.get("expect")
        if expect is not None and res["status"] not in ([expect] if isinstance(expect, int) else expect):
            raise jy.JourneyError(f"{method} {url} answered {res['status']}, expected {expect}")
        if spec.get("extract"):
            try:
                data = json.loads(res.get("text", ""))
            except ValueError:
                data = None
            for name, path in spec["extract"].items():
                val = jy.dig(data, path) if isinstance(path, str) else None
                if val is None:
                    raise jy.JourneyError(f"could not extract {name!r} from {path!r} in the response")
                variables[name] = val

    def _sync_cookies(self) -> None:
        try:
            for c in self._page("Network.getAllCookies", {}, 8).get("cookies", []):
                host = c.get("domain", "").lstrip(".").lower()
                self.jar.setdefault(host or self.start.hostname.lower(), {})[c["name"]] = c["value"]
        except (RuntimeError, TimeoutError, ConnectionError, AttributeError):
            pass

    def _static_pass(self) -> None:
        """GET the concrete endpoints the bundles name that the UI never triggered."""
        if not self.cfg.probe_js:
            return
        pending: list[Task] = []
        for url, text in self._scripts:
            self._probe_refs(Task("GET", url, 0, self.cfg.start, "js"), text, pending)
        for task in pending:
            if not self._budget_left():
                break
            got = self.fetch(task)
            if got is None:
                continue
            item, *_ = got
            self.items.append(item)
            self.stats["requests"] += 1
            self.stats["js_probes"] += 1
