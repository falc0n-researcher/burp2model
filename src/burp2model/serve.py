"""A local endpoint for the Burp extension: it POSTs the selected requests, burp2model builds the model.

Loopback only, no setup. A web page cannot drive it: only loopback host names are accepted and every
request must carry a custom header, which a browser will not send across sites without a preflight that
this server never answers. There is also a size cap. The body is the same XML Burp's own
"Save items" writes, so the engine that reads exports is the one that reads these.
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
import threading
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

MAX_BODY = 512 * 1024 * 1024
DEFAULT_PORT = 8765


def make_server(app: str, out: str, port: int = DEFAULT_PORT, build=None,
                host: str = "127.0.0.1") -> ThreadingHTTPServer:
    """`build(argv)` runs one burp2model build and returns its exit code (the CLI's `main`)."""
    if build is None:
        from .cli import main as build
    lock = threading.Lock()                 # one build at a time
    allowed_hosts = {f"127.0.0.1:{port}", f"localhost:{port}", f"[::1]:{port}"}

    class Handler(BaseHTTPRequestHandler):
        server_version = "burp2model"

        def log_message(self, fmt, *a):       # quiet; the CLI prints what matters
            pass

        def _send(self, code: int, obj: dict) -> None:
            body = json.dumps(obj).encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)

        def _guard(self) -> bool:
            # a web page must not be able to drive this: only loopback host names, and a custom header
            # that a cross-site request cannot add without a preflight (which is never answered)
            if self.headers.get("Host", "") not in allowed_hosts:
                self._send(403, {"error": "unexpected Host header"})
                return False
            if self.headers.get("X-B2M-Client", "") != "burp-extension":
                self._send(403, {"error": "missing client header"})
                return False
            return True

        def do_GET(self) -> None:
            if not self._guard():
                return
            if urllib.parse.urlsplit(self.path).path == "/health":
                self._send(200, {"ok": True, "app": app})
            else:
                self._send(404, {"error": "not found"})

        def do_POST(self) -> None:
            if not self._guard():
                return
            url = urllib.parse.urlsplit(self.path)
            if url.path != "/ingest":
                self._send(404, {"error": "not found"})
                return
            try:
                size = int(self.headers.get("Content-Length", ""))
            except ValueError:
                self._send(411, {"error": "Content-Length required"})
                return
            if size <= 0 or size > MAX_BODY:
                self._send(413, {"error": f"body must be 1 byte to {MAX_BODY // 2**20} MB"})
                return
            q = urllib.parse.parse_qs(url.query)
            argv = ["build", "", "-w", app, "--out", out]
            for key, flag in (("role", "--role"), ("label", "--label")):
                if q.get(key) and q[key][0]:
                    argv += [flag, q[key][0]]
            for sc in q.get("scope", []):
                argv += ["--scope", sc]
            with tempfile.TemporaryDirectory() as tmp:
                path = os.path.join(tmp, "burp-selection.xml")
                left = size
                with open(path, "wb") as f:
                    while left:
                        chunk = self.rfile.read(min(left, 1 << 20))
                        if not chunk:
                            break
                        f.write(chunk)
                        left -= len(chunk)
                if left:
                    self._send(400, {"error": "body ended early"})
                    return
                argv[1] = path
                with lock:
                    code = self._run(build, argv)
            report = os.path.abspath(os.path.join(out, app, "report.html"))
            if code != 0:
                self._send(422, {"error": "could not build a model from that selection"})
            else:
                self._send(200, {"ok": True, "app": app, "report": report,
                                 "report_url": "file://" + urllib.parse.quote(report)})

        @staticmethod
        def _run(build, argv: list[str]) -> int:
            real = sys.stdout
            sys.stdout = sys.stderr          # build progress goes to the terminal log, never the response
            try:
                return build(argv)
            except SystemExit as e:
                return int(e.code or 0)
            finally:
                sys.stdout = real

    return ThreadingHTTPServer((host, port), Handler)


def serve(app: str, out: str, port: int = DEFAULT_PORT) -> int:
    try:
        srv = make_server(app, out, port)
    except OSError as e:
        print(f"serve: cannot listen on 127.0.0.1:{port}: {e}", file=sys.stderr)
        return 2
    print(f"burp2model is listening on http://127.0.0.1:{port} for the Burp extension\n"
          f"  app: {app} -> {os.path.join(out, app)}   (Ctrl-C stops)", file=sys.stderr)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\nserve: stopped", file=sys.stderr)
    finally:
        srv.server_close()
    return 0
