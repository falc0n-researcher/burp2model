"""
Static endpoint extraction from JavaScript and HTML bodies.

A reference found in code is a *claim* that the app may call an endpoint, not
proof that it does, so everything extracted here becomes an INFERRED edge in
the model. Each reference is a (method, host, path, kind) tuple:

  method  "GET", "POST", ... when the call site names it, else None
  host    the host of an absolute URL, else None (relative to the page origin)
  path    templated the same way runtime paths are (`/users/{id}`), so a
          reference and a request for the same endpoint reconcile
  kind    "call" (fetch/axios/XHR/verb call), "string" (bare API-looking
          string literal) or "form" (an HTML <form action>)
"""

from __future__ import annotations

import re
import urllib.parse

from .redact import template_path

# Bodies larger than this are scanned only up to the cap and flagged.
MAX_SCAN_BYTES = 10 * 1024 * 1024

API_HINT = re.compile(r"/(api|v\d+|graphql|rest|gql)(/|$)", re.I)

# `${expr}` inside template literals becomes a {param} placeholder.
_TEMPLATE_EXPR_RE = re.compile(r"\$\{[^{}`]{0,120}\}")

# A URL-ish literal: optional scheme+host, then a path. `{param}` may appear
# (from template literals) anywhere, including as a leading base-URL prefix.
_URL_BODY = r"(?:\{param\})?(?:https?:)?/[^\s\"'`<>\\]{0,300}?"

_VERB_CALL_RE = re.compile(
    r"\.(get|post|put|patch|delete|head)\s*\(\s*([\"'`])(" + _URL_BODY + r")\2", re.I)
_FETCH_RE = re.compile(
    r"(?:\b(?:fetch|axios|ajax|request)|\$http)\s*\(\s*([\"'`])(" + _URL_BODY + r")\1")
_XHR_OPEN_RE = re.compile(
    r"\.open\s*\(\s*[\"'](GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)[\"']\s*,\s*"
    r"([\"'`])(" + _URL_BODY + r")\2", re.I)
_METHOD_NEAR_RE = re.compile(r"""method\s*:\s*["'`](GET|POST|PUT|PATCH|DELETE|HEAD)["'`]""", re.I)
_STRING_RE = re.compile(r"([\"'`])(" + _URL_BODY + r")\1")

_FORM_RE = re.compile(r"<form\b([^>]*)>", re.I)
_ATTR_RE = re.compile(r"""\b(action|method)\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))""", re.I)

_STATIC_EXT = re.compile(
    r"\.(?:png|jpe?g|gif|svg|ico|webp|avif|css|woff2?|ttf|otf|eot|map|mp4|webm|mp3|"
    r"html?|js|mjs|json|txt|md)$", re.I)


def _normalize(raw: str) -> tuple[str | None, str] | None:
    """Split a raw literal into (host, templated path); None if not a path."""
    raw = raw.strip()
    if raw.startswith("{param}"):
        raw = raw[len("{param}"):]          # unknown base URL: treat as relative
    if raw.startswith("//"):
        raw = "https:" + raw
    host = None
    if raw.lower().startswith(("http://", "https://")):
        parts = urllib.parse.urlsplit(raw)
        host = (parts.hostname or "").lower() or None
        path = parts.path or "/"
    else:
        if not raw.startswith("/"):
            return None
        path = raw.split("?", 1)[0].split("#", 1)[0]
    if "//" in path or len(path) > 200:
        return None
    # `"/api/users/" + id` — a trailing slash is a concatenation point
    if len(path) > 1 and path.endswith("/"):
        path = path + "{param}"
    return host, template_path(path)


def _ref(method, raw, kind, out: set) -> None:
    norm = _normalize(raw)
    if norm is None:
        return
    host, path = norm
    if path == "/" and host is None:
        return
    # `${this.host}/${id}/reviews` — the base is a service prefix the bundle
    # keeps in a variable, so all that is left is `/{param}/reviews`. That is
    # not a path anything can be matched to; drop it rather than invent a
    # root-level endpoint (an API-looking segment after it keeps it: `/{t}/api/x`).
    if host is None and path.startswith("/{param}") and not API_HINT.search(path):
        return
    out.add((method.upper() if method else None, host, path, kind))


def extract_js_refs(body: str) -> set[tuple[str | None, str | None, str, str]]:
    """Endpoint references inside JavaScript (or inline <script>) text."""
    out: set = set()
    if not body:
        return out
    body = _TEMPLATE_EXPR_RE.sub("{param}", body)
    call_spans: list[tuple[int, int]] = []

    for m in _XHR_OPEN_RE.finditer(body):
        _ref(m.group(1), m.group(3), "call", out)
        call_spans.append(m.span(3))
    for m in _VERB_CALL_RE.finditer(body):
        _ref(m.group(1), m.group(3), "call", out)
        call_spans.append(m.span(3))
    for m in _FETCH_RE.finditer(body):
        # fetch(url, {method: "POST"}) — read the method only from THIS call's
        # options object, i.e. before the statement ends or the next call begins,
        # so a later call's method can't bleed onto this one.
        window = body[m.end(): m.end() + 200]
        stop = len(window)
        for tok in (";", "fetch(", "axios", ".open(", ".then(", "\n\n"):
            i = window.find(tok)
            if i != -1:
                stop = min(stop, i)
        near = _METHOD_NEAR_RE.search(window[:stop])
        _ref(near.group(1) if near else None, m.group(2), "call", out)
        call_spans.append(m.span(2))

    called = {s for s in call_spans}
    for m in _STRING_RE.finditer(body):
        if m.span(2) in called:
            continue
        raw = m.group(2)
        norm = _normalize(raw)
        if norm is None:
            continue
        _, path = norm
        # a bare string is only interesting if it looks like an API route
        if API_HINT.search(path) and not _STATIC_EXT.search(path):
            _ref(None, raw, "string", out)
    return out


def extract_html_refs(body: str) -> set[tuple[str | None, str | None, str, str]]:
    """<form action> targets plus references inside inline scripts."""
    out: set = set()
    if not body:
        return out
    for fm in _FORM_RE.finditer(body):
        attrs = {}
        for am in _ATTR_RE.finditer(fm.group(1)):
            attrs[am.group(1).lower()] = am.group(2) or am.group(3) or am.group(4) or ""
        action = attrs.get("action", "").strip()
        if not action or action.startswith(("#", "javascript:", "mailto:")):
            continue
        method = (attrs.get("method") or "GET").upper()
        _ref(method if method in ("GET", "POST") else "GET", action, "form", out)
    out |= extract_js_refs(body)
    return out


# ---- source maps and workers -------------------------------------------------

_SOURCEMAP_RE = re.compile(r"//[#@]\s*sourceMappingURL=([^\s'\"]+)")
_WORKER_RES = (
    ("worker", re.compile(r"new\s+(?:Shared)?Worker\s*\(\s*([\"'`])([^\"'`\s]{1,200})\1")),
    ("service_worker", re.compile(r"serviceWorker\s*\.\s*register\s*\(\s*([\"'`])([^\"'`\s]{1,200})\1")),
    ("import_scripts", re.compile(r"importScripts\s*\(\s*([\"'`])([^\"'`\s]{1,200})\1")),
)


def _resolve_asset(raw: str, script_host: str, script_path: str):
    """Resolve a reference found in a script to (host, templated path); None if not a file path."""
    raw = raw.strip()
    if not raw or raw.startswith(("data:", "blob:", "{param}")) or "{param}" in raw:
        return None
    parts = urllib.parse.urlsplit(raw if "://" in raw or raw.startswith("//") else
                                  urllib.parse.urljoin("https://x" + script_path, raw))
    if "://" in raw or raw.startswith("//"):
        host = (parts.hostname or "").lower() or script_host
        path = parts.path
    else:
        host, path = script_host, parts.path
    if not path.startswith("/") or "//" in path or len(path) > 200:
        return None
    return host, template_path(path)


def extract_script_assets(body: str, host: str, path: str,
                          header_map: str | None = None) -> set[tuple[str, str, str]]:
    """Source maps and workers a script names: a set of (kind, host, path).

    kind is "sourcemap", "worker", "service_worker" or "import_scripts". Like every code
    reference these are claims about the code; the model records them as INFERRED."""
    out: set = set()
    refs = [("sourcemap", m.group(1)) for m in _SOURCEMAP_RE.finditer(body or "")]
    if header_map:
        refs.append(("sourcemap", header_map))
    for kind, rx in _WORKER_RES:
        refs += [(kind, m.group(2)) for m in rx.finditer(body or "")]
    for kind, raw in refs:
        r = _resolve_asset(raw, host, path)
        if r:
            out.add((kind, r[0], r[1]))
    return out
