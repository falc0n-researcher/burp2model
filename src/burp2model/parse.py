"""
Parse a Burp Suite "Save items" XML export into redacted HTTP exchanges.

Burp stores each proxied request/response as an <item> with base64-encoded
request and response blobs. This module streams the file (so multi-GB exports
don't blow memory), decodes each blob, splits head/body, and hands back a
plain dataclass with every value already redacted (see redact.py).

Everything the model needs from a *body* (endpoint references in JS/HTML,
GraphQL operation names) is extracted here, from the full body. What survives
of a body is the fully redacted, capped excerpt in `ev` — the report's
request/response panes — with every value masked by name and by shape.

Nothing here writes to disk. Redaction happens before an Exchange leaves this
module, so no raw secret ever reaches the model or the report.
"""

from __future__ import annotations

import base64
import gzip
import json
import os
import re
import urllib.parse
import zlib
from dataclasses import dataclass, field
from xml.etree.ElementTree import iterparse

from .extract import MAX_SCAN_BYTES, extract_html_refs, extract_js_refs, extract_script_assets
from .stack import detect as detect_stack
from .redact import (
    SecretFingerprint,
    classify_segment,
    redact_body,
    redact_headers,
    redact_named,
    redact_params,
    redact_path,
    route_template,
    template_path,  # noqa: F401  (re-exported: parse.template_path is public API)
)

BODY_KEEP = 20000

_SESSION_COOKIE_HINTS = ("sess", "sid", "auth", "token", "jwt", "remember", "login", "user")
_CREDENTIAL_HEADER_HINTS = ("api-key", "apikey", "auth-token", "access-token", "x-token")
_TECH_HEADERS = ("server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version",
                 "x-generator", "x-runtime", "x-framework")


@dataclass
class Exchange:
    """One redacted request/response pair."""
    index: int
    method: str
    scheme: str
    host: str
    port: int
    path: str                 # redacted path incl. redacted query
    path_template: str        # /api/users/{id}
    status: int | None
    mime: str
    req_headers: list[tuple[str, str]] = field(default_factory=list)
    resp_headers: list[tuple[str, str]] = field(default_factory=list)
    query_params: list[tuple[str, str]] = field(default_factory=list)
    body_params: list[tuple[str, str]] = field(default_factory=list)
    req_body: str = ""
    resp_body: str = ""
    role: str | None = None
    secrets: list[SecretFingerprint] = field(default_factory=list)
    # provenance: which export file and which <item> in it
    source: str = ""
    item: int = -1
    # metadata extracted before redaction (names and shapes only)
    referer_host: str | None = None
    referer_path: str | None = None
    cookie_names: list[str] = field(default_factory=list)
    set_cookies: list[dict] = field(default_factory=list)
    credentials: list[str] = field(default_factory=list)
    tech: list[tuple[str, str]] = field(default_factory=list)
    js_refs: list[tuple] = field(default_factory=list)
    js_assets: list[tuple] = field(default_factory=list)      # source maps, workers a script names
    stack: list[tuple] = field(default_factory=list)          # (name, category, how, version) the response shows
    scan_truncated: bool = False
    gql_ops: list[str] = field(default_factory=list)
    preflight: bool = False
    # a fully redacted view of the exchange, for the report's request/response
    # panes: request line, headers and body all masked; values never present.
    ev: dict = field(default_factory=dict)

    @property
    def url(self) -> str:
        return f"{self.scheme}://{self.host}{self.path}"

    @property
    def endpoint_id(self) -> str:
        return f"{self.method}:{self.host}:{self.path_template}"

    # ---- persistence: names, shapes and the redacted `ev` panes — never a
    # raw value; `ev` bodies are masked by name and shape and capped ----
    def to_record(self) -> dict:
        return {
            "index": self.index, "source": self.source, "item": self.item,
            "method": self.method, "scheme": self.scheme, "host": self.host,
            "port": self.port, "path": self.path, "path_template": self.path_template,
            "status": self.status, "mime": self.mime, "role": self.role,
            "query_params": [n for n, _ in self.query_params],
            "body_params": [n for n, _ in self.body_params],
            "secrets": [s.as_dict() for s in self.secrets],
            "referer_host": self.referer_host, "referer_path": self.referer_path,
            "cookie_names": self.cookie_names, "set_cookies": self.set_cookies,
            "credentials": self.credentials, "tech": [list(t) for t in self.tech],
            "js_refs": [list(r) for r in self.js_refs],
            "js_assets": [list(r) for r in self.js_assets],
            "stack": [list(r) for r in self.stack],
            "scan_truncated": self.scan_truncated, "gql_ops": self.gql_ops,
            "preflight": self.preflight, "ev": self.ev,
        }

    @classmethod
    def from_record(cls, r: dict) -> "Exchange":
        return cls(
            index=r["index"], method=r["method"], scheme=r["scheme"], host=r["host"],
            port=r["port"], path=r["path"], path_template=r["path_template"],
            status=r["status"], mime=r["mime"], role=r.get("role"),
            query_params=[(n, "") for n in r.get("query_params", [])],
            body_params=[(n, "") for n in r.get("body_params", [])],
            secrets=[SecretFingerprint(s["kind"], s["hmac_12"], s["length"], s["entropy"])
                     for s in r.get("secrets", [])],
            source=r.get("source", ""), item=r.get("item", -1),
            referer_host=r.get("referer_host"), referer_path=r.get("referer_path"),
            cookie_names=r.get("cookie_names", []), set_cookies=r.get("set_cookies", []),
            credentials=r.get("credentials", []),
            tech=[tuple(t) for t in r.get("tech", [])],
            js_refs=[tuple(x) for x in r.get("js_refs", [])],
            js_assets=[tuple(x) for x in r.get("js_assets", [])],
            stack=[tuple(x) for x in r.get("stack", [])],
            scan_truncated=r.get("scan_truncated", False),
            gql_ops=r.get("gql_ops", []), preflight=r.get("preflight", False),
            ev=r.get("ev", {}),
        )


def _b64(text: str | None, is_b64: bool) -> bytes:
    if text is None:
        return b""
    if is_b64:
        try:
            return base64.b64decode(text)
        except Exception:
            pass
        # whitespace, missing padding or a cut-off tail (a spreadsheet cell limit): decode what is there
        t = re.sub(r"\s+", "", text)
        if len(t) % 4 == 1:
            t = t[:-1]
        try:
            return base64.b64decode(t + "=" * (-len(t) % 4))
        except Exception:
            return text.encode("utf-8", "replace")
    return text.encode("utf-8", "replace")


# Cap decompressed size so a crafted export can't act as a decompression bomb.
_MAX_DECOMPRESS = 50 * 1024 * 1024


def _dechunk(body: bytes) -> bytes:
    """Reassemble a Transfer-Encoding: chunked body; return input on any error."""
    out, pos = [], 0
    try:
        while pos < len(body):
            eol = body.index(b"\r\n", pos)
            size = int(body[pos:eol].split(b";", 1)[0], 16)
            if size == 0:
                break
            chunk = body[eol + 2:eol + 2 + size]
            if len(chunk) < size:
                return body
            out.append(chunk)
            pos = eol + 2 + size + 2
            if sum(map(len, out)) > _MAX_DECOMPRESS:
                break
        return b"".join(out)
    except (ValueError, IndexError):
        return body


def _decompress(body: bytes, encoding: str) -> tuple[bytes, bool]:
    """Decompress a body, bounded. Returns (body, handled) — handled is False
    when the content-encoding is one we cannot decode (br/zstd without the
    optional library), so callers can flag the blind spot instead of silently
    scanning compressed bytes."""
    enc = ",".join(t.strip() for t in encoding.lower().split(","))
    try:
        if body[:2] == b"\x1f\x8b":
            d = zlib.decompressobj(16 + zlib.MAX_WBITS)
            return d.decompress(body, _MAX_DECOMPRESS), True
        if "deflate" in enc:
            try:
                return zlib.decompressobj().decompress(body, _MAX_DECOMPRESS), True
            except zlib.error:
                return zlib.decompressobj(-zlib.MAX_WBITS).decompress(body, _MAX_DECOMPRESS), True
        if "br" in enc.split(","):
            try:
                import brotli  # type: ignore
                return brotli.decompress(body)[:_MAX_DECOMPRESS], True
            except ImportError:
                return body, not body
        if "zstd" in enc:
            try:
                import zstandard  # type: ignore
                return zstandard.ZstdDecompressor().decompress(
                    body, max_output_size=_MAX_DECOMPRESS), True
            except ImportError:
                return body, not body
    except Exception:
        return body, True
    return body, True


def _split_http(raw: bytes) -> tuple[str, bytes]:
    """Split HTTP message into head (text) and body (bytes)."""
    sep = raw.find(b"\r\n\r\n")
    if sep == -1:
        sep = raw.find(b"\n\n")
        head, body = (raw[:sep], raw[sep + 2:]) if sep != -1 else (raw, b"")
    else:
        head, body = raw[:sep], raw[sep + 4:]
    return head.decode("latin-1", "replace"), body


def _parse_headers(head: str) -> tuple[str, list[tuple[str, str]]]:
    lines = head.split("\n")
    start = lines[0].strip() if lines else ""
    headers: list[tuple[str, str]] = []
    for line in lines[1:]:
        line = line.rstrip("\r")
        if not line or ":" not in line:
            continue
        name, _, value = line.partition(":")
        headers.append((name.strip(), value.strip()))
    return start, headers


def _header(headers, name: str) -> str:
    low = name.lower()
    return next((v for k, v in headers if k.lower() == low), "")


def _parse_query(path: str) -> list[tuple[str, str]]:
    if "?" not in path:
        return []
    q = path.split("?", 1)[1].split("#", 1)[0]
    return [(k, v) for k, v in urllib.parse.parse_qsl(q, keep_blank_values=True)]


def _parse_body_params(body: str, content_type: str) -> list[tuple[str, str]]:
    ct = content_type.lower()
    if "application/x-www-form-urlencoded" in ct:
        return [(k, v) for k, v in urllib.parse.parse_qsl(body, keep_blank_values=True)]
    if "json" in ct:
        try:
            data = json.loads(body)
        except Exception:
            return []
        out: list[tuple[str, str]] = []

        def walk(obj, prefix="$", depth=0):
            if depth > 12:
                return
            if isinstance(obj, dict):
                for k, v in obj.items():
                    # a key can itself be a value (an email, a token used as a
                    # map key); collapse it so it never becomes a param name
                    kk = classify_segment(str(k)[:200]) or str(k)[:200]
                    walk(v, f"{prefix}.{kk}", depth + 1)
            elif isinstance(obj, list):
                for i, v in enumerate(obj[:5]):
                    walk(v, f"{prefix}[{i}]", depth + 1)
            else:
                out.append((prefix, str(obj)))

        walk(data)
        return out
    return []


_GQL_OP_RE = re.compile(r"^\s*(query|mutation|subscription)\s+([A-Za-z_][A-Za-z0-9_]*)")


def _gql_ops(path_template: str, body: str, ct: str) -> list[str]:
    if "graphql" not in path_template.lower() and "gql" not in path_template.lower():
        return []
    try:
        data = json.loads(body) if body and "json" in ct.lower() else None
    except Exception:
        data = None
    ops: list[str] = []
    for obj in (data if isinstance(data, list) else [data]):
        if not isinstance(obj, dict):
            continue
        name = obj.get("operationName")
        if not name and isinstance(obj.get("query"), str):
            m = _GQL_OP_RE.match(obj["query"])
            name = m.group(2) if m else None
        if isinstance(name, str) and re.match(r"^[A-Za-z_][A-Za-z0-9_]{0,80}$", name):
            ops.append(name)
    return ops


def _credentials(req_headers, cookie_names, query_params) -> list[str]:
    creds: list[str] = []
    auth = _header(req_headers, "authorization")
    if auth:
        scheme = auth.split(" ", 1)[0].lower() if " " in auth.strip() else "custom"
        creds.append(scheme if re.match(r"^[a-z0-9-]{2,30}$", scheme) else "custom")
    for k, _ in req_headers:
        low = k.lower()
        if low != "authorization" and any(h in low for h in _CREDENTIAL_HEADER_HINTS):
            creds.append(f"header:{low}")
    for c in cookie_names:
        if any(h in c.lower() for h in _SESSION_COOKIE_HINTS):
            creds.append(f"cookie:{c}")
    for k, _ in query_params:
        low = k.lower()
        if low in ("api_key", "apikey", "access_token", "token", "key", "auth"):
            creds.append(f"query:{low}")
    return sorted(set(creds))


def _cookie_names(cookie_header: str) -> list[str]:
    names = []
    for part in cookie_header.split(";"):
        name = part.split("=", 1)[0].strip()
        if name and re.match(r"^[!#$%&'*+\-.^_`|~0-9A-Za-z]{1,100}$", name):
            names.append(name)
    return names


def _set_cookies(resp_headers) -> list[dict]:
    out = []
    for k, v in resp_headers:
        if k.lower() != "set-cookie" or "=" not in v:
            continue
        first, *attrs = v.split(";")
        name = first.split("=", 1)[0].strip()
        if not name:
            continue
        flags = {a.strip().split("=", 1)[0].lower(): a.strip() for a in attrs}
        samesite = flags.get("samesite", "")
        out.append({
            "name": name[:100],
            "httponly": "httponly" in flags,
            "secure": "secure" in flags,
            "samesite": samesite.split("=", 1)[1].strip() if "=" in samesite else None,
        })
    return out


def _referer(req_headers) -> tuple[str | None, str | None]:
    ref = _header(req_headers, "referer")
    if not ref:
        return None, None
    try:
        parts = urllib.parse.urlsplit(ref)
    except ValueError:
        return None, None
    host = (parts.hostname or "").lower() or None
    if not host:
        return None, None
    path = (parts.path or "/") + ("?" + parts.query if parts.query else "")
    red, _ = redact_path(path)
    return host, route_template(red, template_path(parts.path or "/"))


def _is_js_response(mime: str, path_template: str, ct: str) -> bool:
    m = (mime + " " + ct).lower()
    return "script" in m or "ecmascript" in m or path_template.endswith((".js", ".mjs"))


def _is_html_response(mime: str, ct: str) -> bool:
    return "html" in (mime + " " + ct).lower()


def _text(elem) -> str | None:
    return elem.text if elem is not None else None


def _check_no_entities(path: str) -> None:
    """Refuse exports that declare XML entities (billion-laughs / XXE shapes).

    Burp's own exports declare elements and attributes, never entities. The
    whole file is scanned in chunks, so a declaration cannot hide past a
    header-only check. `<!ENTITY` cannot occur inside Burp's base64 payloads.
    """
    with open(path, "rb") as f:
        tail = b""
        while True:
            chunk = f.read(1 << 20)
            if not chunk:
                break
            if b"<!ENTITY" in (tail + chunk).upper():
                raise ValueError(
                    f"{path}: XML entity declarations are not allowed in a Burp export")
            tail = chunk[-8:]


def parse_items(path: str, role: str | None = None, stats: dict | None = None,
                skip_tools: tuple = (), only_tools: tuple = ()):
    """Yield redacted Exchange objects from a Burp export. Streaming.

    Takes a Burp "Save items" XML or a Logger++ CSV export (chosen by the file
    extension). If `stats` is given it is filled with items/parsed/skipped counts.
    `skip_tools` / `only_tools` filter a Logger++ CSV by its Tool column.
    """
    if stats is None:
        stats = {}
    for k in ("items", "parsed", "skipped"):
        stats.setdefault(k, 0)
    if path.lower().endswith(".csv"):
        yield from _parse_logger_csv(path, role, stats, skip_tools, only_tools)
        return
    _check_no_entities(path)
    source = os.path.basename(path)
    idx = 1                  # evidence ids start at 1
    item_no = 0
    root = None
    for event, elem in iterparse(path, events=("start", "end")):
        if event == "start":
            if root is None:
                root = elem
            continue
        if elem.tag != "item":
            continue
        stats["items"] += 1
        try:
            ex = _parse_item(elem, idx, role)
            if ex is None:
                stats["skipped"] += 1
            else:
                ex.source, ex.item = source, item_no
                idx += 1
                stats["parsed"] += 1
                yield ex
        except Exception:
            stats["skipped"] += 1
        finally:
            item_no += 1
            elem.clear()
            # drop the processed <item> from the tree, or the root keeps every
            # cleared element alive and memory grows with the export
            if root is not None:
                root.clear()


# ---------------------------------------------------------------- Logger++ CSV --

_CSV_NEEDED = ("Method", "Host", "Request", "Response")
# A spreadsheet cell holds at most 32,767 characters. A Logger++ CSV that has been through one
# has its longer responses cut there, with the rest spilling onto following rows.
_CELL_LIMIT = 32000


def _csv_rows(path: str):
    """Rows of a Logger++ CSV as dicts, with spilled-over cells put back together."""
    import csv
    csv.field_size_limit(2 ** 31 - 1)
    with open(path, newline="", encoding="utf-8", errors="replace") as fh:
        reader = csv.reader(fh)
        try:
            header = [h.strip() for h in next(reader)]
        except StopIteration:
            return
        missing = [c for c in _CSV_NEEDED if c not in header]
        if missing:
            raise ValueError(f"not a Logger++ CSV export (missing columns: {', '.join(missing)})")
        idx = {h: i for i, h in enumerate(header)}
        pending: dict | None = None
        for row in reader:
            if not any(c.strip() for c in row):
                continue
            row = row + [""] * (len(header) - len(row))
            first = row[0].strip()
            rest_empty = not any(c.strip() for c in row[1:])
            # a continuation: only the first cell is filled, and it is not a numeric request id
            if pending is not None and rest_empty and first and not first.isdigit():
                field = "Response" if pending["Response"] else "Request"
                pending[field] += first
                pending["_spilled"] = True
                continue
            if pending is not None:
                yield pending
            pending = {h: row[i] for h, i in idx.items()}
            pending["_spilled"] = False
        if pending is not None:
            yield pending


def _b64_text(value: str) -> tuple[str, bool]:
    """(`true`/`false` for the base64 attribute, text). Logger++ writes raw HTTP as base64."""
    v = value.strip()
    if not v:
        return "false", ""
    if v.startswith(("GET ", "POST ", "PUT ", "HEAD ", "HTTP/", "OPTIONS ", "DELETE ", "PATCH ")):
        return "false", value
    return "true", re.sub(r"\s+", "", v)


def _parse_logger_csv(path, role, stats, skip_tools, only_tools):
    source = os.path.basename(path)
    skip = {t.strip().lower() for t in skip_tools if t.strip()}
    only = {t.strip().lower() for t in only_tools if t.strip()}
    tools: dict[str, int] = stats.setdefault("tools", {})
    from xml.etree.ElementTree import Element, SubElement
    idx = 1                  # evidence ids start at 1
    for item_no, row in enumerate(_csv_rows(path)):
        tool = (row.get("Tool") or "").strip() or "?"
        tools[tool] = tools.get(tool, 0) + 1
        if (skip and tool.lower() in skip) or (only and tool.lower() not in only):
            stats["filtered"] = stats.get("filtered", 0) + 1
            continue
        stats["items"] += 1
        try:
            item = Element("item")
            qs = (row.get("Query") or "").strip()
            p = (row.get("Path") or "").strip()
            if not p:
                u = urllib.parse.urlsplit(row.get("URL") or "")
                p, qs = (u.path or "/") + ("?" + u.query if u.query else ""), ""
            if qs and "?" not in p:
                p = p + "?" + qs.lstrip("?")
            for tag, val in (("method", row.get("Method")), ("host", row.get("Host")),
                             ("port", row.get("Port")), ("protocol", row.get("Protocol")), ("path", p),
                             ("status", row.get("Status code")), ("mimetype", row.get("MIME type"))):
                SubElement(item, tag).text = (val or "").strip()
            for tag in ("Request", "Response"):
                b64, text = _b64_text(row.get(tag) or "")
                SubElement(item, tag.lower(), {"base64": b64}).text = text
            # a response that stops at the spreadsheet cell limit and never recovered is cut short
            if not row.get("_spilled") and _CELL_LIMIT <= len(row.get("Response") or "") < 32768:
                SubElement(item, "truncated").text = "1"
            ex = _parse_item(item, idx, role)
        except Exception:
            ex = None
        if ex is None:
            stats["skipped"] += 1
            continue
        ex.source, ex.item = source, item_no
        idx += 1
        stats["parsed"] += 1
        yield ex


def parse_elements(items, source: str, role: str | None = None, stats: dict | None = None):
    """Like parse_items, for <item> elements already in memory (the crawler's output).

    The crawler hands over what it fetched without ever writing a raw
    request/response to disk; redaction still happens here, before an Exchange
    leaves this module.
    """
    if stats is None:
        stats = {}
    for k in ("items", "parsed", "skipped"):
        stats.setdefault(k, 0)
    idx = 1                  # evidence ids start at 1
    for item_no, elem in enumerate(items):
        stats["items"] += 1
        try:
            ex = _parse_item(elem, idx, role)
        except Exception:
            ex = None
        if ex is None:
            stats["skipped"] += 1
            continue
        ex.source, ex.item = source, item_no
        idx += 1
        stats["parsed"] += 1
        yield ex


def _int(text: str | None, default=None):
    t = (text or "").strip()
    return int(t) if t.isdigit() else default


def _parse_item(elem, idx: int, role: str | None) -> Exchange | None:
    method = (_text(elem.find("method")) or "GET").strip().upper()
    host = (_text(elem.find("host")) or "").strip().lower()
    port = _int(_text(elem.find("port")), 0)
    protocol = (_text(elem.find("protocol")) or "https").strip().lower()
    path = (_text(elem.find("path")) or "").strip()
    if not path:
        url = (_text(elem.find("url")) or "").strip()
        parts = urllib.parse.urlsplit(url) if url else None
        path = ((parts.path or "/") + ("?" + parts.query if parts.query else "")) if parts else "/"
    status = _int(_text(elem.find("status")))
    mime = (_text(elem.find("mimetype")) or "").strip()
    if not host or not re.match(r"^[a-z0-9.\-:\[\]]{1,255}$", host):
        return None
    if not re.match(r"^[A-Z]{1,20}$", method):
        return None

    req_el = elem.find("request")
    resp_el = elem.find("response")
    req_raw = _b64(_text(req_el), req_el is not None and req_el.get("base64") == "true")
    resp_raw = _b64(_text(resp_el), resp_el is not None and resp_el.get("base64") == "true")

    req_head, req_body_b = _split_http(req_raw) if req_raw else ("", b"")
    resp_head, resp_body_b = _split_http(resp_raw) if resp_raw else ("", b"")
    req_start, req_headers = _parse_headers(req_head)
    resp_start, resp_headers = _parse_headers(resp_head)
    if status is None and resp_start.startswith("HTTP/"):
        status = _int(resp_start.split(" ")[1] if " " in resp_start else None)

    if "chunked" in _header(req_headers, "transfer-encoding").lower():
        req_body_b = _dechunk(req_body_b)
    if "chunked" in _header(resp_headers, "transfer-encoding").lower():
        resp_body_b = _dechunk(resp_body_b)
    req_body_b, _req_dec_ok = _decompress(req_body_b, _header(req_headers, "content-encoding"))
    resp_body_b, resp_dec_ok = _decompress(resp_body_b, _header(resp_headers, "content-encoding"))
    req_ct = _header(req_headers, "content-type")
    resp_ct = _header(resp_headers, "content-type")
    req_body_text = req_body_b.decode("utf-8", "replace")

    # ---- metadata that must be read before values are masked (names only) ----
    cookie_names = _cookie_names(_header(req_headers, "cookie"))
    set_cookies = _set_cookies(resp_headers)
    raw_query = _parse_query(path)
    credentials = _credentials(req_headers, cookie_names, raw_query)
    referer_host, referer_path = _referer(req_headers)
    preflight = method == "OPTIONS" and bool(_header(req_headers, "access-control-request-method"))

    secrets: list[SecretFingerprint] = []
    red_path, s0 = redact_path(path)
    ptemplate = route_template(red_path, template_path(red_path))
    tech = []
    for k, v in resp_headers:
        if k.lower() in _TECH_HEADERS and v:
            tech.append((k.lower(), v[:80]))

    req_headers_r, s1 = redact_headers(req_headers)
    resp_headers_r, s2 = redact_headers(resp_headers)
    query_r, s3 = redact_params(raw_query)
    body_params_r, s4 = redact_params(_parse_body_params(req_body_text, req_ct))
    req_body_r, s5 = redact_body(req_body_text[:BODY_KEEP])
    gql_ops = _gql_ops(ptemplate, req_body_r, req_ct)
    tech_r = []
    for k, v in tech:
        masked, s7 = redact_body(v)
        secrets.extend(s7)
        tech_r.append((k, masked))

    # the whole response body is scanned (secrets + references), up to a cap
    is_js = _is_js_response(mime, ptemplate, resp_ct)
    is_html = _is_html_response(mime, resp_ct)
    # an undecodable content-encoding (e.g. brotli without the library) means
    # the body could not be scanned — flag it so the model can say so
    scan_truncated = (is_js or is_html) and (not resp_dec_ok or elem.find("truncated") is not None)
    js_refs: set = set()
    js_assets: set = set()
    stack_text = ""
    if is_js or is_html:
        scan_b = resp_body_b
        if len(scan_b) > MAX_SCAN_BYTES:
            scan_b, scan_truncated = scan_b[:MAX_SCAN_BYTES], True
        resp_full_r, s6 = redact_body(scan_b.decode("utf-8", "replace"))
        js_refs = extract_js_refs(resp_full_r) if is_js else extract_html_refs(resp_full_r)
        if is_js:
            hdr_map = next((v for k, v in resp_headers if k.lower() in ("sourcemap", "x-sourcemap")), None)
            js_assets = extract_script_assets(resp_full_r, host, ptemplate, hdr_map)
        resp_body_r = resp_full_r[:BODY_KEEP]
        stack_text = resp_full_r
    else:
        resp_body_r, s6 = redact_body(resp_body_b[:BODY_KEEP * 5].decode("utf-8", "replace"))
        resp_body_r = resp_body_r[:BODY_KEEP]

    stack = detect_stack({k.lower(): v for k, v in resp_headers},
                         [c["name"] for c in set_cookies] + cookie_names, stack_text, red_path, is_js or is_html)

    for chunk in (s0, s1, s2, s3, s4, s5, s6):
        secrets.extend(chunk)

    # a fully redacted view of the exchange for the report's HTTP panes.
    # The request line is rebuilt with the redacted path; every header value
    # and both bodies are already masked. No raw value is present.
    _ver = req_start.split(" ")[-1] if req_start.count(" ") >= 2 else "HTTP/1.1"
    _EV_BODY = 6000
    _hdr = lambda hs: [[k, redact_named(v)] for k, v in hs]   # scrub URLs in header values
    ev = {
        "request": {
            "line": redact_named(f"{method} {red_path} {_ver}".strip()),
            "headers": _hdr(req_headers_r),
            "body": redact_named(req_body_r[:_EV_BODY]),
            "truncated": len(req_body_r) > _EV_BODY,
        },
        "response": {
            "line": (resp_start or (f"HTTP/1.1 {status}" if status is not None else "")).strip(),
            "headers": _hdr(resp_headers_r),
            "body": redact_named(resp_body_r[:_EV_BODY]),
            "truncated": len(resp_body_r) > _EV_BODY or scan_truncated,
        },
    }

    return Exchange(
        index=idx,
        method=method,
        scheme=protocol,
        host=host,
        port=port,
        path=red_path,
        path_template=ptemplate,
        status=status,
        mime=mime,
        req_headers=req_headers_r,
        resp_headers=resp_headers_r,
        query_params=query_r,
        body_params=body_params_r,
        req_body=req_body_r,
        resp_body=resp_body_r,
        role=role,
        secrets=secrets,
        referer_host=referer_host,
        referer_path=referer_path,
        cookie_names=cookie_names,
        set_cookies=set_cookies,
        credentials=credentials,
        tech=tech_r,
        js_refs=sorted(js_refs, key=lambda r: (r[2], r[0] or "", r[1] or "", r[3])),
        js_assets=sorted(js_assets),
        stack=stack,
        scan_truncated=scan_truncated,
        gql_ops=gql_ops,
        preflight=preflight,
        ev=ev,
    )
