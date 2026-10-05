"""
Redaction — the trust core of burp2model.

Burp exports contain live session tokens, cookies, API keys and PII. This
module masks every *value* before anything is written to disk, while keeping
the *names and structure* the model needs. That includes URL paths: a reset
token or an email in `/reset/alice@corp.com/Zx9kQ2pLm7Rt` is a value too.

A credential is recorded by a keyed fingerprint (HMAC-SHA256, truncated), its
length and its Shannon entropy — never the value. The fingerprint is keyed so
that someone holding the outputs cannot confirm a guess ("is this the hash of
alice@corp.com?") without also holding the key. The key comes from
BURP2MODEL_FP_KEY, from `set_fingerprint_key()` (the CLI keeps one per user,
outside the output directory), or a random per-process key.

Rule: names and shape stay; values die. `password=secret123` becomes
`password=[REDACTED]`, never a dropped field.
"""

from __future__ import annotations

import hashlib
import hmac
import math
import os
import re
import urllib.parse
from dataclasses import dataclass

# Header names whose values are always masked (case-insensitive).
SENSITIVE_HEADERS = {
    "authorization",
    "proxy-authorization",
    "cookie",
    "set-cookie",
    "x-api-key",
    "x-auth-token",
    "x-csrf-token",
    "x-xsrf-token",
    "api-key",
}

# Header names that *contain* any of these are masked too.
SENSITIVE_HEADER_HINTS = ("token", "secret", "apikey", "api-key", "auth", "session")

# Body/query parameter names whose values are masked.
SENSITIVE_PARAM_HINTS = (
    "password", "passwd", "pwd", "passcode", "secret", "token", "apikey",
    "api_key", "access_key", "refresh_token", "id_token", "client_secret",
    "private_key", "session", "sid", "csrf", "auth", "signature", "sig",
    "code", "otp", "pin", "ssn", "cvv", "cvc", "assertion",
    # security-question answers and recovery phrases are credentials too
    "answer", "passphrase", "totp", "mfa",
    # session and anti-forgery names that do not say "session"/"token": PHPSESSID, ASP.NET_SessionId,
    # WordPress/Django/.NET nonces, __VIEWSTATE and friends
    "sessid", "nonce", "xsrf", "viewstate", "eventvalidation", "verification",
)

# Names that are innocuous alone (`new=true`) but are the password fields of a
# change-password form when they travel together: `current` / `new` / `repeat`
# (Juice Shop), `old_` / `confirm`, … Two or more of them in one query string,
# form or JSON object means a credential change, and every one of them is masked.
_CREDENTIAL_GROUP = {"current", "new", "repeat", "confirm", "old", "retype", "verify",
                     "again", "newpass", "oldpass", "confirmation"}

# Value-shaped patterns masked wherever they appear (bodies included).
VALUE_PATTERNS = [
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{4,}\b")),
    ("openai_key", re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b")),
    ("aws_key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("google_key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
    ("slack_token", re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b")),
    ("github_token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b")),
    ("stripe_key", re.compile(r"\b[rsp]k_(?:live|test)_[A-Za-z0-9]{16,}\b")),
    ("private_key", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    ("card", re.compile(r"\b(?:\d[ -]?){13,19}\b")),
    ("email", re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")),
]

REDACTED = "[REDACTED]"

_KEY: bytes | None = None


def set_fingerprint_key(key: bytes) -> None:
    """Key every fingerprint made from now on (the CLI calls this)."""
    global _KEY
    _KEY = key


def _key() -> bytes:
    global _KEY
    if _KEY is None:
        env = os.environ.get("BURP2MODEL_FP_KEY")
        _KEY = env.encode("utf-8") if env else os.urandom(32)
    return _KEY


@dataclass(frozen=True)
class SecretFingerprint:
    """A credential recorded without its value."""
    kind: str          # jwt, openai_key, authorization, ...
    hmac_12: str       # first 12 hex chars of HMAC-SHA256(key, value)
    length: int
    entropy: float     # Shannon bits/char

    def as_dict(self) -> dict:
        return {
            "kind": self.kind,
            "hmac_12": self.hmac_12,
            "length": self.length,
            "entropy": round(self.entropy, 2),
        }


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts: dict[str, int] = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def fingerprint(value: str, kind: str = "value") -> SecretFingerprint:
    digest = hmac.new(_key(), value.encode("utf-8", "replace"), hashlib.sha256).hexdigest()[:12]
    return SecretFingerprint(kind, digest, len(value), shannon_entropy(value))


def _luhn_ok(digits: str) -> bool:
    total = 0
    for i, ch in enumerate(reversed(digits)):
        d = int(ch)
        if i % 2:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def _is_sensitive_header(name: str) -> bool:
    low = name.strip().lower()
    if low in SENSITIVE_HEADERS:
        return True
    return any(h in low for h in SENSITIVE_HEADER_HINTS)


def _is_sensitive_param(name: str) -> bool:
    # split camelCase before lowering so "userPin" tokenises as user_pin
    low = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", name.strip()).lower()
    # match on name tokens so "code" hits `code`/`auth_code` but not `zipcode`
    tokens = set(re.split(r"[^a-z0-9]+", low)) | {low}
    for h in SENSITIVE_PARAM_HINTS:
        if len(h) <= 4:
            if h in tokens:
                return True
        elif h in low:
            return True
    return False


# `SQLITE_ERROR`, `ERR_BAD_REQUEST`, `ECONNRESET`-style constants are status
# words, not secrets — `{"code":"SQLITE_ERROR"}` is exactly what an analyst needs.
_ERROR_CONSTANT_RE = re.compile(r"^[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+$|^E[A-Z]{4,}$")


def _is_error_constant(value: str) -> bool:
    return bool(_ERROR_CONSTANT_RE.match(value.strip().strip('"')))


def _leaf(name: str) -> str:
    """`$.user.newPass` -> `new_pass`; `a[b]` -> `b` (the field a value sits in)."""
    parts = [p for p in re.split(r"[.\[\]$]+", name.strip()) if p]
    leaf = parts[-1] if parts else ""
    return re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", leaf).lower().replace("_", "")


def _is_credential_group(names) -> bool:
    return len({_leaf(n) for n in names} & _CREDENTIAL_GROUP) >= 2


def redact_headers(headers: list[tuple[str, str]]) -> tuple[list[tuple[str, str]], list[SecretFingerprint]]:
    """Mask sensitive header values; return masked headers + fingerprints."""
    out: list[tuple[str, str]] = []
    prints: list[SecretFingerprint] = []
    for name, value in headers:
        if _is_sensitive_header(name) and value:
            prints.append(fingerprint(value, kind=name.strip().lower()))
            out.append((name, REDACTED))
        else:
            masked, more = redact_value_patterns(value)
            prints.extend(more)
            out.append((name, masked))
    return out, prints


def redact_value_patterns(text: str) -> tuple[str, list[SecretFingerprint]]:
    """Mask value-shaped secrets/PII anywhere in a string."""
    prints: list[SecretFingerprint] = []
    if not text:
        return text, prints
    for kind, pattern in VALUE_PATTERNS:
        def _sub(m: re.Match) -> str:
            val = m.group(0)
            if kind == "card":
                digits = re.sub(r"\D", "", val)
                # 13-19 digits alone is a timestamp as often as a card
                if not (13 <= len(digits) <= 19) or not _luhn_ok(digits):
                    return val
            prints.append(fingerprint(val, kind=kind))
            return f"[REDACTED:{kind}]"
        text = pattern.sub(_sub, text)
    return text, prints


def redact_params(params: list[tuple[str, str]]) -> tuple[list[tuple[str, str]], list[SecretFingerprint]]:
    """Mask sensitive param values by name, then value-shape scan the rest."""
    out: list[tuple[str, str]] = []
    prints: list[SecretFingerprint] = []
    group = _is_credential_group(n for n, _ in params)
    for name, value in params:
        if (_is_sensitive_param(name) or (group and _leaf(name) in _CREDENTIAL_GROUP)) \
                and value and not _is_error_constant(value):
            prints.append(fingerprint(value, kind=name.strip().lower()))
            out.append((name, REDACTED))
        else:
            masked, more = redact_value_patterns(value)
            prints.extend(more)
            out.append((name, masked))
    return out, prints


def redact_body(body: str) -> tuple[str, list[SecretFingerprint]]:
    """Value-shape scan of a raw body (JSON/form/text)."""
    return redact_value_patterns(body)


# Deep, name-based masking for text that is *stored verbatim* (the report's
# request/response panes). The structured pipeline masks sensitive params by
# name, but a raw body/header kept as text also needs the value beside a
# sensitive name masked even when the value has no tell-tale shape
# (e.g. `password=hunter2`, a `session=` inside a Referer URL). The name is
# matched generically and judged by _is_sensitive_param, so `new_password`,
# `accessToken` and `user[password]` are caught, not just the exact hints.
_KV_ANY = re.compile(r"(^|[?&;,#\s])([A-Za-z0-9_.\-\[\]]{1,64})(\s*=\s*)([^&;#\s\"'<>]+)")
_JSON_ANY = re.compile(r'"((?:[^"\\]|\\.){1,64})"(\s*:\s*)("(?:[^"\\]|\\.)*"|-?\d[\d.eE+-]*|true|false|null)')


_INPUT_TAG = re.compile(r"<input\b[^>]*>", re.I)
_ATTR_NAME = re.compile(r"""\bname\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))""", re.I)
_ATTR_VALUE = re.compile(r"""(\bvalue\s*=\s*)(?:"[^"]*"|'[^']*'|[^\s>]+)""", re.I)
_HEADER_LINE = re.compile(
    r"(?i)\b(Cookie|Set-Cookie|Authorization|Proxy-Authorization|X-Auth-Token|X-API-Key|X-CSRF-Token|"
    r"X-XSRF-Token)(\s*:\s*)[^\r\n<]+")


def redact_named(text: str) -> str:
    """Mask values that sit next to a sensitive name in form/query/JSON text.

    Complements value-shape redaction; assumes shape-based masking already ran.
    Returns text only — fingerprints are recorded by the structured pipeline.
    """
    if not text:
        return text

    names = [m.group(2) for m in _KV_ANY.finditer(text)] + \
            [m.group(1) for m in _JSON_ANY.finditer(text)]
    group = _is_credential_group(names)
    sens = lambda n: _is_sensitive_param(n) or (group and _leaf(n) in _CREDENTIAL_GROUP)

    def _kv(m: re.Match) -> str:
        if sens(m.group(2)) and m.group(4) != REDACTED and not _is_error_constant(m.group(4)):
            return m.group(1) + m.group(2) + m.group(3) + REDACTED
        return m.group(0)

    def _json(m: re.Match) -> str:
        if sens(m.group(1)) and not _is_error_constant(m.group(3)):
            return '"' + m.group(1) + '"' + m.group(2) + '"' + REDACTED + '"'
        return m.group(0)

    def _input(m: re.Match) -> str:
        tag = m.group(0)
        n = _ATTR_NAME.search(tag)
        name = next((g for g in (n.groups() if n else ()) if g), "")
        if name and sens(name):
            return _ATTR_VALUE.sub(lambda v: v.group(1) + '"' + REDACTED + '"', tag, count=1)
        return tag

    # an HTML hidden field (`<input name="user_token" value="…">`) is a name/value pair too,
    # and a page that echoes request headers (`Cookie: PHPSESSID=…`) carries them in its body
    text = _INPUT_TAG.sub(_input, text)
    text = _HEADER_LINE.sub(lambda m: m.group(1) + m.group(2) + REDACTED, text)
    text = _KV_ANY.sub(_kv, text)
    text = _JSON_ANY.sub(_json, text)
    return text


# ---------------------------------------------------------------- paths ------

_UUID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
_HEX_RE = re.compile(r"^[0-9a-fA-F]{24,}$")
_HEXPAIR_RE = re.compile(r"^[0-9a-fA-F]{3,8}-[0-9a-fA-F]{8,}$")
_CODE_RE = re.compile(r"^[A-Z0-9]{8,24}$")
_TOKENISH_RE = re.compile(r"^[A-Za-z0-9_\-+=~.]{12,}$")
_B64ISH_RE = re.compile(r"^[A-Za-z0-9_\-+/=]{32,}$")


def classify_segment(seg: str) -> str | None:
    """Placeholder for a path segment that is a value, or None to keep it.

    Structural placeholders ({id}, {uuid}, {hash}) collapse identifiers;
    secret placeholders ({email}, {jwt}, {token}, ...) hide credentials/PII
    that some apps put in the path (reset links, magic links, signed URLs).
    """
    if not seg or (seg.startswith("{") and seg.endswith("}")):
        return None
    s = urllib.parse.unquote(seg)
    if s.isdigit():
        return "{id}"
    if _UUID_RE.match(s):
        return "{uuid}"
    if _HEX_RE.match(s):
        return "{hash}"
    # `5267-f73dcd000abcc353` — a short hex prefix, a dash, a long hex tail
    # (Juice Shop order ids, many framework-generated ids): an id, not a route
    if _HEXPAIR_RE.match(s) and any(c.isdigit() for c in s):
        return "{id}"
    for kind, pattern in VALUE_PATTERNS:
        m = pattern.search(s)
        if m is None:
            continue
        if kind == "card":
            digits = re.sub(r"\D", "", m.group(0))
            if not _luhn_ok(digits):
                continue
        return "{" + kind + "}"
    # `WMNSDY2019` — a shouting alphanumeric code with letters and digits:
    # a coupon / voucher / invite code, which is a value, not a route name
    if _CODE_RE.match(s) and any(c.isdigit() for c in s) and any(c.isalpha() for c in s):
        return "{code}"
    if _B64ISH_RE.match(s) and shannon_entropy(s) >= 3.5:
        return "{token}"
    if _TOKENISH_RE.match(s) and "." not in s:
        classes = sum(bool(re.search(p, s)) for p in ("[a-z]", "[A-Z]", "[0-9]"))
        digits = sum(c.isdigit() for c in s)
        if classes == 3 and digits >= 2 and shannon_entropy(s) >= 3.0:
            return "{token}"
    return None


def _matrix_split(seg: str):
    """Split a `name;k=v;k2=v2` matrix segment (RFC 3986 path params) or None."""
    if ";" not in seg:
        return None
    base, *parts = seg.split(";")
    return base, [p.partition("=") for p in parts]


def _template_matrix(seg: str) -> str | None:
    """Template a matrix segment: `app;jsessionid=1A2B` → `app;jsessionid={value}`."""
    m = _matrix_split(seg)
    if m is None:
        return None
    base, parts = m
    out = [classify_segment(base) or base]
    for k, eq, v in parts:
        if eq and v and (_is_sensitive_param(k) or classify_segment(v)):
            out.append(f"{k}={{value}}")
        else:
            out.append(k + eq + v)
    return ";".join(out)


# `index-1f38ebe00b8f1bef.js`, `4969.7d2c1afc61e06b53.js`: a build hash in a static asset's name
# changes on every deploy, so it is a placeholder, or two builds would share no script nodes.
_HASHED_ASSET = re.compile(r"^(.+?[-._])[0-9a-fA-F]{8,32}(\.(?:js|mjs|css|map|woff2?|png|jpe?g|svg|webp))$")


def template_path(path: str) -> str:
    """Collapse ids and value-like segments to placeholders; drop query/fragment."""
    clean = path.split("?", 1)[0].split("#", 1)[0]
    out = []
    for s in clean.split("/"):
        rep = _template_matrix(s)
        if rep is None:
            rep = classify_segment(s)
        if rep is None:
            hm = _HASHED_ASSET.match(s)
            if hm and not s.endswith((".min.js", ".min.css")) and re.search(r"\d", s[len(hm.group(1)):-len(hm.group(2))] or ""):
                rep = hm.group(1) + "{hash}" + hm.group(2)
        out.append(rep if rep is not None else s)
    templated = "/".join(out)
    return templated or "/"


def redact_path(path: str) -> tuple[str, list[SecretFingerprint]]:
    """Redact a raw request path (segments + query values), keeping its shape."""
    prints: list[SecretFingerprint] = []
    base, sep, query = path.partition("?")
    query = query.split("#", 1)[0]
    segs = []
    for s in base.split("#", 1)[0].split("/"):
        mx = _matrix_split(s)
        if mx is not None:
            mbase, parts = mx
            out_parts = [mbase]
            for k, eq, v in parts:
                if eq and v and (_is_sensitive_param(k) or classify_segment(v)):
                    prints.append(fingerprint(urllib.parse.unquote(v), kind="path:" + k.lower()))
                    out_parts.append(f"{k}={REDACTED}")
                else:
                    out_parts.append(k + eq + v)
            segs.append(";".join(out_parts))
            continue
        rep = classify_segment(s)
        if rep is not None and rep not in ("{id}", "{uuid}", "{hash}"):
            prints.append(fingerprint(urllib.parse.unquote(s), kind="path:" + rep.strip("{}")))
            segs.append(rep)
        else:
            segs.append(s)
    out = "/".join(segs) or "/"
    if sep:
        pairs = urllib.parse.parse_qsl(query, keep_blank_values=True)
        red, more = redact_params(pairs)
        prints.extend(more)
        out += "?" + urllib.parse.urlencode(red, safe="[]:{}")
    return out, prints


# Query parameters that choose WHICH PAGE a front controller renders
# (`index.php?page=login`, `app.cgi?action=cart`). A path template that drops the
# query collapses every such page into one node, so these are kept in the template.
ROUTE_PARAMS = ("page", "action", "view", "module", "route", "section", "tab", "controller",
                "do", "cmd", "mode", "screen", "op", "task", "act", "content", "p")
_ROUTE_VALUE = re.compile(r"^[A-Za-z0-9_.\-/]{1,60}$")
_STATIC_PATH = re.compile(r"(?i)\.(?:png|jpe?g|gif|svg|ico|webp|css|js|mjs|map|woff2?|ttf|eot|json|txt|xml|pdf)$")


def route_template(path_with_query: str, base: str) -> str:
    """`base` plus the page-selecting query parameters: /index.php?page=login.php.

    Numeric values (`?page=2` is pagination), anything shaped like a secret or an id,
    and static assets are left out, so the template stays a small, stable set.
    """
    if _STATIC_PATH.search(base):
        return base
    query = path_with_query.partition("?")[2].split("#", 1)[0]
    keep: dict[str, str] = {}
    for k, v in urllib.parse.parse_qsl(query, keep_blank_values=True):
        k = k.lower()
        if (k in ROUTE_PARAMS and k not in keep and _ROUTE_VALUE.match(v) and not v.isdigit()
                and classify_segment(v) is None and not _is_sensitive_param(k)):
            keep[k] = v
    if not keep:
        return base
    return base + "?" + "&".join(f"{k}={v}" for k, v in sorted(keep.items())[:2])
