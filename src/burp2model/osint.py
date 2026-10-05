"""
Passive/active OSINT for a target host — our own collector, standard library only.

`build` reads a capture you already made and never touches the network. This
module is the opposite kind of work: it reaches out to the target and to public
records to describe the host's *external* surface — DNS, TLS certificate, HTTP
security headers, technology hints, email authentication, certificate-transparency
subdomains, registration (RDAP) and a small set of common ports.

Because it sends traffic to the target and to third-party services (a DoH
resolver, a CT-log index, an RDAP server), it is never run by `build`. The CLI
exposes it as a separate `osint` command with an explicit authorization gate.

Every check is best-effort and independently sandboxed: a failure is recorded as
an `error` on that section, never raised, so one dead lookup can't sink the run.
Nothing here is called a vulnerability; observations are facts + light notes.
"""

from __future__ import annotations

import concurrent.futures
import json
import re
import socket
import ssl
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone

from . import __version__

USER_AGENT = f"burp2model-osint/{__version__} (+https://falc0n-researcher.github.io/burp2model)"
DOH_URL = "https://dns.google/resolve"
CT_URL = "https://crt.sh/?q=%25.{domain}&output=json"
RDAP_BOOTSTRAP = "https://rdap.org/domain/{domain}"
ARCHIVE_URL = "https://archive.org/wayback/available?url={url}"

DNS_TYPES = ("A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA", "CAA")
COMMON_PORTS = {
    21: "ftp", 22: "ssh", 25: "smtp", 53: "dns", 80: "http", 110: "pop3",
    143: "imap", 443: "https", 445: "smb", 587: "smtp-submission", 993: "imaps",
    995: "pop3s", 3000: "http-alt", 3306: "mysql", 3389: "rdp", 5432: "postgres",
    6379: "redis", 8000: "http-alt", 8080: "http-proxy", 8443: "https-alt",
    9200: "elasticsearch", 27017: "mongodb",
}

SECURITY_HEADERS = {
    "strict-transport-security": "HSTS — forces HTTPS",
    "content-security-policy": "CSP — restricts resource origins",
    "x-frame-options": "clickjacking protection",
    "x-content-type-options": "MIME-sniffing protection",
    "referrer-policy": "controls Referer leakage",
    "permissions-policy": "restricts browser features",
    "cross-origin-opener-policy": "cross-origin isolation",
    "cross-origin-resource-policy": "cross-origin resource control",
}

# Response-header / body signatures → a technology name. Intentionally small and
# conservative; a hint is a hint, not a version scanner.
_TECH_HEADER_SIGNS = [
    ("server", re.compile(r"nginx", re.I), "nginx"),
    ("server", re.compile(r"apache", re.I), "Apache"),
    ("server", re.compile(r"cloudflare", re.I), "Cloudflare"),
    ("server", re.compile(r"gunicorn", re.I), "Gunicorn"),
    ("server", re.compile(r"envoy", re.I), "Envoy"),
    ("server", re.compile(r"microsoft-iis", re.I), "IIS"),
    ("server", re.compile(r"\bcowboy\b", re.I), "Cowboy/Erlang"),
    ("x-powered-by", re.compile(r"php", re.I), "PHP"),
    ("x-powered-by", re.compile(r"express", re.I), "Express"),
    ("x-powered-by", re.compile(r"asp\.net", re.I), "ASP.NET"),
    ("x-powered-by", re.compile(r"next\.js", re.I), "Next.js"),
    ("x-aspnet-version", re.compile(r"."), "ASP.NET"),
    ("x-generator", re.compile(r"drupal", re.I), "Drupal"),
    ("x-drupal-cache", re.compile(r"."), "Drupal"),
    ("x-shopify-stage", re.compile(r"."), "Shopify"),
    ("x-vercel-id", re.compile(r"."), "Vercel"),
    ("x-served-by", re.compile(r"cache", re.I), "Fastly/Varnish"),
    ("via", re.compile(r"varnish", re.I), "Varnish"),
    ("set-cookie", re.compile(r"laravel_session", re.I), "Laravel"),
    ("set-cookie", re.compile(r"csrftoken|django", re.I), "Django"),
    ("set-cookie", re.compile(r"JSESSIONID", re.I), "Java/Servlet"),
    ("set-cookie", re.compile(r"connect\.sid", re.I), "Express"),
    ("set-cookie", re.compile(r"_shopify", re.I), "Shopify"),
]
_TECH_BODY_SIGNS = [
    (re.compile(r"/_next/static/", re.I), "Next.js"),
    (re.compile(r"window\.__NUXT__", re.I), "Nuxt.js"),
    (re.compile(r"ng-version=", re.I), "Angular"),
    (re.compile(r"data-reactroot|__REACT_DEVTOOLS", re.I), "React"),
    (re.compile(r"wp-content/|wp-includes/", re.I), "WordPress"),
    (re.compile(r"/sites/default/files|Drupal.settings", re.I), "Drupal"),
    (re.compile(r"cdn\.shopify\.com", re.I), "Shopify"),
    (re.compile(r"static\.parastorage\.com|X-Wix", re.I), "Wix"),
    (re.compile(r"gstatic\.com/recaptcha|grecaptcha", re.I), "reCAPTCHA"),
    (re.compile(r"vue(?:\.runtime)?(?:\.min)?\.js|data-v-[0-9a-f]{8}", re.I), "Vue.js"),
]


@dataclass
class OsintResult:
    host: str
    domain: str
    generated_at: str
    dns: dict = field(default_factory=dict)
    tls: dict = field(default_factory=dict)
    http: dict = field(default_factory=dict)
    technology: list = field(default_factory=list)
    email_security: dict = field(default_factory=dict)
    subdomains: dict = field(default_factory=dict)
    registration: dict = field(default_factory=dict)
    files: dict = field(default_factory=dict)
    archive: dict = field(default_factory=dict)
    ports: dict = field(default_factory=dict)
    ip_geo: dict = field(default_factory=dict)
    notes: list = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _get_json(url: str, timeout: float):
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, "Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode("utf-8", "replace"))


# ------------------------------------------------------------------ DNS ------

def _doh(name: str, rtype: str, timeout: float) -> list[str]:
    data = _get_json(f"{DOH_URL}?name={urllib.parse.quote(name)}&type={rtype}", timeout)
    out = []
    for ans in data.get("Answer", []) or []:
        val = ans.get("data", "").strip()
        if val:
            out.append(val.strip('"') if rtype == "TXT" else val.rstrip("."))
    return out


def collect_dns(domain: str, host: str, timeout: float) -> dict:
    """Each record type is looked up independently, so one failed lookup
    cannot sink the rest."""
    records: dict = {}
    errors = []
    for rtype in DNS_TYPES:
        name = host if rtype in ("A", "AAAA", "CNAME") else domain
        try:
            vals = _doh(name, rtype, timeout)
            if vals:
                records[rtype] = vals
        except Exception as e:
            errors.append(f"{rtype}: {type(e).__name__}")
    if host != domain:
        for rtype in ("A", "AAAA", "CNAME"):
            try:
                vals = _doh(domain, rtype, timeout)
                if vals:
                    records.setdefault("apex_" + rtype, vals)
            except Exception as e:
                errors.append(f"apex_{rtype}: {type(e).__name__}")
    if errors:
        records["error"] = "; ".join(errors[:4])
    return records


# ------------------------------------------------------------------ TLS ------

def _rdn(seq) -> dict:
    out = {}
    for rdn in seq or ():
        for k, v in rdn:
            out[k] = v
    return out


def collect_tls(host: str, port: int, timeout: float) -> dict:
    info: dict = {}
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ss:
                cert = ss.getpeercert()
                info["tls_version"] = ss.version()
                cipher = ss.cipher()
                if cipher:
                    info["cipher"] = cipher[0]
        subject = _rdn(cert.get("subject"))
        issuer = _rdn(cert.get("issuer"))
        info["subject_cn"] = subject.get("commonName")
        info["issuer"] = issuer.get("organizationName") or issuer.get("commonName")
        info["not_before"] = cert.get("notBefore")
        info["not_after"] = cert.get("notAfter")
        sans = [v for t, v in cert.get("subjectAltName", ()) if t == "DNS"]
        info["san"] = sorted(set(sans))[:60]
        try:
            exp = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
            days = (exp - datetime.now(timezone.utc)).days
            info["days_until_expiry"] = days
            if days < 0:
                info["note"] = "certificate is expired"
            elif days < 14:
                info["note"] = f"certificate expires in {days} days"
        except Exception:
            pass
    except ssl.SSLCertVerificationError as e:
        info["error"] = f"certificate verification failed: {e.verify_message or e}"
        # still record what the handshake itself can tell us
        try:
            ctx2 = ssl.create_default_context()
            ctx2.check_hostname = False
            ctx2.verify_mode = ssl.CERT_NONE
            with socket.create_connection((host, port), timeout=timeout) as sock:
                with ctx2.wrap_socket(sock, server_hostname=host) as ss:
                    info["tls_version"] = ss.version()
                    cipher = ss.cipher()
                    if cipher:
                        info["cipher"] = cipher[0]
        except Exception:
            pass
    except Exception as e:
        info["error"] = f"{type(e).__name__}: {e}"
    return info


# ------------------------------------------------------------------ HTTP -----

def _fetch(url: str, timeout: float):
    """Fetch a URL. A 4xx/5xx still returns its status, headers and body —
    a 403 front page carries security headers worth reading. The header object
    is the raw message, so duplicate Set-Cookie headers survive (get_all)."""
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    ctx = ssl.create_default_context()
    opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=ctx))
    try:
        r = opener.open(req, timeout=timeout)
    except urllib.error.HTTPError as e:
        r = e
    with r:
        body = r.read(300_000)
        return r.status, r.headers, body.decode("utf-8", "replace"), r.geturl()


def collect_http(host: str, timeout: float) -> tuple[dict, str]:
    out: dict = {}
    body = ""
    try:
        status, headers, body, final = _fetch(f"https://{host}/", timeout)
        low = {k.lower(): v for k, v in headers.items()}
        out["status"] = status
        out["final_url"] = final
        present, missing = {}, []
        for h, why in SECURITY_HEADERS.items():
            if h in low:
                present[h] = low[h][:200]
            else:
                missing.append(h)
        out["security_headers_present"] = present
        out["security_headers_missing"] = missing
        interesting = ("server", "x-powered-by", "via", "x-cache", "cf-ray",
                       "x-frame-options", "content-type")
        out["headers"] = {k: low[k][:200] for k in interesting if k in low}
        cookies = headers.get_all("set-cookie") if hasattr(headers, "get_all") else []
        flags = []
        for c in cookies or []:
            name = c.split("=", 1)[0].strip()
            lc = c.lower()
            flags.append({"name": name[:80], "secure": "secure" in lc,
                          "httponly": "httponly" in lc,
                          "samesite": bool(re.search(r"samesite", lc))})
        if flags:
            out["cookies"] = flags
        out["_low_headers"] = low       # consumed by tech + email checks, stripped later
    except Exception as e:
        out["error"] = f"{type(e).__name__}: {e}"
    return out, body


def fingerprint_tech(low_headers: dict, body: str) -> list[dict]:
    found: dict[str, str] = {}
    for hname, rx, tech in _TECH_HEADER_SIGNS:
        val = low_headers.get(hname)
        if val and rx.search(val):
            found.setdefault(tech, f"header:{hname}")
    for rx, tech in _TECH_BODY_SIGNS:
        if body and rx.search(body):
            found.setdefault(tech, "body")
    gen = re.search(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)', body or "", re.I)
    if gen:
        found.setdefault(gen.group(1).strip()[:60], "meta:generator")
    return [{"name": k, "evidence": v} for k, v in sorted(found.items())]


# ------------------------------------------------------- email security -----

def collect_email_security(domain: str, dns_txt: list[str], timeout: float) -> dict:
    out: dict = {}
    try:
        spf = next((t for t in dns_txt if t.lower().startswith("v=spf1")), None)
        out["spf"] = spf
        if spf and re.search(r"[~-]all", spf):
            out["spf_note"] = "restrictive all qualifier present"
        elif spf:
            out["spf_note"] = "no restrictive all qualifier (+all/?all is weak)"
        else:
            out["spf_note"] = "no SPF record found"
        dmarc = _doh(f"_dmarc.{domain}", "TXT", timeout)
        rec = next((t for t in dmarc if t.lower().startswith("v=dmarc1")), None)
        out["dmarc"] = rec
        if rec:
            m = re.search(r"\bp\s*=\s*(none|quarantine|reject)", rec, re.I)
            out["dmarc_policy"] = m.group(1).lower() if m else "unset"
            if out["dmarc_policy"] == "none":
                out["dmarc_note"] = "policy p=none only monitors, does not block spoofing"
        else:
            out["dmarc_note"] = "no DMARC record found"
        for sel in ("default", "google", "selector1", "k1", "dkim"):
            got = _doh(f"{sel}._domainkey.{domain}", "TXT", timeout)
            if any("dkim1" in t.lower() or "p=" in t.lower() for t in got):
                out["dkim_selector_found"] = sel
                break
    except Exception as e:
        out["error"] = f"{type(e).__name__}: {e}"
    return out


# ---------------------------------------------------------- subdomains ------

def collect_subdomains(domain: str, timeout: float, cap: int = 200) -> dict:
    out: dict = {}
    try:
        data = _get_json(CT_URL.format(domain=domain), max(timeout, 15.0))
        names: set[str] = set()
        for row in data or []:
            for n in str(row.get("name_value", "")).splitlines():
                n = n.strip().lower().lstrip("*.")
                # exact domain or a true subdomain — never evilexample.com
                if (n == domain or n.endswith("." + domain)) and re.match(r"^[a-z0-9._-]+$", n):
                    names.add(n)
        ordered = sorted(names)
        out["count"] = len(ordered)
        out["source"] = "certificate transparency logs"
        out["names"] = ordered[:cap]
        if len(ordered) > cap:
            out["capped"] = cap
    except Exception as e:
        out["error"] = f"{type(e).__name__}: {e}"
    return out


# --------------------------------------------------------- registration -----

def collect_registration(domain: str, timeout: float) -> dict:
    out: dict = {}
    try:
        data = _get_json(RDAP_BOOTSTRAP.format(domain=domain), timeout)
        events = {e.get("eventAction"): e.get("eventDate") for e in data.get("events", []) or []}
        out["registration"] = events.get("registration")
        out["expiration"] = events.get("expiration")
        out["last_changed"] = events.get("last changed")
        out["status"] = data.get("status", [])[:8]
        registrar = None
        for ent in data.get("entities", []) or []:
            if "registrar" in (ent.get("roles") or []):
                for item in ent.get("vcardArray", [[], []])[1]:
                    if item and item[0] == "fn":
                        registrar = item[3]
        out["registrar"] = registrar
        ns = sorted({n.get("ldhName", "").lower().rstrip(".") for n in data.get("nameservers", []) or []})
        out["nameservers"] = [n for n in ns if n][:12]
    except Exception as e:
        out["error"] = f"{type(e).__name__}: {e}"
    return out


# ------------------------------------------------------------- files --------

def collect_files(host: str, timeout: float) -> dict:
    out: dict = {}
    for path, key in (("/robots.txt", "robots"), ("/.well-known/security.txt", "security_txt"),
                      ("/sitemap.xml", "sitemap"), ("/.well-known/change-password", "change_password")):
        try:
            status, _h, body, _u = _fetch(f"https://{host}{path}", timeout)
            if status == 200 and body.strip() and "<html" not in body[:200].lower():
                if key == "robots":
                    disallow = re.findall(r"(?im)^\s*Disallow:\s*(\S+)", body)
                    sitemaps = re.findall(r"(?im)^\s*Sitemap:\s*(\S+)", body)
                    out["robots"] = {"present": True, "disallow": disallow[:40],
                                     "sitemaps": sitemaps[:10]}
                elif key == "security_txt":
                    out["security_txt"] = {"present": True,
                                           "fields": re.findall(r"(?im)^([A-Za-z-]+):", body)[:12]}
                else:
                    out[key] = {"present": True, "bytes": len(body)}
        except Exception:
            continue
    return out


# ------------------------------------------------------------ archive -------

def collect_archive(host: str, timeout: float) -> dict:
    try:
        data = _get_json(ARCHIVE_URL.format(url=urllib.parse.quote(f"http://{host}/")), timeout)
        snap = data.get("archived_snapshots", {}).get("closest")
        if snap:
            return {"archived": True, "last_snapshot": snap.get("timestamp"), "url": snap.get("url")}
        return {"archived": False}
    except Exception as e:
        return {"error": f"{type(e).__name__}: {e}"}


# -------------------------------------------------------------- ports -------

def _probe(host: str, port: int, timeout: float) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except Exception:
        return False


def collect_ports(host: str, timeout: float, ports=None) -> dict:
    ports = ports or COMMON_PORTS
    open_ports = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=16) as ex:
        futs = {ex.submit(_probe, host, p, timeout): p for p in ports}
        for fut in concurrent.futures.as_completed(futs):
            if fut.result():
                p = futs[fut]
                open_ports.append({"port": p, "service": ports.get(p, "?")})
    open_ports.sort(key=lambda d: d["port"])
    return {"scanned": len(ports), "open": open_ports,
            "note": "TCP connect only; a closed probe is not proof a service is absent"}


def _resolve_ip(host: str, dns: dict) -> str | None:
    a = dns.get("A") or []
    if a:
        return a[0]
    try:
        return socket.gethostbyname(host)
    except Exception:
        return None


def collect_ip_geo(ip: str, timeout: float) -> dict:
    if not ip:
        return {}
    try:
        data = _get_json(f"https://rdap.org/ip/{ip}", timeout)
        return {"ip": ip, "network": data.get("name"),
                "handle": data.get("handle"), "country": data.get("country"),
                "type": data.get("type")}
    except Exception as e:
        return {"ip": ip, "error": f"{type(e).__name__}: {e}"}


# ------------------------------------------------------------- orchestrate ---

def run(host: str, *, timeout: float = 6.0, want_ports: bool = False,
        want_subdomains: bool = True, port_timeout: float = 1.5) -> OsintResult:
    """Collect the OSINT surface for one host. Each section is independent."""
    from .domains import registrable_domain

    host = host.strip().lower().split("/")[0].split(":")[0]
    domain = registrable_domain(host)
    res = OsintResult(host=host, domain=domain, generated_at=_now())

    res.dns = collect_dns(domain, host, timeout)
    ip = _resolve_ip(host, res.dns)

    res.tls = collect_tls(host, 443, timeout)
    res.http, body = collect_http(host, timeout)
    low = res.http.pop("_low_headers", {})
    res.technology = fingerprint_tech(low, body)
    res.email_security = collect_email_security(domain, res.dns.get("TXT", []), timeout)
    if want_subdomains:
        res.subdomains = collect_subdomains(domain, timeout)
    res.registration = collect_registration(domain, timeout)
    res.files = collect_files(host, timeout)
    res.archive = collect_archive(host, timeout)
    if ip:
        res.ip_geo = collect_ip_geo(ip, timeout)
    if want_ports:
        res.ports = collect_ports(host, port_timeout)

    status = res.http.get("status")
    if isinstance(status, int) and status >= 400:
        res.notes.append(f"front page answered {status}: header and cookie observations "
                         "describe that error page, not the application")
    elif res.http.get("security_headers_missing"):
        res.notes.append(f"{len(res.http['security_headers_missing'])} common security "
                         "header(s) not sent on the front page")
    if res.tls.get("note"):
        res.notes.append("TLS: " + res.tls["note"])
    if res.email_security.get("dmarc_note"):
        res.notes.append("Email: " + res.email_security["dmarc_note"])
    return res


def render_text(r: OsintResult) -> str:
    """A compact, human-readable summary. No value is invented; gaps say so."""
    L: list[str] = []
    L.append(f"OSINT · {r.host}  (domain {r.domain})   {r.generated_at}")
    L.append("")

    def line(k, v):
        L.append(f"  {k:<16} {v}")

    L.append("DNS")
    if r.dns.get("error"):
        line("error", r.dns["error"])
    for t in DNS_TYPES:
        if r.dns.get(t):
            line(t, ", ".join(r.dns[t][:6]) + (" …" if len(r.dns[t]) > 6 else ""))
    L.append("")

    L.append("TLS")
    if r.tls.get("error"):
        line("error", r.tls["error"])
    else:
        line("version", r.tls.get("tls_version"))
        line("issuer", r.tls.get("issuer"))
        line("expires", f"{r.tls.get('not_after')} ({r.tls.get('days_until_expiry')} days)")
        line("SAN", f"{len(r.tls.get('san', []))} names")
    L.append("")

    L.append("HTTP")
    if r.http.get("error"):
        line("error", r.http["error"])
    else:
        line("status", r.http.get("status"))
        line("server", r.http.get("headers", {}).get("server", "—"))
        line("sec headers", f"{len(r.http.get('security_headers_present', {}))} present, "
                            f"{len(r.http.get('security_headers_missing', []))} missing")
        if r.http.get("security_headers_missing"):
            line("  missing", ", ".join(r.http["security_headers_missing"]))
    L.append("")

    if r.technology:
        L.append("Technology")
        line("detected", ", ".join(t["name"] for t in r.technology))
        L.append("")

    L.append("Email security")
    line("SPF", r.email_security.get("spf_note", "—"))
    line("DMARC", r.email_security.get("dmarc_policy") or r.email_security.get("dmarc_note", "—"))
    if r.email_security.get("dkim_selector_found"):
        line("DKIM", f"selector '{r.email_security['dkim_selector_found']}' found")
    L.append("")

    if r.subdomains.get("count") is not None:
        L.append(f"Subdomains ({r.subdomains['count']} via certificate transparency)")
        for n in r.subdomains.get("names", [])[:15]:
            L.append(f"    {n}")
        if r.subdomains.get("capped"):
            L.append(f"    … capped at {r.subdomains['capped']}")
        L.append("")

    if r.registration and not r.registration.get("error"):
        L.append("Registration")
        line("registrar", r.registration.get("registrar"))
        line("created", r.registration.get("registration"))
        line("expires", r.registration.get("expiration"))
        L.append("")

    if r.ip_geo and not r.ip_geo.get("error"):
        L.append("Hosting")
        line("IP", r.ip_geo.get("ip"))
        line("network", r.ip_geo.get("network"))
        if r.ip_geo.get("country"):
            line("country", r.ip_geo.get("country"))
        L.append("")

    if r.files:
        L.append("Well-known files")
        if r.files.get("robots"):
            line("robots.txt", f"{len(r.files['robots'].get('disallow', []))} Disallow rule(s)")
        if r.files.get("security_txt"):
            line("security.txt", "present")
        if r.files.get("sitemap"):
            line("sitemap.xml", "present")
        L.append("")

    if r.archive.get("archived"):
        L.append("Archive")
        line("wayback", f"last snapshot {r.archive.get('last_snapshot')}")
        L.append("")

    if r.ports.get("open"):
        L.append("Open ports (TCP connect)")
        for p in r.ports["open"]:
            L.append(f"    {p['port']:<6} {p['service']}")
        L.append("")

    if r.notes:
        L.append("Notes")
        for n in r.notes:
            L.append(f"  · {n}")
        L.append("")
    L.append("Observations only — nothing here is a vulnerability. Authorized targets only.")
    return "\n".join(L)
