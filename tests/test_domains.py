"""
Registrable-domain resolution via the Public Suffix List, and the OSINT
collector's offline-testable parts (parsing, fingerprinting, summarising).
Nothing here touches the network.
"""

import json

import pytest

from burp2model.domains import public_suffix, registrable_domain, same_site
from burp2model import osint
from burp2model.context import osint_summary, context_package
from burp2model import parse_items, build


# --------------------------------------------------- public suffix list ------

@pytest.mark.parametrize("host,expected", [
    # the multi-label suffixes a "last two labels" rule gets wrong
    ("api.shop.bank.in", "shop.bank.in"),
    ("www.aauysh.co.in", "aauysh.co.in"),
    ("shop.example.co.in", "example.co.in"),
    ("portal.other.bank.in", "other.bank.in"),
    ("api.shop.co.uk", "shop.co.uk"),
    ("a.b.example.com.au", "example.com.au"),
    # plain gTLD
    ("www.example.com", "example.com"),
    ("deep.sub.example.com", "example.com"),
    ("example.com", "example.com"),
    # PSL private section: a github.io user site is its own registrable domain
    ("user.github.io", "user.github.io"),
    ("a.b.user.github.io", "user.github.io"),
    # literals and single labels pass through
    ("10.0.0.1", "10.0.0.1"),
    ("localhost", "localhost"),
    ("host:8443", "host"),
    ("shop.example.com:8443", "example.com"),
])
def test_registrable_domain(host, expected):
    assert registrable_domain(host) == expected


def test_wildcard_and_exception_rules():
    # *.ck makes every foo.ck a suffix, but !www.ck is an exception
    assert public_suffix("foo.bar.ck") == "bar.ck"
    assert registrable_domain("a.foo.ck") == "a.foo.ck"
    assert public_suffix("www.ck") == "ck"
    assert registrable_domain("www.ck") == "www.ck"


def test_idn_normalisation():
    assert registrable_domain("münchen.de") == registrable_domain("xn--mnchen-3ya.de")


def test_same_site():
    assert same_site("api.shop.co.in", "www.shop.co.in")
    assert not same_site("api.shop.bank.in", "api.other.bank.in")


def test_env_override_uses_supplied_list(tmp_path, monkeypatch):
    psl = tmp_path / "psl.dat"
    psl.write_text("// test\nexample\ncustom.example\n")
    monkeypatch.setenv("BURP2MODEL_PSL", str(psl))
    from burp2model import domains
    domains._load.cache_clear()
    assert registrable_domain("a.b.custom.example") == "b.custom.example"
    assert registrable_domain("a.example") == "a.example"
    domains._load.cache_clear()


def test_model_uses_psl_for_scope(tmp_path):
    from test_gaps import export, item
    m = build(list(parse_items(export(tmp_path, [
        item(host="www.shop.co.in", path="/"),
        item(host="www.shop.co.in", path="/p"),
        item(host="api.shop.co.in", path="/v1/x", mime="JSON", resp_body="{}"),
        item(host="evil.co.in", path="/", mime="JSON", resp_body="{}"),
    ]))), name="t")
    assert m.scope == ["shop.co.in"]
    types = {n.label: n.type for n in m.nodes.values() if n.type in ("host", "third_party")}
    assert types["api.shop.co.in"] == "host"          # same registrable domain
    assert types["evil.co.in"] == "third_party"       # different site under co.in


# ------------------------------------------------ osint: offline parsing -----

def test_fingerprint_tech_from_headers_and_body():
    tech = osint.fingerprint_tech(
        {"server": "nginx", "x-powered-by": "Express", "set-cookie": "JSESSIONID=abc"},
        '<div data-reactroot></div><meta name="generator" content="Hugo 0.1">')
    names = {t["name"] for t in tech}
    assert {"nginx", "Express", "Java/Servlet", "React", "Hugo 0.1"} <= names


def test_common_ports_and_security_headers_defined():
    # guardrails on the collector's constants, so a bad edit is caught
    assert osint.COMMON_PORTS[443] == "https" and osint.COMMON_PORTS[22] == "ssh"
    assert "strict-transport-security" in osint.SECURITY_HEADERS
    assert "content-security-policy" in osint.SECURITY_HEADERS


def test_render_text_no_crash_on_sparse_result():
    r = osint.OsintResult(host="x.test", domain="x.test", generated_at="now",
                          dns={"error": "timeout"}, tls={"error": "refused"},
                          http={"error": "refused"})
    text = osint.render_text(r)
    assert "OSINT · x.test" in text
    assert "nothing here is a vulnerability" in text.lower()


def test_osint_summary_trims_and_labels():
    raw = {
        "host": "shop.test", "generated_at": "2026-01-01T00:00:00Z",
        "dns": {"A": ["1.2.3.4"], "MX": ["mail"], "SOA": ["x"]},
        "tls": {"tls_version": "TLSv1.3", "issuer": "Let's Encrypt", "days_until_expiry": 40,
                "cipher": "drop-me"},
        "http": {"security_headers_missing": ["content-security-policy"]},
        "technology": [{"name": "nginx", "evidence": "header:server"}],
        "email_security": {"dmarc_policy": "none", "dmarc_note": "monitor only", "spf_note": "ok"},
        "subdomains": {"count": 3, "names": ["a.shop.test", "b.shop.test"]},
        "registration": {"registrar": "MarkMonitor"},
        "ports": {"open": [{"port": 443, "service": "https"}]},
        "notes": ["a note"],
    }
    s = osint_summary(raw)
    assert s["dns"] == {"A": ["1.2.3.4"], "MX": ["mail"]}      # SOA dropped
    assert "cipher" not in s["tls"]
    assert s["technology"] == ["nginx"]
    assert s["open_ports"] == [443]
    assert s["subdomains_count"] == 3
    assert "provenance" in s


def test_report_map_includes_osint_infrastructure(tmp_path):
    from burp2model.report import build_payload
    from test_gaps import export, item
    m = build(list(parse_items(export(tmp_path, [item(path="/"), item(path="/p")]))), name="t")
    osint = {"host": "t.example.com", "tls": {"issuer": "Let's Encrypt", "not_after": "x"},
             "dns": {"A": ["1.2.3.4"], "MX": ["10 mail"]}, "technology": [{"name": "nginx"}],
             "ip_geo": {"network": "Cloudflare, Inc."}, "email_security": {"dmarc_policy": "reject"},
             "subdomains": {"count": 5}}
    p = build_payload(m, osint=osint)
    infra = [n for n in p["graph"]["nodes"] if n["type"] == "infra"]
    labels = " ".join(n["label"] for n in infra)
    assert "TLS" in labels and "nginx" in labels and "1.2.3.4" in labels and "Cloudflare" in labels
    assert p["osint"]["technology"] == ["nginx"]
    # an infra node hangs off the app host; the osint host is not a node in
    # this model, so edges anchor to the model's primary host, never dangling
    node_ids = {n["id"] for n in p["graph"]["nodes"]}
    host_edges = [e for e in p["graph"]["edges"] if e["type"] == "OSINT"]
    assert host_edges and all(e["s"] in node_ids for e in host_edges)
    # without osint there are no infra nodes
    assert not [n for n in build_payload(m)["graph"]["nodes"] if n["type"] == "infra"]


def test_context_package_includes_osint_and_extra_rule(tmp_path):
    from test_gaps import export, item
    m = build(list(parse_items(export(tmp_path, [item(path="/"), item(path="/p")]))), name="t")
    raw = {"host": "shop.test", "generated_at": "t", "technology": [{"name": "nginx", "evidence": "h"}],
           "subdomains": {"count": 2, "names": ["a.shop.test"]}}
    pkg = context_package(m, osint=raw)
    assert pkg["osint"]["technology"] == ["nginx"]
    assert any("OSINT is external recon" in r for r in pkg["rules"])
    # without osint, no key and no extra rule
    pkg2 = context_package(m)
    assert "osint" not in pkg2
    assert not any("OSINT is external recon" in r for r in pkg2["rules"])
    json.dumps(pkg)   # serialisable
