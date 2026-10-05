"""
Registrable domains from the Public Suffix List.

`api.sbi.bank.in` belongs to `sbi.bank.in`, `shop.aayush.co.in` to
`aayush.co.in`, and `user.github.io` is its own site, not part of
`github.io`. A "last two labels" rule gets all three wrong; the Public Suffix
List gets them right.

A snapshot of the list ships inside the package (data/public_suffix_list.dat),
so resolving a domain never touches the network. To use a newer list, point
BURP2MODEL_PSL at a local copy of https://publicsuffix.org/list/public_suffix_list.dat.

The algorithm is the one publicsuffix.org specifies: the longest matching rule
wins, `*` matches one label, and `!` exception rules beat wildcards.
"""

from __future__ import annotations

import os
import re
from functools import lru_cache

_BUNDLED = os.path.join(os.path.dirname(__file__), "data", "public_suffix_list.dat")
_IPV4_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")


def _to_ascii(label: str) -> str:
    try:
        return label.encode("idna").decode("ascii")
    except UnicodeError:
        return label


@lru_cache(maxsize=4)
def _load(path: str) -> tuple[frozenset, frozenset, frozenset]:
    rules, wildcards, exceptions = set(), set(), set()
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("//"):
                continue
            rule = line.split()[0].lower()
            if rule.startswith("!"):
                exceptions.add(".".join(_to_ascii(p) for p in rule[1:].split(".")))
            elif rule.startswith("*."):
                wildcards.add(".".join(_to_ascii(p) for p in rule[2:].split(".")))
            else:
                rules.add(".".join(_to_ascii(p) for p in rule.split(".")))
    return frozenset(rules), frozenset(wildcards), frozenset(exceptions)


def _rules():
    return _load(os.environ.get("BURP2MODEL_PSL") or _BUNDLED)


def _normalize(host: str) -> str:
    h = host.strip().lower().rstrip(".")
    if h.startswith("[") or h.count(":") > 1:       # IPv6 literal
        return h
    h = h.split(":")[0]                             # drop a port
    return ".".join(_to_ascii(p) for p in h.split(".") if p)


def public_suffix(host: str) -> str:
    """The public suffix of `host` (`bank.in` for `www.sbi.bank.in`)."""
    h = _normalize(host)
    labels = h.split(".")
    rules, wildcards, exceptions = _rules()
    for i in range(len(labels)):
        cand = ".".join(labels[i:])
        parent = ".".join(labels[i + 1:])
        if cand in exceptions:
            return parent                           # !www.ck → suffix is ck
        if cand in rules:
            return cand
        if parent and parent in wildcards:
            return cand                             # *.ck matches foo.ck
    return labels[-1]                               # unlisted TLD: implicit "*" rule


def registrable_domain(host: str) -> str:
    """The domain a registrant controls: public suffix + one label.

    IP addresses, IPv6 literals and single-label hosts come back unchanged;
    a host that *is* a public suffix comes back as itself.
    """
    h = _normalize(host)
    if not h or _IPV4_RE.match(h) or h.startswith("[") or ":" in h or "." not in h:
        return h
    suffix = public_suffix(h)
    if h == suffix:
        return h
    head = h[: -len(suffix) - 1]
    return head.split(".")[-1] + "." + suffix


def same_site(a: str, b: str) -> bool:
    return registrable_domain(a) == registrable_domain(b)
