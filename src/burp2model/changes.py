"""
Diff two models of the same app, grouped into feature areas.

Recon is not a one-shot: an app changes, and the interesting question at each
release is *what moved*. This compares an older model to the current one and
reports the drift — what appeared, what is gone — grouped by feature area and
annotated with why a researcher would care.

It never says "this is a bug". A new admin endpoint or a new third party is a
change in the attack surface worth a look, stated as such and cited to the
evidence in the current model.
"""

from __future__ import annotations

from .graph import ReasonGraph
from .model import PRIV_RE, Model, match_key


def _by_type(m: Model, t: str) -> dict[str, object]:
    return {nid: n for nid, n in m.nodes.items() if n.type == t}


def _why_appeared(kind: str, node) -> str | None:
    path = node.attrs.get("path", "") or ""
    if kind == "endpoint":
        if PRIV_RE.search(path):
            return "a new privileged-looking endpoint — confirm who may reach it"
        if node.attrs.get("api_state") == "STATIC_ONLY":
            return "new, and only referenced in code — an unwalked path to try"
        return "a new endpoint in the surface"
    if kind == "third_party":
        return "new third-party code the app now talks to — trust left the app"
    if kind == "host":
        return "a new first-party host in scope"
    if kind == "tech":
        return "a newly advertised technology marker"
    if kind == "cookie":
        return "a new cookie — check its flags and what it carries"
    if kind == "auth":
        return "a new credential scheme on the surface"
    return None


def _why_gone(kind: str) -> str | None:
    if kind == "endpoint":
        return "an endpoint no longer seen — retired, renamed, or just not walked this time"
    if kind == "third_party":
        return "a third party the app no longer talks to"
    if kind == "host":
        return "a host no longer in the capture"
    return None


def diff_models(old: Model, new: Model) -> dict:
    """What moved between two models of the same app. Drift, never findings."""
    rg = ReasonGraph(new)
    area_of = {}
    for c in rg.communities():
        for lbl in c["members"]:
            area_of[lbl] = c["name"]

    KINDS = ("endpoint", "route", "script", "host", "third_party", "cookie", "auth", "tech")
    areas: dict[str, dict] = {}
    totals = {"appeared": 0, "gone": 0}

    def area(name):
        return areas.setdefault(name, {"area": name, "appeared": [], "gone": []})

    def _keys(m: Model, method_known: bool) -> set:
        return {(n.attrs.get("host"), match_key(n.attrs.get("path", "")))
                for n in _by_type(m, "endpoint").values()
                if bool(n.attrs.get("method_known", True)) == method_known}

    # a path named in code with no method (`* /api/x`) that a later capture
    # actually walked (`GET /api/x`) was not retired — it was resolved
    old_unwalked = _keys(old, False)
    now_walked = _keys(new, True)

    for kind in KINDS:
        old_ids = set(_by_type(old, kind))
        new_nodes = _by_type(new, kind)
        new_ids = set(new_nodes)
        old_nodes = _by_type(old, kind)
        for nid in sorted(new_ids - old_ids):
            n = new_nodes[nid]
            why = _why_appeared(kind, n)
            if kind == "endpoint" and (n.attrs.get("host"), match_key(n.attrs.get("path", ""))) \
                    in old_unwalked and n.attrs.get("method_known", True):
                why = "named in code before, now walked in traffic — a gap closed"
            if why is None:
                continue
            area(area_of.get(n.label, kind)) ["appeared"].append({
                "kind": kind, "label": n.label, "why": why,
                "state": n.attrs.get("api_state"),
                "evidence": list(n.evidence[:3])})
            totals["appeared"] += 1
        for nid in sorted(old_ids - new_ids):
            n = old_nodes[nid]
            why = _why_gone(kind)
            if kind == "endpoint" and not n.attrs.get("method_known", True) and \
                    (n.attrs.get("host"), match_key(n.attrs.get("path", ""))) in now_walked:
                continue            # resolved by traffic, reported above as a closed gap
            if why is None:
                continue
            area(area_of.get(n.label, kind))["gone"].append({
                "kind": kind, "label": n.label, "why": why})
            totals["gone"] += 1

    lines = []
    for a in sorted(areas.values(),
                    key=lambda a: (-(len(a["appeared"]) + len(a["gone"])), a["area"])):
        if a["appeared"] or a["gone"]:
            a["appeared"].sort(key=lambda x: (x["kind"], x["label"]))
            a["gone"].sort(key=lambda x: (x["kind"], x["label"]))
            lines.append(a)

    return {
        "app": new.name,
        "totals": totals,
        "note": "Drift between two captures. An appearance is a change in the "
                "attack surface to understand, never a finding.",
        "areas": lines,
    }
