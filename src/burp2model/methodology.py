"""
From a model to a methodology.

A generic checklist ("test for IDOR, check CORS, …") ignores the app in front
of you. This module turns the model into the opposite: a target-specific
*scaffold* for a recon-and-hunting methodology, derived from what the capture
actually shows — the app's feature areas, how each is reached, its trust posture,
what the capture could not answer — every line cited to a real request.

The scaffold is deterministic and honest. It is not the methodology itself: it
is the grounded structure an AI reasons over to produce one — sequencing the
work, connecting areas, and going deeper than any list could. `methodology_prompt`
packages the scaffold and the graph with instructions that push the model toward
a plan built from *this* app's evidence, not a template.

Nothing here is a finding or a payload. Each line of inquiry ends in an
observation or a two-account comparison to make in an authorised session — the
question that would advance understanding, not an exploit.
"""

from __future__ import annotations

from .graph import ReasonGraph
from .model import PRIV_RE, Model

# How much each structural signal raises an area's priority for *understanding*
# (not risk): an unwalked path teaches the most, a privileged path matters, an
# ambiguous auth boundary is worth resolving.
_WEIGHT = {
    "static_only": 3,      # referenced in code, never called — an unknown door
    "privileged": 3,       # admin/internal path
    "mixed_auth": 2,       # seen with and without a credential
    "no_auth_state": 2,    # state-changing, no credential observed
    "role_divergence": 2,  # different roles, different answers
    "only_errored": 1,     # behaviour with valid input unseen
    "credentialed": 1,     # known surface, still worth confirming authz
    "input_page": 2,       # a server-rendered page that takes parameters
}


def _area_of(rg: ReasonGraph):
    """Map each endpoint label to its community (feature area) name + id."""
    out = {}
    for c in rg.communities():
        for lbl in c["members"]:
            out[lbl] = (c["id"], c["name"])
    return out


def _signals(n, roles: list[str]) -> list[dict]:
    """The structural questions this one endpoint raises, cited."""
    a = n.attrs
    ev = list(n.evidence[:3])
    sig = []
    path = a.get("path", "") or ""
    priv = bool(PRIV_RE.search(path))
    statuses = a.get("statuses") or []
    reached = bool(a.get("requests"))

    if a.get("api_state") == "STATIC_ONLY":
        sig.append({"kind": "static_only", "weight": _WEIGHT["static_only"],
                    "observation": "named in client code but never requested in the capture",
                    "question": "what is this endpoint for, and which role is meant to call it?",
                    "next": "request it in an authorised session and read the response",
                    "evidence": ev})
    if priv and reached:
        sig.append({"kind": "privileged", "weight": _WEIGHT["privileged"],
                    "observation": "privileged-looking path that was actually reached"
                    + (f" (roles: {', '.join(n.roles)})" if n.roles else ""),
                    "question": "was every caller supposed to see this, or is the boundary softer than intended?",
                    "next": "replay across two accounts and compare the responses",
                    "evidence": ev})
    elif priv:
        sig.append({"kind": "privileged", "weight": _WEIGHT["privileged"] - 1,
                    "observation": "privileged-looking path, only referenced in code",
                    "question": "who is allowed through this door?",
                    "next": "request it in an authorised session and observe who is admitted",
                    "evidence": ev})
    if a.get("anonymous_requests") and a.get("credentials"):
        sig.append({"kind": "mixed_auth", "weight": _WEIGHT["mixed_auth"],
                    "observation": "seen both with and without a credential",
                    "question": "is authentication actually required here, or only sometimes sent?",
                    "next": "replay it unauthenticated and compare",
                    "evidence": ev})
    method = a.get("method")
    if (reached and method not in (None, "*", "GET", "HEAD")
            and not a.get("credentials")):
        sig.append({"kind": "no_auth_state", "weight": _WEIGHT["no_auth_state"],
                    "observation": f"{method} with no credential observed on it",
                    "question": "does this state-changing call require identity?",
                    "next": "confirm whether it is meant to be authenticated",
                    "evidence": ev})
    if len(roles) >= 2 and n.roles:
        sbr = a.get("status_by_role", {})
        got_2xx = [r for r in roles if any(200 <= s < 300 for s in sbr.get(r, []))]
        got_deny = [r for r in roles if any(s in (401, 403) for s in sbr.get(r, []))]
        if got_2xx and got_deny:
            sig.append({"kind": "role_divergence", "weight": _WEIGHT["role_divergence"],
                        "observation": f"{', '.join(got_2xx)} got through; {', '.join(got_deny)} were denied",
                        "question": "is the difference an authorization control, or content that leaks anyway?",
                        "next": "diff the two responses for role-specific data",
                        "evidence": ev})
    if statuses and all(s >= 400 for s in statuses):
        sig.append({"kind": "only_errored", "weight": _WEIGHT["only_errored"],
                    "observation": f"only ever returned {', '.join(map(str, statuses))}",
                    "question": "how does it behave with valid input and auth?",
                    "next": "exercise the feature normally in an authorised session",
                    "evidence": ev})
    return sig


def investigation_plan(m: Model) -> dict:
    """A grounded scaffold for a target-specific methodology. Deterministic."""
    rg = ReasonGraph(m)
    roles = sorted(m.roles)
    area_of = _area_of(rg)
    eps = [n for n in m.nodes.values() if n.type == "endpoint"]

    # group endpoints and their signals by feature area
    areas: dict[str, dict] = {}
    for n in eps:
        aid, aname = area_of.get(n.label, ("cluster_?", "app"))
        area = areas.setdefault(aid, {"id": aid, "name": aname, "endpoints": [],
                                      "signals": [], "reached_by": set(), "score": 0})
        area["endpoints"].append(n.label)
        area["reached_by"].update(n.roles)
        for s in _signals(n, roles):
            area["signals"].append({**s, "endpoint": n.label})
            area["score"] += s["weight"]

    # Server-rendered apps put their input handling in pages, not API endpoints
    # (DVWA's /vulnerabilities/sqli/?id=…). A page that takes parameters is a line of inquiry too.
    pages = 0
    for n in m.nodes.values():
        if n.type != "route":
            continue
        params = sorted({m.nodes[dst].label for dst, e in rg.out.get(n.id, [])
                         if e.type == "USES_PARAMETER" and dst in m.nodes})
        if not params:
            continue
        pages += 1
        aid, aname = area_of.get(n.label, ("cluster_?", "app"))
        area = areas.setdefault(aid, {"id": aid, "name": aname, "endpoints": [],
                                      "signals": [], "reached_by": set(), "score": 0})
        area["endpoints"].append(n.label)
        area["reached_by"].update(n.roles)
        sig = {"kind": "input_page", "weight": _WEIGHT["input_page"],
               "observation": f"page takes input: {', '.join(params[:8])}",
               "question": "how is each input handled — validated, reflected, stored, or passed to another system?",
               "next": "vary one input at a time in an authorised session and compare the responses",
               "evidence": list(n.evidence[:3]), "endpoint": n.label}
        area["signals"].append(sig)
        area["score"] += sig["weight"]

    # attach the model's named unknowns to the area they concern
    for u in m.unknowns:
        ent = m.nodes[u.entity].label if u.entity in m.nodes else None
        aid = area_of.get(ent, (None, None))[0] if ent else None
        target = areas.get(aid)
        if target is not None:
            oq = target.setdefault("open_questions", [])
            key = (u.type, ent)
            if key not in {(q["type"], q["entity"]) for q in oq}:
                oq.append({"type": u.type, "entity": ent,
                           "unknown": u.we_dont_know, "to_find_out": u.next_step})

    lines = []
    for area in sorted(areas.values(), key=lambda a: (-a["score"], a["name"])):
        area["signals"].sort(key=lambda s: (-s["weight"], s["endpoint"]))
        lines.append({
            "area": area["name"], "id": area["id"], "leverage": area["score"],
            "why_it_matters": _why(area),
            "endpoints": sorted(set(area["endpoints"]))[:20],
            "reached_by": sorted(area["reached_by"]),
            "reach": _reach_summary(rg, area["endpoints"]),
            "signals": area["signals"][:12],
            "open_questions": area.get("open_questions", [])[:6],
        })

    # recon phase: what to establish before hunting, from the model's blind spots
    recon = _recon(m, rg, roles)
    coup = rg.coupling()
    return {
        "app": m.name,
        "scope": m.scope,
        "posture": {
            "endpoints": len(eps),
            "input_pages": pages,
            "feature_areas": len([l for l in lines if l["endpoints"]]),
            "roles": roles,
            "static_only": sum(1 for n in eps if n.attrs.get("api_state") == "STATIC_ONLY"),
            "privileged": sum(1 for n in eps if PRIV_RE.search(n.attrs.get("path", "") or "")),
            "credentialed": sum(1 for n in eps if n.attrs.get("credentials")),
            "open_questions": len(m.unknowns),
            "third_parties": len(coup["to_third_party"]),
        },
        "recon": recon,
        "lines_of_inquiry": lines,
        "watch": {
            "third_party_trust": coup["to_third_party"][:12],
            "cross_area_coupling": coup["cross_community"][:12],
        },
    }


def _why(area: dict) -> str:
    kinds = {s["kind"] for s in area["signals"]}
    bits = []
    if "static_only" in kinds:
        bits.append("holds paths named in code but never walked")
    if "privileged" in kinds:
        bits.append("contains privileged-looking endpoints")
    if "role_divergence" in kinds:
        bits.append("roles diverge here")
    if "mixed_auth" in kinds or "no_auth_state" in kinds:
        bits.append("the auth boundary is ambiguous")
    if not bits:
        bits.append("a mapped part of the surface to confirm")
    return "; ".join(bits) + "."


def _reach_summary(rg: ReasonGraph, ep_labels: list[str]) -> list[str]:
    """A few 'how this area is reached' notes, distinct entry points."""
    entries: dict[str, str] = {}
    id_by_label = {n.label: nid for nid, n in rg.m.nodes.items() if n.type == "endpoint"}
    for lbl in ep_labels[:8]:
        nid = id_by_label.get(lbl)
        if not nid:
            continue
        for p in rg.reach(nid).get("paths", [])[:2]:
            if p["hops"]:
                state = "code" if any(h["state"] == "INFERRED" for h in p["hops"]) else "traffic"
                entries.setdefault(p["entry"], state)
    return [f"from {e} (via {state})" for e, state in sorted(entries.items())][:5]


def _recon(m: Model, rg: ReasonGraph, roles: list[str]) -> list[dict]:
    """What to establish first — from the capture's own blind spots."""
    out = []
    types = {u.type for u in m.unknowns}
    if "AUTHENTICATED_STATE_NOT_OBSERVED" in types:
        out.append({"step": "get an authenticated capture",
                    "why": "no credentialed traffic was seen, so the app's real surface is unmapped",
                    "how": "log in and re-capture, building with --role <name>"})
    if not roles or "ROLE_NOT_TAGGED" in types:
        out.append({"step": "capture each role separately",
                    "why": "cross-role comparison needs traffic tagged by who made it",
                    "how": "build each account's capture with --role, then `cross-role`"})
    static = [n for n in m.nodes.values()
              if n.type == "endpoint" and n.attrs.get("api_state") == "STATIC_ONLY"]
    if static:
        out.append({"step": "walk the paths found only in code",
                    "why": f"{len(static)} endpoint(s) are referenced in scripts but were never called — the biggest map gaps",
                    "how": "request each in an authorised session and observe"})
    if rg.coupling()["to_third_party"]:
        out.append({"step": "account for third-party code",
                    "why": "the app runs code it does not control; understand what those origins receive",
                    "how": "review the Supply chain view and what each third party is sent"})
    if not out:
        out.append({"step": "confirm the map is complete",
                    "why": "the capture looks well-covered; verify no feature area is missing",
                    "how": "compare the endpoint list against the app's visible navigation"})
    return out


METHODOLOGY_PROMPT = [
    "You are a senior application-security researcher planning how to investigate ONE web application you are authorised to test. Below is an evidence-backed model of it, built from captured traffic, plus a grounded scaffold: the app's feature areas, how each is reached, its trust posture, and what the capture could not answer. Every item cites evidence ids (ev_N) that resolve to real requests.",
    "",
    "Produce a RECON AND HUNTING METHODOLOGY specific to THIS application. Not a generic checklist — a plan that reads as if written after studying this app's structure.",
    "",
    "Rules that make it a methodology and not a list:",
    "- Sequence it. Recon first (close the blind spots the scaffold names), then mapping, then focused investigation per feature area, ordered by where understanding pays off most (use the `leverage` and `why_it_matters` the scaffold gives, and your own reading of the graph).",
    "- Ground every step in this model. Reference the actual endpoints, areas, roles, execution flows and unknowns by name, and cite the ev_N behind each. Never introduce an endpoint, parameter or edge the model does not contain.",
    "- For each line of inquiry, state: what the evidence shows, what is unknown, the specific question worth answering, and the single next observation or two-account comparison that would answer it. Prefer what the graph supports over any OWASP category.",
    "- Explain the reasoning, not just the action: why this area, why this order, what an answer here tells you about the rest of the app.",
    "- Everything is a hypothesis to verify safely in an authorised session. No payloads, no exploits — the goal is to understand the app deeply and know where to look, faster and better than a checklist would.",
    "",
    "Structure your answer as: (1) What this app is, in three sentences from the model. (2) Recon — what to establish first and why. (3) A prioritised set of lines of inquiry, one per feature area, each as described above. (4) What stays uncertain and the capture that would resolve it.",
]


# How much resolving each kind of unknown improves the picture. Higher = the
# answer teaches you more about the app, so it belongs at the top of the queue.
_GAP_WEIGHT = {
    "AUTHENTICATED_STATE_NOT_OBSERVED": 5,   # a whole side of the app is unseen
    "API_PURPOSE_UNKNOWN": 4,                 # a code-only path — what is it?
    "ROLE_NOT_TAGGED": 4,
    "AUTHORIZATION_UNKNOWN": 3,
    "ENDPOINT_ONLY_ERRORED": 2,
    "SCRIPT_PARTIALLY_SCANNED": 2,
    "CAPTURE_ITEMS_SKIPPED": 1,
}


def rank_gaps(m: Model) -> dict:
    """Rank the model's unknowns by how much resolving each improves the picture,
    each with the smallest next step. Good recon says what you have not seen yet."""
    rg = ReasonGraph(m)
    priv_paths = {n.label for n in m.nodes.values()
                  if n.type == "endpoint" and PRIV_RE.search(n.attrs.get("path", "") or "")}
    ranked = []
    for u in m.unknowns:
        ent = m.nodes[u.entity].label if u.entity in m.nodes else u.entity.split(":")[-1]
        w = _GAP_WEIGHT.get(u.type, 1)
        if ent in priv_paths:
            w += 1   # an unknown on a privileged path is worth more
        ranked.append({
            "leverage": w, "type": u.type, "entity": ent,
            "we_know": u.we_know, "unknown": u.we_dont_know,
            "next": u.next_step,
        })
    ranked.sort(key=lambda g: (-g["leverage"], g["type"], g["entity"]))
    return {
        "app": m.name,
        "note": "Ranked by how much resolving each improves the picture. "
                "Absence is a gap in observation, never a statement about the target.",
        "gaps": ranked,
    }


FALSIFY_PROMPT = [
    "You are a senior application-security researcher practising disciplined doubt. Below is an evidence-backed model of one web application and a set of hypotheses drawn from its structure (the investigation scaffold). Your job is the OPPOSITE of proving something is vulnerable: for each hypothesis, try to ELIMINATE it from the evidence alone.",
    "",
    "For each hypothesis:",
    "- State what would have to be true for it to hold, and whether the model already contradicts it (cite ev_N).",
    "- If the evidence neither confirms nor kills it, say exactly what single observation would falsify it — the cheapest test that could prove it wrong.",
    "- Prefer to discard weak hypotheses. A hypothesis that survives honest attempts to kill it is the only kind worth a researcher's time.",
    "",
    "Rules: reason only from the model; never invent an endpoint, parameter or edge; every claim cites ev_N; produce questions and falsifying tests, never payloads or exploits. Rank what SURVIVES scrutiny, and say plainly what you were able to rule out and why.",
]


def methodology_package(m: Model, cap: int = 60, prompt=None) -> dict:
    """Everything an AI needs to write a target-specific methodology (or, with
    a different `prompt`, to falsify the scaffold's hypotheses)."""
    from .context import context_package
    ctx = context_package(m, lens="attention", cap=cap, graph=True)
    return {
        "instructions": prompt or METHODOLOGY_PROMPT,
        "plan_scaffold": investigation_plan(m),
        "model": {k: ctx[k] for k in ("app", "scope", "roles", "shape", "graph",
                                      "endpoints", "unknowns", "evidence")
                  if k in ctx},
    }
