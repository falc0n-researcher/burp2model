"""What changed between two builds of the same app, grouped so a release reads as a handful of lines.

The comparison is by deterministic id: a node is the same node in both builds if its id is the same, and an
edge is the same if its source, type and target are the same. From that:

  NEW      in the newer build only
  CHANGED  in both, but its fingerprint moved (a status, a server header, a cookie flag, a version)
  GONE     in the older build only

Additions that connect to each other collapse into one workflow: a new page, the script it loads, the
endpoints that script names and their parameters are one line, not a dozen. Everything is drift to
understand, never a finding, and each line cites the requests that show it (from the newer build for new
and changed things, from the older one for things that went).
"""

from __future__ import annotations

from .model import Model, match_key

_ORDER = {"host": 0, "route": 1, "script": 2, "endpoint": 3, "operation": 4, "parameter": 5, "third_party": 6,
          "auth": 7, "cookie": 8, "role": 9, "tech": 10}
_HEAD = ("host", "route", "endpoint", "script", "third_party", "tech", "cookie", "auth", "role", "operation", "parameter")


def _fp(n) -> dict:
    """The facts about a node that can move without it being a different node."""
    a = n.attrs
    out: dict = {}
    if n.type == "endpoint":
        out["state"] = a.get("api_state")
        out["statuses"] = sorted(a.get("statuses") or [])
        out["by role"] = {r: sorted(v) for r, v in sorted((a.get("status_by_role") or {}).items())}
        out["credentials"] = sorted(a.get("credentials") or [])
        out["roles"] = sorted(n.roles)
    elif n.type == "route":
        out["statuses"] = sorted(a.get("statuses") or [])
        out["roles"] = sorted(n.roles)
    elif n.type == "host":
        out["header"] = {k: v for k, v in sorted((a.get("tech") or {}).items())}
        out["schemes"] = sorted(a.get("schemes") or [])
        out["ports"] = sorted(a.get("ports") or [])
    elif n.type == "cookie":
        out["HttpOnly"] = a.get("httponly")
        out["Secure"] = a.get("secure")
        out["SameSite"] = a.get("samesite")
    elif n.type == "script":
        sm = a.get("sourcemap") or {}
        out["source map captured"] = sm.get("captured") if sm else None
        out["worker kind"] = a.get("worker")
    return out


def _show(v) -> str:
    if isinstance(v, list):
        return ", ".join(str(x) for x in v) or "none"
    if isinstance(v, dict):
        return "; ".join(f"{k}: {_show(x)}" for k, x in v.items()) or "none"
    return "none" if v is None else str(v)


def _summarise(field: str, a, b) -> str:
    if isinstance(a, list) and isinstance(b, list):
        gone, new = [x for x in a if x not in b], [x for x in b if x not in a]
        if len(gone) == 1 and len(new) == 1:
            return f"{field} {gone[0]} → {new[0]}"
        return f"{field} " + " ".join([f"+{x}" for x in new] + [f"−{x}" for x in gone])
    if isinstance(a, dict) and isinstance(b, dict):
        parts = []
        for k in sorted(set(a) | set(b)):
            if a.get(k) != b.get(k):
                parts.append(_summarise(f"{field} {k}:", a.get(k), b.get(k)) if isinstance(a.get(k), list)
                             and isinstance(b.get(k), list) else f"{field} {k}: {_show(a.get(k))} → {_show(b.get(k))}")
        return "; ".join(parts)
    return f"{field} {_show(a)} → {_show(b)}"


def _changes(a, b) -> list[dict]:
    fa, fb = _fp(a), _fp(b)
    out = []
    for k in fa:
        if fa[k] != fb.get(k):
            out.append({"field": k, "from": fa[k], "to": fb.get(k), "summary": _summarise(k, fa[k], fb.get(k))})
    return out


def _stack_index(m: Model) -> dict:
    return {(t["category"], t["name"]): t for t in getattr(m, "stack", [])}


def _components(ids: set[str], edges) -> list[list[str]]:
    parent = {i: i for i in ids}

    def find(x):
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    for e in edges:
        if e.src in ids and e.dst in ids:
            parent[find(e.src)] = find(e.dst)
    groups: dict[str, list[str]] = {}
    for i in sorted(ids):
        groups.setdefault(find(i), []).append(i)
    return list(groups.values())


def _label(m: Model, nid: str) -> str:
    n = m.nodes.get(nid)
    return n.label if n else nid.split(":", 1)[-1]


def _workflow(kind: str, m: Model, ids: list[str], edges, other: Model, hist=None) -> dict:
    nodes = sorted((m.nodes[i] for i in ids), key=lambda n: (_ORDER.get(n.type, 99), n.label))
    head = next((n for t in _HEAD for n in nodes if n.type == t), nodes[0])
    counts: dict[str, int] = {}
    for n in nodes:
        counts[n.type] = counts.get(n.type, 0) + 1
    rest = [f"{c} {t.replace('_', ' ')}{'s' if c != 1 else ''}" for t, c in
            sorted(((t, c) for t, c in counts.items() if t != head.type or c > 1), key=lambda x: _ORDER.get(x[0], 99))]
    links = []
    for e in edges:
        a_in, b_in = e.src in ids, e.dst in ids
        if a_in != b_in:
            outside = e.dst if a_in else e.src
            if (outside in other.nodes or outside in m.nodes) and \
                    getattr(m.nodes.get(outside) or other.nodes.get(outside), "type", "") not in ("host", "tech"):
                links.append({"from" if b_in else "to": _label(m, outside), "edge": e.type.lower(),
                              "node": _label(m, e.dst if b_in else e.src)})
    ev = sorted({i for n in nodes for i in n.evidence})[:8]
    return {"kind": kind, "title": f"{head.type.replace('_', ' ')} {head.label}", "head": head.label,
            "summary": ", ".join(rest), "nodes": [{"id": n.id, "type": n.type, "label": n.label} for n in nodes],
            "chain": [n.label for n in nodes if n.type != "parameter"][:8]
            + ([f"+{sum(1 for n in nodes if n.type == 'parameter')} parameters"]
               if any(n.type == "parameter" for n in nodes) else []),
            "links": links[:3], "evidence": ev}


def diff_models(old: Model, new: Model, old_meta: dict | None = None, new_meta: dict | None = None,
                hist=None) -> dict:
    """Compare two models. `hist(kind, key)` may return {'first_seen','last_seen'} for the history lines."""
    on, nn = old.nodes, new.nodes
    # technology markers are covered by the host's headers and the stack below, so they are not repeated
    new_ids = {i for i in set(nn) - set(on) if nn[i].type != "tech"}
    gone_ids = {i for i in set(on) - set(nn) if on[i].type != "tech"}

    # a path the code named without a method that traffic then walked was not retired: a gap closed
    closed: dict[str, str] = {}
    walked = {(n.attrs.get("host"), match_key(n.attrs.get("path", ""))): n.id for n in nn.values()
              if n.type == "endpoint" and n.attrs.get("method_known", True)}
    for gid in sorted(gone_ids):
        n = on[gid]
        if n.type == "endpoint" and not n.attrs.get("method_known", True):
            hit = walked.get((n.attrs.get("host"), match_key(n.attrs.get("path", ""))))
            if hit and hit in new_ids:
                closed[gid] = hit
    for g, h in closed.items():
        gone_ids.discard(g)
        new_ids.discard(h)

    changed = []
    for nid in sorted(set(on) & set(nn)):
        ch = _changes(on[nid], nn[nid])
        if ch:
            changed.append({"kind": nn[nid].type, "id": nid, "label": nn[nid].label, "changes": ch,
                            "evidence": sorted(nn[nid].evidence)[:3]})
    for g, h in sorted(closed.items()):
        changed.append({"kind": "endpoint", "id": h, "label": nn[h].label,
                        "changes": [{"field": "state", "from": "STATIC_ONLY", "to": nn[h].attrs.get("api_state"),
                                     "summary": f"named in code before, now walked in traffic ({on[g].label} → {nn[h].label})"}],
                        "evidence": sorted(nn[h].evidence)[:3]})

    # the technology stack, compared by (category, name)
    so, sn = _stack_index(old), _stack_index(new)
    stack_new = [{"kind": "stack", "label": f"{k[1]}{' ' + v['version'] if v.get('version') else ''}", "category": k[0],
                  "evidence": v.get("evidence", [])[:3]} for k, v in sorted(sn.items()) if k not in so]
    stack_gone = [{"kind": "stack", "label": f"{k[1]}{' ' + v['version'] if v.get('version') else ''}", "category": k[0]}
                  for k, v in sorted(so.items()) if k not in sn]
    for k in sorted(set(so) & set(sn)):
        if (so[k].get("version") or "") != (sn[k].get("version") or ""):
            changed.append({"kind": "stack", "id": f"stack:{k[0]}:{k[1]}", "label": k[1], "category": k[0],
                            "changes": [{"field": "version", "from": so[k].get("version"), "to": sn[k].get("version"),
                                         "summary": f"version {so[k].get('version') or 'none'} → {sn[k].get('version') or 'none'}"}],
                            "evidence": sn[k].get("evidence", [])[:3]})
    # a server swap reads as one thing: edge/web-server entries going and coming in the same category
    for cat in ("Edge & CDN", "Web server", "Language & framework"):
        g = [x for x in stack_gone if x["category"] == cat]
        a = [x for x in stack_new if x["category"] == cat]
        if len(g) == 1 and len(a) == 1:
            changed.append({"kind": "stack", "id": f"stack:{cat}", "label": cat, "category": cat,
                            "changes": [{"field": "technology", "from": g[0]["label"], "to": a[0]["label"],
                                         "summary": f"{cat.lower()} {g[0]['label']} → {a[0]['label']}"}],
                            "evidence": a[0].get("evidence", [])})
            stack_gone.remove(g[0])
            stack_new.remove(a[0])

    ekey = lambda e: (e.src, e.type, e.dst)       # noqa: E731
    old_e, new_e = {ekey(e): e for e in old.edges}, {ekey(e): e for e in new.edges}
    added_e = [new_e[k] for k in sorted(set(new_e) - set(old_e))]
    removed_e = [old_e[k] for k in sorted(set(old_e) - set(new_e))]

    def workflows(kind, model, ids, edges, other):
        wf, singles = [], []
        for comp in _components(set(ids), edges):
            if len(comp) >= 2:
                wf.append(_workflow(kind, model, comp, edges, other))
            else:
                singles.append(comp[0])
        wf.sort(key=lambda w: (-len(w["nodes"]), w["title"]))
        return wf, singles

    new_wf, new_single = workflows("new_workflow", new, new_ids, added_e, old)
    gone_wf, gone_single = workflows("gone_workflow", old, gone_ids, removed_e, new)
    in_wf_new = {n["id"] for w in new_wf for n in w["nodes"]} | set(new_single)
    in_wf_gone = {n["id"] for w in gone_wf for n in w["nodes"]} | set(gone_single)

    def single(model, nid, side):
        n = model.nodes[nid]
        d = {"kind": n.type, "label": n.label, "state": n.attrs.get("api_state"),
             "evidence": sorted(n.evidence)[:3]}
        if hist:
            h = hist("node", nid)
            if h:
                d["first_seen" if side == "new" else "last_seen"] = h["first_seen" if side == "new" else "last_seen"]
        return d

    def loose_edges(edges, model, touched):
        out = []
        for e in edges:
            if e.src in touched or e.dst in touched:
                continue               # already part of a workflow or a new/gone node
            if any(getattr(model.nodes.get(x), "type", "") == "tech" for x in (e.src, e.dst)):
                continue               # a technology marker: the host's headers and the stack say it
            out.append({"from": _label(model, e.src), "edge": e.type.lower(), "to": _label(model, e.dst),
                        "state": e.state, "evidence": sorted(e.evidence)[:3]})
        return out

    new_edges = loose_edges(added_e, new, in_wf_new)
    gone_edges = loose_edges(removed_e, old, in_wf_gone)
    summary = {"new": len(new_single) + len(stack_new) + len(new_edges),
               "changed": len(changed),
               "gone": len(gone_single) + len(stack_gone) + len(gone_edges),
               "new_workflows": len(new_wf), "gone_workflows": len(gone_wf)}
    summary["total"] = sum(summary[k] for k in ("new", "changed", "gone", "new_workflows", "gone_workflows"))
    changed.sort(key=lambda c: (_ORDER.get(c["kind"], 99), c["label"]))
    return {
        "app": new.name,
        "from": old_meta or {}, "to": new_meta or {},
        "same": summary["total"] == 0,
        "summary": summary,
        "workflows": new_wf + gone_wf,
        "new": {"nodes": sorted((single(new, i, "new") for i in new_single), key=lambda d: (_ORDER.get(d["kind"], 99), d["label"])),
                "stack": stack_new, "edges": new_edges},
        "changed": changed,
        "gone": {"nodes": sorted((single(old, i, "gone") for i in gone_single), key=lambda d: (_ORDER.get(d["kind"], 99), d["label"])),
                 "stack": stack_gone, "edges": gone_edges},
        "note": "Drift between two builds. Each line is a change in the attack surface to understand, never a finding. "
                "Evidence ids are from the newer build for new and changed things, the older build for gone ones.",
    }


def _ev(ids) -> str:
    return ("  " + ", ".join(f"ev_{i}" for i in ids)) if ids else ""


def format_text(d: dict) -> str:
    """The grouped change report as plain text."""
    f, t, s = d.get("from") or {}, d.get("to") or {}, d["summary"]
    tag = lambda m: (f"build {m.get('id')}" + (f" ({m['built_at'][:10]})" if m.get("built_at") else "")) if m else "?"   # noqa: E731
    out = [f"{d['app']}: {tag(f)} → {tag(t)}"]
    if d["same"]:
        out.append("No drift between these two builds.")
        return "\n".join(out)
    out.append(f"  {s['new_workflows']} new workflow(s) · {s['new']} new · {s['changed']} changed · "
               f"{s['gone']} gone" + (f" · {s['gone_workflows']} removed workflow(s)" if s["gone_workflows"] else ""))
    wf_new = [w for w in d["workflows"] if w["kind"] == "new_workflow"]
    wf_gone = [w for w in d["workflows"] if w["kind"] == "gone_workflow"]
    if wf_new:
        out += ["", "NEW WORKFLOWS (connected additions, one line each)"]
        for w in wf_new:
            out.append(f"  ▸ {w['title']}  ({len(w['nodes'])} things: {w['summary']})")
            out.append("      " + " → ".join(w["chain"]))
            for l in w["links"]:
                out.append(f"      {l.get('node')} {l['edge']} {l.get('from') or l.get('to')}")
            if w["evidence"]:
                out.append("      " + ", ".join(f"ev_{i}" for i in w["evidence"]))
    if d["changed"]:
        out += ["", "CHANGED"]
        for c in d["changed"]:
            out.append(f"  ~ {c['label']}  [{c['kind']}]")
            for x in c["changes"]:
                out.append(f"      {x['summary']}")
            if c["evidence"]:
                out.append("      " + ", ".join(f"ev_{i}" for i in c["evidence"]))
    n = d["new"]
    if n["nodes"] or n["stack"] or n["edges"]:
        out += ["", "NEW"]
        for x in n["nodes"]:
            out.append(f"  + {x['label']}  [{x['kind']}]{_ev(x['evidence'])}")
        for x in n["stack"]:
            out.append(f"  + {x['label']}  [{x['category']}]{_ev(x['evidence'])}")
        for x in n["edges"]:
            out.append(f"  + {x['from']} {x['edge']} {x['to']}{_ev(x['evidence'])}")
    g = d["gone"]
    if g["nodes"] or g["stack"] or g["edges"] or wf_gone:
        out += ["", "GONE (evidence is from the older build)"]
        for w in wf_gone:
            out.append(f"  - {w['title']}  ({len(w['nodes'])} things: {w['summary']})")
        for x in g["nodes"]:
            seen = f"  last seen {x['last_seen'][:10]}" if x.get("last_seen") else ""
            out.append(f"  - {x['label']}  [{x['kind']}]{seen}")
        for x in g["stack"]:
            out.append(f"  - {x['label']}  [{x['category']}]")
        for x in g["edges"]:
            out.append(f"  - {x['from']} {x['edge']} {x['to']}")
    return "\n".join(out)
