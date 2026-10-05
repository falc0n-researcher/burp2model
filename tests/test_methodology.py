"""
Tests for the methodology scaffold (methodology.py): that it is target-specific
(derived from this app's structure), ranked by leverage, cited, and framed as
lines of inquiry rather than a generic checklist.
"""

import json

import pytest

from burp2model import build, parse_items, investigation_plan, methodology_package
from burp2model.cli import main

from test_gaps import export, item


def _two_role_model(tmp_path):
    """A user capture and an admin capture, merged — enough for divergence."""
    user = [
        item(host="www.shop.test", path="/dashboard"),
        item(host="www.shop.test", path="/app.js", mime="script",
             resp_ct="application/javascript",
             resp_body='fetch("/api/orders");fetch("/api/admin/report");'),
        item(host="api.shop.test", path="/api/orders", mime="JSON",
             resp_ct="application/json", resp_body="{}",
             req_headers=[("Authorization", "Bearer u"),
                          ("Referer", "https://www.shop.test/dashboard")]),
        item(host="api.shop.test", path="/api/admin/users", mime="JSON", status=403,
             resp_ct="application/json", resp_body="{}",
             req_headers=[("Authorization", "Bearer u")]),
        item(method="POST", host="api.shop.test", path="/auth/login", mime="JSON",
             resp_ct="application/json", resp_body="{}"),
    ]
    admin = [
        item(host="api.shop.test", path="/api/admin/users", mime="JSON", status=200,
             resp_ct="application/json", resp_body="{}",
             req_headers=[("Authorization", "Bearer a")]),
    ]
    ux = list(parse_items(export(tmp_path, user, "u.xml"), role="user"))
    ax = list(parse_items(export(tmp_path, admin, "a.xml"), role="admin"))
    ex = ux + ax
    for i, e in enumerate(ex):
        e.index = i
    return build(ex, name="shop", scope=["shop.test"])


def test_plan_is_structured(tmp_path):
    plan = investigation_plan(_two_role_model(tmp_path))
    assert set(plan) >= {"app", "posture", "recon", "lines_of_inquiry", "watch"}
    assert plan["posture"]["roles"] == ["admin", "user"]
    assert plan["lines_of_inquiry"]


def test_lines_are_ranked_by_leverage(tmp_path):
    lines = investigation_plan(_two_role_model(tmp_path))["lines_of_inquiry"]
    scores = [l["leverage"] for l in lines]
    assert scores == sorted(scores, reverse=True)
    # the admin area (privileged + role divergence) should outrank plain areas
    top = lines[0]
    assert top["leverage"] > 0


def test_admin_area_surfaces_privilege_and_divergence(tmp_path):
    plan = investigation_plan(_two_role_model(tmp_path))
    # signals for the /api/admin/users endpoint (user 403 vs admin 200), wherever
    # its area landed
    sigs = [s for l in plan["lines_of_inquiry"] for s in l["signals"]
            if "/api/admin/users" in s["endpoint"]]
    kinds = {s["kind"] for s in sigs}
    assert "privileged" in kinds
    assert "role_divergence" in kinds, "user 403 vs admin 200 is a divergence"
    div = next(s for s in sigs if s["kind"] == "role_divergence")
    assert div["evidence"] and "next" in div and "question" in div


def test_login_area_flags_ambiguous_auth(tmp_path):
    plan = investigation_plan(_two_role_model(tmp_path))
    login = next((l for l in plan["lines_of_inquiry"]
                  if any("/auth/login" in e for e in l["endpoints"])), None)
    assert login is not None
    assert any(s["kind"] == "no_auth_state" for s in login["signals"])


def test_every_signal_is_cited_and_actionable(tmp_path):
    plan = investigation_plan(_two_role_model(tmp_path))
    for line in plan["lines_of_inquiry"]:
        for s in line["signals"]:
            assert s["evidence"], "each signal cites evidence"
            assert s["question"] and s["next"], "each is a question + a next observation"


def test_recon_is_derived_from_blind_spots(tmp_path):
    # a capture with NO credentials should tell you to get an authenticated one
    xml = export(tmp_path, [item(host="www.shop.test", path="/"),
                            item(host="api.shop.test", path="/api/x", mime="JSON",
                                 resp_ct="application/json", resp_body="{}")])
    plan = investigation_plan(build(list(parse_items(xml)), name="shop",
                                    scope=["shop.test"]))
    steps = " ".join(r["step"] for r in plan["recon"])
    assert "authenticated capture" in steps or "role" in steps


def test_static_only_becomes_a_recon_step_and_signal(tmp_path):
    # /api/admin/report is referenced in app.js but never called -> STATIC_ONLY
    plan = investigation_plan(_two_role_model(tmp_path))
    steps = " ".join(r["step"] for r in plan["recon"])
    assert "code" in steps  # "walk the paths found only in code"
    all_sigs = [s for l in plan["lines_of_inquiry"] for s in l["signals"]]
    assert any(s["kind"] == "static_only" for s in all_sigs)


def test_watch_lists_third_party_trust(tmp_path):
    # add a third party the app loads
    items = [item(host="www.shop.test", path="/"),
             item(host="cdn.analytics.test", path="/t.js", mime="script",
                  resp_ct="application/javascript", resp_body="//x")]
    plan = investigation_plan(build(list(parse_items(export(tmp_path, items))),
                                    name="shop", scope=["shop.test"]))
    tos = {e["to"] for e in plan["watch"]["third_party_trust"]}
    assert any("analytics" in t for t in tos)


def test_methodology_package_is_ai_ready_and_grounded(tmp_path):
    pkg = methodology_package(_two_role_model(tmp_path))
    assert pkg["instructions"] and "checklist" in " ".join(pkg["instructions"]).lower()
    assert pkg["plan_scaffold"]["lines_of_inquiry"]
    assert "graph" in pkg["model"] and "evidence" in pkg["model"]
    # every evidence id the scaffold cites resolves in the model evidence table
    ev_keys = set(pkg["model"]["evidence"])
    cited = []

    def walk(o):
        if isinstance(o, dict):
            for k, v in o.items():
                if k == "evidence" and isinstance(v, list):
                    cited.extend(i for i in v if isinstance(i, int))
                else:
                    walk(v)
        elif isinstance(o, list):
            for v in o:
                walk(v)
    walk(pkg["plan_scaffold"])
    for i in cited:
        assert f"ev_{i}" in ev_keys


# ---------------------------------------------- CLI --------------------------

def test_cli_methodology_text_and_prompt(tmp_path, capsys):
    xml = export(tmp_path, [item(host="www.shop.test", path="/"),
                            item(method="POST", host="api.shop.test",
                                 path="/api/admin/x", mime="JSON",
                                 resp_ct="application/json", resp_body="{}",
                                 req_headers=[("Authorization", "Bearer x")])])
    out = tmp_path / "o"
    assert main([xml, "-w", "shop", "--out", str(out), "--scope", "shop.test"]) == 0
    capsys.readouterr()
    assert main(["methodology", "shop", "--out", str(out)]) == 0
    text = capsys.readouterr().out
    assert "investigation scaffold" in text and "LINES OF INQUIRY" in text
    assert main(["methodology", "shop", "--out", str(out), "--prompt"]) == 0
    prompt = capsys.readouterr().out
    assert "METHODOLOGY" in prompt.upper() and "plan_scaffold" in prompt
    assert main(["methodology", "shop", "--out", str(out), "--json"]) == 0
    plan = json.loads(capsys.readouterr().out)
    assert "lines_of_inquiry" in plan
