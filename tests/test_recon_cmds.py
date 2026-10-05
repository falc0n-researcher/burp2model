"""
Tests for the analyst commands built on the scaffold: gaps (ranked unknowns),
changes (drift between two models), and falsify (a hypothesis-elimination prompt).
"""

import json

import pytest

from burp2model import build, parse_items, rank_gaps, diff_models
from burp2model.cli import main
from burp2model.model import to_dict, from_dict

from test_gaps import export, item


def _priv_model(tmp_path, name="shop"):
    items = [
        item(host="www.shop.test", path="/dashboard"),
        item(host="www.shop.test", path="/app.js", mime="script",
             resp_ct="application/javascript",
             resp_body='fetch("/api/orders");fetch("/rest/admin/config");'),
        item(host="api.shop.test", path="/api/orders", mime="JSON",
             resp_ct="application/json", resp_body="{}",
             req_headers=[("Authorization", "Bearer x"),
                          ("Referer", "https://www.shop.test/dashboard")]),
    ]
    return build(list(parse_items(export(tmp_path, items, name + ".xml"))),
                 name=name, scope=["shop.test"])


# ---------------------------------------------- gaps -------------------------

def test_rank_gaps_orders_by_leverage_with_next_steps(tmp_path):
    g = rank_gaps(_priv_model(tmp_path))
    assert g["gaps"], "there should be unknowns to rank"
    levs = [x["leverage"] for x in g["gaps"]]
    assert levs == sorted(levs, reverse=True)
    for x in g["gaps"]:
        assert x["next"] and x["unknown"]
    # the code-only /rest/admin path (privileged) should rank at or near the top
    top = g["gaps"][0]
    assert top["leverage"] >= g["gaps"][-1]["leverage"]


def test_cli_gaps(tmp_path, capsys):
    xml = export(tmp_path, [item(host="www.shop.test", path="/"),
                            item(host="api.shop.test", path="/api/x", mime="JSON",
                                 resp_ct="application/json", resp_body="{}")])
    out = tmp_path / "o"
    assert main([xml, "-w", "shop", "--out", str(out), "--scope", "shop.test"]) == 0
    capsys.readouterr()
    assert main(["gaps", "shop", "--out", str(out)]) == 0
    text = capsys.readouterr().out
    assert "ranked by how much resolving each" in text
    assert main(["gaps", "shop", "--out", str(out), "--json"]) == 0
    assert "gaps" in json.loads(capsys.readouterr().out)


# ---------------------------------------------- changes ----------------------

def test_diff_detects_appeared_and_gone(tmp_path):
    old = _priv_model(tmp_path, "old")
    # new model adds an admin endpoint actually reached, and a third party
    new_items = [
        item(host="www.shop.test", path="/dashboard"),
        item(host="www.shop.test", path="/app.js", mime="script",
             resp_ct="application/javascript", resp_body='fetch("/api/orders");'),
        item(host="api.shop.test", path="/api/orders", mime="JSON",
             resp_ct="application/json", resp_body="{}",
             req_headers=[("Authorization", "Bearer x"),
                          ("Referer", "https://www.shop.test/dashboard")]),
        item(method="POST", host="api.shop.test", path="/api/admin/users", mime="JSON",
             resp_ct="application/json", resp_body="{}",
             req_headers=[("Authorization", "Bearer x")]),
        item(host="cdn.analytics.test", path="/t.js", mime="script",
             resp_ct="application/javascript", resp_body="//x"),
    ]
    new = build(list(parse_items(export(tmp_path, new_items, "new.xml"))),
                name="shop", scope=["shop.test"])
    d = diff_models(old, new)
    appeared = [x["label"] for a in d["areas"] for x in a["appeared"]]
    assert any("/api/admin/users" in l for l in appeared)
    assert any("analytics" in l for l in appeared)   # new third party
    # the admin endpoint appearance is annotated as privileged
    admin_why = [x["why"] for a in d["areas"] for x in a["appeared"]
                 if "/api/admin/users" in x["label"]][0]
    assert "privileged" in admin_why
    assert d["totals"]["appeared"] >= 2
    assert "never a finding" in d["note"]


def test_diff_no_change_is_empty(tmp_path):
    m = _priv_model(tmp_path, "same")
    d = diff_models(m, from_dict(to_dict(m)))
    assert d["areas"] == [] and d["totals"]["appeared"] == 0


def test_cli_changes(tmp_path, capsys):
    x1 = export(tmp_path, [item(host="www.shop.test", path="/"),
                           item(host="api.shop.test", path="/api/a", mime="JSON",
                                resp_ct="application/json", resp_body="{}")], "v1.xml")
    x2 = export(tmp_path, [item(host="www.shop.test", path="/"),
                           item(host="api.shop.test", path="/api/a", mime="JSON",
                                resp_ct="application/json", resp_body="{}"),
                           item(method="POST", host="api.shop.test", path="/api/admin/x",
                                mime="JSON", resp_ct="application/json", resp_body="{}",
                                req_headers=[("Authorization", "Bearer x")])], "v2.xml")
    o1, o2 = tmp_path / "o1", tmp_path / "o2"
    assert main([x1, "-w", "shop", "--out", str(o1), "--scope", "shop.test"]) == 0
    assert main([x2, "-w", "shop", "--out", str(o2), "--scope", "shop.test"]) == 0
    capsys.readouterr()
    assert main(["changes", "shop", "--out", str(o2),
                 "--against", str(o1 / "shop" / "model.json")]) == 0
    text = capsys.readouterr().out
    assert "what changed" in text and "appeared" in text


def test_cli_changes_bad_against_is_clean_error(tmp_path, capsys):
    xml = export(tmp_path, [item(host="www.shop.test", path="/")])
    out = tmp_path / "o"
    assert main([xml, "-w", "shop", "--out", str(out), "--scope", "shop.test"]) == 0
    capsys.readouterr()
    assert main(["changes", "shop", "--out", str(out), "--against", str(tmp_path / "nope.json")]) == 2
    assert "could not load --against" in capsys.readouterr().err


# ---------------------------------------------- falsify ----------------------

def test_cli_falsify_emits_prompt_and_scaffold(tmp_path, capsys):
    xml = export(tmp_path, [item(host="www.shop.test", path="/"),
                            item(method="POST", host="api.shop.test", path="/api/admin/x",
                                 mime="JSON", resp_ct="application/json", resp_body="{}",
                                 req_headers=[("Authorization", "Bearer x")])])
    out = tmp_path / "o"
    assert main([xml, "-w", "shop", "--out", str(out), "--scope", "shop.test"]) == 0
    capsys.readouterr()
    assert main(["falsify", "shop", "--out", str(out)]) == 0
    text = capsys.readouterr().out
    assert "eliminate" in text.lower() and "plan_scaffold" in text
    assert "payloads" in text.lower()
