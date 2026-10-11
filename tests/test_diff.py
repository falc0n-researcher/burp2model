"""Drift between two builds: ground truth from a synthetic v1 and v2 of one app."""

import json
import os
import sqlite3

import pytest

from burp2model import build, from_dict, parse_items, to_dict
from burp2model import diff as dm
from burp2model import store
from burp2model.cli import main
from test_gaps import export, item

REF = ("Referer", "https://www.shop.test/checkout")


def v1():
    return [
        item(path="/", resp_ct="text/html", resp_headers=[("Server", "nginx/1.24.0")],
             resp_body='<html><script src="/static/app.js"></script></html>'),
        item(path="/static/app.js", mime="script", resp_ct="application/javascript",
             resp_body='fetch("/api/me");'),
        item(path="/api/me", mime="JSON", resp_ct="application/json", resp_body="{}"),
        item(path="/api/admin/users", mime="JSON", status=200, resp_ct="application/json", resp_body="[]"),
        item(path="/api/legacy", mime="JSON", resp_ct="application/json", resp_body="{}"),
    ]


def v2():
    return [
        item(path="/", resp_ct="text/html", resp_headers=[("Server", "cloudflare")],
             resp_body='<html><script src="/static/app.js"></script></html>'),
        item(path="/static/app.js", mime="script", resp_ct="application/javascript",
             resp_body='fetch("/api/me");'),
        item(path="/api/me", mime="JSON", resp_ct="application/json", resp_body="{}"),
        item(path="/api/admin/users", mime="JSON", status=403, resp_ct="application/json", resp_body="{}"),
        # a new page, the script it loads, the endpoint that script names, and its parameters
        item(path="/checkout", resp_ct="text/html",
             resp_body='<html><script src="/static/checkout.js"></script></html>'),
        item(path="/static/checkout.js", mime="script", resp_ct="application/javascript",
             req_headers=[REF], resp_body='fetch("/api/pay", {method: "POST"});'),
        item(method="POST", path="/api/pay", mime="JSON", req_headers=[REF, ("Content-Type", "application/json")],
             req_body='{"amount": 5, "currency": "EUR"}', resp_ct="application/json", resp_body="{}"),
    ]


def model(tmp_path, items, name="shop"):
    return build(list(parse_items(export(tmp_path, items, name=f"{name}-{len(items)}.xml"))), name="shop")


def test_same_build_twice_is_zero_drift(tmp_path):
    d = dm.diff_models(model(tmp_path, v1()), model(tmp_path, v1()))
    assert d["same"] and d["summary"]["total"] == 0


def test_connected_additions_collapse_into_one_workflow(tmp_path):
    d = dm.diff_models(model(tmp_path, v1()), model(tmp_path, v2()))
    wf = [w for w in d["workflows"] if w["kind"] == "new_workflow"]
    assert len(wf) == 1
    labels = {n["label"] for n in wf[0]["nodes"]}
    assert "POST /api/pay" in labels and "checkout.js" in labels
    assert any(n["type"] == "parameter" for n in wf[0]["nodes"])
    assert d["summary"]["new_workflows"] == 1
    assert wf[0]["evidence"]                                     # cites the requests that show it
    # none of it is repeated as a loose new line
    assert not any(x["label"] == "POST /api/pay" for x in d["new"]["nodes"])


def test_fingerprint_changes_are_reported_as_changed(tmp_path):
    d = dm.diff_models(model(tmp_path, v1()), model(tmp_path, v2()))
    text = json.dumps(d["changed"], ensure_ascii=False)
    assert "statuses 200 → 403" in text                          # status moved
    assert any(c["kind"] == "stack" and "nginx" in json.dumps(c) and "Cloudflare" in json.dumps(c)
               for c in d["changed"]) or "cloudflare" in text.lower()          # server swap read as one thing


def test_things_that_went_away_are_reported_as_gone(tmp_path):
    d = dm.diff_models(model(tmp_path, v1()), model(tmp_path, v2()))
    assert any(x["label"] == "GET /api/legacy" for x in d["gone"]["nodes"])


def test_text_report_reads_in_groups(tmp_path):
    out = dm.format_text(dm.diff_models(model(tmp_path, v1()), model(tmp_path, v2())))
    assert "NEW WORKFLOWS" in out and "CHANGED" in out and "GONE" in out
    assert out.index("NEW WORKFLOWS") < out.index("CHANGED") < out.index("GONE")


# ------------------------------------------------------------ history ------

@pytest.fixture
def run(tmp_path, monkeypatch):
    monkeypatch.setenv("BURP2MODEL_FP_KEY", "ci")
    monkeypatch.setenv("BURP2MODEL_OFFLINE", "1")
    out = str(tmp_path / "out")

    def go(items, label=None, name=None):
        xml = export(tmp_path, items, name=name or f"h{len(items)}.xml")
        argv = [xml, "-w", "shop", "--out", out] + (["--label", label] if label else [])
        assert main(argv) == 0
        return os.path.join(out, "shop", "graph.db")
    return go


def test_each_build_is_kept_and_first_last_seen_span_them(run):
    db = run(v1(), label="release-1")
    run(v2(), label="release-2")
    conn = store.open_db(db)
    builds = store.list_builds(conn)
    assert [b["id"] for b in builds] == [1, 2] and builds[1]["label"] == "release-2"
    pay = store.history(conn, "node", "endpoint:POST:www.shop.test:/api/pay")
    assert pay["first_build"] == 2 and pay["last_build"] == 2
    me = store.history(conn, "node", "endpoint:GET:www.shop.test:/api/me")
    assert me["first_build"] == 1 and me["last_build"] == 2          # in both builds
    legacy = store.history(conn, "node", "endpoint:GET:www.shop.test:/api/legacy")
    assert legacy["first_build"] == 1 and legacy["last_build"] == 1   # went after build 1
    assert store.resolve_build(conn, "release-1") == 1 and store.resolve_build(conn, "previous") == 1
    conn.close()


def test_cli_diff_and_builds_and_bql_history(run, capsys):
    db = run(v1())
    run(v2())
    out = os.path.dirname(os.path.dirname(db))
    assert main(["builds", "shop", "--out", out]) == 0
    assert "2 build(s)" in capsys.readouterr().out
    assert main(["diff", "shop", "--out", out]) == 0
    text = capsys.readouterr().out
    assert "NEW WORKFLOWS" in text and "statuses 200 → 403" in text
    assert main(["diff", "shop", "1", "2", "--json", "--out", out]) == 0
    assert json.loads(capsys.readouterr().out)["summary"]["new_workflows"] == 1
    assert main(["diff", "shop", "1", "1", "--out", out]) == 2           # a build against itself is refused
    from burp2model import bql
    conn = bql.connect(db)
    rows = bql.run_query(conn, "node.type:endpoint AND node.first_build:2").rows
    assert {r["label"] for r in rows} == {"POST /api/pay"}
    conn.close()


def test_an_older_graph_db_is_upgraded_without_losing_builds(tmp_path):
    p = str(tmp_path / "graph.db")
    conn = sqlite3.connect(p)
    conn.executescript("CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT);"
                       "INSERT INTO meta VALUES ('schema','1');"
                       "CREATE TABLE builds (id INTEGER PRIMARY KEY, built_at TEXT, nodes INTEGER, edges INTEGER,"
                       " exchanges INTEGER, osint_run INTEGER, model_gz BLOB);"
                       "INSERT INTO builds(built_at,nodes,edges,exchanges) VALUES ('2026-01-01T00:00:00Z',1,1,1);")
    conn.commit()
    conn.close()
    conn = store.open_db(p)
    assert store.list_builds(conn)[0]["id"] == 1
    assert conn.execute("SELECT value FROM meta WHERE key='schema'").fetchone()[0] == str(store.DB_SCHEMA_VERSION)
    conn.close()


def test_keep_builds_env_caps_history(run, monkeypatch):
    monkeypatch.setenv("BURP2MODEL_KEEP_BUILDS", "1")
    db = run(v1())
    run(v2())
    conn = store.open_db(db)
    assert [b["id"] for b in store.list_builds(conn)] == [2]
    conn.close()


# -------------------------------------------------------------------- watch ---

def test_watch_turns_each_new_export_into_a_build_and_prints_the_change(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("BURP2MODEL_FP_KEY", "ci")
    monkeypatch.setenv("BURP2MODEL_OFFLINE", "1")
    folder = tmp_path / "exports"
    folder.mkdir()
    (folder / "monday.xml").write_text(open(export(tmp_path, v1(), name="a.xml")).read())
    out = str(tmp_path / "out")
    args = ["watch", str(folder), "-w", "shop", "--out", out, "--once"]
    assert main(args) == 0
    (folder / "tuesday.xml").write_text(open(export(tmp_path, v2(), name="b.xml")).read())
    capsys.readouterr()
    assert main(args) == 0
    text = capsys.readouterr().out
    assert "NEW WORKFLOWS" in text and "statuses 200 → 403" in text
    conn = store.open_db(os.path.join(out, "shop", "graph.db"))
    assert [b["label"] for b in store.list_builds(conn)] == ["monday", "tuesday"]
    conn.close()
    # nothing new: no further build
    assert main(args) == 0
    conn = store.open_db(os.path.join(out, "shop", "graph.db"))
    assert len(store.list_builds(conn)) == 2
    conn.close()


def test_watch_can_ignore_what_is_already_in_the_folder(tmp_path, monkeypatch):
    monkeypatch.setenv("BURP2MODEL_FP_KEY", "ci")
    monkeypatch.setenv("BURP2MODEL_OFFLINE", "1")
    folder = tmp_path / "exports"
    folder.mkdir()
    (folder / "old.xml").write_text(open(export(tmp_path, v1(), name="a.xml")).read())
    out = str(tmp_path / "out")
    assert main(["watch", str(folder), "-w", "shop", "--out", out, "--once", "--skip-existing"]) == 0
    assert not os.path.exists(os.path.join(out, "shop", "graph.db"))


def test_watch_needs_a_real_folder(tmp_path, capsys):
    assert main(["watch", str(tmp_path / "nope"), "-w", "shop", "--once"]) == 2
    assert "not a folder" in capsys.readouterr().err
