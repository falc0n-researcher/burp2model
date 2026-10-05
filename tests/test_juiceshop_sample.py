"""A deep, real OWASP Juice Shop 20.2.0 capture (four roles), end to end.

samples/juiceshop-*.xml were recorded by scripts/capture_juiceshop.py against a
local container (~420 requests): real JWTs, real throwaway logins, test cards, a
password change, multipart uploads, cache revalidation, CORS preflights, redirects,
every status from 200 to 500, and a 1 MB Angular bundle. This is the test that the
tool survives a real app.
"""

import base64
import glob
import json
import os
import re
import urllib.parse

import pytest

from burp2model import bql, from_dict, ReasonGraph, rank_gaps, investigation_plan
from burp2model.cli import main
from burp2model.model import cross_role

HERE = os.path.dirname(__file__)
SAMPLES = os.path.join(HERE, "..", "samples")
ROLES = ("anon", "user", "accountant", "admin")

pytestmark = pytest.mark.skipif(
    not all(os.path.exists(os.path.join(SAMPLES, f"juiceshop-{r}.xml")) for r in ROLES),
    reason="Juice Shop samples not present")

# values that must never reach any derived file
KNOWN_SECRETS = ["Sup3r-Secret-Pa55", "N3w-Secret-Pa55", "Th1rd-Secret-Pa55", "admin123",
                 "4111111111111111", "5555555555554444", "Marlowe", "admin@juice-sh.op",
                 "accountant@juice-sh.op", "i am an awesome accountant"]


@pytest.fixture(scope="module")
def built(tmp_path_factory):
    out = tmp_path_factory.mktemp("js")
    for r in ROLES:
        assert main([os.path.join(SAMPLES, f"juiceshop-{r}.xml"), "-w", "js", "--role", r,
                     "--out", str(out)]) == 0
    return out / "js"


@pytest.fixture(scope="module")
def conn(built):
    c = bql.connect(str(built / "graph.db"))
    yield c
    c.close()


@pytest.fixture(scope="module")
def model(built):
    return from_dict(json.load(open(built / "model.json")))


def _harvest():
    found = set(KNOWN_SECRETS)
    for f in glob.glob(os.path.join(SAMPLES, "juiceshop-*.xml")):
        for b in re.findall(r'base64="true"><!\[CDATA\[(.*?)\]\]>', open(f).read(), re.S):
            t = base64.b64decode(b).decode("latin-1")
            found |= set(re.findall(r"eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{5,}", t))
            found |= set(re.findall(r'"token":"([^"]{12,})"', t))
            found |= {m for m in re.findall(r"[\w.+-]+@b2m-test\.dev", t)}
    return found


def test_no_real_secret_survives_in_any_output(built):
    secrets = _harvest()
    assert len(secrets) > 8
    leaks = []
    for path in glob.glob(str(built / "**" / "*"), recursive=True):
        if os.path.isdir(path):
            continue
        data = open(path, "rb").read()
        for s in secrets:
            for form in {s, urllib.parse.quote(s, safe=""), urllib.parse.quote_plus(s)}:
                if form.encode() in data:
                    leaks.append((os.path.relpath(path, built), form[:24]))
    assert not leaks, leaks


def test_model_recovers_the_real_app(model):
    eps = [n for n in model.nodes.values() if n.type == "endpoint"]
    assert len(eps) >= 95
    states = {}
    for n in eps:
        states[n.attrs["api_state"]] = states.get(n.attrs["api_state"], 0) + 1
    assert states["BOTH"] >= 40 and states["STATIC_ONLY"] >= 10      # the bundle was read
    assert model.roles == {"anon", "user", "accountant", "admin"}
    labels = {n.label for n in eps}
    # ids and codes collapse instead of fanning out
    assert "GET /rest/track-order/{id}" in labels
    assert not [l for l in labels if re.search(r"track-order/[0-9a-f]{4}-", l)]
    assert not [l for l in labels if "WMNSDY2019" in l]
    # no invented root-level endpoints from unresolved bundle prefixes
    assert not [l for l in labels if re.search(r"\s/\{param\}(/|$)", l)]


def test_areas_are_features_not_one_blob(model):
    names = {c["name"] for c in ReasonGraph(model).communities()}
    assert len(names) >= 20
    assert {"basket", "feedbacks", "admin", "2fa", "cards", "addresss", "recycles"} <= names


def test_cross_role_finds_the_real_authorization_questions(model):
    user_vs_admin = cross_role(model, "user", "admin")
    priv = {x["endpoint"] for x in user_vs_admin["low_reached_privileged"]}
    assert "GET /rest/admin/application-configuration" in priv
    both = {x["endpoint"] for x in user_vs_admin["shared_same_success"]}
    assert "GET /api/Users/" in both                                   # a user listing every user
    anon_vs_user = cross_role(model, "anon", "user")
    assert "GET /api/Cards" in {x["endpoint"] for x in anon_vs_user["high_only"]}


def test_bql_over_the_real_capture(conn):
    assert bql.run_query(conn, "role:anon AND resp.code:401").total >= 5
    assert bql.run_query(conn, "resp.code.gte:500").total >= 5
    assert bql.run_query(conn, 'resp.body.regex:"SQLITE_\\w+"').total >= 1    # error constant kept
    assert bql.run_query(conn, "node.type:endpoint AND node.state:STATIC_ONLY").total >= 15
    r = bql.run_query(conn, 'reach "POST /rest/basket/{id}/checkout"')
    assert r.total >= 1 and any(row["state"] == "OBSERVED" for row in r.rows)


def test_methodology_and_gaps_are_target_specific(model):
    plan = investigation_plan(model)
    areas = {a["area"] for a in plan["lines_of_inquiry"]}
    assert {"user", "admin"} <= areas and len(areas) >= 15
    assert rank_gaps(model)["gaps"]


def test_token_package_is_bounded(model):
    from burp2model.methodology import methodology_package
    blob = json.dumps(methodology_package(model), separators=(",", ":"))
    assert len(blob) < 300_000          # the raw capture is ~2.7 MB of decoded bodies


def test_capture_is_deep_enough_to_exercise_the_parser(conn):
    statuses = {r["status"] for r in conn.execute("SELECT DISTINCT status FROM exchanges")}
    assert {200, 201, 204, 302, 304, 400, 401, 403, 404, 500} <= statuses
    methods = {r["method"] for r in conn.execute("SELECT DISTINCT method FROM exchanges")}
    assert {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"} <= methods
    assert conn.execute("SELECT count(*) FROM exchanges").fetchone()[0] >= 400
    # multipart upload, urlencoded form and JSON bodies all parsed without a skip
    assert bql.run_query(conn, 'req.header.cont:"multipart/form-data"').total >= 3
    assert bql.run_query(conn, 'req.header.cont:"application/x-www-form-urlencoded"').total >= 2


def test_accountant_role_adds_a_fourth_view(model):
    from burp2model.model import cross_role
    r = cross_role(model, "user", "accountant")
    assert r["shared_same_success"]
    assert "accountant" in model.roles
