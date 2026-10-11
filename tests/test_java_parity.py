"""The Burp extension's Java engine must build the same model as the Python engine."""

import json
import os
import shutil
import subprocess

import pytest

from burp2model.cli import main
from burp2model import bql
from burp2model import diff as dm
from burp2model.model import from_dict

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
ENGINE = os.path.join(ROOT, "burp-extension", "src", "main", "java", "burp2model", "engine")
UI = os.path.join(ROOT, "burp-extension", "src", "main", "java", "burp2model", "ui")
RES = os.path.join(ROOT, "burp-extension", "src", "main", "resources")
SAMPLES = os.path.join(ROOT, "samples")


def _java():
    javac, java = shutil.which("javac"), shutil.which("java")
    if not javac or not java:
        return None
    try:
        subprocess.run([javac, "-version"], check=True, capture_output=True, timeout=30)
        subprocess.run([java, "-version"], check=True, capture_output=True, timeout=30)
    except (OSError, subprocess.SubprocessError):
        return None
    return javac, java


pytestmark = pytest.mark.skipif(_java() is None, reason="no JDK installed")


@pytest.fixture(scope="module")
def classes(tmp_path_factory):
    out = tmp_path_factory.mktemp("jc")
    javac, _ = _java()
    srcs = [os.path.join(d, f) for d in (ENGINE, UI) for f in os.listdir(d) if f.endswith(".java")]
    subprocess.run([javac, "--release", "17", "-d", str(out)] + srcs, check=True, capture_output=True)
    shutil.copy(os.path.join(RES, "public_suffix_list.dat"), out)
    return str(out)


def _run(java, classes, cls, *args):
    env = dict(os.environ, BURP2MODEL_FP_KEY="k")
    r = subprocess.run([java, "-cp", classes, "burp2model.engine." + cls, *args], check=True, capture_output=True, text=True, env=env)
    return r.stdout


def _py_model(tmp_path, xml, name):
    assert main([xml, "-w", name, "--out", str(tmp_path)]) == 0
    return json.load(open(tmp_path / name / "model.json")), str(tmp_path / name / "graph.db")


@pytest.fixture(autouse=True)
def _env(monkeypatch):
    from burp2model import redact
    monkeypatch.setenv("BURP2MODEL_FP_KEY", "k")
    monkeypatch.setenv("BURP2MODEL_OFFLINE", "1")
    monkeypatch.setattr(redact, "_KEY", b"k")          # an earlier test in this process may have keyed it already


XMLS = ["burp-history-sample.xml", "burp-history-admin-sample.xml", "juiceshop-admin.xml", "juiceshop-user.xml"]


@pytest.mark.parametrize("xml", XMLS)
def test_same_model_as_python(classes, tmp_path, xml):
    java = _java()[1]
    src = os.path.join(SAMPLES, xml)
    py, _ = _py_model(tmp_path, src, "app")
    jp = tmp_path / "j.json"
    _run(java, classes, "Dump", src, str(jp), "app")
    j = json.load(open(jp))
    assert j["scope"] == py["scope"]
    jn = {n["id"]: n for n in j["nodes"]}
    pn = {n["id"]: n for n in py["nodes"]}
    assert set(jn) == set(pn)
    for i in pn:
        for f in ("type", "layer", "label", "evidence", "roles", "attrs"):
            assert jn[i][f] == pn[i][f], (i, f)
    je = {(e["src"], e["dst"], e["type"]): e for e in j["edges"]}
    pe = {(e["src"], e["dst"], e["type"]): e for e in py["edges"]}
    assert set(je) == set(pe)
    assert all(je[k]["evidence"] == pe[k]["evidence"] and je[k]["state"] == pe[k]["state"] for k in pe)
    assert j["stack"] == py["stack"]
    assert j["roles"] == py["roles"]
    key = lambda s: (s["kind"], s["hmac_12"])          # noqa: E731
    assert sorted(j["secrets"], key=key) == sorted(py["secrets"], key=key)


def test_same_answers_as_python_bql(classes, tmp_path):
    java = _java()[1]
    from test_bql_parity import CORPUS
    import re
    src = os.path.join(SAMPLES, "burp-history-sample.xml")
    py, db = _py_model(tmp_path, src, "shop")
    queries = [q for q in CORPUS if not re.search(r"osint|node\.type:subdomain|node\.layer:0|stats", q)]
    (tmp_path / "q.json").write_text(json.dumps(queries))
    jr = json.loads(_run(java, classes, "QueryMain", str(tmp_path / "shop" / "model.json"), str(tmp_path / "q.json")))
    conn = bql.connect(db)
    for q, j in zip(queries, jr):
        try:
            r = bql.run_query(conn, q)
        except bql.BQLError:
            assert not j["ok"], q
            continue
        assert j["ok"], q
        assert (j["kind"], j["total"], j["columns"]) == (r.kind, r.total, r.columns), q
        norm = lambda rows: [json.dumps(x, sort_keys=True) for x in rows]          # noqa: E731
        assert norm(j["rows"]) == norm(r.rows), q


def test_same_diff_as_python(classes, tmp_path):
    java = _java()[1]
    a, _ = _py_model(tmp_path, os.path.join(SAMPLES, "burp-history-sample.xml"), "a")
    b, _ = _py_model(tmp_path, os.path.join(SAMPLES, "burp-history-admin-sample.xml"), "b")
    want = dm.diff_models(from_dict(a), from_dict(b), {"id": 1}, {"id": 2})
    got = json.loads(_run(java, classes, "DiffMain", str(tmp_path / "a" / "model.json"), str(tmp_path / "b" / "model.json")))
    want["app"] = got["app"] = None
    assert json.dumps(want, sort_keys=True) == json.dumps(got, sort_keys=True)


def test_same_redaction_as_python(classes, tmp_path):
    """The shapes a secret hides in, and ordinary text: the Java engine must mask and keep exactly what Python does."""
    from test_redaction_realistic import BENIGN, CASES
    from burp2model.redact import redact_named, redact_value_patterns
    texts = [t for t, _ in CASES.values()] + BENIGN + [
        'password=a&new=b&repeat=b', '<input name="user_token" value="zzzzzzzz">', "Cookie: PHPSESSID=abc123; x=1",
        '{"a":{"b":{"secret":"s3cr3t-value"}}}', "name: shop\nauthor: someone", 'const x = {code: 5, id: "abcdefgh"};']
    (tmp_path / "t.json").write_text(json.dumps(texts))
    got = json.loads(_run(_java()[1], classes, "RedactMain", str(tmp_path / "t.json")))
    want = [redact_named(redact_value_patterns(t)[0]) for t in texts]
    for t, w, g in zip(texts, want, got):
        assert g == w, (t, w, g)


@pytest.mark.parametrize("xml", ["burp-history-sample.xml", "burp-history-admin-sample.xml"])
def test_same_stored_requests_as_python(classes, tmp_path, xml):
    """What is stored for every request (the masked request and response) is the same in both engines."""
    java = _java()[1]
    src = os.path.join(SAMPLES, xml)
    py, _ = _py_model(tmp_path, src, "app")
    jp = tmp_path / "j.json"
    _run(java, classes, "Dump", src, str(jp), "app")
    assert json.load(open(jp))["evidence"] == py["evidence"]


def test_same_model_from_a_har_as_python(classes, tmp_path):
    from test_har import SHOP, har
    java = _java()[1]
    src = har(tmp_path, SHOP)
    py, _ = _py_model(tmp_path, src, "app")
    jp = tmp_path / "j.json"
    _run(java, classes, "Dump", src, str(jp), "app")
    j = json.load(open(jp))
    assert {n["id"]: (n["label"], n["attrs"], n["evidence"]) for n in j["nodes"]} == {n["id"]: (n["label"], n["attrs"], n["evidence"]) for n in py["nodes"]}
    assert j["evidence"] == py["evidence"]
    key = lambda s: (s["kind"], s["hmac_12"])          # noqa: E731
    assert sorted(j["secrets"], key=key) == sorted(py["secrets"], key=key)
