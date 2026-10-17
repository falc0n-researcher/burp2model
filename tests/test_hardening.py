"""The CLI under crashes, damaged files, half-copied exports and large captures.

Each test pins one fix: writes are whole or absent, a damaged graph.db or snapshot is kept aside or
refused (never silently wiped), HAR is streamed, the entity check cannot be dodged by re-encoding,
watch never builds a file that is still moving, and the model builder's n^2 loops are gone without
changing what they produce.
"""

import gzip
import io
import json
import os
import random
import sqlite3
import stat
import time

import pytest

from burp2model import build, parse_items
from burp2model import cli, cmd_history, store
from burp2model import diff as dm
from burp2model import parse as parse_mod
from burp2model.atomic import atomic_write, keep_aside
from burp2model.cli import main
from burp2model.model import _param_of, collapse_siblings
from test_diff import v1, v2
from test_gaps import export, item


def _build(tmp_path, items, name="a.xml", *extra):
    out = str(tmp_path / "out")
    assert main([export(tmp_path, items, name=name), "-w", "shop", "--out", out, *extra]) == 0
    return os.path.join(out, "shop")


# -------------------------------------------------------------- atomic writes ---

def test_a_failed_write_leaves_the_old_file_and_no_temp_file(tmp_path):
    p = tmp_path / "model.json"
    p.write_text("old")
    with pytest.raises(RuntimeError):
        with atomic_write(str(p)) as f:
            f.write("half of a new")
            raise RuntimeError("crash")
    assert p.read_text() == "old"
    assert os.listdir(tmp_path) == ["model.json"]


def test_an_atomic_write_keeps_the_files_permissions(tmp_path):
    p = tmp_path / "x"
    p.write_text("a")
    os.chmod(p, 0o640)
    with atomic_write(str(p)) as f:
        f.write("b")
    assert p.read_text() == "b" and stat.S_IMODE(os.stat(p).st_mode) == 0o640


def test_a_crash_while_writing_the_model_keeps_the_previous_model(tmp_path, monkeypatch, capsys):
    outdir = _build(tmp_path, v1())
    before = open(os.path.join(outdir, "model.json")).read()

    def half(m, indent=None):
        yield "{\"half\": "
        raise OSError("disk full")
    monkeypatch.setattr(cli, "dump_model", half)
    assert main([export(tmp_path, v2(), name="b.xml"), "-w", "shop", "--out", str(tmp_path / "out")]) == 2
    assert "disk full" in capsys.readouterr().err
    assert open(os.path.join(outdir, "model.json")).read() == before
    assert not [f for f in os.listdir(outdir) if f.endswith(".tmp")]


def test_a_crash_after_parsing_never_leaves_the_build_with_no_input(tmp_path, monkeypatch):
    outdir = _build(tmp_path, v1())

    def interrupted(*a, **kw):
        raise KeyboardInterrupt
    monkeypatch.setattr(cli, "_clear_inputs", interrupted)
    with pytest.raises(KeyboardInterrupt):
        main([export(tmp_path, v2(), name="b.xml"), "-w", "shop", "--out", str(tmp_path / "out")])
    # the new input went in before the old ones were cleared
    assert os.listdir(os.path.join(outdir, "inputs")) == ["_default.jsonl"]


def test_a_new_fingerprint_key_is_private_and_whole(tmp_path, monkeypatch):
    monkeypatch.delenv("BURP2MODEL_FP_KEY")
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    key = tmp_path / "burp2model" / "fingerprint.key"
    key.parent.mkdir()
    key.write_bytes(b"short")                       # a truncated key is replaced
    try:
        cli._init_key()
    finally:
        cli.set_fingerprint_key(b"test-key")
    assert len(key.read_bytes()) == 32 and stat.S_IMODE(os.stat(key).st_mode) == 0o600


def test_keep_aside_never_overwrites_an_earlier_kept_file(tmp_path):
    a = tmp_path / "graph.db"
    kept = []
    for body in (b"one", b"two"):
        a.write_bytes(body)
        kept.append(keep_aside(str(a)))
    assert len(set(kept)) == 2 and [open(k, "rb").read() for k in kept] == [b"one", b"two"]


# ------------------------------------------------------------ damaged graph.db ---

def test_a_damaged_graph_db_is_kept_aside_and_the_build_goes_on(tmp_path, capsys):
    outdir = _build(tmp_path, v1())
    db = os.path.join(outdir, "graph.db")
    junk = b"this is not a database" * 100
    open(db, "wb").write(junk)
    capsys.readouterr()
    assert main([export(tmp_path, v2(), name="b.xml"), "-w", "shop", "--out", str(tmp_path / "out")]) == 0
    err = capsys.readouterr().err
    assert "was damaged; kept it aside" in err
    kept = [f for f in os.listdir(outdir) if f.startswith("graph.db.damaged-")]
    assert open(os.path.join(outdir, kept[0]), "rb").read() == junk          # kept byte for byte
    conn = store.open_db(db)
    assert len(store.list_builds(conn)) == 1
    conn.close()


def test_a_truncated_graph_db_is_refused_by_readers_and_replaced_by_the_next_build(tmp_path, capsys):
    outdir = _build(tmp_path, v1())
    for items, name in ((v2(), "b.xml"), (v1(), "c.xml")):
        assert main([export(tmp_path, items, name=name), "-w", "shop", "--out", str(tmp_path / "out")]) == 0
    db = os.path.join(outdir, "graph.db")
    with open(db, "r+b") as f:
        f.truncate(os.path.getsize(db) // 2)
    damaged = open(db, "rb").read()
    capsys.readouterr()
    for cmd in (["builds", "shop"], ["diff", "shop"], ["q", "shop", "endpoints"]):
        rc = main([*cmd, "--out", str(tmp_path / "out")])
        assert rc == 2, cmd
        assert "damaged" in capsys.readouterr().err
    assert open(db, "rb").read() == damaged                     # readers never touch it
    assert main([export(tmp_path, v2(), name="d.xml"), "-w", "shop", "--out", str(tmp_path / "out")]) == 0
    assert "kept it aside" in capsys.readouterr().err


def test_a_damaged_snapshot_is_reported_not_a_traceback(tmp_path, capsys):
    outdir = _build(tmp_path, v1())
    assert main([export(tmp_path, v2(), name="b.xml"), "-w", "shop", "--out", str(tmp_path / "out")]) == 0
    db = os.path.join(outdir, "graph.db")
    conn = sqlite3.connect(db)
    blob = conn.execute("SELECT model_gz FROM builds WHERE id=1").fetchone()[0]
    conn.execute("UPDATE builds SET model_gz=? WHERE id=1", (blob[: len(blob) // 2],))   # a cut gzip stream
    conn.execute("UPDATE builds SET model_gz=? WHERE id=2", (gzip.compress(b"{not json"),))
    conn.commit()
    conn.close()
    capsys.readouterr()
    assert main(["diff", "shop", "--out", str(tmp_path / "out")]) == 2
    assert "damaged" in capsys.readouterr().err
    conn = store.open_db(db)
    for bid in (1, 2):
        with pytest.raises(ValueError, match="damaged"):
            store.load_build(conn, bid)
    conn.close()
    capsys.readouterr()
    assert main(["q", "shop", "changed-since 1", "--out", str(tmp_path / "out")]) == 2
    assert "damaged" in capsys.readouterr().err


def test_a_journal_goes_aside_with_its_damaged_database(tmp_path):
    db = tmp_path / "graph.db"
    db.write_bytes(b"junk")
    (tmp_path / "graph.db-journal").write_bytes(b"stale")
    aside = store._set_aside(str(db))
    assert sorted(os.listdir(tmp_path)) == sorted([os.path.basename(aside), os.path.basename(aside) + "-journal"])


def test_a_locked_graph_db_is_not_mistaken_for_a_damaged_one():
    assert not store.is_damaged(sqlite3.OperationalError("database is locked"))
    assert store.is_damaged(sqlite3.DatabaseError("file is not a database"))


# ------------------------------------------------------------------------ HAR ---

def _har_text(entries, **extra):
    return json.dumps({"log": {"version": "1.2", "creator": {"name": "t"}, "entries": entries, **extra}, **extra})


def _entry(i):
    return {"request": {"method": "GET", "url": f"https://shop.test/p/{i}?q={i}", "headers": []},
            "response": {"status": 200, "headers": [],
                         "content": {"mimeType": "text/html", "text": "<p>é \\\" ☃ " + "x" * (i % 13) + "</p>"}},
            "n": [i, -1.5e3, True, None, {"k": "v,]}"}]}


@pytest.mark.parametrize("chunk", [1, 2, 7, 64, 1 << 20])
def test_streamed_har_entries_match_json_load(chunk):
    entries = [_entry(i) for i in range(40)] + [123456789, "s", [], {}]
    text = _har_text(entries, pages=[{"id": "p"}])
    got = list(parse_mod._har_entries(io.StringIO(text), chunk=chunk))
    assert got == json.loads(text)["log"]["entries"]
    pretty = json.dumps(json.loads(text), indent=3)
    assert list(parse_mod._har_entries(io.StringIO(pretty), chunk=chunk)) == got


class _Counting(io.StringIO):
    read_chars = 0

    def read(self, n=-1):
        out = super().read(n)
        self.read_chars += len(out)
        return out


def test_a_har_is_read_entry_by_entry_not_all_at_once(monkeypatch):
    text = _har_text([_entry(i) for i in range(5000)])
    f = _Counting(text)
    entries = parse_mod._har_entries(f, chunk=4096)
    assert next(entries)["n"][0] == 0
    assert f.read_chars < len(text) / 50                # one entry read, not the whole capture

    def no_json_load(*a, **kw):
        raise AssertionError("the HAR reader must not load the whole file")
    monkeypatch.setattr(parse_mod.json, "load", no_json_load)
    assert sum(1 for _ in entries) == 4999


@pytest.mark.parametrize("text, why", [
    ('{"log": {"entries": [{"a": 1}, {"b": ', "not valid JSON"),         # cut off mid-copy
    ('{"log": {"entries": []}} trailing', "not valid JSON"),
    ('{"log": {"entries": {"a": 1}}}', "no log.entries"),
    ('{"log": []}', "no log.entries"),
    ('[1, 2]', "no log.entries"),
    ('{"nolog": {"entries": []}}', "no log.entries"),
    ('not json', "not valid JSON"),
])
def test_a_bad_or_half_copied_har_is_refused(tmp_path, text, why):
    p = tmp_path / "x.har"
    p.write_text(text)
    with pytest.raises(ValueError, match=why):
        list(parse_items(str(p)))


def test_a_har_with_a_byte_order_mark_is_read(tmp_path):
    p = tmp_path / "x.har"
    p.write_bytes(b"\xef\xbb\xbf" + _har_text([_entry(1)]).encode())
    assert len(list(parse_items(str(p)))) == 1


# ------------------------------------------------------------------------ XML ---

BOMB = ('<?xml version="1.0" encoding="UTF-16"?><!DOCTYPE items [<!ENTITY a "aaaaaaaaaa">'
        '<!ENTITY b "&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;">]><items>&b;</items>')


@pytest.mark.parametrize("encoding", ["utf-16", "utf-16-le", "utf-16-be", "utf-32"])
def test_entity_declarations_cannot_hide_in_a_wide_encoding(tmp_path, encoding):
    p = tmp_path / "bomb.xml"
    body = BOMB.encode(encoding)
    if encoding in ("utf-16-le", "utf-16-be"):
        body = BOMB.replace(' encoding="UTF-16"', "").encode(encoding)   # no BOM, found by the first bytes
    p.write_bytes(body)
    with pytest.raises(ValueError, match="entity declarations"):
        list(parse_items(str(p)))


def test_an_entity_declaration_split_across_read_chunks_is_found(tmp_path, monkeypatch):
    p = tmp_path / "x.xml"
    pad = "<!-- " + "p" * ((1 << 20) - 12) + " -->"
    p.write_text('<?xml version="1.0"?>' + pad + '<!DOCTYPE i [<!ENTITY a "b">]><items/>')
    with pytest.raises(ValueError, match="entity declarations"):
        list(parse_items(str(p)))


def test_a_utf16_export_without_entities_still_parses(tmp_path):
    xml = '<?xml version="1.0" encoding="UTF-16"?><items>' + "".join(v1()) + "</items>"
    p = tmp_path / "wide.xml"
    p.write_bytes(xml.encode("utf-16"))
    assert len(list(parse_items(str(p)))) == len(v1())


# ---------------------------------------------------------------------- watch ---

def _watch(tmp_path, *extra):
    return main(["watch", str(tmp_path / "exports"), "-w", "shop", "--out", str(tmp_path / "out"), "--once", *extra])


def test_watch_does_not_mark_done_an_export_that_changed_while_it_was_read(tmp_path, monkeypatch, capsys):
    folder = tmp_path / "exports"
    folder.mkdir()
    full = open(export(tmp_path, v2(), name="full.xml")).read()
    (folder / "monday.xml").write_text(open(export(tmp_path, v1(), name="half.xml")).read())
    real = cmd_history._main
    calls = []

    def build_while_copy_finishes(argv):
        rc = real(argv)
        if argv[0] == "build" and not calls:
            (folder / "monday.xml").write_text(full)          # the copy carries on under the build
            st = os.stat(folder / "monday.xml")
            os.utime(folder / "monday.xml", ns=(st.st_atime_ns, st.st_mtime_ns + 10**9))
        calls.append(argv[0])
        return rc
    monkeypatch.setattr(cmd_history, "_main", build_while_copy_finishes)
    assert _watch(tmp_path) == 0
    assert "changed while it was being read" in capsys.readouterr().err
    state = os.path.join(tmp_path, "out", "shop", "watch.json")
    assert not os.path.exists(state) or "monday.xml" not in json.load(open(state))
    # once it holds still, the next look builds the whole file
    assert _watch(tmp_path) == 0
    assert "monday.xml" in json.load(open(state))


def test_a_damaged_watch_state_is_kept_aside_not_silently_reset(tmp_path, capsys):
    folder = tmp_path / "exports"
    folder.mkdir()
    (folder / "monday.xml").write_text(open(export(tmp_path, v1(), name="a.xml")).read())
    assert _watch(tmp_path) == 0
    state = tmp_path / "out" / "shop" / "watch.json"
    state.write_text('{"monday.xml": [1')
    capsys.readouterr()
    assert _watch(tmp_path) == 0
    assert "kept it aside" in capsys.readouterr().err
    assert [f for f in os.listdir(state.parent) if f.startswith("watch.json.damaged-")]


def test_watch_survives_an_export_vanishing_between_listing_and_stat(tmp_path, monkeypatch):
    folder = tmp_path / "exports"
    folder.mkdir()
    (folder / "monday.xml").write_text(open(export(tmp_path, v1(), name="a.xml")).read())
    real = os.listdir
    monkeypatch.setattr(cmd_history.os, "listdir",
                        lambda d: real(d) + (["gone.xml"] if str(d) == str(folder) else []))
    assert _watch(tmp_path) == 0
    assert "monday.xml" in json.load(open(tmp_path / "out" / "shop" / "watch.json"))


# ------------------------------------------------------- n^2 loops, same output ---

def _collapse_before(exchanges):
    """collapse_siblings as it was before the per-group index (single host, so the host scoping cannot differ)."""
    from burp2model.model import SIBLING_SHAPE, SIBLING_STEM, _FILE_SEG, is_probe
    seen = {}
    for ex in exchanges:
        if ex.method == "OPTIONS" or is_probe(ex) or _FILE_SEG.search(ex.path_template.rsplit("/", 1)[-1] or ""):
            continue
        seen.setdefault((ex.host, ex.path_template.partition("?")[0]), set())
    templates = {k: [x for x in k[1].strip("/").split("/") if x] for k in seen}
    depth = max((len(v) for v in templates.values()), default=0)
    cur = {k: list(v) for k, v in templates.items()}
    for d in range(depth):
        groups = {}
        for k, segs in cur.items():
            if len(segs) > d:
                groups.setdefault((k[0], tuple(segs[:d])), set()).add(segs[d])
        for (host, prefix), values in groups.items():
            plain = {v for v in values if "{" not in v and not _FILE_SEG.search(v)}
            if len(plain) < SIBLING_STEM:
                continue
            fold, stems = {}, {}
            for v in plain:
                if "-" in v:
                    stems.setdefault(v.rsplit("-", 1)[0] + "-", []).append(v)
            for st, members in stems.items():
                if len(members) >= SIBLING_STEM and len(st) >= 6:
                    for v in members:
                        fold[v] = st + "{slug}"
            rest = plain - set(fold)
            if len(rest) >= SIBLING_SHAPE:
                kids = {v: frozenset(segs[d + 1] for segs in cur.values()
                                     if len(segs) > d + 1 and segs[d] == v and tuple(segs[:d]) == prefix)
                        for v in rest}
                shaped = {v: ks for v, ks in kids.items() if ks}
                if shaped:
                    modal = max(set(shaped.values()), key=list(shaped.values()).count)
                    same = [v for v, ks in shaped.items() if ks == modal]
                    if len(same) >= SIBLING_SHAPE and len(same) >= 0.8 * len(shaped):
                        for v in same:
                            fold[v] = "{slug}"
            if not fold:
                continue
            for k, segs in cur.items():
                if k[0] == host and len(segs) > d and tuple(segs[:d]) == prefix and segs[d] in fold:
                    segs[d] = fold[segs[d]]
    return {k: "/" + "/".join(s) for k, s in cur.items()}


class _Ex:
    def __init__(self, path):
        self.method, self.host, self.path, self.path_template = "GET", "shop.test", path, path
        self.referer_host = self.referer_path = None


def _slug_paths(rng, n):
    words = ["red", "blue", "best-laundry-in", "live-channel", "city", "deal", "item", "cat"]
    out = []
    for i in range(n):
        shape = rng.randrange(5)
        if shape == 0:
            out.append(f"/best-laundry-in-{rng.choice(words)}{i}")
        elif shape == 1:
            out.append(f"/channels/{rng.choice(words)}-{i}/{{id}}")
        elif shape == 2:
            out.append(f"/shop/{rng.choice(words)}{i % 40}/reviews")
        elif shape == 3:
            out.append(f"/api/{rng.choice(words)}")
        else:
            out.append(f"/c/{rng.choice(words)}/{rng.choice(words)}-x{i % 30}/{rng.choice(['a', 'b'])}")
    return out


@pytest.mark.parametrize("seed", range(6))
def test_sibling_folding_matches_the_quadratic_version(seed):
    paths = _slug_paths(random.Random(seed), 3000)
    old = _collapse_before([_Ex(p) for p in paths])
    exs = [_Ex(p) for p in paths]
    collapse_siblings(exs)
    for ex, p in zip(exs, paths):
        assert ex.path_template == old[("shop.test", p)], p


def test_sibling_folding_scales_to_a_large_export():
    exs = [_Ex(f"/channel/show-{i}/episodes") for i in range(20000)]
    start = time.perf_counter()
    assert collapse_siblings(exs) == 20000
    assert time.perf_counter() - start < 5            # the quadratic scan took 14 s here
    assert exs[0].path_template == "/channel/{slug}/episodes"


def test_dropped_endpoint_params_match_the_scan_over_every_dropped_id():
    rng = random.Random(1)
    dead = {f"endpoint:GET:h{rng.randrange(9)}.test:/p/{i}" for i in range(300)} | {"route:h.test:/a:b"}
    pids = [f"param:{rng.choice(sorted(dead))}:{rng.choice(['q', 'id', 'x:y'])}" for _ in range(500)]
    pids += [f"param:endpoint:GET:h1.test:/p/{i}x:q" for i in range(300)]
    pids += ["param:route:h.test:/a:b:c", "param:route:h.test:/a", "param::"]
    for pid in pids:
        assert _param_of(pid, dead) == any(pid.startswith(f"param:{g}:") for g in dead), pid


def test_diff_workflows_are_unchanged(tmp_path):
    d = dm.diff_models(build(list(parse_items(export(tmp_path, v1(), name="a.xml"))), name="shop"),
                       build(list(parse_items(export(tmp_path, v2(), name="b.xml"))), name="shop"))
    wf = [w for w in d["workflows"] if w["kind"] == "new_workflow"]
    assert len(wf) == 1 and wf[0]["head"] == "/checkout"


def test_many_new_workflows_diff_quickly():
    from burp2model.model import Model
    old, new = Model("shop"), Model("shop")
    for m in (old, new):
        m.add_node("endpoint:GET:shop.test:/api/me", "endpoint", 4, "GET /api/me")
    n = 8000
    for i in range(n):                  # each new page loads its own new script: n workflows of two
        new.add_node(f"route:/p{i}", "route", 2, f"/p{i}")
        new.add_node(f"script:/s{i}.js", "script", 3, f"s{i}.js")
        new.add_edge(f"route:/p{i}", f"script:/s{i}.js", "LOADS", "OBSERVED", 1)
        new.add_edge(f"script:/s{i}.js", "endpoint:GET:shop.test:/api/me", "CALLS", "INFERRED", 1)
    start = time.perf_counter()
    d = dm.diff_models(old, new)
    assert time.perf_counter() - start < 3            # each workflow used to scan every added edge: 10 s
    wf = [w for w in d["workflows"] if w["kind"] == "new_workflow"]
    assert len(wf) == n and all(w["links"] == [{"to": "GET /api/me", "edge": "calls", "node": w["nodes"][1]["label"]}]
                                for w in wf)


def test_spilled_logger_cells_are_joined_in_one_pass(tmp_path):
    from burp2model.parse import _csv_rows
    head = "Number,Tool,Method,Host,Path,Request,Response\n"
    p = tmp_path / "l.csv"
    p.write_text(head + "1,Proxy,GET,shop.test,/,R0,S0\n" + "".join(f"S{i}\n" for i in range(1, 2000))
                 + "2,Proxy,GET,shop.test,/b,Q0,\n" + "".join(f"Q{i}\n" for i in range(1, 5)))
    rows = list(_csv_rows(str(p)))
    assert rows[0]["Response"] == "".join(f"S{i}" for i in range(2000)) and rows[0]["_spilled"]
    assert rows[1]["Request"] == "Q0Q1Q2Q3Q4" and rows[1]["Response"] == ""
