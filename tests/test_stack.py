"""What the app is built on: detection from responses, the model's stack, and the screenshot guard."""

import base64
import json
import os
import types

import pytest

from burp2model import context_package, from_dict, parse_items, to_dict
from burp2model import shot
from burp2model.cli import _wants_screenshot, main
from burp2model.stack import detect, vendors_for
from test_gaps import export, item, model_of


def names(hits):
    return {h[0] for h in hits}


def test_headers_cookies_and_markup_are_read():
    hits = detect({"server": "nginx/1.24.0", "x-powered-by": "Express", "cf-ray": "abc"},
                  ["PHPSESSID"], '<html ng-version="17.1.0"><app-root></app-root>', "/", True)
    got = {(n, c): v for n, c, _how, v in hits}
    assert got[("nginx", "Web server")] == "1.24.0"
    assert ("Express", "Language & framework") in got and ("PHP", "Language & framework") in got
    assert ("Cloudflare", "Edge & CDN") in got
    assert got[("Angular", "Frontend")] == "17.1.0"


def test_generator_meta_and_paths():
    hits = detect({}, [], '<meta name="generator" content="WordPress 6.4.2">', "/graphql", True)
    got = {(n, c): v for n, c, _h, v in hits}
    assert got[("WordPress", "CMS & platform")] == "6.4.2"
    assert ("GraphQL", "API") in got


def test_nothing_is_invented():
    assert detect({"server": "something-custom"}, [], "<html>plain</html>", "/", True) == []


def test_third_party_hosts_map_to_vendors():
    v = vendors_for(["www.googletagmanager.com", "js.stripe.com", "cdn.example.com"])
    assert {(a, b) for a, b, _ in v} == {("Google Tag Manager", "Analytics"), ("Stripe", "Payments")}


def test_model_stack_cites_evidence_and_survives_a_round_trip(tmp_path):
    m = model_of(tmp_path, [
        item(path="/", resp_ct="text/html", resp_headers=[("Server", "nginx/1.2.3")],
             resp_body='<script src="https://js.stripe.com/v3"></script>'),
        item(path="/api/x", mime="JSON", resp_ct="application/json", resp_body="{}"),
    ])
    by = {t["name"]: t for t in m.stack}
    assert by["nginx"]["version"] == "1.2.3" and by["nginx"]["evidence"] == [1]
    m2 = from_dict(json.loads(json.dumps(to_dict(m))))
    assert m2.stack == m.stack
    ctx = context_package(m)
    assert any(t["name"] == "nginx" and t["evidence"] == ["ev_1"] for t in ctx["stack"])
    assert "ev_1" in ctx["evidence"]


# ------------------------------------------------------------ screenshots ---

PNG = b"\x89PNG\r\n\x1a\n" + b"\x00" * 64
JPG = b"\xff\xd8\xff\xe0" + b"\x00" * 64


def test_only_real_images_are_accepted(tmp_path):
    ok = tmp_path / "a.png"
    ok.write_bytes(PNG)
    assert shot.load(str(ok))[0] == "image/png"
    bad = tmp_path / "b.png"
    bad.write_bytes(b"<svg onload=alert(1)>")
    with pytest.raises(ValueError):
        shot.load(str(bad))
    big = tmp_path / "c.jpg"
    big.write_bytes(JPG + b"\x00" * shot.MAX_BYTES)
    with pytest.raises(ValueError):
        shot.load(str(big))


def test_a_screenshot_is_embedded_and_saved_next_to_the_report(tmp_path, monkeypatch):
    monkeypatch.setenv("BURP2MODEL_FP_KEY", "ci")
    monkeypatch.setenv("BURP2MODEL_OFFLINE", "1")
    png = tmp_path / "s.png"
    png.write_bytes(PNG)
    xml = export(tmp_path, [item(path="/", resp_ct="text/html", resp_body="hi")])
    out = tmp_path / "out"
    assert main([xml, "-w", "app", "--out", str(out), "--screenshot", str(png)]) == 0
    assert (out / "app" / "screenshot.png").read_bytes() == PNG
    html = (out / "app" / "report.html").read_text()
    assert "data:image/png;base64," + base64.b64encode(PNG).decode() in html
    # a later rebuild keeps the picture
    assert main([xml, "-w", "app", "--out", str(out)]) == 0
    assert "data:image/png;base64," in (out / "app" / "report.html").read_text()


def test_a_bad_screenshot_is_a_clear_error(tmp_path, capsys, monkeypatch):
    monkeypatch.setenv("BURP2MODEL_FP_KEY", "ci")
    monkeypatch.setenv("BURP2MODEL_OFFLINE", "1")
    bad = tmp_path / "x.png"
    bad.write_text("not an image")
    xml = export(tmp_path, [item(path="/", resp_ct="text/html", resp_body="hi")])
    assert main([xml, "-w", "app", "--out", str(tmp_path / "o"), "--screenshot", str(bad)]) == 2
    assert "not a PNG, JPEG or WebP" in capsys.readouterr().err


def _args(**kw):
    base = dict(no_screenshot=False, screenshot=None, auth_login=None, auth_storage=None)
    base.update(kw)
    return types.SimpleNamespace(**base)


def test_only_an_anonymous_crawl_takes_a_picture_by_itself():
    assert _wants_screenshot(_args(), {}, {}, [], {})
    assert not _wants_screenshot(_args(), {"Authorization": "Bearer x"}, {}, [], {})
    assert not _wants_screenshot(_args(), {}, {"session": "1"}, [], {})
    assert not _wants_screenshot(_args(auth_login="/login"), {}, {}, [], {})
    assert not _wants_screenshot(_args(), {}, {}, ["journey.json"], {})
    assert not _wants_screenshot(_args(no_screenshot=True), {}, {}, [], {})
