"""The report is a single-page app: drive it in a real Chrome and fail on any script error.

Skipped when no Chrome/Chromium is installed (the same rule as the browser-crawl tests).
"""

import json
import os
import tempfile
import time

import pytest

from burp2model.browser import CDP, WebSocket, find_chrome, launch_chrome
from burp2model.cli import main

pytestmark = pytest.mark.skipif(find_chrome() is None, reason="no Chrome/Chromium installed")

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
VIEWS = ["overview", "ask", "graph", "priorities", "surface", "code", "supply", "trust",
         "crossrole", "unknowns", "inventory", "infra"]


class Page:
    """A headless Chrome tab with the report open; collects script errors."""

    def __init__(self, report):
        self.tmp = tempfile.mkdtemp(prefix="b2m-ui-")
        self.proc, url = launch_chrome(find_chrome(), self.tmp,
                                       ["--window-size=1400,900", "--allow-file-access-from-files"])
        self.cdp = CDP(WebSocket(url))
        tid = self.cdp.call("Target.createTarget", {"url": "about:blank"})["targetId"]
        self.session = self.cdp.call("Target.attachToTarget", {"targetId": tid, "flatten": True})["sessionId"]
        self.errors = []
        for d in ("Page", "Runtime"):
            self.call(d + ".enable")
        self.call("Page.navigate", {"url": "file://" + os.path.abspath(report)})
        self.pump(1.5)

    def call(self, method, params=None):
        return self.cdp.call(method, params, self.session, 30)

    def pump(self, seconds):
        end = time.monotonic() + seconds
        while time.monotonic() < end:
            ev = self.cdp.next_event(0.1)
            if not ev:
                continue
            if ev.get("method") == "Runtime.exceptionThrown":
                d = ev["params"]["exceptionDetails"]
                self.errors.append((d.get("exception") or {}).get("description") or d.get("text"))
            elif ev.get("method") == "Runtime.consoleAPICalled" and ev["params"]["type"] == "error":
                self.errors.append("console.error: " + " ".join(str(a.get("value", "")) for a in ev["params"]["args"]))

    def js(self, expr, wait=0.3):
        r = self.call("Runtime.evaluate", {"expression": expr, "returnByValue": True, "awaitPromise": True})
        if "exceptionDetails" in r:
            self.errors.append("js: " + json.dumps(r["exceptionDetails"])[:200])
        self.pump(wait)
        return (r.get("result") or {}).get("value")

    def close(self):
        try:
            self.proc.terminate()
        except OSError:
            pass


@pytest.fixture(scope="module")
def report(tmp_path_factory):
    out = tmp_path_factory.mktemp("ui")
    with pytest.MonkeyPatch.context() as mp:
        mp.setenv("BURP2MODEL_FP_KEY", "ci")
        mp.setenv("BURP2MODEL_OFFLINE", "1")
        for role, f in (("user", "burp-history-sample.xml"), ("admin", "burp-history-admin-sample.xml")):
            assert main([os.path.join(ROOT, "samples", f), "-w", "shop", "--role", role, "--out", str(out)]) == 0
    return str(out / "shop" / "report.html")


@pytest.fixture(scope="module")
def page(report):
    p = Page(report)
    yield p
    p.close()


def test_every_view_renders_without_a_script_error(page):
    for v in VIEWS:
        page.js(f"location.hash='#{v}'", wait=0.5)
        assert page.js("document.querySelector('#main').textContent.length") > 20, v
    assert page.errors == []


def test_overview_leads_with_what_to_check(page):
    page.js("location.hash='#overview'")
    assert page.js("document.querySelectorAll('.big4 button').length") == 4
    assert page.js("document.querySelectorAll('.lead').length") >= 1
    assert page.js("document.querySelectorAll('.lead').length") <= 5          # a short list, not a wall
    assert page.js("!!document.querySelector('.donut')")
    assert page.js("!!document.querySelector('.smap .tp')")                   # the technology stack map
    assert "Inter" in page.js("getComputedStyle(document.body).fontFamily")      # the embedded fonts
    assert page.js("document.querySelector('.view').getBoundingClientRect().width") > 1000   # uses the full width


def test_evidence_is_labelled_evd_not_ev_underscore(page):
    page.js("location.hash='#inventory'", wait=0.6)
    page.js("document.querySelector('[data-id]').click()")
    page.js("document.querySelector('[data-act=open]').click()", wait=0.5)
    assert "EVD " in page.js("document.querySelector('#dtitle').textContent")
    assert "ev_" not in page.js("document.querySelector('#drawer').textContent")


def test_inventory_lists_every_request_and_filters(page):
    page.js("location.hash='#inventory'", wait=0.6)
    stat = page.js("document.querySelector('#invstat').textContent")
    total = int(stat.split(" of ")[1].split()[0])
    assert total > 10 and stat.startswith(f"{total} of")
    assert page.js("document.querySelectorAll('#invview .pane2').length") == 2       # request and response
    page.js("document.querySelector('[data-m=POST]').click()")
    assert int(page.js("document.querySelector('#invstat').textContent").split(" of ")[0]) < total
    page.js("document.querySelector('#invclear').click()")
    assert page.js("document.querySelector('#invstat').textContent").startswith(f"{total} of")
    assert page.errors == []


def test_one_ask_box_takes_plain_questions_and_bql(page):
    page.js("location.hash='#ask'", wait=0.5)
    page.js("(()=>{const i=document.querySelector('#qin');i.value='which endpoints only returned errors';document.querySelector('#qgo').click();})()")
    assert page.js("!!document.querySelector('#qout .answer')")
    assert "No AI" in page.js("document.querySelector('#qout').textContent")
    page.js("(()=>{const i=document.querySelector('#qin');i.value='req.method:POST';document.querySelector('#qgo').click();})()")
    assert page.js("document.querySelectorAll('.qtab tbody tr').length") > 0
    page.js("(()=>{const i=document.querySelector('#qin');i.value='req.method:POST AND';document.querySelector('#qgo').click();})()")
    assert page.js("!!document.querySelector('.qerr2')")
    assert page.errors == []


def test_map_draws_and_selects_a_node(page):
    page.js("location.hash='#graph'", wait=1.0)
    assert "nodes" in page.js("document.querySelector('#mhud').textContent")
    for mode in ("flow", "focus", "force"):
        page.js(f"document.querySelector('[data-mode={mode}]').click()", wait=0.8)
        assert "nodes" in page.js("document.querySelector('#mhud').textContent"), mode
    page.js("(()=>{const i=document.querySelector('#msq');i.value='checkout';i.dispatchEvent(new Event('input'));"
            "document.querySelector('#msug button').dispatchEvent(new MouseEvent('mousedown',{bubbles:true}));})()")
    assert "checkout" in page.js("document.querySelector('#minsp').textContent")
    assert page.errors == []
