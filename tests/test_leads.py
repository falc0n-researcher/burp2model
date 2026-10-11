"""A beacon is traffic, not a lead."""

from burp2model import build, parse_items
from burp2model.cli import main
from burp2model.context import context_package
from burp2model.report import build_payload
from test_gaps import export, item


def model(tmp_path):
    items = [item("POST", "shop.test", "/api/checkout", "JSON", 200, req_body='{"a":1}'),
             item("POST", "shop.test", "/v1/collect", "JSON", 202, req_body='{"e":1}'),
             item("POST", "shop.test", "/api/track", "JSON", 204, req_body='{"e":2}'),
             item("GET", "shop.test", "/admin/analytics", "JSON", 200)]
    return build(list(parse_items(export(tmp_path, items))), name="shop")


def test_endpoints_that_are_beacons_are_marked(tmp_path):
    eps = {e["label"]: e for e in build_payload(model(tmp_path))["endpoints"]}
    assert eps["POST /v1/collect"]["telemetry"] and eps["POST /api/track"]["telemetry"]
    assert not eps["POST /api/checkout"]["telemetry"]


def test_beacons_go_last_in_what_an_ai_is_handed(tmp_path):
    labels = [e["label"] for e in context_package(model(tmp_path))["endpoints"]]
    assert labels.index("POST /api/checkout") < labels.index("POST /v1/collect")
    assert labels.index("POST /api/checkout") < labels.index("POST /api/track")
