"""Query-routed pages (index.php?page=...) and wide namespaces, found on DVWA and Mutillidae."""

from burp2model.graph import ReasonGraph
from burp2model.model import Model
from burp2model.redact import route_template, template_path


def rt(p):
    return route_template(p, template_path(p))


def test_page_selecting_query_parameters_stay_in_the_template():
    assert rt("/index.php?page=login.php") == "/index.php?page=login.php"
    assert rt("/index.php?page=login.php&x=1") == "/index.php?page=login.php"
    assert rt("/app.cgi?action=cart&view=full") == "/app.cgi?action=cart&view=full"
    assert rt("/index.php?page=register.php") != rt("/index.php?page=login.php")


def test_ids_secrets_pagination_and_assets_are_not_routes():
    assert rt("/products?page=2") == "/products"                       # pagination
    assert rt("/items?q=shoes&sort=asc") == "/items"
    assert rt("/x?page=0123456789abcdef0123456789abcdef") == "/x"        # shaped like a hash
    assert rt("/x?page=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abcdefghij") == "/x"
    assert rt("/static/app.js?page=home") == "/static/app.js"
    assert rt("/x?code=ABC") == "/x"                                    # not a route parameter


def _m(paths):
    m = Model("t")
    for i, p in enumerate(paths):
        m.add_node(f"route:h{i}", "route", 2, p, host="h", path=p, statuses=[])
    return m


def test_a_wide_namespace_splits_on_its_second_segment():
    paths = [f"/vulnerabilities/{x}/" for x in ("sqli", "xss_r", "xss_s", "exec", "csrf", "upload")] + ["/about.php"]
    rg = ReasonGraph(_m(paths))
    assert rg._resource_key("/vulnerabilities/sqli/") == "vulnerabilities/sqli"
    assert rg._resource_key("/vulnerabilities/xss_r/") != rg._resource_key("/vulnerabilities/exec/")
    assert rg._resource_key("/about.php") == "about"


def test_a_narrow_namespace_does_not_split_and_query_routes_use_their_page():
    rg = ReasonGraph(_m(["/api/users", "/api/users/{id}", "/api/orders"]))
    assert rg._resource_key("/api/users/{id}") == "user" and rg._resource_key("/api/orders") == "order"
    assert rg._resource_key("/index.php?page=login.php") == "login"
    assert rg._resource_key("/index.php?do=toggle-hints&page=x.php") == "toggle-hints"


def test_underscored_names_stay_distinct():
    paths = [f"/v/{x}/" for x in ("xss_r", "xss_s", "xss_d", "sqli", "sqli_blind")]
    rg = ReasonGraph(_m(paths))
    keys = {rg._resource_key(p) for p in paths}
    assert len(keys) == 5 and "v/xss_r" in keys


def test_pages_that_take_parameters_become_lines_of_inquiry():
    from burp2model.methodology import investigation_plan
    m = Model("t")
    m.add_node("host:h", "host", 1, "h")
    m.add_node("route:h/sqli/", "route", 2, "/sqli/", host="h", path="/sqli/", statuses=[200])
    m.add_node("param:a", "parameter", 4, "id", location="query")
    m.add_edge("route:h/sqli/", "param:a", "USES_PARAMETER", "OBSERVED", 1)
    plan = investigation_plan(m)
    sigs = [s for a in plan["lines_of_inquiry"] for s in a["signals"]]
    assert plan["posture"]["input_pages"] == 1
    assert any(s["kind"] == "input_page" and "id" in s["observation"] for s in sigs)


def test_query_page_names_the_area_only_for_a_front_controller():
    rg = ReasonGraph(_m(["/x"]))
    assert rg._resource_key("/index.php?page=login.php") == "login"
    assert rg._resource_key("/index.php?do=toggle-hints&page=x.php") == "toggle-hints"
    assert rg._resource_key("/?page=credits.php") == "credits"
    # a real path already names the area; `?page=` there is just a parameter
    assert rg._resource_key("/vulnerabilities/fi/?page=file1.php").startswith("vulnerabilit")


# ---- found on real Logger++ exports (a Next.js site, a WordPress site, an active scan) ----

def _ex(path, host="h", method="GET", status=200, referer=None):
    from burp2model.parse import Exchange
    return Exchange(index=0, method=method, scheme="https", host=host, port=443, path=path,
                    path_template=path.split("?")[0], status=status, mime="HTML",
                    referer_host=host if referer else None, referer_path=referer)


def test_a_page_per_city_collapses_to_a_stem_and_an_api_does_not():
    from burp2model.model import collapse_siblings
    pages = [_ex(f"/best-laundry-in-{c}/") for c in
             "leh likabali lonavala lucknow ludhiana madurai mahbubnagar maheshtala nagpur".split()]
    api = [_ex(f"/api/list{i}") for i in range(14)]
    collapse_siblings(pages + api)
    assert {e.path_template for e in pages} == {"/best-laundry-in-{slug}/"}
    assert {e.path_template for e in api} == {f"/api/list{i}" for i in range(14)}


def test_siblings_with_the_same_children_are_a_variable():
    from burp2model.model import collapse_siblings
    chans = [_ex(f"/live-channel/{n}/{i}") for i, n in enumerate(
        "aaj-tak dangal colors-hd zee-news india-tv ndtv star-plus sony-sab and-tv &tv mtv vh1 abp".split())]
    chans = [_ex(f"/live-channel/{n}/{{id}}") for n in
             "aaj-tak dangal colors-hd zee-news india-tv ndtv star-plus sony-sab and-tv tv9 mtv vh1 abp".split()]
    collapse_siblings(chans)
    assert {e.path_template for e in chans} == {"/live-channel/{slug}/{id}"}


def test_collapsing_also_rewrites_the_referer_so_page_edges_survive():
    from burp2model.model import collapse_siblings
    pages = [_ex(f"/best-laundry-in-{c}/") for c in
             "leh likabali lonavala lucknow ludhiana madurai mahbubnagar maheshtala nagpur".split()]
    call = _ex("/api/x", referer="/best-laundry-in-leh/")
    collapse_siblings(pages + [call])
    assert call.referer_path == "/best-laundry-in-{slug}/"


def test_build_hashes_in_asset_names_are_placeholders():
    assert template_path("/_next/static/chunks/index-1f38ebe00b8f1bef.js") == "/_next/static/chunks/index-{hash}.js"
    assert template_path("/_next/static/chunks/4969.7d2c1afc61e06b53.js") == "/_next/static/chunks/4969.{hash}.js"
    assert template_path("/static/jquery.min.js") == "/static/jquery.min.js"
    assert template_path("/assets/app.js") == "/assets/app.js"


def test_scanner_payload_paths_and_404_only_paths_are_not_part_of_the_map():
    from burp2model.model import build
    ok = _ex("/about")
    probe = _ex("/assets/../../etc/passwd")
    probe.index = 1
    gone = _ex("/wp-admin/setup-config.php", status=404)
    gone.index = 2
    m = build([ok, probe, gone], "t", scope=["h"])
    labels = {n.label for n in m.nodes.values() if n.type == "route"}
    assert labels == {"/about"}
    assert m.stats["probe_requests"] == 1 and m.stats["not_found_paths_dropped"] == 1
    assert len(m.evidence_log) == 3                      # the requests stay as evidence


def test_more_scanner_shapes_are_probes():
    from burp2model.model import is_probe
    for p in ("/%25%7b(%23dm%3d@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS)%7d/", "/a/%24%7bjndi:ldap://x%7d", "/x/%3Cscript%3E", "/%2A%7E1%2A%2Fa.asp", "/x/*~1*/a.aspx", "/assets/index-ab12cd34.js/foo", "/a/..%5c..%5cwin.ini"):
        assert is_probe(_ex(p)), p
    assert is_probe(_ex("/", method="TRACE")) and is_probe(_ex("/", method="DEBUG"))
    for p in ("/", "/assets/app.js", "/api/users/{id}", "/img/logo.png"):
        assert not is_probe(_ex(p)), p
