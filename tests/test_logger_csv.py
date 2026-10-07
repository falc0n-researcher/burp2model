"""Logger++ CSV exports (Burp extension): base64 requests/responses, tool filter, cells that spilled."""

import base64
import csv

from burp2model import bql, parse_items
from burp2model.cli import main

HEAD = ["ID", "Time", "Tool", "Method", "Protocol", "Host", "Port", "URL", "IP", "Path", "Query", "Param count",
        "Param names", "Status code", "Length", "MIME type", "Extension", "Page title", "Start response timer",
        "End response timer", "Comment", "Connection ID", "Request", "Response"]


def b64(s):
    return base64.b64encode(s.encode()).decode()


def row(i, tool, method, path, status, body="", ctype="text/html", req_extra="", host="shop.test", raw=False):
    req = f"{method} {path} HTTP/1.1\r\nHost: {host}\r\n{req_extra}\r\n"
    resp = f"HTTP/1.1 {status} X\r\nContent-Type: {ctype}\r\nContent-Length: {len(body)}\r\n\r\n{body}"
    r = [""] * len(HEAD)
    for k, v in (("ID", str(i)), ("Tool", tool), ("Method", method), ("Protocol", "https"), ("Host", host),
                 ("Port", "443"), ("Path", path), ("Status code", str(status)), ("MIME type", "HTML")):
        r[HEAD.index(k)] = v
    r[HEAD.index("Request")] = req if raw else b64(req)
    r[HEAD.index("Response")] = resp if raw else b64(resp)
    return r


def write(tmp_path, rows, name="log.csv"):
    p = tmp_path / name
    with open(p, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(HEAD)
        w.writerows(rows)
    return str(p)


def test_parses_base64_requests_and_responses_into_the_same_exchanges(tmp_path):
    p = write(tmp_path, [row(1, "Proxy", "GET", "/", 200, '<a href="/x">x</a>'),
                         row(2, "Proxy", "POST", "/api/login", 200, '{"token":"abc"}', "application/json",
                             "Cookie: sid=SECRETSESSIONVALUE1234\r\nContent-Type: application/json\r\n")])
    stats = {}
    ex = list(parse_items(p, role="user", stats=stats))
    assert [(e.method, e.path_template, e.status) for e in ex] == [("GET", "/", 200), ("POST", "/api/login", 200)]
    assert stats["parsed"] == 2 and stats["tools"] == {"Proxy": 2}
    assert ex[1].role == "user" and "SECRETSESSIONVALUE1234" not in str([e.ev for e in ex])


def test_raw_http_in_the_cells_is_accepted_too(tmp_path):
    p = write(tmp_path, [row(1, "Proxy", "GET", "/raw", 200, "<p>hi</p>", raw=True)])
    ex = list(parse_items(p))
    assert ex[0].path_template == "/raw" and "<p>hi</p>" in ex[0].ev["response"]["body"]


def test_tool_filters(tmp_path):
    p = write(tmp_path, [row(1, "Proxy", "GET", "/a", 200), row(2, "Scanner", "GET", "/b", 404),
                         row(3, "Extensions", "TRACE", "/", 405)])
    assert [e.path_template for e in parse_items(p, skip_tools=("Scanner", "Extensions"))] == ["/a"]
    assert [e.path_template for e in parse_items(p, only_tools=("scanner",))] == ["/b"]
    assert len(list(parse_items(p))) == 3


def test_a_response_that_spilled_over_a_spreadsheet_cell_is_put_back_together(tmp_path):
    body = "<html>" + "x" * 50000 + '<a href="/after-the-limit">end</a></html>'
    full = b64(f"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n{body}")
    first, rest = full[:32767], full[32767:]
    r = row(1, "Proxy", "GET", "/big", 200)
    r[HEAD.index("Response")] = first
    cont = [""] * len(HEAD)
    cont[0] = rest                                  # the overflow lands in the first column of the next row
    p = write(tmp_path, [r, cont, row(2, "Proxy", "GET", "/next", 200)])
    stats = {}
    ex = list(parse_items(p, stats=stats))
    assert [e.path_template for e in ex] == ["/big", "/next"] and stats["parsed"] == 2
    assert not ex[0].scan_truncated                 # nothing was lost: the tail was found on the next row
    assert ex[0].resp_body.startswith("<html>xxx")


def test_a_cut_off_response_does_not_break_parsing_and_is_flagged(tmp_path):
    body = "<html>" + "y" * 60000
    full = b64(f"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n{body}")
    r = row(1, "Proxy", "GET", "/cut", 200)
    r[HEAD.index("Response")] = full[:32767]       # nothing follows: the tail is lost
    ex = list(parse_items(write(tmp_path, [r])))
    assert len(ex) == 1 and ex[0].scan_truncated


def test_not_a_logger_csv_is_a_clear_error(tmp_path, capsys):
    p = tmp_path / "x.csv"
    p.write_text("a,b\n1,2\n")
    assert main(["build", str(p), "-w", "t", "--out", str(tmp_path / "o")]) == 2
    assert "Logger++" in capsys.readouterr().err


def test_cli_builds_from_a_csv_and_reports_the_tool_mix(tmp_path, capsys):
    rows = [row(i, "Scanner", "GET", f"/probe{i}", 404) for i in range(25)] + \
           [row(100, "Proxy", "GET", "/", 200, '<a href="/about">a</a>'), row(101, "Proxy", "GET", "/about", 200)]
    p = write(tmp_path, rows)
    out = str(tmp_path / "o")
    assert main(["build", p, "-w", "t", "--out", out, "--skip-tools", "Scanner"]) == 0
    err = capsys.readouterr().err
    assert "Scanner 25" in err and "skipped 25 by tool" in err
    c = bql.connect(out + "/t/graph.db")
    assert bql.run_query(c, "stats").rows[2]["value"] == 2


def test_scanner_notice_when_unfiltered(tmp_path, capsys):
    p = write(tmp_path, [row(i, "Scanner", "GET", f"/p{i}", 404) for i in range(25)] + [row(99, "Proxy", "GET", "/", 200)])
    assert main(["build", p, "-w", "t", "--out", str(tmp_path / "o")]) == 0
    assert "--skip-tools Scanner" in capsys.readouterr().err
