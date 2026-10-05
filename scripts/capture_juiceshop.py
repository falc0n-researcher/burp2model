#!/usr/bin/env python3
"""
Drive a LOCAL OWASP Juice Shop like a browser + a tester and record every
exchange as a Burp Suite "Save items" XML (base64 CDATA, like the real export).

Four sessions, so role-diffing has something to chew on:
  anon       - first visit: SPA shell, bundles, the whole catalogue, public files,
               every method/status an unauthenticated visitor can provoke
  user       - register + login a fresh account and use every customer feature:
               shop, pay, wallet, deluxe, addresses, cards, reviews, feedback,
               complaints, recycling, photo wall, data export, profile, password
               change, plus a few requests for things a customer should not reach
  accountant - the seeded accounting user (documented default): orders, stock
  admin      - the seeded admin (documented default): users, config, moderation

Coverage is ordinary use of the application plus the error, redirect, cache,
CORS, multipart, urlencoded and method-not-allowed behaviour a tester notices.
There are no exploit payloads.

Usage:
    docker run --rm -d -p 127.0.0.1:3000:3000 bkimminich/juice-shop
    python scripts/capture_juiceshop.py [--out samples]

Writes juiceshop-{anon,user,accountant,admin}.xml (and juiceshop-history.xml
with --combined). Run it against a fresh container so ids are deterministic. The
captures deliberately contain a real throwaway login, JWTs and a test card
number from a local training app: masking them is what burp2model has to get
right, and tests/test_juiceshop_sample.py checks it does.

Only ever talks to 127.0.0.1.
"""
import base64
import http.client
import json
import os
import random
import re
import string
import sys
import time
import uuid
from datetime import datetime

HOST, PORT = "127.0.0.1", 3000
HOSTHDR = "localhost:3000"
OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "samples")
UA = ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36")
REASONS = {200: "OK", 201: "Created", 204: "No Content", 301: "Moved Permanently",
           302: "Found", 304: "Not Modified", 400: "Bad Request", 401: "Unauthorized",
           403: "Forbidden", 404: "Not Found", 405: "Method Not Allowed",
           409: "Conflict", 500: "Internal Server Error"}


def burp_mime(ct: str, path: str) -> str:
    ct = (ct or "").split(";")[0].strip().lower()
    return {"text/html": "HTML", "application/json": "JSON", "text/css": "CSS",
            "application/javascript": "script", "text/javascript": "script",
            "image/png": "PNG", "image/jpeg": "JPEG", "image/svg+xml": "XML",
            "image/x-icon": "image", "image/vnd.microsoft.icon": "image",
            "application/xml": "XML", "text/xml": "XML", "text/plain": "text",
            "text/markdown": "text", "application/pdf": "PDF",
            "font/woff2": "app", "application/octet-stream": "app"}.get(ct, "text" if ct.startswith("text/") else "")


class Recorder:
    def __init__(self, role: str):
        self.role = role
        self.items: list[str] = []
        self.cookies = {"language": "en", "welcomebanner_status": "dismiss",
                        "cookieconsent_status": "dismiss"}
        self.token: str | None = None
        self.conn = http.client.HTTPConnection(HOST, PORT, timeout=20)

    def request(self, method, path, body=None, headers=None, ctype=None, referer="/",
                ajax=True, bearer=True, accept=None):
        h = {"Host": HOSTHDR, "Connection": "keep-alive", "User-Agent": UA,
             "Accept": accept or ("application/json, text/plain, */*" if ajax else "*/*"),
             "Accept-Language": "en-US,en;q=0.9", "Accept-Encoding": "gzip, deflate"}
        if referer:
            h["Referer"] = f"http://{HOSTHDR}{referer}"
        if ajax:
            h["Sec-Fetch-Mode"] = "cors"
        if self.token and bearer:
            h["Authorization"] = f"Bearer {self.token}"
        if self.cookies:
            h["Cookie"] = "; ".join(f"{k}={v}" for k, v in self.cookies.items())
        if isinstance(body, (dict, list)):
            body = json.dumps(body, separators=(",", ":")).encode()
            ctype = ctype or "application/json"
        elif isinstance(body, str):
            body = body.encode()
        if body is not None:
            h["Content-Type"] = ctype or "application/json"
            h["Content-Length"] = str(len(body))
            h["Origin"] = f"http://{HOSTHDR}"
        h.update(headers or {})
        raw_req = f"{method} {path} HTTP/1.1\r\n" + "".join(f"{k}: {v}\r\n" for k, v in h.items()) + "\r\n"
        raw_req = raw_req.encode("latin-1") + (body or b"")
        try:
            self.conn.request(method, path, body=body, headers={k: v for k, v in h.items() if k != "Host"})
            resp = self.conn.getresponse()
            data = resp.read()
        except (http.client.HTTPException, OSError):
            self.conn = http.client.HTTPConnection(HOST, PORT, timeout=20)
            self.conn.request(method, path, body=body, headers={k: v for k, v in h.items() if k != "Host"})
            resp = self.conn.getresponse()
            data = resp.read()
        heads = [(k, v) for k, v in resp.getheaders() if k.lower() not in ("transfer-encoding", "content-length")]
        heads.append(("Content-Length", str(len(data))))
        head = f"HTTP/1.1 {resp.status} {REASONS.get(resp.status, resp.reason)}\r\n" + \
               "".join(f"{k}: {v}\r\n" for k, v in heads) + "\r\n"
        raw_resp = head.encode("latin-1") + data
        ct = resp.getheader("Content-Type", "")
        b64 = lambda b: base64.b64encode(b).decode()
        ts = datetime.now().strftime("%a %b %d %H:%M:%S IST %Y")
        ext = "null"
        m = re.search(r"\.([A-Za-z0-9]{1,5})(?:\?|$)", path.split("?")[0])
        if m:
            ext = m.group(1)
        self.items.append(
            "  <item>\n"
            f"    <time>{ts}</time>\n"
            f"    <url><![CDATA[http://{HOSTHDR}{path}]]></url>\n"
            f'    <host ip="127.0.0.1">localhost</host>\n'
            f"    <port>{PORT}</port>\n    <protocol>http</protocol>\n"
            f"    <method>{method}</method>\n"
            f"    <path><![CDATA[{path}]]></path>\n"
            f"    <extension>{ext}</extension>\n"
            f'    <request base64="true"><![CDATA[{b64(raw_req)}]]></request>\n'
            f"    <status>{resp.status}</status>\n"
            f"    <responselength>{len(raw_resp)}</responselength>\n"
            f"    <mimetype>{burp_mime(ct, path)}</mimetype>\n"
            f'    <response base64="true"><![CDATA[{b64(raw_resp)}]]></response>\n'
            "    <comment></comment>\n  </item>\n")
        return resp.status, data, dict((k.lower(), v) for k, v in resp.getheaders())

    def j(self, method, path, body=None, **kw):
        st, data, hd = self.request(method, path, body, **kw)
        if hd.get("content-encoding") == "gzip":
            import gzip
            data = gzip.decompress(data)
        try:
            return st, json.loads(data.decode("utf-8", "replace") or "null")
        except ValueError:
            return st, None

    def get(self, path, **kw):
        return self.request("GET", path, **kw)


def write_xml(name, recorders):
    items = "".join(i for r in recorders for i in r.items)
    with open(os.path.join(OUT, name), "w", encoding="utf-8") as f:
        f.write('<?xml version="1.1"?>\n<!DOCTYPE items [\n<!ELEMENT items (item*)>\n'
                '<!ATTLIST items burpVersion CDATA "">\n<!ATTLIST items exportTime CDATA "">\n'
                ']>\n<items burpVersion="2026.1" exportTime="' +
                datetime.now().strftime("%a %b %d %H:%M:%S IST %Y") + '">\n' + items + "</items>\n")
    print(f"wrote {name}: {sum(len(r.items) for r in recorders)} items")


def spa_boot(r: Recorder, full=True, bundles=True):
    """What the browser does on first load of the single-page app."""
    st, html, hd = r.get("/", ajax=False, referer=None, accept="text/html,application/xhtml+xml")
    if hd.get("content-encoding") == "gzip":
        import gzip
        html = gzip.decompress(html)
    text = html.decode("utf-8", "replace")
    scripts = re.findall(r'<script[^>]+src="([^"]+)"', text)
    styles = re.findall(r'<link[^>]+href="([^"]+\.css)"', text)
    if bundles:     # a returning browser has these cached: later sessions skip them
        for s in styles:
            r.get("/" + s.lstrip("/"), ajax=False, accept="text/css,*/*;q=0.1")
        for s in scripts:
            r.get("/" + s.lstrip("/"), ajax=False, accept="*/*")
    r.get("/assets/public/favicon_js.ico", ajax=False, accept="image/avif,image/webp,*/*")
    r.get("/assets/i18n/en.json", ajax=True)
    r.get("/rest/admin/application-version")
    r.get("/rest/admin/application-configuration")
    r.get("/rest/languages")
    r.get("/api/Challenges/?name=Score%20Board")
    r.get("/rest/products/search?q=")
    r.get("/rest/user/whoami")
    r.get("/socket.io/?EIO=4&transport=polling&t=" + "Pb" + "".join(random.choices(string.ascii_letters + string.digits, k=5)))
    r.get("/rest/chatbot/status")
    r.get("/api/Quantitys/")
    if full:
        for img in ("apple_juice.jpg", "orange_juice.jpg", "banana_juice.jpg", "eggfruit_juice.jpg",
                    "fruit_press.jpg", "lemon_juice.jpg", "melon_bike.jpeg", "carrot_juice.jpeg"):
            r.get(f"/assets/public/images/products/{img}", ajax=False, accept="image/avif,image/webp,image/*,*/*;q=0.8")
        r.get("/assets/public/images/JuiceShop_Logo.png", ajax=False, accept="image/*")
    return text


def rnd(n=6):
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=n))


PNG = base64.b64decode("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR4nGP4//8/AwAI/AL+XJ/PcQAAAABJRU5ErkJggg==")


def multipart(fields: dict, files: dict):
    """fields: name -> str; files: name -> (filename, content-type, bytes)."""
    bd = "----WebKitFormBoundary" + rnd(16)
    out = b""
    for k, v in fields.items():
        out += f'--{bd}\r\nContent-Disposition: form-data; name="{k}"\r\n\r\n{v}\r\n'.encode()
    for k, (fn, ct, data) in files.items():
        out += (f'--{bd}\r\nContent-Disposition: form-data; name="{k}"; filename="{fn}"\r\n'
                f"Content-Type: {ct}\r\n\r\n").encode() + data + b"\r\n"
    out += f"--{bd}--\r\n".encode()
    return out, f"multipart/form-data; boundary={bd}"


def login(r: Recorder, email: str, pw: str):
    st, res = r.j("POST", "/rest/user/login", {"email": email, "password": pw})
    auth = (res or {}).get("authentication") or {}
    r.token = auth.get("token")
    r.cookies["token"] = r.token or ""
    return auth


def session_anon():
    r = Recorder("anon")
    spa_boot(r)
    st, prods = r.j("GET", "/api/Products")
    plist = (prods or {}).get("data", [])
    ids = [p["id"] for p in plist] or list(range(1, 40))
    # the whole catalogue, the way the product dialogs load it
    for pid in ids:
        r.get(f"/api/Products/{pid}")
        r.get(f"/rest/products/{pid}/reviews")
    for p in plist[8:18]:
        if p.get("image"):
            r.get(f"/assets/public/images/products/{p['image']}", ajax=False,
                  accept="image/avif,image/webp,image/*,*/*;q=0.8")
    for q in ("apple", "juice", "lemon", "banana", "e", "100%25", "a%20b", "%E2%9C%93", "zzzz-no-match"):
        r.get(f"/rest/products/search?q={q}")
    r.get("/api/Challenges/")
    r.get("/api/Challenges/?name=Score%20Board")
    r.get("/api/Challenges/1")
    r.get("/rest/continue-code")
    r.get("/rest/continue-code-findIt")
    r.get("/rest/continue-code-fixIt")
    r.get("/rest/repeat-notification?challenge=Score%20Board")
    r.get("/rest/country-mapping")
    r.get("/api/Quantitys/")
    r.get("/api/Hints/")
    r.get("/api/SecurityQuestions/")
    r.get("/api/SecurityQuestions/1")
    r.get("/api/Feedbacks/")
    r.get("/rest/memories")
    r.get("/rest/languages")
    r.get("/rest/chatbot/status")
    r.get("/rest/track-order/5267-f73dcd000abcc353")
    # public files, directory listings, well-known paths
    for path in ("/robots.txt", "/.well-known/security.txt", "/ftp", "/ftp/legal.md", "/ftp/acquisitions.md",
                 "/ftp/announcement_encrypted.md", "/ftp/eastere.gg", "/ftp/package.json.bak",
                 "/encryptionkeys/", "/support/logs", "/metrics", "/api-docs/", "/promotion",
                 "/sitemap.xml", "/favicon.ico", "/redirect?to=https://github.com/juice-shop/juice-shop",
                 "/redirect?to=https://example.invalid/not-allowed"):
        r.get(path, ajax=False)
    # cache validators: a browser revalidating what it already holds
    st, _, hd = r.get("/assets/i18n/en.json")
    if hd.get("etag"):
        r.get("/assets/i18n/en.json", headers={"If-None-Match": hd["etag"]})
    st, _, hd = r.get("/", ajax=False, referer=None, accept="text/html")
    if hd.get("etag"):
        r.get("/", ajax=False, referer=None, accept="text/html", headers={"If-None-Match": hd["etag"]})
    r.request("HEAD", "/", ajax=False, referer=None)
    r.request("HEAD", "/api/Products")
    # CORS preflights for the calls the SPA makes
    for path, m in (("/rest/user/login", "POST"), ("/api/Users", "POST"), ("/api/Feedbacks", "POST"),
                    ("/rest/products/search?q=a", "GET"), ("/api/BasketItems", "POST")):
        r.request("OPTIONS", path, headers={"Access-Control-Request-Method": m,
                  "Access-Control-Request-Headers": "authorization,content-type",
                  "Origin": f"http://{HOSTHDR}"})
    # what an unauthenticated visitor is refused
    for path in ("/api/Users/", "/api/Users/1", "/api/Cards/", "/api/Addresss", "/rest/basket/1", "/rest/basket/2",
                 "/rest/order-history", "/rest/order-history/orders", "/rest/wallet/balance",
                 "/rest/deluxe-membership", "/rest/2fa/status", "/rest/user/authentication-details/",
                 "/api/Complaints/", "/api/Recycles/", "/api/Deliverys", "/rest/saveLoginIp",
                 "/rest/image-captcha/"):
        r.get(path)
    for m, path in (("POST", "/api/Products"), ("PUT", "/api/Products/1"), ("DELETE", "/api/Products/1"),
                    ("DELETE", "/api/Feedbacks/1"), ("PUT", "/api/Users/1"), ("POST", "/api/Cards")):
        r.j(m, path, {} if m != "DELETE" else None)
    # error and method behaviour
    r.get("/this/does/not/exist", ajax=False)
    r.get("/rest/nonexistent")
    r.get("/api/Nonexistent/1")
    r.get("/api/Products/99999")
    r.get("/api/Products/abc")
    r.request("POST", "/rest/products/search?q=a", {})
    r.get("/rest/products/search?q=%27")                 # malformed input -> error page
    r.get("/rest/products/search?q=%27%28")
    r.j("POST", "/rest/user/login", {"email": "nobody@example.invalid", "password": "wrong-pass-1"})
    r.j("POST", "/rest/user/login", {"email": "nobody@example.invalid"})
    r.request("POST", "/rest/user/login", "not json", ctype="application/json")
    r.request("POST", "/rest/user/login", "email=a%40b.co&password=x", ctype="application/x-www-form-urlencoded")
    r.j("POST", "/api/Users", {"email": "not-an-email", "password": "x"})
    r.get("/rest/captcha/")
    r.get("/rest/image-captcha/")
    r.get("/rest/user/security-question?email=nobody@example.invalid")
    r.j("POST", "/rest/user/reset-password", {"email": "nobody@example.invalid", "answer": "x",
                                              "new": "Xx-1234567", "repeat": "Xx-1234567"})
    return r


def session_user():
    r = Recorder("user")
    spa_boot(r, full=False, bundles=False)
    email, pw = f"tester.{rnd()}@b2m-test.dev", "Sup3r-Secret-Pa55!"
    st, sq = r.j("GET", "/api/SecurityQuestions/")
    st, reg = r.j("POST", "/api/Users", {
        "email": email, "password": pw, "passwordRepeat": pw,
        "securityQuestion": {"id": 1, "question": "Your eldest siblings middle name?",
                             "createdAt": "2026-10-01T00:00:00.000Z", "updatedAt": "2026-10-01T00:00:00.000Z"},
        "securityAnswer": "Marlowe"})
    uid = ((reg or {}).get("data") or {}).get("id")
    r.j("POST", "/api/Users", {"email": email, "password": pw, "passwordRepeat": pw})        # duplicate -> 4xx
    r.get(f"/rest/user/security-question?email={email}")
    auth = login(r, email, pw)
    bid = auth.get("bid")
    for path in ("/rest/user/whoami", "/rest/user/whoami?fields=id,email", "/rest/continue-code",
                 "/rest/deluxe-membership", "/rest/wallet/balance", "/api/Addresss", "/api/Cards",
                 "/rest/order-history", "/rest/memories", "/api/Deliverys", "/rest/2fa/status",
                 "/rest/user/authentication-details/", "/rest/saveLoginIp", f"/rest/basket/{bid}"):
        r.get(path)
    # shop
    st, prods = r.j("GET", "/api/Products")
    ids = [p["id"] for p in (prods or {}).get("data", [])][:8] or [1, 2, 3]
    for pid in ids[:3]:
        r.get(f"/api/Products/{pid}")
        r.get(f"/rest/products/{pid}/reviews")
    item_ids = []
    for pid in ids[:4]:
        st, it = r.j("POST", "/api/BasketItems", {"ProductId": pid, "BasketId": str(bid), "quantity": 1})
        item_ids.append(((it or {}).get("data") or {}).get("id"))
    r.j("POST", "/api/BasketItems", {"ProductId": ids[0], "BasketId": str(bid), "quantity": 1})   # already there
    if item_ids and item_ids[0]:
        r.j("PUT", f"/api/BasketItems/{item_ids[0]}", {"quantity": 2})
        r.get(f"/api/BasketItems/{item_ids[0]}")
    if len(item_ids) > 2 and item_ids[2]:
        r.j("DELETE", f"/api/BasketItems/{item_ids[2]}")
    r.get(f"/rest/basket/{bid}")
    r.j("PUT", f"/rest/basket/{bid}/coupon/WMNSDY2019")                # an invalid coupon
    # reviews
    r.j("PUT", f"/rest/products/{ids[0]}/reviews", {"message": "Tasty and cheap. Would order again.", "author": email})
    st, revs = r.j("GET", f"/rest/products/{ids[0]}/reviews")
    rev_id = next((x.get("_id") for x in (revs or {}).get("data", []) if x.get("author") == email), None)
    if rev_id:
        r.j("PATCH", "/rest/products/reviews", {"id": rev_id, "message": "Edited: still tasty."})
        r.j("POST", "/rest/products/reviews", {"id": rev_id})          # like
    # addresses and cards: create, read, update, delete
    st, addr = r.j("POST", "/api/Addresss", {"country": "Testland", "fullName": "Test Er",
        "mobileNum": 5551234567, "zipCode": "12345", "streetAddress": "1 Probe Street",
        "city": "Examplia", "state": "TS"})
    st, addr2 = r.j("POST", "/api/Addresss", {"country": "Testland", "fullName": "Test Er",
        "mobileNum": 5557654321, "zipCode": "54321", "streetAddress": "2 Probe Street", "city": "Examplia"})
    st, card = r.j("POST", "/api/Cards", {"fullName": "Test Er", "cardNum": 4111111111111111,
        "expMonth": 12, "expYear": 2090})
    st, card2 = r.j("POST", "/api/Cards", {"fullName": "Test Er", "cardNum": 5555555555554444,
        "expMonth": 7, "expYear": 2091})
    aid = ((addr or {}).get("data") or {}).get("id")
    aid2 = ((addr2 or {}).get("data") or {}).get("id")
    cid = ((card or {}).get("data") or {}).get("id")
    cid2 = ((card2 or {}).get("data") or {}).get("id")
    r.get("/api/Addresss")
    r.get("/api/Cards")
    if aid:
        r.get(f"/api/Addresss/{aid}")
        r.j("PUT", f"/api/Addresss/{aid}", {"city": "Examplia-2"})
    if cid:
        r.get(f"/api/Cards/{cid}")
    if aid2:
        r.j("DELETE", f"/api/Addresss/{aid2}")
    if cid2:
        r.j("DELETE", f"/api/Cards/{cid2}")
    r.get("/api/Deliverys/1")
    r.get("/api/Deliverys/2")
    # wallet and deluxe membership
    if cid:
        r.j("PUT", "/rest/wallet/balance", {"balance": 50, "paymentId": cid})
    r.get("/rest/wallet/balance")
    r.j("POST", "/rest/deluxe-membership", {"paymentMode": "wallet"})
    r.get("/rest/deluxe-membership")
    # checkout
    oid = None
    if aid and cid:
        st, order = r.j("POST", f"/rest/basket/{bid}/checkout",
                        {"couponData": "bnVsbA==", "orderDetails": {"paymentId": str(cid), "addressId": str(aid), "deliveryMethodId": "1"}})
        oid = (order or {}).get("orderConfirmation")
        r.get("/rest/order-history")
        if oid:
            r.get(f"/rest/track-order/{oid}")
    r.get("/rest/wallet/balance")
    # feedback (captcha round-trip), complaints, recycling
    st, cap = r.j("GET", "/rest/captcha/")
    if cap:
        r.j("POST", "/api/Feedbacks", {"UserId": uid, "captchaId": cap.get("captchaId"),
            "captcha": str(cap.get("answer")), "comment": "Great store (anonymous tester)", "rating": 4})
        r.j("POST", "/api/Feedbacks", {"UserId": uid, "captchaId": cap.get("captchaId"),
            "captcha": "wrong", "comment": "second try", "rating": 5})                    # refused
    st, fb = r.j("GET", "/api/Feedbacks/")
    body, ct = multipart({"UserId": str(uid or ""), "message": "Package arrived late."},
                         {"file": ("claim.pdf", "application/pdf", b"%PDF-1.4\n%b2m-sample\n")})
    r.request("POST", "/file-upload", body, ctype=ct)
    r.j("POST", "/api/Complaints", {"UserId": uid, "message": "Package arrived late."})
    r.get("/api/Complaints/")
    r.j("POST", "/api/Recycles", {"quantity": 40, "AddressId": aid, "isPickup": True,
                                 "date": "2090-01-01", "UserId": uid})
    r.get("/api/Recycles/")
    # profile: page, urlencoded form, image upload, photo wall
    r.get("/profile", ajax=False, accept="text/html")
    r.request("POST", "/profile", "username=b2m_tester", ctype="application/x-www-form-urlencoded",
              ajax=False, referer="/profile")
    body, ct = multipart({}, {"file": ("avatar.png", "image/png", PNG)})
    r.request("POST", "/profile/image/file", body, ctype=ct, ajax=False, referer="/profile")
    body, ct = multipart({"caption": "Juice with a view"}, {"image": ("juice.png", "image/png", PNG)})
    r.request("POST", "/rest/memories", body, ctype=ct)
    r.get("/rest/memories")
    # data export (captcha gated)
    st, icap = r.j("GET", "/rest/image-captcha/")
    if icap:
        r.j("POST", "/rest/user/data-export", {"answer": "0", "UserId": uid, "format": "1"})
    # password change (GET with secrets in the query), reset, re-login
    r.get(f"/rest/user/change-password?current={pw}&new=N3w-Secret-Pa55!&repeat=N3w-Secret-Pa55!")
    r.get("/rest/user/change-password?current=wrong&new=a&repeat=b")                       # refused
    auth = login(r, email, "N3w-Secret-Pa55!")
    r.j("POST", "/rest/user/reset-password", {"email": email, "answer": "Marlowe",
        "new": "Th1rd-Secret-Pa55!", "repeat": "Th1rd-Secret-Pa55!"})
    r.j("POST", "/rest/chatbot/respond", {"action": "query", "query": "hello"})
    r.get("/rest/chatbot/status")
    # 2FA: status only (enrolment needs a TOTP app)
    r.get("/rest/2fa/status")
    # things a customer should not be able to reach
    r.get("/api/Users/")
    r.get(f"/api/Users/{uid}")
    r.get("/api/Users/1")
    r.get("/rest/admin/application-configuration")
    r.get("/rest/order-history/orders")
    r.get("/api/Complaints/")
    r.get("/api/Feedbacks/")
    r.get("/api/Quantitys/")
    r.get(f"/rest/basket/{int(bid) + 1}")                     # someone else's basket
    r.get("/api/Cards/1")
    r.get("/api/Addresss/1")
    r.j("POST", "/b2b/v2/orders", {"cid": "JUICE-B2B-1", "orderLinesData": "[]"})
    r.j("PUT", "/api/Quantitys/1", {"quantity": 100})
    fbs = (fb or {}).get("data", [])
    if fbs:
        r.j("DELETE", f"/api/Feedbacks/{fbs[0].get('id')}")      # not mine
    r.get("/rest/user/whoami")
    return r, email


def session_accountant():
    r = Recorder("accountant")
    spa_boot(r, full=False, bundles=False)
    login(r, "accountant@juice-sh.op", "i am an awesome accountant")
    for path in ("/rest/user/whoami", "/rest/order-history/orders", "/rest/order-history", "/api/Quantitys/",
                 "/api/Quantitys/1", "/api/Products", "/api/Users/", "/api/Cards", "/api/Addresss",
                 "/rest/admin/application-configuration", "/rest/wallet/balance", "/rest/deluxe-membership",
                 "/api/Complaints/", "/api/Feedbacks/"):
        r.get(path)
    r.j("PUT", "/api/Quantitys/1", {"quantity": 100})
    r.j("PUT", "/api/Quantitys/2", {"quantity": 100})
    r.get("/api/Quantitys/1")
    r.get("/rest/saveLoginIp")
    return r


def session_admin():
    r = Recorder("admin")
    spa_boot(r, full=False, bundles=False)
    auth = login(r, "admin@juice-sh.op", "admin123")
    bid = auth.get("bid")
    r.get("/rest/user/whoami")
    st, users = r.j("GET", "/api/Users/")
    uids = [u["id"] for u in (users or {}).get("data", [])][:6] or [1, 2, 3]
    for uid in uids:
        r.get(f"/api/Users/{uid}")
    for path in ("/rest/admin/application-configuration", "/rest/admin/application-version", "/api/Feedbacks/",
                 "/api/Complaints/", "/api/Quantitys/", "/api/Recycles/", "/rest/order-history/orders",
                 "/rest/order-history", "/api/Cards", "/api/Addresss", f"/rest/basket/{bid}",
                 "/rest/deluxe-membership", "/rest/wallet/balance", "/rest/memories", "/rest/2fa/status",
                 "/rest/user/authentication-details/", "/api/Deliverys", "/rest/continue-code"):
        r.get(path)
    st, fb = r.j("GET", "/api/Feedbacks/")
    fbs = (fb or {}).get("data", [])
    if fbs:
        r.get(f"/api/Feedbacks/{fbs[-1].get('id')}")
        r.j("DELETE", f"/api/Feedbacks/{fbs[-1].get('id')}")         # moderation
    st, comp = r.j("GET", "/api/Complaints/")
    st, prods = r.j("GET", "/api/Products")
    r.get("/rest/products/search?q=admin")
    r.j("PUT", "/api/Quantitys/1", {"quantity": 100})
    r.j("GET", "/api/Quantitys/1")
    r.get("/rest/saveLoginIp")
    r.get("/profile", ajax=False, accept="text/html")
    r.get("/metrics", ajax=False)
    r.get("/ftp/quarantine", ajax=False)
    r.get("/rest/track-order/1")
    return r


def main():
    global OUT
    argv = sys.argv[1:]
    if "--out" in argv:
        OUT = argv[argv.index("--out") + 1]
    os.makedirs(OUT, exist_ok=True)
    random.seed(20261001)
    st = http.client.HTTPConnection(HOST, PORT, timeout=5)
    st.request("GET", "/rest/admin/application-version")
    ver = json.loads(st.getresponse().read())["version"]
    print("Juice Shop", ver)
    anon = session_anon()
    user, email = session_user()
    acct = session_accountant()
    admin = session_admin()
    write_xml("juiceshop-anon.xml", [anon])
    write_xml("juiceshop-user.xml", [user])
    write_xml("juiceshop-accountant.xml", [acct])
    write_xml("juiceshop-admin.xml", [admin])
    if "--combined" in argv:
        write_xml("juiceshop-history.xml", [anon, user, acct, admin])
    print("test account:", email)


if __name__ == "__main__":
    main()
