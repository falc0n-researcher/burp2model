# Example: OWASP Juice Shop

A real burp2model report built from a recorded session against a local
[OWASP Juice Shop](https://owasp.org/www-project-juice-shop/) 20.2.0 — a deliberately
vulnerable app published for security training. Open
[`juiceshop/report.html`](juiceshop/report.html) in any browser (offline, self
contained); it includes the **Query (BQL)** console and the **Evidence** table.

Everything in it came from actual requests to the running app, recorded by
[`scripts/capture_juiceshop.py`](../../scripts/capture_juiceshop.py) in four sessions so
there are roles to compare: a first-time anonymous visit (the whole catalogue, public files,
every refusal an unauthenticated visitor can provoke); a freshly registered user who uses
every customer feature (shop, wallet, deluxe membership, addresses, cards, checkout, reviews,
feedback, complaints, recycling, photo wall, profile, password change) and tries a few
things a customer should not reach; and the documented default accounting and admin users.
It includes cache revalidation, CORS preflights, redirects and multipart uploads, with no
exploit payloads. Nothing is invented.

What the model recovered from 417 requests:

- **105 API endpoints**: 48 seen in both code and traffic, 42 in traffic only, and
  **15 named only in the Angular bundle and never called** (2FA enrolment, the challenge
  continue-codes, web3): what even a deep session leaves unwalked.
- **Feature areas** (`user`, `basket`, `feedbacks`, `admin`, `2fa`, `cards`, …) and, per
  area, what the capture could not answer.
- **Cross-role questions**: a normal user got `200` on `/api/Users/`; anonymous visitors
  reached `/rest/admin/application-configuration`.
- **Redaction proof**: the session holds real JWTs, a throwaway login, a password change
  and a test card number. All of it is masked everywhere in this report. Search it: you
  will not find them.

`context.json` is the evidence package for an AI (with the reasoning graph, about 37k
tokens against about 1.02M for the raw capture); `graph.json` is the node-link export for
D3 / Cytoscape / Gephi.

Rebuild it yourself:

```bash
docker run --rm -d -p 127.0.0.1:3000:3000 bkimminich/juice-shop
python scripts/capture_juiceshop.py                     # writes samples/juiceshop-*.xml
for r in anon user accountant admin; do burp2model samples/juiceshop-$r.xml -w juiceshop --role $r; done
burp2model q juiceshop 'role:anon AND resp.code:401'
```

The capture files are in [`samples/`](../../samples/), and
`tests/test_juiceshop_sample.py` checks every output for leaked secrets on each run.
