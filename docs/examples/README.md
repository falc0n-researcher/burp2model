# Example: OWASP Juice Shop

A burp2model report built from recorded sessions against a local
[OWASP Juice Shop](https://owasp.org/www-project-juice-shop/) 20.2.0, an app made for security training.
Open [`juiceshop/report.html`](juiceshop/report.html) in a browser. It works offline.

The capture is 417 requests in four sessions (anonymous, a new user, accounting, admin), recorded by
[`scripts/capture_juiceshop.py`](../../scripts/capture_juiceshop.py). It holds no exploit payloads.

What the model recovered:

- 105 API endpoints: 48 seen in code and traffic, 42 in traffic only, 15 named only in the Angular bundle and never called.
- Feature areas, and for each one what the capture could not answer.
- Role differences: a normal user got `200` on `/api/Users/`, and anonymous visitors reached `/rest/admin/application-configuration`.
- Redaction: the sessions contain real JWTs, a throwaway login and a test card number. None appears in the report.

`context.json` is the package for an AI and `graph.json` is the node-link export.

To rebuild it:

```bash
docker run --rm -d -p 127.0.0.1:3000:3000 bkimminich/juice-shop
python scripts/capture_juiceshop.py          # writes samples/juiceshop-*.xml
for r in anon user accountant admin; do burp2model samples/juiceshop-$r.xml -w juiceshop --role $r; done
```

The capture files are in [`samples/`](../../samples/).
