# Crawling a running app

`burp2model crawl` builds the same model from a live app, with no proxy and no export. With Chrome or Chromium installed it runs the app in a real browser, so JavaScript executes and the real XHR/fetch traffic is recorded. It clicks through menus and buttons, submits safe forms, follows hash and history routes, then requests the GET endpoints the scripts name that the UI never fired. Without a browser it falls back to a static crawler (links, forms, sitemap, assets).

```bash
burp2model crawl https://shop.example.com/ -w shop --yes --role anon
burp2model crawl https://shop.example.com/ -w shop --yes --role user \
    --auth-login /rest/user/login --auth-body @login.json --auth-token authentication.token
burp2model cross-role shop --low anon --high user
```

Traffic passes through the same parser and redaction as a Burp export, in memory. Nothing raw is written; `--save-xml` is an opt-in raw export. Defaults are 3,000 requests, depth 12 and 25 clicks per page state. Tune with `--max-requests` (0 removes the cap), `--max-seconds`, `--max-clicks`, `--depth`, `--per-template-cap`, `--threads` and `--delay`.

## Safety

Only crawl targets you are authorized to test.

| It always | It never |
| --- | --- |
| refuses to run without `--yes` and prints the target first | crawls without that confirmation |
| stays on the start origin plus `--scope` hosts; out-of-scope requests are blocked before they are sent | follows a link off-scope (subdomains only with `--include-subdomains`) |
| skips destructive-looking URLs and never clicks `logout`, `delete`, `remove`, `purge`, ... | follows them to see what happens |
| answers `confirm()` with cancel and denies downloads | accepts a confirmation for you |
| never submits a form with a password field | types a password it was not given |
| lets the app make its own in-scope requests | allows a non-GET under `--read-only` |

## Journeys

A crawler cannot register, log in or check out on its own. A journey is a short JSON file that does, in the same browser session, before the crawl:

```json
{ "name": "customer",
  "steps": [
    {"request": {"method": "POST", "path": "/rest/user/login",
                 "json": {"email": "${env:SHOP_EMAIL}", "password": "${env:SHOP_PASSWORD}"},
                 "extract": {"token": "authentication.token"}}, "required": true},
    {"set_header": {"Authorization": "Bearer ${token}"}},
    {"goto": "/#/basket"},
    {"click": {"text": "Checkout"}}
  ] }
```

```bash
SHOP_EMAIL=... SHOP_PASSWORD=... burp2model crawl https://shop.example.com/ -w shop --yes \
    --role user --journey checkout.json
```

Steps: `goto` `click` `fill` `press` `wait` `wait_for` `wait_idle` `request` `set_header` `set_storage` `set_cookie` `scroll`. `extract` saves reply fields as variables, `expect` checks the status, and `${env:NAME}` and `--var name=value` supply values. Files are validated before anything is sent. A failed step is reported by number; the journey continues unless the step is `"required": true`. Journey steps skip the destructive-looking filter but still obey scope, `--read-only` and `--yes`. `--journey-only` skips the autonomous crawl. A sample is in [`samples/journeys/`](../samples/journeys/).

## What to expect

On a local Juice Shop, a browser crawl reached about 70 endpoints in about 900 requests per role. A hand-driven capture reached 105. For state-changing flows, record a real session and build from the export. See [TESTED_APPS.md](TESTED_APPS.md).
