# Changelog: Burp extension

## Unreleased

- Fix: after **Clear this model**, the model could not be opened again (the next Burp start or rename failed with a missing build file). Clearing now removes the build list too, and a model whose build file has gone missing opens with the builds before it.
- Fix: live capture lost one request each time a batch filled up (500 requests in one tick).
- Fix: requests captured live before the first build was recorded were lost when Burp restarted. They are now read back from the saved requests.
- Fix: while live capture was on, every refresh reset the Settings fields, wiping a role or scope you were typing.
- Fix: live capture no longer records a build when only duplicates arrived, and its every-40-requests trigger counts new requests rather than everything in the batch. A build is recorded from the model already built, without building it twice.
- Sending, importing and live capture read the Settings from a copy kept up to date as you type, instead of reading the Swing fields from a background thread; the build history can be read while requests are being added.
- Unit tests for the extension (`gradle test`, JUnit 5, test-only: the jar still has no dependencies), run in CI.

## 1.1.0 — 2026-10-16

- **Import HAR or Burp export** in Settings: add the requests from a HAR file (browser DevTools, Hetty, mitmproxy, ZAP) or a Burp "Save items" XML to the model.
- Redaction matches the command line tool's new coverage (multipart parts, XML elements, quoted assignments in code and config, YAML, JSON arrays and encoded JSON, `cookie` / `credential` / `bearer` values), checked against it in `tests/test_java_parity.py`.
- Analytics and telemetry calls are not shown as leads.

## 1.0.0 — 2026-10-12

First release of the burp2model Burp Suite extension: burp2model's model builder, entirely in Java, inside Burp. One jar; no Python, no local server, no files.

- Right-click requests, **Send to burp2model**, and the model builds in the burp2model tab. Or turn on live capture for in-scope Proxy traffic.
- Overview dashboard, ranked leads and open questions, a stable zoomable map (network and flow layouts), the surface as a list or site map, every request with its masked request and response, a query console (plain questions and BQL, offline), what changed between builds, role comparison, light recon, Copy for AI, JSON and Markdown export.
- Follows Burp's light and dark themes.
- Fast on large sessions: 20,000 requests build in about four seconds in under 400 MB.
- The Java engine matches the Python one: same model, same query answers, same diff (`tests/test_java_parity.py`).
