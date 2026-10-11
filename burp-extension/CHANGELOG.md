# Changelog: Burp extension

## 1.0.0 — 2026-10-12

First release of the burp2model Burp Suite extension: burp2model's model builder, entirely in Java, inside Burp. One jar; no Python, no local server, no files.

- Right-click requests, **Send to burp2model**, and the model builds in the burp2model tab. Or turn on live capture for in-scope Proxy traffic.
- Overview dashboard, ranked leads and open questions, a stable zoomable map (network and flow layouts), the surface as a list or site map, every request with its masked request and response, a query console (plain questions and BQL, offline), what changed between builds, role comparison, light recon, Copy for AI, JSON and Markdown export.
- Follows Burp's light and dark themes.
- Fast on large sessions: 20,000 requests build in about four seconds in under 400 MB.
- The Java engine matches the Python one: same model, same query answers, same diff (`tests/test_java_parity.py`).
