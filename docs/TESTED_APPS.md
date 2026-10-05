# Tested apps

Each app was a local training instance. Numbers are from real runs.

| App | Result |
| --- | --- |
| OWASP Juice Shop 20.2.0 | 105 endpoints from a four-role capture (417 requests). Browser crawl: about 70 endpoints and 50 page states per role. A scripted journey raised state-changing endpoints from 8 to 12. |
| DVWA 1.10 | All 15 modules and 25 routes reached, including a CSRF-protected login. |
| Mutillidae II | 105 page states and 80 routes. The first pass saw 12 because every page collapsed into `index.php`. |
| WebGoat | 1,715 requests, 11 endpoints behind the login. |
| React shop (written for the test) | 15 of 19 API endpoints and 11 of 11 routes. The four misses are by design. |
| Logger++ exports from three real engagements (private) | Next.js, WordPress and an active scan. Secret-like values harvested from them appear in no output. |

## Found and fixed

- Redaction leaks: HTML hidden fields and headers echoed in a page body were not masked. Names such as `PHPSESSID`, `__VIEWSTATE` and `XSRF-TOKEN` are now treated as credentials.
- Query-routed pages (`index.php?page=...`) merged into one node. Page-selecting parameters are now part of the route.
- Pages with parameters were missing from the methodology. They are now lines of inquiry.
- A login that failed went unnoticed. Journeys gained `assert`.
- Setup, install and wipe links were crawled. They are now on the do-not-touch list.

## Still weak

- API calls made through a wrapper do not reconcile with code (React shop: all endpoints runtime-only).
- Forms with a password field are not submitted by the crawler, and destructive controls are not clicked. A journey can do both.
- A time budget ends the crawl on depth, not breadth.
- Hash routes (`#/login`) are visible only through the requests they make.
- The autonomous crawl found about two thirds of what a hand-driven session did.

## Not yet tested

A Burp "Save items" XML from a real engagement, a GraphQL-first app, an app behind a WAF or captcha, and Linux.
