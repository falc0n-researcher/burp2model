# Worked example: OWASP Juice Shop

A run of this method against a local [OWASP Juice Shop](https://owasp.org/www-project-juice-shop/), an app built for training. Full report: `docs/examples/juiceshop/report.html`. Captures: `samples/juiceshop-{anon,user,accountant,admin}.xml`, recorded by `scripts/capture_juiceshop.py`.

## Input
Four sessions, 417 requests: an anonymous visit, a newly registered user, and the documented default accounting and admin users. Nothing was attacked beyond ordinary use.

## Model
- **105 API endpoints**: 48 in code and traffic, 42 in traffic only, 15 referenced only in `main.js` and never called.
- **Feature areas**: `user`, `basket`, `feedbacks`, `admin`, `2fa`, `cards` and others. Trust layer: the `Authorization: Bearer` scheme and where it was seen.
- **Cross-role questions**: a normal user got `200` on `/api/Users/`. Anonymous visitors reached `/rest/admin/application-configuration`.
- **Redaction held.** The sessions hold real JWTs, a login, a password change and a test card number. None appears in any output.

## Tasks
- **gaps** ranked `/rest/admin` first (code-only, privileged-looking path). Next step: request it in an authorised session.
- **methodology** put the code-only paths first in recon, then areas by leverage, each ending in the observation that would advance it.
- **changes** (anonymous vs all four sessions) showed the auth scheme and authenticated endpoints appearing, by feature area. It reported `GET /rest/user/change-password` as a closed gap.

None of this is a finding. It is a map of the app, the unwalked paths, and the questions worth a researcher's time, each tied to a real request.
