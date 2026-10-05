# Redaction

Mask every value. Keep every name and shape. Do it before any analysis and before anything is shown or written. `password=secret123` becomes `password=[REDACTED]`. Never drop the field.

## Header values always masked (case-insensitive)

`Authorization`, `Proxy-Authorization`, `Cookie`, `Set-Cookie`, `X-API-Key`, `X-Auth-Token`, `X-CSRF-Token`, `X-XSRF-Token`, `API-Key`. Also any header whose name contains `token`, `secret`, `apikey`, `api-key`, `auth` or `session`.

## Parameter values masked by name (query and body)

Split the name on non-alphanumerics and on camelCase, lowercase it, and mask the value if it matches a hint. So `new_password`, `accessToken`, `user[password]` and `otpCode` are caught.

`password, passwd, pwd, passcode, secret, token, apikey, api_key, access_key, refresh_token, id_token, client_secret, private_key, session, sid, csrf, auth, signature, sig, code, otp, pin, ssn, cvv, cvc, assertion`

Hints of 4 characters or fewer (`sid`, `otp`, `pin`, `cvv`, `code`, `sig`) match only whole name tokens. `code` hits `auth_code` but not `zipcode`.

## Value shapes masked anywhere (bodies, header values, fragments)

| kind | shape |
| --- | --- |
| `jwt` | `eyJ…` three base64url parts |
| `openai_key` | `sk-…` 20+ |
| `aws_key` | `AKIA`/`ASIA` + 16 |
| `google_key` | `AIza…` 35 |
| `slack_token` | `xox[baprs]-…` |
| `github_token` | `gh[pousr]_…` 36+ |
| `stripe_key` | `[rsp]k_(live\|test)_…` |
| `private_key` | `-----BEGIN … PRIVATE KEY-----` |
| `card` | 13–19 digits that pass a Luhn check |
| `email` | `local@domain.tld` |

## URL path segments that are values

Replace them with placeholders. Drop query and fragment from the template.

- Pure digits: `{id}`. UUID: `{uuid}`. 24+ hex: `{hash}`.
- A value-shape match: `{email}`, `{jwt}` and so on.
- Base64-like, 32+ chars, entropy ≥ 3.5: `{token}`.
- Token-like: 12+ chars, three character classes, 2+ digits, entropy ≥ 3.0, no dot: `{token}`.
- Matrix params `name;k=v`: mask the value of any sensitive or value-shaped part. `/app;jsessionid=1A2B…` becomes `app;jsessionid={value}`.

## What to record about a secret

`kind`, `length`, Shannon `entropy` (bits per char) and `count`. Never the value. Never a plain hash a guess could be checked against.

## Bodies

Keep only a redacted, capped excerpt, masked by name and by shape. Never store a raw body.

## Self-check before emitting

Scan your output for `eyJ…`, `AKIA…`, `sk-…`, any `@` address, any string next to a masked param name, and any long high-entropy token. If one survived, mask it and say you missed it.
