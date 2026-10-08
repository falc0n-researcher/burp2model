# How burp2model works

Traffic goes in, a model comes out. Parsing, redaction, modelling and querying are offline. The network is used only by `crawl` and `osint` (and `build --osint`). `BURP2MODEL_OFFLINE=1` forces recon off.

```
Burp export (or crawl)  ->  parse  ->  redact  ->  model  ->  six-layer graph
                                                              |-- graph.db   (SQLite, queried with BQL)
                                                              |-- report.html
                                                              |-- context.json  (for an AI)
                                                              `-- model.json
```

## 1. Parse

The parser streams the XML, decodes the base64 items, splits headers from bodies and undoes gzip/deflate. Paths are templated (`/api/users/123` becomes `/api/users/{id}`) so one endpoint is one node. Items that cannot be parsed are counted and reported as the `CAPTURE_ITEMS_SKIPPED` unknown.

From each body (up to 10 MB; larger scripts raise `SCRIPT_PARTIALLY_SCANNED`) it extracts:

- API references in JavaScript: `fetch`, `axios`-style calls, `XHR.open`, template literals, string concatenation, absolute URLs
- form targets and inline scripts in HTML
- cookie names and flags, credential kinds sent, tech headers, GraphQL operation names

## 2. Redact

Every value is masked before an exchange leaves the parser. Names and shapes are kept.

- Sensitive headers and parameters (`Authorization`, `Cookie`, `password`, `token`, ...) become `[REDACTED]`.
- Secrets recognised by shape (JWTs, API keys, private keys, card numbers, emails) become `[REDACTED:kind]`.
- Path segments that are values become `{email}`, `{jwt}`, `{token}`, `{id}`, `{uuid}`, `{hash}`.

Each masked value is stored as a fingerprint: a keyed HMAC-SHA256 prefix, its length and its entropy. The key lives in `~/.config/burp2model/`, outside the output directory, so fingerprints cannot be used to confirm a guess. `BURP2MODEL_FP_KEY` overrides it. Tests check that no planted secret appears in any output file.

## 3. Model

By default, every host under the registrable domain of the busiest host is first-party. `--scope` overrides this. Other hosts are third parties.

| Layer | Nodes | Built from |
| --- | --- | --- |
| 1 edge | host | every first-party request |
| 2 routes | route | GET HTML and navigation responses |
| 3 code | script | JavaScript responses, forms, inline scripts |
| 4 apis | endpoint, parameter, operation | API requests, form posts, GraphQL, code references |
| 5 trust | third_party, role, auth, cookie | off-scope hosts, `--role`, credentials, `Set-Cookie` |
| 6 unknowns | unknown | gaps the capture leaves |

Layer 3 also records workers (`new Worker`, `serviceWorker.register`, `importScripts`) as scripts linked by `SPAWNS` edges, and source maps (`sourceMappingURL`) as a `sourcemap` attribute on the script. If the `.map` file was not captured, the model raises `SOURCE_MAP_NOT_CAPTURED`.

## Technology stack

While parsing, burp2model reads what each response shows: `Server` and similar headers, cookie names, HTML and script markers, and the third-party hosts the app talks to. The result is a short list (edge or CDN, web server, language or framework, frontend, platform, services), each entry tied to the requests that showed it. These are hints from the capture, not a version scan. The report draws them as a stack map, and `context.json` carries them as `stack`.

## 4. OBSERVED vs INFERRED

Every edge says how it is known.

| State | Meaning | Examples |
| --- | --- | --- |
| OBSERVED | seen in traffic | host `SERVES` route, route `CALLS` endpoint (from Referer), role `REACHED` node, `SETS_COOKIE` |
| INFERRED | read from code, not proven | script `REFERENCES` endpoint, script `SPAWNS` worker |
| EXTERNAL | from OSINT | host to IP, certificate, subdomain |

## 5. Reconcile

Code references are matched to observed endpoints by templated path, then method, then host.

- `BOTH`: referenced in code and observed
- `STATIC_ONLY`: in the code, never called in the capture
- `RUNTIME_ONLY`: observed, with no code reference found

A reference whose method cannot be read is shown as `*`, never guessed as `GET`.

## 6. Unknowns

The model names its gaps. Absence in the model means absence in the capture, not in the target.

| Unknown | When |
| --- | --- |
| `AUTHENTICATED_STATE_NOT_OBSERVED` | no credentials sent and no role tagged |
| `ROLE_NOT_TAGGED` | credentials sent but no `--role` |
| `API_PURPOSE_UNKNOWN` | a `STATIC_ONLY` endpoint |
| `AUTHORIZATION_UNKNOWN` | any endpoint a role reached |
| `ENDPOINT_ONLY_ERRORED` | every response was 4xx/5xx |
| `SCRIPT_PARTIALLY_SCANNED` | a script exceeded the scan cap |
| `SOURCE_MAP_NOT_CAPTURED` | a script names a source map that was not captured |
| `CAPTURE_ITEMS_SKIPPED` | export items could not be parsed |

## 7. Roles and evidence

Each `--role` build saves redacted records to `inputs/<role>.jsonl`, then rebuilds one model from all saved roles. Rebuilding a role replaces only that role. A build without `--role`, or with `--fresh`, starts over.

Every claim cites an evidence id (`ev_1`, `ev_2`, ... numbered from 1). The report shows the same ids as EVD 1, EVD 2. The `evidence` table in `model.json` maps each id to its source file and item. Ids are renumbered when roles merge, so treat the outputs of one build as one set and re-copy after a rebuild.

## 8. Outputs

- `graph.db`: the model as a SQLite graph, queried with [BQL](QUERYING.md).
- `report.html`: an offline, self-contained report.
- `context.json`: the package for an AI. See [USING_WITH_AI.md](USING_WITH_AI.md).
- `model.json`, `inputs/`, and exports from `burp2model graph` (JSON, GraphML, Cypher).

## 9. OSINT

`burp2model osint <host> --yes` contacts the target and public services (DNS, TLS, HTTP headers, certificate transparency, RDAP). `build --osint` runs a light version on the primary public host and carries on if it fails. A plain `build` never does. Results are saved to `graph.db` as `EXTERNAL` nodes, kept apart from captured traffic.

## 10. Crawling

`burp2model crawl URL --yes` builds the same model from a running app. Its traffic passes through the same parser and redaction. See [CRAWLING.md](CRAWLING.md).
