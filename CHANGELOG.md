# Changelog

## Unreleased

- **Crash-safe outputs.** model.json, report.html, context.json, graph.json, graph.graphml, build.svg, osint.json, the saved inputs, watch.json and the fingerprint key are written to a temporary file and renamed into place, so a crash, a full disk or Ctrl-C leaves the previous file whole instead of half of a new one. A rebuild puts the new input in place before clearing the old ones.
- **A damaged graph.db is kept, never wiped.** If SQLite reports graph.db as not a database or malformed, the next build moves it (and any journal beside it) to `graph.db.damaged-<time>`, says so, and starts a new one. `builds`, `diff` and `q` refuse a damaged file with a clear message and leave it untouched. A damaged build snapshot is reported instead of crashing `diff`, `changes` and `changed-since`. A damaged watch.json is kept aside too.
- **HAR is streamed.** A HAR is read entry by entry instead of loading the whole file (and a parsed copy) into memory. A half-copied or invalid HAR is still refused. A HAR with a byte-order mark is accepted.
- **The XML entity check cannot be dodged by re-encoding.** An export in UTF-16, UTF-32 or another declared encoding is decoded before it is scanned for `<!ENTITY`.
- **`watch` never keeps a half-copied export.** An export must hold its size and modification time for a whole interval before it is built, and one that changes while it is being read is built again once it settles. A file that disappears mid-scan no longer stops the watcher.
- **Faster on large exports.** Slug folding, the diff's workflow grouping and dropping 404-only paths no longer compare every path or edge with every other one (the same fixes as the Burp extension's 1.x performance work). Logger++ cells spilled over many rows are joined in one pass. Model output is byte-identical on every bundled sample.

## 1.2.0 — 2026-10-16

- **HAR input.** `burp2model session.har -w app` builds from a HAR file (browser DevTools, Hetty, mitmproxy, ZAP, Charles), through the same masking as a Burp export. `watch` picks up `*.har` too.
- **Redaction covers more shapes.** Found with two real exports: a secret next to its name now gets masked in multipart form parts, XML elements, quoted assignments in scripts and config (`const apiKey = "..."`, `{token:'...'}`), YAML lines, JSON arrays of secrets, JSON inside a percent-encoded form field, and values named `cookie`, `credential` or `bearer`. `tests/test_redaction_realistic.py` plants each shape and fails if the value survives; ordinary text is left alone.
- **Beacons are not leads.** Analytics and telemetry calls (`/collect`, `/track`, `/beacon`, `/pixel` ...) no longer show in To check, and go last in what an AI is handed. They stay in the surface and the requests.
- Added `SECURITY.md`, `CONTRIBUTING.md`, issue and pull request templates.

## 1.1.0 — 2026-10-12

- Fix: one malformed bracketed URL in a script (`https://[{x}]/...`) made the whole response unreadable, so a page and its code were silently dropped from the model. Such strings are now skipped on their own.
- Fix: a value in an HTML attribute named for a secret (`data-context-token="..."`, `<meta name="csrf-token">`) is masked in the stored request and response.
- A 13-digit millisecond timestamp that happens to pass the card checksum is no longer masked as a card.
- In the report, a large pile of code-only endpoints no longer outranks the endpoints that were actually called.
- The Burp extension is now released separately, with its own version and changelog: see [`burp-extension/`](burp-extension/).
- Much lower memory on large exports: a 40 MB export now peaks near 135 MB instead of 860 MB. The export is parsed straight to disk, request and response text is kept compressed in memory, and model.json, the report and the build snapshot are written piece by piece. Every output file is byte-identical to before.
- `reaches-privileged` also shows the shortest path from the host to each endpoint.

## 1.0.4 — 2026-10-11

- Four more `burp2model q` verbs: `provenance NODE`, `static-only`, `changed-since BUILD` and `reaches-privileged ROLE`. Each answer cites evidence and works offline. (They are CLI-only; the report console says so.)
- The report's request viewer shows when an endpoint first appeared ("new in build N", "since build N", or "gone after build N") once graph.db holds two or more builds.

## 1.0.3 — 2026-10-11

- **`burp2model watch FOLDER -w APP`** rebuilds whenever a new Burp export (Save items XML or
  Logger++ CSV) lands in a folder. Each export becomes a build labelled with its file name, and the
  change from the previous build is printed. Works with Community Edition. `--interval`, `--once`,
  `--skip-existing`, `--role`, `--scope`.
- **`burp2model diff APP [FROM] [TO]`** compares two builds kept in `graph.db` and groups the drift:
  *new workflows* (a new page, the script it loads, the endpoints that script names and their
  parameters are one line), *changed* fingerprints (a status 200 to 403, a server header nginx to
  Cloudflare, a cookie flag, a version, a role that now reaches an endpoint), and what is *gone*.
  The same build twice gives zero drift. `--json` for tooling.
- **History.** Every build is kept (set `BURP2MODEL_KEEP_BUILDS=N` to cap it), `--label TEXT` names a
  build, `burp2model builds APP` lists them, and each node and edge records its first and last build and
  time (`node.first_seen`, `node.last_seen`, `node.first_build`, `node.last_build` in BQL). An older
  `graph.db` is upgraded in place.
- **Changes in the report.** When there is a previous build, the overview shows a "since build N" bar and
  To check gets a Changes tab that opens the request behind each change.

## 1.0.2 — 2026-10-09

A new report, a technology stack, and lower memory use on large exports.

### Report
- **Overview in a minute.** A short summary, five leads to check first (each with a next step), the
  infrastructure and technology stack, and two small charts. The rest sits under "More numbers".
- **Map.** A network of coloured icon nodes with arrowed links. Select a node and its relationships are
  named on the edges (exposes, calls, references) while the rest fades; shift-click a second node to trace
  the shortest path. Network, Cluster, Flow and Focus layouts, search and filters. It follows the report
  theme: white canvas and deeper colours in light, near-black in dark.
- **Requests.** A Burp-style site map, sortable request table, and the masked request and response.
- **One viewer everywhere.** Requests, To check, Ask and Reference all open the same request and response
  viewer under the list. Scripts and pages are indented and coloured; the report keeps 40 KB of each script
  and 20 KB of each page (up from 6 KB).
- **To check** merges leads and open questions. **Ask** takes plain questions or BQL in one box.
- **Reference** is a layered chart of the app (pages, scripts, endpoints, third parties, trust,
  infrastructure). Click a ring to list it, a row to read its request. The old Endpoints, Client code,
  Third parties, Trust, Cross-role and Infrastructure links open it.
- **Fonts.** Inter, Space Grotesk and JetBrains Mono are embedded (about 150 KB, SIL OFL), so it looks the
  same offline.
- **Evidence ids start at 1** and show as EVD 1, EVD 2 in the report. Files and the CLI still use `ev_1`,
  `ev_2`; BQL accepts either form.
- A headless-Chrome test drives every view.

### Model
- **Technology stack.** Servers, CDNs, frameworks and third-party services read from headers, cookies,
  pages and hosts, each tied to its evidence. In `model.json` and `context.json`.
- **Screenshot.** An anonymous browser crawl captures the start page for the overview. Attach your own with
  `--screenshot FILE`, or skip it with `--no-screenshot`. Signed-in crawls never capture one on their own.

### Fixes and docs
- Large exports use about half the Python memory: parsed requests are freed once saved and once the model
  is built (a 20,000-request build peaked at 224 MB, down from 437 MB). Output is unchanged.
- A failed Chrome start is retried before a browser crawl or test gives up.
- Docs now say plainly that masked, truncated request and response bodies are stored in `model.json`,
  `graph.db` and the report.

## 1.0.1 — 2026-10-08

- **`build` is fully offline by default.** External recon (DNS, TLS, headers) no longer runs
  unless you pass `--osint` to `build` or `crawl`, or run the `osint` command.
  `BURP2MODEL_OFFLINE=1` still forces it off. The `--no-osint` flag is gone, since it is now
  the default.
- Docs trimmed and corrected to match.

## 1.0.0 — 2026-10-06 (first release)

burp2model turns a web app's traffic into an evidence-backed model of its attack surface that
a person or an AI can query. It is a model builder, never a scanner or exploit tool: every
claim cites the request that proves it, and what the capture could not show is listed as an
unknown instead of guessed.

### Ingest
- Burp "Save items" XML (streaming, base64, gzip/chunked/brotli/zstd bodies) and Burp Logger++
  CSV exports (`--skip-tools` / `--only-tools`).
- `burp2model crawl`: build the model from a running app in a real browser, with scripted
  journeys (`--journey`, `--var`), no Burp needed. Authorized targets only.
- Malformed items are skipped and counted, never fatal. A file that is not a Burp export gets
  a clear error with the export steps.

### The model (six layers)
- Edge, routes (with path templating: `/user/{id}`, slug and build-hash folding), client code
  (scripts, the workers they spawn, and the source maps they name), APIs (each `BOTH` / `STATIC_ONLY` / `RUNTIME_ONLY`), trust (auth, third parties, cookies),
  and named unknowns.
- Deterministic content-hash IDs; `OBSERVED` vs `INFERRED` edges. Same export, same model,
  byte-identical output (set `SOURCE_DATE_EPOCH` to pin the build timestamp stored in
  `graph.db` and shown in the report).
- Scanner noise, 404-only paths and payload probes are kept as evidence but not modelled
  as routes.

### Redaction
- Secrets, cookies, tokens and PII are masked before anything is written; secrets are kept as
  a keyed fingerprint (kind, length, entropy), never the value.
- CI plants secrets in samples and fails if any appears in any derived file.

### Query (no AI)
- `burp2model query <app> <intent>`: `list-apis`, `reconcile` (also `code vs runtime`),
  `list-routes`, `route-apis`, `provenance`, `third-parties`, `auth-surface`, `unknowns`,
  `entity-evidence`, plus `parameters`, `secrets`, `privileged`, `errors`, `shape`.
- Every answer cites evidence ids and ends `Model call: none`. A question it cannot answer
  is refused, never guessed.
- `burp2model q`: BQL, an HTTPQL-style filter and graph-verb language over a SQLite
  `graph.db` (including `reach`).

### Copy-for-AI
- `context.json`: shape, endpoints, unknowns and a token estimate under a rules block (cite
  evidence, never invent endpoints, name unknowns, hypotheses not findings).
- `falsify` and `methodology` emit prompts that stress-test the model and scaffold a
  target-specific recon plan.

### Output
- A self-contained interactive HTML report, `model.json`, `graph.json`, `graph.graphml`,
  Cypher export, and an animated build SVG.
- `cross-role`, `gaps`, `changes` (drift between two models, grouped by feature area) and
  `osint` (run by `build` unless `--no-osint`; `BURP2MODEL_OFFLINE=1` disables it).

### Validated on
OWASP Juice Shop, DVWA, Mutillidae II, WebGoat, a React SPA and three real Logger++ exports.
See `docs/TESTED_APPS.md`.
