# Changelog

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
