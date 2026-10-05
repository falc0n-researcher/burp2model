# Playbook

Build an evidence-backed model of a web app by reasoning over captured traffic. Follow the stages in order. Redaction comes first.

The model is a six-layer graph. Every node cites the exchanges it came from. Every edge is OBSERVED, INFERRED (from a reference in code) or EXTERNAL (from recon). Nothing is called a vulnerability.

```
6  unknowns   what the capture could not answer
5  trust      third parties, auth schemes, roles, cookies and flags
4  apis       endpoints, parameters, GraphQL operations, code-vs-runtime state
3  code       scripts and the endpoints they reference
2  routes     pages and navigations, linked to the APIs they call
1  edge       first-party hosts, schemes, ports, server technology
```

## 0. Authorisation and scope

Confirm the person is authorised. Scope is the set of first-party hosts. Default to the registrable domain of the busiest host. Everything else is a third party. If the person names a scope, use it.

## 1. Parse

For each exchange (Burp `<item>`, HAR entry, pasted pair): decode request and response (Burp stores them base64) and read method, host, port, scheme, path, status, MIME type, headers and bodies. Decompress gzip, deflate, br and zstd bodies. Reassemble chunked bodies. If a body cannot be decoded, record a blind spot. Do not guess its contents. Refuse an export that declares XML entities.

## 2. Redact

Do this before anything leaves your hands. Mask every value, keep every name and shape. Patterns are in [reference/redaction.md](reference/redaction.md). Record a secret as kind, length, entropy and count. Never record the value or a plain hash of it. After this stage no raw secret may exist in your notes or output.

## 3. Classify

Label each first-party exchange from the templated path and MIME type:

- **script**: JavaScript.
- **asset**: image, font, css and similar on a GET. Count it, set it aside.
- **preflight**: a CORS `OPTIONS` with `Access-Control-Request-Method`. Count it.
- **endpoint**: any non-GET/HEAD, or a GET that returns JSON/XML or has query params and is not an HTML page or redirect.
- **route**: HTML pages, GET redirects, other GET resources.

Off-scope exchanges become third_party hosts with a request count. If one served JavaScript, add a script node.

## 4. Nodes and edges

Record the exchanges behind every node. Vocabulary: [reference/graph-schema.md](reference/graph-schema.md).

- **host**: schemes, ports. Add a **tech** node and `host RUNS tech` for each `Server` or `X-Powered-By` style marker.
- **route**: `host SERVES route`, with statuses. **script**: `host LOADS script`.
- **endpoint**: `host EXPOSES endpoint`, with method, statuses, per-role statuses, credentials seen, request count, and whether any request was anonymous.
- **parameter** (names only): `route|endpoint USES_PARAMETER param`. GraphQL: `endpoint USES_OPERATION op`.
- **cookie**: `host SETS_COOKIE cookie` with the weakest HttpOnly/Secure/SameSite flags seen. **auth**: `endpoint SENT_CREDENTIAL auth`. **role**: `role REACHED node`, if the capture is tagged with a role.
- **Referer edges** (OBSERVED): if a request's Referer is a modelled in-scope page, link it with `CALLS`, `INCLUDES` or `NAVIGATES_TO`.

## 5. Read client code

Scan every first-party script and HTML page, up to a sane cap. Flag anything past the cap as partially scanned. Extract endpoint references: `fetch`, `axios`, `$http`, `XHR.open`, `<form action method>`, template literals, concatenations, absolute and relative URLs.

Add an INFERRED `REFERENCES` edge from the script or page to the endpoint. If the endpoint is not in traffic, create the node and mark an unknown method. Resolve relative paths against the page origin, not the script host. A reference to an off-scope host is a `REFERENCES` edge to that third party.

## 6. Reconcile code and runtime

Set each endpoint's `api_state`:

- **BOTH**: in code and in traffic.
- **RUNTIME_ONLY**: in traffic, not in code.
- **STATIC_ONLY**: in code, never called in the capture. These are the unwalked doors. They matter most.

## 7. Name the unknowns

State what the capture could not answer:

- `AUTHENTICATED_STATE_NOT_OBSERVED`: no credential was ever sent.
- `ROLE_NOT_TAGGED`: credentials sent, not attributed to a role.
- `API_PURPOSE_UNKNOWN`: a STATIC_ONLY endpoint.
- `AUTHORIZATION_UNKNOWN`: a role reached it, authorization not verified.
- `ENDPOINT_ONLY_ERRORED`: every status was 4xx/5xx.
- `SCRIPT_PARTIALLY_SCANNED`, `CAPTURE_ITEMS_SKIPPED`: coverage limits.

For each, say what you know, what stays unknown, and the smallest next step.

## 8. Reason over the model

Derive these with citations:

- **reach(node)**: shortest path(s) back to an entry point, hop by hop, each OBSERVED or INFERRED.
- **blast(node) / touched_by(node)**: what a node affects downstream, and what it depends on upstream.
- **trust_zones**: endpoints grouped by how identity reaches them: credentialed, seen-anonymous, privileged-looking path, no-auth-observed.
- **communities**: feature areas. Cluster the graph without host, role and auth connectors. Name each by its shared path segment.
- **hubs**: nodes with the most connections. **coupling**: edges that cross an area or leave to a third party.

Then run the task from `tasks/`. Keep the evidence contract in [SKILL.md](SKILL.md).
