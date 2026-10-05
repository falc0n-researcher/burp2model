# Graph schema reference

The model is a directed graph with stable, descriptive node ids.

## Node types

| type | layer | is | key attrs |
| --- | --- | --- | --- |
| `host` | 1 | a first-party host | schemes, ports |
| `tech` | 1 | a server/framework marker from a response header | header it came from |
| `route` | 2 | a page / navigation | host, path, statuses |
| `script` | 3 | a JavaScript file | host, scope |
| `endpoint` | 4 | an API endpoint | method, host, path, `api_state`, statuses, `status_by_role`, credentials, requests, anonymous_requests |
| `parameter` | 4 | a query or body parameter (name only) | location (query/body) |
| `operation` | 4 | a GraphQL operation name | — |
| `third_party` | 5 | an off-scope host | requests |
| `auth` | 5 | a credential scheme seen on requests | — |
| `cookie` | 5 | a cookie (name + flags only) | httponly, secure, samesite |
| `role` | 5 | a capture tagged with a role | — |
| `infra` | 5 | an external-recon fact (TLS, DNS, hosting, …) | detail, kind |

## Edge types

| edge | meaning | typical state |
| --- | --- | --- |
| `RUNS` | host runs a technology | OBSERVED |
| `SERVES` | host serves a page | OBSERVED |
| `LOADS` | host loads a script | OBSERVED |
| `EXPOSES` | host exposes an endpoint | OBSERVED |
| `INCLUDES` | page includes a script | OBSERVED |
| `CALLS` | page calls an endpoint | OBSERVED |
| `NAVIGATES_TO` | page navigates to a route | OBSERVED |
| `USES_PARAMETER` | route/endpoint uses a parameter | OBSERVED |
| `USES_OPERATION` | endpoint uses a GraphQL operation | OBSERVED |
| `SETS_COOKIE` | host sets a cookie | OBSERVED |
| `SENT_CREDENTIAL` | endpoint carried a credential scheme | OBSERVED |
| `REACHED` | a role reached a node | OBSERVED |
| `REFERENCES` | script/page names an endpoint or third party (found in code) | INFERRED |
| `OSINT` | app host → an external-recon fact | EXTERNAL |

## Edge states (never blur them)

- **OBSERVED**: happened in the captured traffic.
- **INFERRED**: deduced from a reference in code. Not proof it was called.
- **EXTERNAL**: collected by external recon, not from the capture.

## Endpoint provenance (`api_state`)

- **BOTH**: in code and in traffic.
- **RUNTIME_ONLY**: in traffic, not found in code.
- **STATIC_ONLY**: in code, never called in the capture (the unwalked doors).

## Privileged-path heuristic

A path segment matching `admin, administrator, internal, manage, management,
config, privileged, superuser, staff, root, debug, actuator, console, backoffice,
ops` marks the endpoint privileged-looking. It is a label to check, never a claim.
