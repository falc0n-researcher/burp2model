# Output shapes

Offer these when the person wants the model as data (a baseline for `changes`, a visualiser, an archive). All output is redacted. Values never appear.

## model

One JSON object: `app`, `scope`, `roles`, `counts` (per node type, plus the `api_state` breakdown), `nodes` (id, type, layer, label, attrs, evidence ids, roles), `edges` (src, dst, type, state, evidence ids), `unknowns` (type, entity, known, not known, next step), `secrets` (kind, length, entropy, count; never a value), and an `evidence` table mapping each id to the method, host, templated path, status and role.

## context

The trimmed package to give a model instead of raw traffic: `rules`, `shape`, capped lists of `routes`, `endpoints` (most interesting first), `scripts`, `third_parties`, the `trust` layer, `unknowns`, a `coverage` block that states the caps, a `graph` block (adjacency and reasoning views) and the `evidence` table.

## graph exports

- Node-link JSON (`nodes` + `links`), for D3 or Cytoscape.
- GraphML, for Gephi or yEd.
- Cypher, one `MERGE` per node and edge, for Neo4j.

## task outputs

- **methodology**: `posture`, `recon` steps, `lines_of_inquiry` (ranked by leverage, each with signals, questions and next observation), and a `watch` list.
- **gaps**: unknowns ranked by leverage, each with the smallest next step.
- **changes**: `totals` and per-area `appeared` / `gone` lists, each with a one-line reason a researcher cares.
- **falsify**: per hypothesis, what must be true, what contradicts it, the cheapest falsifying observation, and the ranked survivors.

Keep field names stable so two captures can be compared mechanically.
