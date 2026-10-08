# Querying the model

## Plain questions (no AI)

```
$ burp2model query shop "code vs runtime"
APIs: 10 endpoints
  BOTH 6 · STATIC_ONLY 1 · RUNTIME_ONLY 3
    static-only  * /api/admin/audit  ev_4
Source: model graph · Model call: none
```

Every line cites the request behind it. `*` means the code names the path but not the method.

| Intent | Answers |
| --- | --- |
| `list-apis` | every endpoint with state, statuses, evidence |
| `reconcile` | code vs runtime |
| `list-routes` | pages, SPA states, forms |
| `route-apis /x` | APIs a route calls |
| `provenance /api/orders` | where an endpoint was seen |
| `third-parties` | off-scope hosts |
| `auth-surface` | credentials, roles, cookie flags |
| `unknowns` | what the capture could not answer |
| `entity-evidence <name>` | evidence ids behind any node |

Also: `parameters`, `secrets` (masked), `privileged`, `errors`, `shape`. Anything else is refused: the answer comes from the model or the tool says it cannot. `burp2model query shop help` lists them.

## BQL

`graph.db` holds the whole model. `burp2model q` queries it with filters and graph verbs:

```bash
burp2model q shop 'req.method:POST AND resp.code.gte:400'
burp2model q shop 'node.type:endpoint AND node.state:STATIC_ONLY'
burp2model q shop 'reach "POST /api/checkout"'
burp2model q shop 'sql SELECT type, count(*) FROM nodes GROUP BY type'
burp2model q shop            # interactive; `help` lists the language
```

Fields are `req.*`, `resp.*`, `node.*`, `edge.*`. Operators: `eq ne cont ncont like regex gt gte lt lte`. Combine with `AND OR NOT ( )`. Values are bound as SQL parameters. The same console is in `report.html`.

## Graph reach

```
$ burp2model graph shop --reach /api/checkout
  api.example.com --EXPOSES--> POST /api/checkout              ev_15
  cdn.example.com/app.js --REFERENCES(inferred)--> POST /api/checkout  ev_9
```

- `--reach NODE`: how a node is reached from an entry point.
- `--blast NODE` / `--touched-by NODE`: what it affects, or what leads into it.
- `--format json|graphml|cypher|reason`: export, or a single package for an AI.

`burp2model graph shop` alone gives functional areas, trust zones and coupling.

## Analyst commands

```bash
burp2model gaps shop                               # unknowns ranked by value of resolving them
burp2model changes shop --against old/model.json   # drift by area, never "a bug"
burp2model falsify shop                            # prompt that tries to disprove each hypothesis
burp2model methodology shop [--prompt]             # target-specific plan, or the AI prompt for it
```

All results are hypotheses to verify in an authorized session. The same five analyst roles are packaged in [`skills/`](../skills/). A sample report is in [`examples/juiceshop/report.html`](examples/juiceshop/report.html).
