# Using the model with an AI

Give an AI the evidence package instead of raw traffic.

```bash
burp2model history.xml --webapp shop
cat burp2model-out/shop/context.json
```

## What is in it

- endpoints: state (`STATIC_ONLY`, `RUNTIME_ONLY`, `BOTH`), statuses, parameter names, roles, credential kinds, callers
- routes, scripts, third parties
- trust: auth schemes, cookies and their flags
- secrets: kind, length and entropy only, never the value
- unknowns: each gap with what is known and the next step
- coverage and evidence: every `ev_N` cited, resolved to method, host, path, status and role

## Rules it carries

- Cite an evidence id for every claim.
- Do not name an endpoint, route or parameter that is not in the package.
- State unknowns; do not guess authorization behaviour.
- Output hypotheses and how to test them, not findings.
- `REFERENCES` edges are inferred from code; only observed facts happened.
- Absence in the package is absence in the capture.

## Lenses

Each section holds 40 items by default (`--cap N`). `--lens` decides what survives:

| `--lens` | Keeps |
| --- | --- |
| `attention` (default) | all, ordered by interest: code-only, privileged-looking, role-reached first |
| `auth` | endpoints that carried credentials or were reached by a role |
| `all` | all, in model order |

## Prompting

Ask for a plan grounded in the package: "What does each endpoint reach, how can the open questions be checked safely, and what stays uncertain? Cite evidence ids. Name nothing that is not in the package."

The package is provider-agnostic. Paste it into any chat model or give the file to a coding agent. Ready-made analyst prompts are in [`skills/`](../skills/). For size, see [MEASUREMENTS.md](MEASUREMENTS.md).
