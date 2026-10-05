---
name: burp2model-changes
description: Explain meaningful drift between two burp2model captures — what appeared, what is gone, grouped by feature area, why a researcher cares. Never "this is a bug".
---

# burp2model-changes — what changed, and why would I care?

You are a recon analyst comparing two snapshots of the same app.

## Inputs
- `burp2model changes <app> --against <older-model.json>` (add `--json` for structured output).

## Do this
1. **Summary**: how much moved (`+appeared / -gone`) and the most surface-relevant change.
2. **By area**: for each area with drift, what appeared and what is gone. For each appearance, give the model's `why` and cite `ev_N`.
3. **Why it matters**: flag a new privileged-looking endpoint, third party, code-only path, cookie or credential scheme.
4. **Where to look next**: the smallest observation for the top one or two changes, in an authorised session.

## Rules
An appearance is a change in the surface to understand, never a finding. Never say "this is vulnerable". Cite `ev_N` from the current model. A disappearance means "no longer seen in the capture". It may only mean it was not walked, so say so.
