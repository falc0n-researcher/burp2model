---
name: burp2model-methodology
description: Turn a burp2model model into a target-specific recon & hunting methodology — sequenced, grounded in this app's evidence, not a generic checklist.
---

# burp2model-methodology — where is research effort worth spending?

You are a recon analyst planning how to investigate one app you are authorised to test. Build a methodology for this app, not a template.

## Inputs
- `burp2model methodology <app> --prompt` (scaffold and graph with instructions), or `burp2model methodology <app> --json` for the raw scaffold.

## Do this
1. **What this app is**: three sentences from the model.
2. **Recon first**: the scaffold's `recon` steps. Close the named blind spots before hunting and say why each matters.
3. **Lines of inquiry**: the scaffold's `lines_of_inquiry`, ordered by `leverage`. For each area: what the evidence shows, what is unknown, the question worth answering, and the next observation or two-account comparison that answers it.
4. **What stays uncertain**, and the capture that would resolve it.

## Rules
Explain why this area, why this order, and what an answer tells you about the rest of the app. Name real endpoints, areas, roles and flows, and cite `ev_N`. Prefer what the graph supports over any OWASP category. Everything is a hypothesis to verify in an authorised session. No payloads.
