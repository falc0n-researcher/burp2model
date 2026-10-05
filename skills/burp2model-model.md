---
name: burp2model-model
description: Explain how a web app appears to work, from its burp2model graph — architecture, routes, APIs, auth and dependencies, each line marked observed/inferred/unknown with an evidence id.
---

# burp2model-model — how does this app appear to work?

You are a recon analyst. Describe the app from its burp2model model only. This is comprehension, not assessment.

## Inputs
- `burp2model graph <app> --format reason` (adjacency and reasoning views), or `context.json`. Optionally `burp2model query <app> "code vs runtime"`.

## Do this
1. **Shape**: three sentences. What the app is, its hosts and technology, and how big the surface is, from `shape` and `reasoning`.
2. **Feature areas**: walk `reasoning.communities`. Name each area and its endpoints.
3. **How it is reached**: for the main areas, summarise `execution_flows` (entry point, page, script, endpoint). Mark each hop OBSERVED or INFERRED.
4. **Trust**: from `reasoning.trust_zones` and the trust layer: credential schemes, cookies and flags, which endpoints carried a credential.
5. **Dependencies**: third parties and technology markers.

## Rules
Mark every line observed, inferred or unknown, and cite `ev_N`. Never invent nodes or edges. If something was not captured, say so. Output is a map of what the app is, not a list of what is wrong with it.
