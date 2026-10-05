# Task: methodology — where is research effort worth spending?

Build a recon-and-hunting methodology for this app, not a generic template.

## Prerequisite
Build the model first ([../PLAYBOOK.md](../PLAYBOOK.md)), including communities, execution flows and trust zones.

## Score each feature area

Leverage comes from the signals its endpoints raise:

- referenced in code, never called (unwalked door): highest
- privileged-looking path: high
- seen with and without a credential: medium
- state-changing call with no credential observed: medium
- roles diverge (one got through, another was denied): medium
- only ever returned errors: low

Attach the model's open questions to the area they concern.

## Produce, in this order

1. **What this app is**: three sentences from the model.
2. **Recon first**: close the named blind spots before hunting (no authenticated traffic: get a session; paths seen only in code: walk them; third-party code: account for it). Say why each matters.
3. **Lines of inquiry**: one per area, ordered by leverage. For each: what the evidence shows, what is unknown, the question worth answering, and the next observation or two-account comparison that answers it.
4. **What stays uncertain**, and the capture that would resolve it.

## Rules
Explain why this area, why this order, and what an answer tells you about the rest of the app. Name real endpoints, areas, roles and flows, and cite evidence. Prefer what the graph supports over any OWASP category. Everything is a hypothesis to verify in an authorised session. No payloads. Nothing called a vulnerability.
