# Task: changes — what changed, and why would I care?

Compare a new capture against an earlier baseline of the same app and report the drift.

## Prerequisite
Two models of the same app: the older baseline and the current one. Build the current one if needed ([../PLAYBOOK.md](../PLAYBOOK.md)).

## Compute the drift

For each node kind (endpoint, route, script, host, third_party, cookie, auth, tech), diff by id: what is new, what is gone. Group by feature area of the current model. Say why a researcher cares:

- new privileged-looking endpoint: confirm who may reach it
- new third party: trust now leaves the app somewhere new
- new code-only path: a new unwalked door
- new cookie or credential scheme: check what it carries
- gone: retired, renamed, or not walked this time

## Produce

1. **Summary**: how much moved (`+appeared / -gone`) and the most surface-relevant change.
2. **By area**: what appeared and what is gone, each with why it matters and evidence from the current model.
3. **Where to look next**: the smallest observation for the top one or two changes.

## Rules
An appearance is a change in the surface to understand, never a finding. Never say "this is vulnerable". A disappearance means "no longer seen in the capture". It may only mean it was not walked, so say so. Cite the current model's evidence.
