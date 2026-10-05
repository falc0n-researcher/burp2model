# Task: gaps — what am I missing about this target?

Point at where the model is incomplete.

## Prerequisite
Build the model and name its unknowns ([../PLAYBOOK.md](../PLAYBOOK.md), stage 7).

## Rank by leverage

| unknown | leverage |
| --- | --- |
| `AUTHENTICATED_STATE_NOT_OBSERVED` | 5 |
| `API_PURPOSE_UNKNOWN`, `ROLE_NOT_TAGGED` | 4 |
| `AUTHORIZATION_UNKNOWN` | 3 |
| `ENDPOINT_ONLY_ERRORED`, `SCRIPT_PARTIALLY_SCANNED` | 2 |
| `CAPTURE_ITEMS_SKIPPED` | 1 |

Add 1 when the unknown is on a privileged-looking path.

## Produce

1. **Ranked gaps**, highest first. For each: what the capture shows, what stays unknown, and the smallest next step to close it. Cite evidence where the model has it.
2. **The one move**: the single gap to close next, and why it unlocks the most.

## Rules
Absence is a gap in observation, never a statement about the target. Do not guess what the unseen part contains. Name what would reveal it. The next step is a capture or an authorised observation, never a payload.
