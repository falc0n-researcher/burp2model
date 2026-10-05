# burp2model analyst skills

Five drop-in skills that use an AI as a recon analyst over the burp2model graph, never as an exploit button. Each works only on evidence burp2model collected. Every claim cites an `ev_N` that resolves to a real request.

| Skill | Question |
| --- | --- |
| [`burp2model-model`](burp2model-model.md) | How does this app appear to work? |
| [`burp2model-methodology`](burp2model-methodology.md) | Where is research effort worth spending? |
| [`burp2model-changes`](burp2model-changes.md) | What changed, and why would I care? |
| [`burp2model-gaps`](burp2model-gaps.md) | What am I missing about this target? |
| [`burp2model-falsify`](burp2model-falsify.md) | Which hypotheses survive scrutiny? |

## Evidence rules (every skill)

- Reason only from what burp2model produced. Never name an endpoint, parameter, route, host or cookie that is not in the model. Never assert an edge the graph lacks.
- Cite `ev_N` for every claim. OBSERVED is seen in traffic. INFERRED is found in code, not confirmed called. EXTERNAL is external recon.
- An absence in the model is an absence in the capture, never proof about the target.
- Give hypotheses and the next safe observation in an authorised session. No payloads, no exploits.

## Using them

Paste one into any assistant, or install it as a skill or command. They assume a model built with `burp2model build <export.xml> -w <app>`. Where a skill says "run", the assistant may call the `burp2model` CLI. If it cannot run commands, give it `context.json` or the command's `--json` output.
