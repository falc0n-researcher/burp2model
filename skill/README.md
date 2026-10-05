# burp2model skill

Give an AI your web traffic. It builds an evidence-backed model of the app and a plan for where to look. It never produces exploits.

This directory is self-contained. Hand an AI assistant a Burp "Save items" XML export, a HAR, or pasted request/response pairs. Nothing needs to be installed.

## What it produces

1. **Model**: how the app appears to work.
2. **Methodology**: a recon plan for this app, ordered by leverage.
3. **Gaps**: what is not seen yet, ranked, with the smallest next step.
4. **Changes**: drift between two captures, by feature area.
5. **Falsify**: the hypotheses that survive an attempt to eliminate them.

## Rules

- Cite `ev_N` for every claim.
- Never invent endpoints, parameters or edges.
- Mark OBSERVED, INFERRED and EXTERNAL. Do not blur them.
- Absence is a gap in the capture, not a claim about the target.
- Hypotheses, not findings. No payloads.
- Mask values, keep names. Redact before analysis.

## How to use it

1. Read [SKILL.md](SKILL.md).
2. Build the model with [PLAYBOOK.md](PLAYBOOK.md).
3. Run a task from [`tasks/`](tasks/).
4. Use [`reference/`](reference/) for redaction, graph schema and output shapes.
5. See [`examples/juiceshop.md`](examples/juiceshop.md) for a real run.

Confirm the person is authorised to test the target. Work only from traffic they captured.

For authorised security research, education and defensive work only.
