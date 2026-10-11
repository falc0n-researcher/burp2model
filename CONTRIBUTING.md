# Contributing

Thanks for helping. A few things keep this project trustworthy.

## Run it

```bash
pip install -e ".[dev]"
pytest -q                      # about two minutes; the UI tests use Chrome if it is installed
```

The Burp extension is plain Java 17 with no dependencies besides Burp's API (see `burp-extension/README.md`). With a JDK installed, `tests/test_java_parity.py` compiles it and checks it against the Python engine.

## Ground rules

- **Redaction first.** Any new way of reading input must mask values before anything is stored. Add the new shape to `tests/test_redaction_realistic.py`; the test fails if the value survives.
- **Evidence for every claim.** A new node, edge or answer must cite the request behind it.
- **Never call anything a vulnerability.** This is a model builder, not a scanner. Leads are hypotheses to verify.
- **Deterministic.** The same input gives the same output. No timestamps or random ids in model files (see `SOURCE_DATE_EPOCH`).
- **Two engines, one answer.** The Python engine and the extension's Java engine must agree. If you change modelling, redaction, queries or diffing in one, change the other and extend `tests/test_java_parity.py`.
- **No new runtime dependencies** in the Python package.
- **Docs stay short and public.** Say what it does and how to use it; no internal notes.

## Pull requests

Describe what changed and why, and say how you tested it. Do not attach real captures: use the samples in `samples/` or invent one. Keep a PR to one change.
