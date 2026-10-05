# Size of the package

The package (`context.json`) grows with an app's structure (endpoints, areas, unknowns), not with its bytes. Tokens are estimated at 4 bytes each.

| Capture | Raw (decoded) | `context.json` | Saving |
| --- | --- | --- | --- |
| Synthetic `shop` sample (17 requests) | ~5k | ~6k | none |
| Juice Shop, API traffic only | ~366k | ~33k | ~11x |
| Juice Shop, full capture (417 requests, 4 roles) | ~1.02M | ~37k | ~28x |

- **Small captures save nothing.** The model adds structure on top of a capture that was already small.
- **Large captures save the most.** Bundles, HTML and images add bytes but little structure.
- The package is capped; its coverage section says what was cut.
- `methodology --prompt` adds the reasoning graph and plan (~53k tokens for the Juice Shop capture).

To reproduce, run `scripts/capture_juiceshop.py`, build the captures with `--role`, and compare the decoded XML size to `context.json`.
