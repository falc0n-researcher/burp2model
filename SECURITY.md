# Security

burp2model handles captured traffic, so the thing that matters most is that **no secret value ever reaches an output**. A case where one does is a security bug, not an ordinary one.

## Report a problem

Please report privately, not in a public issue: use **Security > Report a vulnerability** on this repository (GitHub private advisories). Include:

- what you ran (command, version from `burp2model --version` or the extension's Settings tab),
- the smallest input that shows it, **with the secret replaced by a made-up value** (never send a real token, cookie or key),
- which output held the value (`model.json`, `report.html`, `graph.db`, the extension's stored model ...).

You will get a reply within a few days. A fix ships as a patch release, and the CHANGELOG says what was affected.

## What counts

- A secret, cookie, token, key or personal value that survives redaction into any file burp2model writes, or into the extension's saved models.
- Anything that makes burp2model send captured data somewhere without being asked. (Recon and `osint` contact the host you name; nothing else should leave your machine.)
- Reading or writing files outside the output folder.
- A crafted export (XML, CSV or HAR) that crashes, hangs or exhausts memory.

## Supported versions

The latest release of the command line tool and of the Burp extension.

## Using it safely

Capture and model only systems you are authorised to test. Outputs hold masked requests and responses, names and shapes, never values, but treat them as sensitive anyway: they describe an application's surface.
