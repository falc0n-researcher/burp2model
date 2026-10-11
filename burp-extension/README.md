# burp2model for Burp Suite

burp2model, inside Burp. Right-click requests, choose **Send to burp2model**, and the model builds in the **burp2model** tab: every claim tied to the request that shows it, secrets masked before anything is stored. The extension is one Java jar. There is nothing else to install, no Python, no local server and no files to export.

## Use it

1. In Burp: **Extensions > Add > Java**, pick `burp2model.jar`.
2. In Proxy history or Site map, select requests, right-click, **Send to burp2model**.
3. Open the **burp2model** tab.

| Tab | What it shows |
| --- | --- |
| Overview | Counts, code vs runtime, the technology stack, the first leads to check |
| To check | Ranked leads, each with why it matters and the request behind it |
| Surface | Endpoints, pages, scripts, third parties, cookies, credentials and more, each with its evidence |
| Requests | Every captured request, with its masked request and response |
| Query | Plain questions and BQL filters, offline, every row citing evidence |
| Changes | Each send is a build; see what changed between any two |
| Roles | Send each account under its own role, then compare what they reached |
| Settings | Model name, role for the next send, scope, export, clear |

Sending the same request twice adds it once. Each send builds the model again from everything sent so far and keeps the build, so *Changes* and the `changed-since` query show what moved.

## Query

```
list-apis · reconcile · static-only · privileged · auth-surface · secrets · unknowns
req.method:POST AND resp.code.gte:400
node.type:endpoint AND node.state:STATIC_ONLY
reach "POST /api/checkout"        blast <node> depth 2        path <a> to <b>
provenance <node>        changed-since 1        reaches-privileged user
```

`help` in the Query tab lists everything.

## Where things are stored

Models are kept in `~/.burp2model/models/<name>/` and hold only masked requests and responses. The fingerprint key is in `~/.burp2model/key`. Nothing is sent anywhere.

## Build the jar

Java 17: `gradle jar` in this folder, or see the `extension` job in `.github/workflows/ci.yml` for the plain `javac` steps. The Java engine is checked against the Python one in `tests/test_java_parity.py`: the same model, query answers and diff on the bundled samples.

Requires Burp 2023.x or later (Montoya API). Only capture traffic you are allowed to test.
