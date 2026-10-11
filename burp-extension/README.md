# burp2model for Burp Suite

Right-click requests in Burp, choose **Send to burp2model**, and the model report opens. The extension starts burp2model itself, so there is nothing to run first and nothing to configure.

## Use it

1. Install the engine once: `pip install burp2model`.
2. Build the extension (Java 17): `cd burp-extension && gradle jar` (writes `build/libs/burp2model.jar`).
3. In Burp: **Extensions > Add > Java**, pick the jar.
4. In Proxy history or Site map, select requests, right-click, **Send to burp2model**.

Each send is a build named by time, so `burp2model diff burp` shows what changed between sends. The **burp2model** tab holds optional settings: model name, port, the command to run (give the full path if Burp cannot find `burp2model`), and a role for comparing accounts.

## How it works

The extension sends the selected requests to a local `burp2model serve` and starts it if it is not running; the Python engine does all the modeling. The receiver listens on `127.0.0.1` only, rejects other host names and any request without the extension's header (so a web page cannot drive it), and caps the body size. Nothing leaves your machine.

Requires Burp 2023.x or later (Montoya API). Only capture traffic you are allowed to test.
