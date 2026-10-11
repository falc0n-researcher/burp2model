# burp2model for Burp Suite

Right-click requests in Burp, choose **Send to burp2model**, and the model report opens. The jar carries its own engine, so there is nothing to install: no Python, no setup, no token.

## Use it

1. In Burp: **Extensions > Add > Java**, pick `burp2model.jar`.
2. In Proxy history or Site map, select requests, right-click, **Send to burp2model**.

The first send unpacks the engine to `~/.burp2model/engine/` and starts it. Models are written to `~/burp2model-out/<name>/` and the report opens in your browser. Each send is a build, so `burp2model diff burp` (with the same engine) shows what changed between sends.

The **burp2model** tab holds optional settings: model name (default `burp`), port, a role for comparing accounts, and an engine command if you want to use your own install instead of the bundled one.

## How it works

The extension sends the selected requests to a local `burp2model serve` and starts the bundled engine when it is not running. The receiver listens on `127.0.0.1` only, rejects other host names and any request without the extension's header (so a web page cannot drive it), and caps the body size. Nothing leaves your machine.

## Build the jar

`./build.sh` builds the engine for your platform with PyInstaller, puts it in the jar, and runs `gradle jar` (Java 17). The `extension` workflow builds one jar with the engine for macOS (Apple silicon and Intel), Linux and Windows. A jar built on one platform only runs on that platform.

Requires Burp 2023.x or later (Montoya API). Only capture traffic you are allowed to test.
