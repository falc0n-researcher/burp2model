# burp2model for Burp Suite

Right-click requests in Burp, choose **Send to burp2model**, and the model report opens. This is a thin bridge: the extension sends the selected requests to a local `burp2model serve`, and the Python engine does all the modeling.

## Use it

1. Start the receiver and note the token it prints:

   ```bash
   burp2model serve -w myapp
   ```

2. Build the extension (Java 17):

   ```bash
   cd burp-extension && gradle jar        # writes build/libs/burp2model.jar
   ```

3. In Burp: **Extensions > Add > Java**, pick the jar. Open the **burp2model** tab, paste the token, **Save**.
4. In Proxy history or Site map, select requests, right-click, **Send to burp2model**.

Each send is a build named by time, so `burp2model diff myapp` shows what changed between sends. Set a role in the tab to merge selections from different accounts.

## Safe by default

The receiver listens on `127.0.0.1` only, needs the token on every request, rejects other host names, and caps the body size. Nothing leaves your machine.

Requires Burp 2023.x or later (Montoya API) and the same authorization as any other use of burp2model: only capture traffic you are allowed to test.
