# Changelog: Burp extension

## 1.2.0 — 2026-10-17

A safer, faster and calmer extension: saved models survive crashes and damaged files, Burp never waits on the tab, live capture stays bounded, the map holds still, and a welcome page with a sample model gets you started.

### Fixes

- Live capture lost one request each time a batch filled up (500 requests in one tick).
- Requests captured live before the first build was recorded were lost when Burp restarted. They are now read back from the saved requests.
- Live capture no longer records a build when only duplicates arrived, and its every-40-requests trigger counts new requests rather than everything in the batch. A build is recorded from the model already built, without building it twice.
- After **Clear this model**, the model could not be opened again (the next Burp start or rename failed with a missing build file). Clearing now removes the build list too, and a model whose build file has gone missing opens with the builds before it.
- The dedupe list (`seen.txt`) was first written without a final newline, so the next batch's first key joined the previous last key on one line, and after a restart those two requests could be added again. New saves end with a newline, and lines already joined in existing models are split when read.
- While live capture was on, every refresh reset the Settings fields, wiping a role or scope you were typing.
- A large map (over 200 nodes) jumped whenever live capture added to it: the view re-fitted itself, the map blanked while the new layout ran, and nodes restarted from older positions. The current map now stays on screen until the new layout is ready (see the map under UI).
- Inside Burp, some text showed raw markup such as `<html>…</html>` (facts titles, connection links, the site map, the Copy for AI menu). Burp's theme does not always let labels render HTML, so these are now drawn with fonts and colours instead.
- Under Burp's theme the Settings form squeezed its fields to nothing and cut the labels short (see Settings below).
- Roles first compares the lower-sounding role against the higher one (user against admin, not admin against user).

### Data safety

- **Saved models survive crashes and damaged files.** Every file is written to a temporary file and moved into place. The appended requests file is read one gzip member at a time: if the last append was cut off, the complete requests are kept and the next save writes a clean file. An unreadable request line skips only that line. An unreadable `session.json` restarts the build history but keeps every saved request. Nothing is cleared because a file is damaged any more; damaged files are kept as `*.corrupt-<time>`, and what happened shows in the status bar and the extension output.
- **Clean unload.** Unloading waits for a save in progress instead of interrupting it, adds what live capture still holds, waits for sends and imports, and stops the parsing threads, the map's timers and the caches, so a reload no longer leaks the previous copy.
- A model folder is locked while Burp has it open; a second Burp opening the same model is told so instead of writing over it. The same model name always reuses its open model.
- Sending, importing and live capture read the Settings from a copy kept up to date as you type, instead of reading the Swing fields from a background thread; the build history can be read while requests are being added.
- Burp XML import turns on secure processing (entity expansion is capped) and never reads external entities or DTDs.
- The JSON reader rejects malformed or cut-off input with the position, and the writer keeps lone surrogates as escapes instead of saving them as `?`.
- **Live capture is bounded.** The queue holds at most 5,000 requests or 256 MB, and responses beyond what is scanned (10 MB) are cut before queueing. Requests that do not fit are counted and reported instead of silently dropped. Live capture keeps at most 10 requests of any one shape (method, host, path template, query names, status, role), so polling and cache-busters no longer grow the model without end; a manual send is never capped.

### Performance

- **Faster and lighter on large models.** Measured at 20,000 requests with ten live-capture builds (`ScaleBench`):

  | | 1.1.0 | 1.2.0 |
  |---|---|---|
  | live-capture tick | 275 ms | 130 ms |
  | recording a build | 675 ms | 113 ms |
  | diff between two builds | 5.2 s | 0.31 s |
  | heap after the run | 567 MB | 293 MB |
  | disk (builds) | 80 MB | 8 MB |
  | reopening the model | 1.0 s | 0.74 s |

  - A saved build no longer repeats every request and response; the saved requests already hold them, and diffs need only the nodes, edges and evidence ids. Older builds still open.
  - Only the last three builds read back for diffs are kept in memory.
  - Saving and loading stream the requests line by line instead of building one large string.
  - Path folding, the workflow grouping in diffs and the cleanup of removed endpoints no longer compare every path with every other.
  - Technology detection skips most signatures with a cheap text check before running their pattern over a page.
  - The content cache keeps the most recently used scans rather than stopping once full.
  - Burp XML import reads the export one item at a time instead of loading it as a document; checking a `.json` file for HAR reads only its first 4 KB.
- A later change made the live-capture tick about a fifth cheaper again (140 ms to 110 ms in its own run): a repeated secret no longer rebuilds its record, dropping not-found paths no longer rebuilds the whole edge index, and path folding keeps each request's folding key between rebuilds and splits paths without a regex.
- **Burp never waits on the tab.** The longest the Swing thread is busy, measured on a 20,000-request model (`EdtBench`):

  | | 1.1.0 | 1.2.0 |
  |---|---|---|
  | opening the model | 1.1 s | 8 ms |
  | a body regex query | 351 ms | 12 ms |
  | showing Changes | 108 ms | 3 ms |
  | showing the Map | 86 ms | 3 ms |

  - The tab is built on the Swing thread and the model opens in the background ("Opening the model…"); a send right after Burp starts waits for it.
  - Queries, comparing builds, Copy for AI, exporting the model or a summary, switching models and clearing all run in the background, with a progress indicator in the status line.
  - A query can be cancelled, and stops by itself after 20 seconds, so a regex that backtracks badly cannot hang Burp.
  - Maps over 200 nodes are laid out on a background thread while the current map stays on screen.
  - A large map draws only what is on screen and, while the camera moves or a node is dragged, leaves out dashes and labels (they come back when it stops). Moving the mouse over empty canvas no longer redraws it.
  - The map's Find and the Surface and Requests filters wait for a pause in typing instead of running on every keystroke.
  - The site map counts each folder once per model instead of on every row it paints, and a node's facts no longer scan every edge.
- While another Burp tab is in front, live capture no longer refreshes the burp2model tab; it catches up when shown. The map keeps its layout, selection and view when new requests add nothing to draw.

The model itself is unchanged by all of this: the same export gives byte-identical output, checked against the previous engine.

### UI

- **A welcome page.** The first time the tab opens, and whenever the open model is empty, it shows what burp2model does, three steps to a first model, and buttons that start one: try the sample model, import a HAR or Burp export, turn on live capture, or open Settings. It explains what stays on your machine. The **?** in the header and **About burp2model** in Settings open it any time; the first requests in an empty model take you to the tabs. Display type is IBM Plex Mono, bundled with the extension (SIL Open Font License); everything meant to be read at length stays in Burp's font. It follows Burp's light and dark themes, wraps to one column in a narrow pane, and every button works from the keyboard.
- **The sample model is the default.** With no model chosen, the extension opens the sample model, already filled with a small demo shop seen as a user and as an admin. The old empty "burp" default is gone: an empty "burp" model left by an earlier version gives way to the sample and is not created again (a "burp" model with requests in it is kept).
- **The header** shows the open model as a switcher (every model saved on this machine that has something in it, plus New model…), a **Live** button that turns live capture on and off and shows which, and a ⋯ menu for import, export, Delete this model… and Settings. The count pills, which repeated the Overview, are gone, and so is the "Search" label (the box says what it is). Role, scope, replace and live capture are kept as soon as they change; only a new model name needs Save.
- **Settings** is laid out as cards (Model, Next send, Live capture, Data, About) whose fields keep their width.
- **Delete this model…** in ⋯ and in Settings removes a model and everything in it (after asking) and opens the sample.
- **The map holds still.** Each layout is computed to the end and shown once instead of animating; nodes already on the map keep their exact place and new ones settle among them, so live capture only ever adds. The camera moves only when you ask (Fit, a new layout, the first map). Re-layout starts over. Roles, cookies and credentials ("Trust") are off at first, because each links to most of the map and turned it into a ball of lines; the layout is roomier, and a map of 80 nodes or fewer labels everything that fits. The Network and Flow toggles always show the layout drawn, the rings around code-only endpoints are lighter, and labels stay at least 10 px however far out you zoom.
- **Overview** reflows: six tiles in a row when there is room, then three or two, and the charts stack in a narrow pane; long lines are cut short instead of scrolling sideways. The technology stack uses two columns when wide. A lead row opens on click or Enter and lights up under the pointer (the separate Open buttons are gone), and "any" replaces "*" for any method. The empty Overview links to the welcome page.
- The Query tab starts with a short guide instead of an empty table. The status line marks errors in red, and "Comparing builds…" and similar messages give way to the model summary as soon as the work ends.
- **Keyboard.** Every button can be reached with Tab. While focus is in the tab: Cmd/Ctrl+1–9 and 0 switch tabs, Cmd/Ctrl+F searches, Cmd/Ctrl+L goes to the query box, Cmd/Ctrl+Shift+C copies the whole model for AI, Alt+Left goes back after a jump, and `/` on the map jumps to Find. None of these are taken from the rest of Burp.
- **Readable in both themes, at any font size.** Text sizes, row heights and tiles follow Burp's font setting instead of fixed pixels. Coloured text (badges, links, the live indicator, errors) is shaded until it reaches 4.5:1 against its background. Borders and muted text follow a switch between Burp's light and dark themes without reloading.

### Under the hood

- Each tab is its own class behind a small `Tab` interface (the panel no longer switches tabs by number), the map's layout is its own class, and live capture's flush logic is separate from Burp and unit tested.
- Unit tests for the extension (`gradle test`, JUnit 5, test-only: the jar still has no dependencies), run in CI.

## 1.1.0 — 2026-10-16

- **Import HAR or Burp export** in Settings: add the requests from a HAR file (browser DevTools, Hetty, mitmproxy, ZAP) or a Burp "Save items" XML to the model.
- Redaction matches the command line tool's new coverage (multipart parts, XML elements, quoted assignments in code and config, YAML, JSON arrays and encoded JSON, `cookie` / `credential` / `bearer` values), checked against it in `tests/test_java_parity.py`.
- Analytics and telemetry calls are not shown as leads.

## 1.0.0 — 2026-10-12

First release of the burp2model Burp Suite extension: burp2model's model builder, entirely in Java, inside Burp. One jar; no Python, no local server, no files.

- Right-click requests, **Send to burp2model**, and the model builds in the burp2model tab. Or turn on live capture for in-scope Proxy traffic.
- Overview dashboard, ranked leads and open questions, a stable zoomable map (network and flow layouts), the surface as a list or site map, every request with its masked request and response, a query console (plain questions and BQL, offline), what changed between builds, role comparison, light recon, Copy for AI, JSON and Markdown export.
- Follows Burp's light and dark themes.
- Fast on large sessions: 20,000 requests build in about four seconds in under 400 MB.
- The Java engine matches the Python one: same model, same query answers, same diff (`tests/test_java_parity.py`).
