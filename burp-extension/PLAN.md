# Burp extension: working plan (v1.2 cycle)

Drafted 2026-10-16 from a read-only review of `burp-extension/src` (extension 1.1.0). File references are `path:line` under `src/main/java/burp2model/` as of commit `e682211`.

## Goals

1. **Trustworthy.** No lost requests, no silently wiped models, no corruption on crash or unload.
2. **Never freeze Burp.** Nothing heavy runs on the Swing thread, and every long action shows progress.
3. **Scales with live capture.** Disk and memory stay bounded over a long session.
4. **A first-run experience.** A styled landing page (pixel-font hero) that explains burp2model and gets the user to a first model in one click.
5. **Code that is easy to change.** Split the two 1,200-line classes, share widgets and a type scale, and add a real Java test suite.

## Where things stand

- **Engine.** Every add, including each 5s live tick, rebuilds the model from scratch (`engine/Session.java:202-237`). That costs about 170 ms at 20k requests: fine today, but it grows linearly. Parsing dominates a fresh import (`Stack.bodyHits`, `Redact.sub`).
- **Persistence** lives under `~/.burp2model/models/<name>/`:
  - `inputs.jsonl.gz` and `seen.txt` are appended.
  - `builds/<id>.json.gz` holds the full model with every evidence pane: 18 MB per build at 20k requests.
  - `session.json` holds scope, the build list and node history.
- **UI.**
  - There are 10 top tabs, built up front. Their data is filled lazily.
  - Navigation works by hard-coded tab index.
  - A lot of heavy work runs on the EDT: queries, diff, Copy for AI, export, map layout and leads analysis.
  - Fonts use absolute sizes, which ignores Burp's font-size setting.
  - Nothing remembers whether the user has seen a welcome screen, and the empty state has no actions.
- **Tests.**
  - The Python parity tests (`tests/test_java_parity.py`) check that the Java engine matches the Python one.
  - Java has only `main()` programs: Smoke, MapStability and two benches.
  - There is no JUnit, and no `gradle test`.

## Phases

Each phase is a separate PR that leaves `main` releasable. Effort: S under half a day, M one or two days, L three or more days.

### Phase 0: Bug fixes (patch release 1.1.1)

These are confirmed defects. They are small, so ship them first.

| # | Fix | Where | Effort |
|---|-----|-------|--------|
| 0.1 | The live drain loses one request every time a batch hits 500 (it polls before checking the size). Check the size first. | `Burp2ModelExtension.java:169` | S |
| 0.2 | "Clear this model" leaves `session.json` pointing at deleted builds, so the model can never be reopened (`NoSuchFileException`). Delete or rewrite `session.json` in `clear()`, and let `load()` tolerate missing build files. | `engine/Session.java:182-200` | S |
| 0.3 | Every refresh (every 5s during live capture) resets the Settings fields from stored prefs, wiping half-typed edits. Load the fields once and on Save. | `ui/MainPanel.java:242-251` | S |
| 0.4 | Background threads read Swing fields (`scope()`, `role()`, `replaceRoleOnSend()`). Keep a volatile settings snapshot that is updated on Save. | `MainPanel.java:212-229`, `Burp2ModelExtension.java:172-174` | S |
| 0.5 | `Session.builds()` returns the live list while the flusher appends to it, a ConcurrentModificationException risk. Return `List.copyOf`, make `model` volatile, and guard `cache`. | `Session.java:36, 53, 241-263` | S |
| 0.6 | Snapshots with nothing new still rebuild and write a full build. Skip them, and base the snapshot trigger on the added count, not the batch size. | `Session.java:144-149`, `Burp2ModelExtension.java:173` | S |
| 0.7 | Delete dead code: the `unused()` stubs, `Dashboard.onSend`, `GraphPanel.hiddenTypes` and `showNode` (unless Phase 3 wires `showNode` up). | several | S |

**Done when:** each fix has a regression test (Phase 0 adds the JUnit scaffold, see 5.1), the parity tests pass, and the 1.1.1 changelog entry is written.

### Phase 1: Data safety and lifecycle

| # | Change | Where | Effort |
|---|--------|-------|--------|
| 1.1 | **Atomic writes.** Write to a temp file and `ATOMIC_MOVE` it into place for `session.json` and builds. Read gzip members tolerantly, keeping the complete members and dropping a torn tail. Write `seen.txt` after inputs, or derive it from inputs. | `Session.java:268-292, 315, 368-372` | M |
| 1.2 | **Never auto-wipe on a load error.** Today one bad line clears the in-memory state, and the next save overwrites good data. Instead, load what parses, rename the bad file to `.corrupt-<ts>`, tell the user, and block overwrites until they confirm. | `Session.java:358-365` | M |
| 1.3 | **Harden the JSON code.** Validate `:` and `,`, throw a typed error with the offset, escape lone surrogates, and add round-trip tests. | `engine/Json.java:112-131, 192-226` | S |
| 1.4 | **Clean unload.** Run `shutdown()`, `awaitTermination`, then a final `flushLive`. Shut down `Session.pool` (today it pins the classloader, so memory leaks on every reload). Stop the GraphPanel timers, call `Parse.clearCache()`, and run all worker threads through one tracked executor. | `Burp2ModelExtension.java:103`, `Session.java:153-174`, `GraphPanel.java:191-192` | M |
| 1.5 | **One Session per directory.** Use `ConcurrentHashMap.computeIfAbsent` plus a lock file per model directory. | `Burp2ModelExtension.java:84-91` | S |
| 1.6 | **Secure XML parsing.** Turn on `FEATURE_SECURE_PROCESSING` for Burp XML import, and keep external entities off. | `engine/BurpXml.java:84-90` | S |

**Done when:** a test kill-switch can truncate any file mid-write and the model still reopens with no data lost except the torn tail, and a reload loop of 10 unload/load cycles shows flat heap.

### Phase 2: Performance and scale

| # | Change | Where | Effort |
|---|--------|-------|--------|
| 2.1 | **Slim builds.** Store nodes, edges, unknowns and stats, with evidence as ids into the inputs (diff and history need nothing more). Make `cache` an LRU of 2-3 models. This turns quadratic disk growth into linear. | `Session.java:33, 226, 246, 295` | M |
| 2.2 | **Stream on save and load.** Add `Json.write(Appendable)` and write into a gzip stream (today an 88 MB String is built, then copied). Read inputs line by line with a BufferedReader over gzip. | `Session.java:274-295, 338, 369` | S |
| 2.3 | **Byte budget for the live queue.** Add an `AtomicLong` byte cap, truncate bodies to `Extract.MAX_SCAN_BYTES`, count dropped items and show the count. Replace the O(n) `live.size()`. | `Burp2ModelExtension.java:149-152` | S |
| 2.4 | **Live dedupe by shape.** Dedupe on (method, host, template, param names, status, body hash) instead of raw bytes, optionally keeping at most K samples per endpoint. | `Session.java:71-90` | M |
| 2.5 | **Cheaper live ticks (short term).** Coalesce ticks, and skip the UI refresh when the tab isn't showing. Don't relayout the map when its node and edge sets are unchanged. | `MainPanel.java:242`, `GraphPanel.java:236-310` | S |
| 2.6 | **Hot-loop fixes:** | | S |
| | - a literal prefilter for the `Stack` body signatures | `Stack.java:84-89` | |
| | - make `SCANS` a size-bounded LRU that holds only the derived fields | `Parse.java:427-446` | |
| | - `HexFormat` instead of a `String.format` call per byte | `Session.java:83`, `Parse.java:418`, `Redact.java:154` | |
| | - precompile the regexes | `Diff.java:36`, `Query.java:384` | |
| | - index the role keys | `Session.java:103` | |
| 2.7 | **Remove `collapseSiblings` O(n²).** Index `cur` by (host, prefix) at each depth. | `Builder.java:208-249` | M |
| 2.8 | **Stream big imports.** Use StAX for Burp XML and a streamed HAR reader. Sniff HAR files from the first 4 KB only. | `BurpXml.java`, `Har.java:149-160` | M |
| 2.9 | *(Stretch)* **Incremental builder.** Split `Builder.build` into passes, accumulate pass 1 incrementally, and re-run only folding, reconcile and unknowns. | `Builder.java:349` | L |

**Done when:**
- `Bench` gets a 20k-request scenario.
- A live tick takes at most 60 ms at 20k requests.
- Snapshot peak heap is at most 1.5x the model size.
- Disk use for a simulated 3-hour live session is under 300 MB.
- The model is byte-identical to before (parity tests).

### Phase 3: Responsive UI

| # | Change | Where | Effort |
|---|--------|-------|--------|
| 3.1 | **Build the UI on the EDT.** Build MainPanel inside `invokeAndWait`, and load the session on a worker with a "Loading model…" state. | `Burp2ModelExtension.java:68-97`, `MainPanel.java:141-182` | S |
| 3.2 | **`Async` helper.** Add a SwingWorker wrapper plus a busy state, and move every heavy call onto it: `Analysis.leads/gaps`, query, diff, Copy for AI, export, opening a model on rename, and clear. | `MainPanel.java:244, 362, 470, 785-856, 917-938, 1166, 1185-1213` | M |
| 3.3 | **Query safety.** Add a timeout through an interruptible `CharSequence` wrapper so a catastrophic regex can't hang Burp, and a Cancel button. | `MainPanel.java:785-856`, `Query.java` | S |
| 3.4 | **Map layout off the EDT.** Run force and flow layout on a worker against a copy of the positions, then swap the result in. | `GraphPanel.java:297-300, 382-438` | M |
| 3.5 | **Map repaint cost:** | `GraphPanel.java:777-785, 965-1117` | M |
| | - cache strokes, lowercase labels and edge paths | | |
| | - cull everything outside the view | | |
| | - render the minimap as an image | | |
| | - repaint on hover changes only | | |
| | - turn antialiasing off while panning above about 800 nodes | | |
| 3.6 | **Debounce input.** Map Find waits about 200 ms and selects on Enter. Table filters wait about 150 ms. | `GraphPanel.java:163-176`, `MainPanel.java:516, 613` | S |
| 3.7 | **Linear lookups.** Precompute SiteTree counts and use a HashMap of children. Build the Facts adjacency index once per model. | `SiteTree.java:53, 76-143`, `Facts.java:126-141` | S |
| 3.8 | **Progress everywhere.** Show an indeterminate indicator in the header and status bar during send, import and recon, and give import a Cancel button. The status bar gets levels (info, ok, error) with a coloured dot and reverts automatically. | `MainPanel.java:208-210, 1085, 1236` | M |

**Done when:** a 20k-request model never blocks the EDT for more than 100 ms (checked with a small EDT watchdog in debug builds), and the map pans at 60 fps with 2k nodes.

### Phase 4: Landing page and visual polish

#### 4A. Landing page (the feature request)

**When it shows**
- The first time the tab opens, tracked by the preference `welcome.seen` through `Host.get/set`, which is backed by `api.persistence().preferences()`.
- Whenever no model has requests.
- On demand, from a new `?` button in the header and an "About burp2model" link in Settings.

**How it is wired**
- MainPanel's centre becomes a `CardLayout` with two cards, `welcome` and `tabs`.
- It is **not** a new tab 0, which would shift every hard-coded index. Phase 5.2 removes the indices anyway.
- Dismiss it with "Get started", or automatically after the first successful send or import.

**Layout** (centred column, max width about 880 px, scrolls on small panes):

```
┌──────────────────────────────────────────────────────────────┐
│  ▄▄ BURP2MODEL ▄▄            (pixel font, 32px, accent)      │
│  Turn Burp traffic into an evidence-backed model of the app. │
│  v1.2.0 · offline · secrets masked before storage            │
│                                                              │
│  [ 1 ] SEND        [ 2 ] EXPLORE        [ 3 ] ASK            │
│  Right-click →     Leads, map,          BQL queries or       │
│  Send to           surface, every       Copy for AI into     │
│  burp2model        request masked       your own model       │
│                                                              │
│  ( Import HAR / Burp XML )  ( Turn on live capture )         │
│  ( Try the sample model )   ( Open settings )                │
│                                                              │
│  ── What stays private ──────────────────────────────────    │
│  Models live in ~/.burp2model. Nothing leaves Burp except    │
│  Recon (on demand) and what you paste into your own AI.      │
│                                                              │
│  [x] Show this on start              Get started  ▶          │
└──────────────────────────────────────────────────────────────┘
```

**Design rules**
- **Pixel font for display text only:** the hero title, the step numbers and the section labels. The tagline, body text, tables and HTTP stay in Burp's UI and editor fonts for readability.
- **Font choice:**
  - Hero: **Silkscreen** (or Press Start 2P).
  - Labels: **Pixelify Sans**, or a pixel mono such as **Departure Mono**.
  - All are SIL OFL. Bundle the TTF and `OFL.txt` under `src/main/resources/fonts/`, about 50-150 KB in total.
- **Crisp rendering:**
  - Derive sizes only at whole multiples of the design size (8/16/24/32 px, times the Burp UI scale).
  - Draw with `KEY_TEXT_ANTIALIASING=OFF` and `KEY_FRACTIONALMETRICS=OFF` through a new `Theme.pixelHints(g)`.
  - Check `Font.canDisplayUpTo`, because most pixel fonts lack →, ·, …, ▾ and ●. Fall back per string.
- **Theme-aware.**
  - Colours come from `Theme` tokens. The accent bar and hero colour follow the existing orange accent.
  - Dark mode gets a subtle 1px dither or scanline background tile, drawn in code.
  - Light mode gets a flat surface.
- **Pixel motifs drawn in Swing:** a blocky 2px border on the step cards, an 8-bit style arrow, and a small pixel logo mark (a 16×16 icon as an int-array bitmap, scaled by nearest neighbour). No image assets are needed beyond the font.
- **Working buttons:**
  - Import and live capture call the existing Settings actions.
  - "Try the sample model" loads a small bundled sample into a `sample` model, so a new user sees a full UI in one click. This needs a tiny embedded sample, about 30 KB, under resources.
- **Accessible.**
  - Every button can be focused, has a mnemonic and works with Enter.
  - Text contrast is at least 4.5:1 in both themes.
  - It respects Burp's font size.

**Code**
- `ui/Welcome.java` (new, about 250 lines).
- `Theme.pixel(float)` and `Theme.pixelHints(Graphics2D)`.
- `ui/PixelArt.java` for the logo bitmap and borders.
- Resource fonts.
- A `welcome.seen` preference.

**Done when:**
- It shows on a fresh install, never shows again after dismissal unless reopened, and every button works.
- It renders crisply at 1x and 2x and in light and dark themes.
- The README gets a screenshot.

#### 4B. Visual polish

| # | Change | Where | Effort |
|---|--------|-------|--------|
| 4.1 | **Type and spacing scale.** Add `Theme.H1/H2/BODY/SMALL/MONO` and `GAP_S/M/L`, sized relative to Burp's display and editor fonts (`api.userInterface().currentDisplayFont()`). Replace the scattered absolute sizes and fixed row heights. | `Theme.java:73-80`, `Tables.java:57-65`, `Widgets`, `Dashboard` | M |
| 4.2 | **Live theme switching.** Resolve borders and colours at paint time (a `Theme.lineBorder()` class) or re-apply them in `updateUI()`, so a theme switch in Burp leaves no stale colours. | `MainPanel.java:165, 319, 327, 412, 660`, `Facts`, `HttpPane`, `SiteTree` | S |
| 4.3 | **Contrast.** Badge text uses `fg()` with a coloured dot or edge. Add `Theme.accentText(c)`, darkened in light mode. | `Renderers.java:57-60`, `Facts.java:245` | S |
| 4.4 | **Overview.** Make the tile grid responsive (WrapLayout). Show "any" instead of `*`. Replace the duplicate Open buttons with row hover. Shorten paths in the status line, with the full path as a tooltip. Use the Technology stack card's width. Turn the empty state into a compact action card (the same actions as the landing page). | `Dashboard.java:78, 245-267, 311-339` | M |
| 4.5 | **Map visuals:** | `GraphPanel.java:422-436, 577, 981-1026` | M |
| | - lighter "code only" rings | | |
| | - edge labels go through the collision placer | | |
| | - a minimum label size on screen | | |
| | - fit padding sized to the widest label | | |
| | - fix the Network/Flow toggle staying out of sync | | |
| 4.6 | **Header:** | `MainPanel.java:301-377, 1106-1223` | M |
| | - a model switcher (a combo box over the existing model directories) | | |
| | - a live-capture on/off indicator instead of count pills that repeat the Overview | | |
| | - an overflow menu (⋯) for Import and Export | | |
| | - Settings auto-save on focus loss | | |
| 4.7 | **Keyboard and accessibility:** | `MainPanel`, `GraphPanel`, `HttpPane`, `Dashboard` | S |
| | - remove `setFocusable(false)` from the buttons | | |
| | - Cmd/Ctrl+1..9 for tabs, Ctrl+F for search, Ctrl+L for the query field, Ctrl+Shift+C for Copy for AI, `/` for Map Find, Alt+← to go back | | |

### Phase 5: Code structure and tests

These run alongside the other phases. Do 5.1 first, because it underpins every "done when" above.

| # | Change | Effort |
|---|--------|--------|
| 5.1 | **JUnit 5.** Add it to `build.gradle.kts` (test scope only, so the jar stays dependency-free). Port `Smoke` into tests. Add cases for clear then reopen, corrupt and truncated files, role replacement, `flushLive` batching, the snapshot trigger, concurrent add plus reads, the JSON round trip and `collapseSiblings`. Run `gradle test` in the CI `extension` job. | M |
| 5.2 | **`Tab` interface and `select(Tab)`.** It has `title()`, `view()` and `fill(model, session)`, and replaces the magic indices. A small back history comes with it. | M |
| 5.3 | **Split MainPanel (1,301 lines)** into `Header`, `Nav` (goToNode, say, ask, session) and one class per tab (`LeadsTab`, `MapTab`, `SurfaceTab`, `RequestsTab`, `QueryTab`, `ChangesTab`, `RolesTab`, `ReconTab`, `SettingsTab`). MainPanel ends up as about 150 lines of wiring. | L |
| 5.4 | **Split GraphPanel (1,186 lines)** into `GraphData`, `ForceLayout`, `FlowLayout`, `Viewport`, `GraphCanvas`/`GraphPainter` and `GraphToolbar`. Do this before 3.4 and 3.5 so the perf work lands in small files. | L |
| 5.5 | **Pull `LiveCapture` out of the entry point,** with an injectable clock and queue, so it can be unit tested. | S |
| 5.6 | **Shared helpers:** `Layouts.split`, `Widgets.smallButton`, `Files.saveAsync`, `Theme.canvas()` and one `hex()`. Cache fonts and borders in the renderers. Remove the duplicated parts of `BurpXml` and of the raw building in the entry point. | S |
| 5.7 | **Split the large engine methods:** `Builder.build` (about 340 lines) into passes, plus `Parse.item`, `ContextPack.pack`, `Diff.diff` and `Query.termPred`. Pure refactors, guarded by the parity tests. | M |

## Suggested order and releases

| Release | Contents |
|---------|----------|
| **1.1.1** | Phase 0 and 5.1 (the test scaffold). |
| **1.2.0** | Phase 1, then 5.2 and the 4A landing page (it needs only the CardLayout and preferences, so it can land early), and 3.1-3.3 and 3.8. |
| **1.3.0** | Phase 2, then 5.4, 3.4-3.7 and 4B. |
| **Ongoing** | 5.3, 5.6 and 5.7, done opportunistically while touching each area. |

Parallel tracks that don't touch the same files:
- **Track A, engine:** `engine/*` and the entry point (Phases 0-2, 5.5, 5.7).
- **Track B, landing page:** `ui/Welcome.java`, `Theme` additions and resources (4A).
- **Track C, map:** `GraphPanel` split and perf (5.4, 3.4-3.6, 4.5).

## Open decisions

1. **Pixel font pairing.** Silkscreen hero with Pixelify Sans labels (my pick: friendly and legible), Press Start 2P (more arcade, heavier), or a pixel mono throughout (more terminal-like).
2. **Bundled sample model.** Embedding about 30 KB of a redacted Juice Shop sample makes "Try the sample" possible but adds jar weight and maintenance.
3. **Slim builds (2.1)** change the on-disk format. Old builds should be read and migrated on open. Decide whether to support downgrade, which I'd say isn't needed.
4. **Montoya message editor (UI item 33).** Using Burp's own read-only HTTP editor would replace `HttpPane`, but the masked bodies must stay masked. Spike before committing to it.
