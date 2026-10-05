# 90-second demo clip — script

The clip that carries the talk and travels afterward. One terminal, one browser,
no cuts needed. Everything below runs against a **real** local OWASP Juice Shop,
so nothing on screen is staged.

## Setup (before you record)

```bash
# a real, local, intentionally-vulnerable target
docker run -d -p 3000:3000 bkimminich/juice-shop

# browse it through Burp Community, Save history -> juice-shop.xml
# (or reuse the capture that produced docs/examples/juiceshop/)
pip install burp2model
```

Terminal: large font, minimal prompt. Record with asciinema, or screen-record
the terminal + browser side by side.

---

## The 90 seconds

**0:00 — the hook (title card or voiceover)**
> "Every AI recon demo answers *more data*. Wrong axis. Watch what happens when
> you give the model something to reason about instead."

**0:06 — build the model** *(type it live)*
```bash
for r in anon user accountant admin; do burp2model samples/juiceshop-$r.xml -w juiceshop --role $r; done
```
On screen:
```
routes 22 · APIs 105 (48 both, 42 runtime-only, 15 static-only) · edges 725 · nodes 222
123 named unknowns
```
> "A hundred and five endpoints — and fifteen of them the tool found inside main.js
> that even a deep session never called."

**0:22 — turn the AI OFF, ask a fact** *(the memorable moment)*
```bash
burp2model query juiceshop "endpoint /rest/basket/{id}/checkout"
```
On screen (ends with):
```
Source: Knowledge Graph
Model call: none
```
> *(pause on `Model call: none`)* "I turned the AI off. The model still answered,
> and cited the request that proves it. Nothing to hallucinate."

**0:38 — the redaction beat** *(open the report in the browser)*
- Open `burp2model-out/juiceshop/report.html`, go to **Evidence**, open the login.
- Ctrl-F the token prefix `eyJ` → highlight `[REDACTED]`. Then open **Query (BQL)**:
  `resp.body.cont:"eyJ"` returns 0 matches (no JWT survives), while
  `req.body.cont:"password"` lists the logins with `"password":"[REDACTED]"` — names kept, values gone.
> "That login returned a real JWT. It never hit disk — masked before the model
> ever saw it. Safety isn't traded for signal."

**0:52 — the payoff: a methodology, not a checklist**
```bash
burp2model methodology juiceshop --prompt | pbcopy
```
Paste into any chat model on screen. It returns a plan that:
- sequences recon first, then the 40 code-only paths,
- names `/rest/admin` and `/api/Challenges/{param}` by hand,
- cites `ev_N` on every line.
> "Same capture. But now the AI reasons over a model — target-specific, cited,
> sequenced. Not the OWASP list every target gets."

**1:15 — the contrast card** *(cut to `before-after.png`)*
> "Left: paste raw traffic, get invented endpoints. Right: a model it can walk."

**1:22 — close (title card, verbatim from the deck)**
> "Don't ask where's the bug. Ask: what do I understand, what don't I, and where
> should I look next."

---

## Captions for the social post

> Turned the AI off. The recon model still answered — and cited the request.
> That's the difference between a model and a prompt.
>
> burp2model: your Burp history is already a target model. Built it from a real
> four-role Juice Shop session — 105 endpoints, 15 hidden in main.js, every JWT and password masked.

Pin `before-after.png` as the post image. Link the live report:
`docs/examples/juiceshop/report.html` (via GitHub Pages).

## Teardown
```bash
docker rm -f $(docker ps -q --filter ancestor=bkimminich/juice-shop)
```
