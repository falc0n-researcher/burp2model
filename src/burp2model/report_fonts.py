"""Fonts and type for the offline report.

The three typefaces are embedded as base64 so the single-file report looks the same with no
network. The CSP allows `font-src data:` and nothing else.
"""

from __future__ import annotations

import base64
import functools
import os

_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "fonts")
_FACES = [("Inter", "inter-latin-wght-normal.woff2"),
          ("Space Grotesk", "space-grotesk-latin-wght-normal.woff2"),
          ("JetBrains Mono", "jetbrains-mono-latin-wght-normal.woff2")]


@functools.lru_cache(maxsize=1)
def font_css() -> str:
    """@font-face rules with the files inlined; empty if the files are missing (system fonts then)."""
    out = []
    for family, fn in _FACES:
        try:
            with open(os.path.join(_DIR, fn), "rb") as f:
                b64 = base64.b64encode(f.read()).decode("ascii")
        except OSError:
            return ""
        out.append(f'@font-face{{font-family:"{family}";font-style:normal;font-weight:100 900;font-display:swap;'
                   f'src:url(data:font/woff2;base64,{b64}) format("woff2")}}')
    return "\n".join(out)


# headings and numerals use the display face; everything else keeps the body and mono faces
TYPE_CSS = r"""
:root{--sans:"Inter",-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;
--mono:"JetBrains Mono",ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;
--display:"Space Grotesk","Inter",-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}
body{font-feature-settings:"cv11","ss01","tnum" 0;letter-spacing:-.003em}
h1.vt,.ovh h1,.inv-bar h1,.mtop h1{font-family:var(--display);font-weight:700;letter-spacing:-.035em}
h1.vt{font-size:28px}
.big4 .n,.dk .n,.ls .n{font-variant-numeric:tabular-nums;letter-spacing:-.04em}
.sech h2,.dc>.h,.tile b,.card>.hd,.nlabel,.ahd,.lead .w{font-family:var(--display);font-weight:600;letter-spacing:-.015em}
.sech h2{font-size:17px}
.dc>.h,.card>.hd{font-size:14px}
.vsub,.ovh .sum{font-size:15.5px;line-height:1.6}
.kicker,nav.views h3,.minsp h3,.dnote{font-family:var(--mono)}
"""
