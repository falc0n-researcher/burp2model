"""
The viral surface: turn a build into an animation people share.

Two outputs, no runtime dependencies:

  render_terminal(model)  -> prints a typed, colored build sequence to the
                             terminal (the `--animate` flag). Looks like a
                             live demo even when it's deterministic.

  render_svg(model)       -> a single self-contained animated SVG string that
                             loops in a GitHub README with no JS and no CDN.
                             This is the thing that gets screenshotted.
"""

from __future__ import annotations

import sys
import time

from .model import Model

# brand
ORANGE = "\033[38;5;208m"
CYAN = "\033[38;5;39m"
VIOLET = "\033[38;5;99m"
DIM = "\033[38;5;244m"
WHITE = "\033[97m"
BOLD = "\033[1m"
RESET = "\033[0m"


def _type(text: str, delay: float = 0.012, color: str = WHITE, nl: bool = True):
    for ch in text:
        sys.stdout.write(color + ch + RESET)
        sys.stdout.flush()
        time.sleep(delay)
    if nl:
        sys.stdout.write("\n")


def render_terminal(m: Model, fast: bool = False) -> None:
    d = 0.0 if fast else 0.012
    c = m.counts()
    print()
    _type("$ burp2model <burp-export>.xml --webapp " + m.name, d, ORANGE)
    time.sleep(0.15 if not fast else 0)
    for stage, note in [
        ("parsing burp export", "streaming items, base64-decoding"),
        ("redacting values", "tokens, cookies, keys, PII → fingerprints"),
        ("typing assets", "routes · scripts · endpoints · params"),
        ("relating nodes", "OBSERVED vs INFERRED edges"),
        ("reconciling", "code references vs runtime traffic"),
        ("naming unknowns", "what the capture could not answer"),
    ]:
        _type(f"  {DIM}▸{RESET} {stage:<20}{DIM}{note}{RESET}", d, WHITE, nl=True)
        time.sleep(0.08 if not fast else 0)
    print()
    # the payoff line
    static = c["api_state"].get("STATIC_ONLY", 0)
    both = c["api_state"].get("BOTH", 0)
    runtime = c["api_state"].get("RUNTIME_ONLY", 0)
    _type(f"{BOLD}  routes {c['routes']} · APIs {c['endpoints']} "
          f"({both} both, {runtime} runtime-only, {static} static-only)"
          f" · edges {c['edges']} · nodes {c['nodes']}{RESET}", d, CYAN)
    _type(f"  {VIOLET}{c['unknowns']} named unknowns{RESET}   "
          f"{DIM}absence = a gap in observation, never in the target{RESET}", d, WHITE)
    print()
    _type("  a model your AI can reason over — not a dump it hallucinates on", d, ORANGE)
    print()


# ---------------------------------------------------------------- SVG --------

def render_svg(m: Model) -> str:
    c = m.counts()
    both = c["api_state"].get("BOTH", 0)
    runtime = c["api_state"].get("RUNTIME_ONLY", 0)
    static = c["api_state"].get("STATIC_ONLY", 0)

    # the six build stages, revealed one at a time
    stages = [
        ("parse", "streaming the burp export"),
        ("redact", "values masked before any write"),
        ("type", "routes · scripts · endpoints"),
        ("relate", "observed vs inferred edges"),
        ("reconcile", "code vs runtime"),
        ("model", "an evidence-backed graph"),
    ]
    W, H = 760, 480
    line_h = 30
    base_y = 150
    dur_each = 0.9  # seconds per line reveal

    parts = [
        f'<svg viewBox="0 0 {W} {H}" xmlns="http://www.w3.org/2000/svg" '
        f'font-family="ui-monospace,SFMono-Regular,Menlo,monospace" role="img" '
        f'aria-label="burp2model turning a Burp history into a web-app model">',
        f'<rect width="{W}" height="{H}" rx="14" fill="#0d1117"/>',
        # window chrome
        '<circle cx="24" cy="26" r="6" fill="#ff5f56"/>',
        '<circle cx="46" cy="26" r="6" fill="#ffbd2e"/>',
        '<circle cx="68" cy="26" r="6" fill="#27c93f"/>',
        f'<text x="{W/2}" y="30" fill="#8b98a8" font-size="12" text-anchor="middle">burp2model</text>',
        # prompt line (typed via width mask)
        '<text x="28" y="78" fill="#e85002" font-size="15" font-weight="700">'
        '$ burp2model burp_history.xml</text>',
        f'<rect x="28" y="66" width="0" height="18" fill="#0d1117">'
        f'<animate attributeName="width" from="360" to="0" dur="1s" fill="freeze"/></rect>',
        f'<text x="392" y="78" fill="#3a424e" font-size="15">'
        f'<animate attributeName="opacity" values="1;0;1" dur="0.8s" repeatCount="indefinite"/>▋</text>',
    ]

    # stage lines, each fades in in sequence
    for i, (stage, note) in enumerate(stages):
        y = base_y + i * line_h
        begin = 1.0 + i * dur_each
        parts.append(
            f'<g opacity="0"><animate attributeName="opacity" from="0" to="1" '
            f'dur="0.35s" begin="{begin:.2f}s" fill="freeze"/>'
            f'<text x="40" y="{y}" fill="#4fd1c5" font-size="14">▸</text>'
            f'<text x="66" y="{y}" fill="#e6edf3" font-size="14">{stage}</text>'
            f'<text x="180" y="{y}" fill="#8b98a8" font-size="13">{note}</text></g>'
        )

    reveal_all = 1.0 + len(stages) * dur_each + 0.3
    # payoff panel
    py = base_y + len(stages) * line_h + 26
    parts.append(
        f'<g opacity="0"><animate attributeName="opacity" from="0" to="1" '
        f'dur="0.5s" begin="{reveal_all:.2f}s" fill="freeze"/>'
        f'<rect x="28" y="{py-22}" width="{W-56}" height="96" rx="10" '
        f'fill="#11161d" stroke="#1e2733"/>'
        f'<text x="44" y="{py+2}" fill="#e6edf3" font-size="15" font-weight="700">'
        f'routes {c["routes"]} · APIs {c["endpoints"]} · edges {c["edges"]}</text>'
        f'<text x="44" y="{py+26}" fill="#39d0ff" font-size="13">'
        f'{both} both · {runtime} runtime-only · </text>'
        f'<text x="{44 + 8.0*len(str(both)+str(runtime)) + 165}" y="{py+26}" '
        f'fill="#e85002" font-size="13" font-weight="700">{static} static-only ← look here</text>'
        f'<text x="44" y="{py+50}" fill="#9b8cff" font-size="13">'
        f'{c["unknowns"]} named unknowns — what the model does not know</text></g>'
    )
    # closing tagline
    parts.append(
        f'<text x="{W/2}" y="{H-24}" fill="#8b98a8" font-size="13" text-anchor="middle" '
        f'opacity="0"><animate attributeName="opacity" from="0" to="1" dur="0.6s" '
        f'begin="{reveal_all+0.6:.2f}s" fill="freeze"/>'
        f'a model your AI reasons over — not a dump it hallucinates on</text>'
    )
    # loop: fade whole thing at the end and restart
    total = reveal_all + 3.0
    parts.append(
        f'<rect width="{W}" height="{H}" fill="#0d1117" opacity="0">'
        f'<animate attributeName="opacity" values="0;0;1;0" '
        f'keyTimes="0;0.93;0.97;1" dur="{total:.1f}s" repeatCount="indefinite"/></rect>'
    )
    parts.append("</svg>")
    return "\n".join(parts)


def write_svg(m: Model, path: str) -> None:
    with open(path, "w", encoding="utf-8") as f:
        f.write(render_svg(m))
