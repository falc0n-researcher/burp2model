"""
Scripted journeys: the flows an automatic crawl cannot invent.

A crawler can click what is on the screen. It will not register an account, log
in, fill a checkout, upload a file or ask for something a role should not reach.
A journey is a short JSON file that says how, and the crawler performs it in the
same browser session as the crawl, so the traffic lands in the same model (and
an authenticated session carries on into the autonomous crawl that follows).

    {
      "name": "customer checkout",
      "vars": {"email": "${env:SHOP_EMAIL}"},
      "steps": [
        {"request": {"method": "POST", "path": "/rest/user/login",
                     "json": {"email": "${email}", "password": "${env:SHOP_PASSWORD}"},
                     "extract": {"token": "authentication.token", "bid": "authentication.bid"}}},
        {"set_header": {"Authorization": "Bearer ${token}"}},
        {"set_storage": {"token": "${token}"}},
        {"goto": "/#/basket"},
        {"click": {"text": "Checkout"}},
        {"fill": {"selector": "#address", "value": "1 Probe Street"}},
        {"press": "Enter"},
        {"wait_idle": true}
      ]
    }

Steps:  goto  click  fill  press  wait  wait_for  wait_idle  request  set_header
        set_storage  set_cookie  scroll  assert  (browser mode; a static crawl runs
        goto, request, set_header and set_cookie only)

`assert` checks where the journey has got to: {"assert": {"url_contains": "/welcome",
"text": "Sign out", "not_text": "Invalid password", "selector": "#account"}}. A login
that did not log in is the usual reason, and without it the crawl would carry on
anonymously and say nothing.

Values may use ${name} (a var, or something an earlier `extract` saved) and
${env:NAME} (an environment variable: keep passwords out of the file and out of
your shell history). Each step may carry "required": true to abort the journey if
it fails; otherwise a failure is reported and the journey carries on.

A journey is deliberate, so its requests are not held to the crawler's
"looks destructive" filter. They are still held to the scope, to --read-only, and
to --yes.
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field

STEPS = {"goto", "click", "fill", "press", "wait", "wait_for", "wait_idle", "request",
         "set_header", "set_storage", "set_cookie", "scroll", "assert"}
BROWSER_ONLY = {"click", "fill", "press", "wait_for", "wait_idle", "set_storage", "scroll", "assert"}
_VAR = re.compile(r"\$\{(env:)?([A-Za-z_][A-Za-z0-9_]*)\}")


class JourneyError(ValueError):
    """A journey file that cannot be run (bad JSON, unknown step, missing variable)."""


@dataclass
class Journey:
    name: str
    vars: dict = field(default_factory=dict)
    steps: list = field(default_factory=list)
    path: str = ""


def load(path: str) -> Journey:
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
    except OSError as e:
        raise JourneyError(f"cannot read journey {path}: {e}")
    except ValueError as e:
        raise JourneyError(f"{path} is not valid JSON: {e}")
    if isinstance(data, list):
        data = {"steps": data}
    if not isinstance(data, dict) or not isinstance(data.get("steps"), list) or not data["steps"]:
        raise JourneyError(f"{path}: a journey needs a non-empty \"steps\" list")
    j = Journey(name=str(data.get("name") or os.path.basename(path)), vars=dict(data.get("vars") or {}),
                steps=data["steps"], path=path)
    for n, step in enumerate(j.steps, 1):
        validate_step(step, f"{path} step {n}")
    return j


def validate_step(step, where: str) -> None:
    if not isinstance(step, dict):
        raise JourneyError(f"{where}: a step is an object like {{\"goto\": \"/\"}}")
    kinds = [k for k in step if k in STEPS]
    if len(kinds) != 1:
        extra = [k for k in step if k not in STEPS and k not in ("required", "label")]
        raise JourneyError(f"{where}: exactly one of {sorted(STEPS)} per step"
                           + (f" (unknown key {extra[0]!r})" if extra else ""))
    kind, arg = kinds[0], step[kinds[0]]
    if kind == "goto" and not isinstance(arg, str):
        raise JourneyError(f"{where}: goto takes a URL or path string")
    if kind in ("click", "fill", "wait_for") and not isinstance(arg, (str, dict)):
        raise JourneyError(f"{where}: {kind} takes a selector or {{\"text\": ...}}")
    if kind == "fill" and not (isinstance(arg, dict) and "value" in arg and ("selector" in arg or "name" in arg)):
        raise JourneyError(f"{where}: fill takes {{\"selector\": ..., \"value\": ...}}")
    if kind == "request":
        if not (isinstance(arg, dict) and arg.get("path") or isinstance(arg, dict) and arg.get("url")):
            raise JourneyError(f"{where}: request takes {{\"method\": ..., \"path\": ...}}")
    if kind == "assert" and not (isinstance(arg, dict) and set(arg) & {"url_contains", "text", "not_text", "selector"}):
        raise JourneyError(f"{where}: assert takes url_contains, text, not_text or selector")
    if kind in ("set_header", "set_storage", "set_cookie") and not isinstance(arg, dict):
        raise JourneyError(f"{where}: {kind} takes an object of name: value")


def substitute(value, variables: dict):
    """Replace ${name} and ${env:NAME} anywhere in a step; a missing one is an error."""
    if isinstance(value, str):
        # a value that is exactly one ${var} keeps the variable's type, so an extracted
        # id stays a JSON number instead of becoming "7"
        whole = _VAR.fullmatch(value)
        if whole and not whole.group(1) and whole.group(2) in variables:
            return variables[whole.group(2)]

        def one(m: re.Match) -> str:
            name = m.group(2)
            if m.group(1):
                if name not in os.environ:
                    raise JourneyError(f"environment variable {name} is not set (used as ${{env:{name}}})")
                return os.environ[name]
            if name not in variables:
                raise JourneyError(f"variable ${{{name}}} is not defined (set it under \"vars\", "
                                   "pass --var, or extract it in an earlier step)")
            return str(variables[name])
        return _VAR.sub(one, value)
    if isinstance(value, dict):
        return {k: substitute(v, variables) for k, v in value.items()}
    if isinstance(value, list):
        return [substitute(v, variables) for v in value]
    return value


def dig(node, path: str):
    """`authentication.token`, `data.0.id` -> the value, or None."""
    for part in path.split("."):
        try:
            node = node[int(part)] if isinstance(node, list) else node[part]
        except (KeyError, IndexError, ValueError, TypeError):
            return None
    return node
