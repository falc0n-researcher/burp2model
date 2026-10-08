"""A picture of the app for the report: validated, size-capped, embedded as a data URI.

The pixels are not masked the way text is, so a screenshot is taken automatically only from an
anonymous crawl's start page. For anything else the user supplies one with --screenshot.
"""

from __future__ import annotations

import base64
import os

MAX_BYTES = 3 * 1024 * 1024
_NAMES = {"image/jpeg": "screenshot.jpg", "image/png": "screenshot.png", "image/webp": "screenshot.webp"}


def kind(data: bytes) -> str | None:
    if data[:3] == b"\xff\xd8\xff":
        return "image/jpeg"
    if data[:8] == b"\x89PNG\r\n\x1a\n":
        return "image/png"
    if data[:4] == b"RIFF" and data[8:12] == b"WEBP":
        return "image/webp"
    return None


def load(path: str) -> tuple[str, bytes]:
    """Read an image file; ValueError says what is wrong with it."""
    with open(path, "rb") as f:
        data = f.read(MAX_BYTES + 1)
    if len(data) > MAX_BYTES:
        raise ValueError(f"{path} is larger than {MAX_BYTES // (1024 * 1024)} MB")
    mime = kind(data)
    if mime is None:
        raise ValueError(f"{path} is not a PNG, JPEG or WebP image")
    return mime, data


def filename(mime: str) -> str:
    return _NAMES[mime]


def existing(outdir: str) -> tuple[str, bytes] | None:
    """A screenshot a previous build saved next to the outputs."""
    for name in _NAMES.values():
        p = os.path.join(outdir, name)
        if os.path.exists(p):
            try:
                return load(p)
            except (OSError, ValueError):
                return None
    return None


def data_uri(mime: str, data: bytes) -> str:
    return f"data:{mime};base64," + base64.b64encode(data).decode("ascii")
