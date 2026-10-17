"""Crash-safe file writes, and keeping a damaged file aside instead of losing it.

Every output is written to a temporary file next to its target and renamed over it once complete,
so a crash, a full disk or Ctrl-C mid-write leaves the previous file intact, never half of a new one.
"""

from __future__ import annotations

import os
import tempfile
from contextlib import contextmanager
from datetime import datetime


def _umask() -> int:
    mask = os.umask(0)
    os.umask(mask)
    return mask


# the mode `open(path, "w")` gives a new file (read once: setting the umask to read it is not thread-safe)
_NEW_FILE_MODE = 0o666 & ~_umask()


@contextmanager
def atomic_write(path: str, mode: str = "w", encoding: str = "utf-8", perms: int | None = None):
    """Like `open(path, mode)`, but the file only appears, whole, when the block finishes without error.

    The file keeps an existing target's permissions, else gets the usual umask ones, or `perms` when given.
    """
    target = os.path.abspath(path)
    if os.path.exists(target) and not os.path.isfile(target):
        # /dev/stdout, a named pipe: nothing to rename over, write straight through
        with open(target, mode, encoding=None if "b" in mode else encoding) as f:
            yield f
        return
    fd, tmp = tempfile.mkstemp(prefix="." + os.path.basename(target) + ".", suffix=".tmp",
                               dir=os.path.dirname(target))
    try:
        with os.fdopen(fd, mode, encoding=None if "b" in mode else encoding) as f:
            if perms is None:
                try:
                    perms = os.stat(target).st_mode & 0o7777
                except OSError:
                    perms = _NEW_FILE_MODE
            os.chmod(tmp, perms)
            yield f
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, target)
    except BaseException:
        try:
            os.remove(tmp)
        except OSError:
            pass
        raise


def keep_aside(path: str) -> str:
    """Rename a damaged file to `<name>.damaged-<time>` so a fresh one can take its place. Returns the new path."""
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    dest = f"{path}.damaged-{stamp}"
    n = 1
    while os.path.exists(dest):
        n += 1
        dest = f"{path}.damaged-{stamp}-{n}"
    os.replace(path, dest)
    return dest
