"""History commands: what changed between builds, the build list, and watching a folder of exports."""

from __future__ import annotations

import json
import os
import sqlite3
import sys

from . import diff as diffmod
from . import store
from .atomic import atomic_write, keep_aside
from .model import from_dict


def _main(argv):
    from .cli import main
    return main(argv)


def _db_path(args):
    from .cli import _db_path as db_path
    return db_path(args)


def _changes_since_previous(db_path: str, build_id: int | None) -> dict | None:
    """The drift from the build before this one, for the report. None on a first build or any trouble."""
    if not build_id or build_id < 2:
        return None
    try:
        conn = store.open_db(db_path)
        try:
            ids = [r[0] for r in conn.execute("SELECT id FROM builds WHERE id<? ORDER BY id DESC LIMIT 1", (build_id,))]
            if not ids:
                return None
            old, ometa = _snapshot_of(conn, ids[0])
            new, nmeta = _snapshot_of(conn, build_id)
            return diffmod.diff_models(old, new, ometa, nmeta, hist=lambda k, key: store.history(conn, k, key))
        finally:
            conn.close()
    except (ValueError, KeyError, TypeError, OSError, sqlite3.Error):
        return None


def _snapshot_of(conn, bid: int):
    snap = store.load_build(conn, bid)
    if snap is None:
        raise ValueError(f"no build #{bid} in graph.db")
    row = conn.execute("SELECT built_at, label FROM builds WHERE id=?", (bid,)).fetchone()
    return from_dict(snap), {"id": bid, "built_at": row["built_at"], "label": row["label"] or ""}


def cmd_watch(args) -> int:
    """Poll a folder: every settled new export is built, labelled with its file name, and diffed."""
    import fnmatch
    import time
    folder = args.folder
    if not os.path.isdir(folder):
        print(f"watch: {folder} is not a folder", file=sys.stderr)
        return 2
    pats = [p.strip() for p in args.pattern.split(",") if p.strip()]
    outdir = os.path.join(args.out, args.webapp)
    state_path = os.path.join(outdir, "watch.json")
    done = _load_watch_state(state_path)

    def stat(fn):
        try:
            st = os.stat(os.path.join(folder, fn))
        except OSError:                             # gone between the listing and the look
            return None
        return (st.st_mtime_ns, fn, st.st_size) if os.path.isfile(os.path.join(folder, fn)) else None

    def listing():
        try:
            names = os.listdir(folder)
        except OSError as e:
            print(f"watch: cannot list {folder} ({e}); will look again", file=sys.stderr)
            return []
        found = [stat(fn) for fn in names if any(fnmatch.fnmatch(fn.lower(), x.lower()) for x in pats)]
        return sorted(t for t in found if t)

    sig = lambda t: [t[0], t[2]]                    # noqa: E731
    if args.skip_existing and not done:
        done = {fn: sig((m, fn, sz)) for m, fn, sz in listing()}
    last: dict[str, list] = {}
    built = 0
    print(f"watch: {folder}  ({', '.join(pats)}) → {args.webapp}"
          + ("" if args.once else f"  every {args.interval:g}s, Ctrl-C to stop"), file=sys.stderr)
    try:
        while True:
            for mtime, fn, size in listing():
                if done.get(fn) == sig((mtime, fn, size)) or size == 0:
                    continue
                # still being written (or copied): the size and the time must hold still for one interval
                if not args.once and last.get(fn) != sig((mtime, fn, size)):
                    last[fn] = sig((mtime, fn, size))
                    continue
                label = os.path.splitext(fn)[0]
                argv = ["build", os.path.join(folder, fn), "-w", args.webapp, "--out", args.out, "--label", label]
                for flag, val in (("--role", args.role), ("--skip-tools", args.skip_tools)):
                    if val:
                        argv += [flag, val]
                for sc in args.scope or []:
                    argv += ["--scope", sc]
                if args.osint:
                    argv.append("--osint")
                print(f"\nwatch: new export {fn}", file=sys.stderr)
                rc = _main(argv)
                after = stat(fn)
                if after is None or sig(after) != sig((mtime, fn, size)):
                    # the file moved under the build: what was read may be part of it. Build it again once it settles.
                    print(f"watch: {fn} changed while it was being read; will build it again once it settles",
                          file=sys.stderr)
                    last.pop(fn, None)
                    continue
                if rc != 0:
                    print(f"watch: could not build from {fn}; will try again if it changes", file=sys.stderr)
                    done[fn] = sig((mtime, fn, size))
                    continue
                done[fn] = sig((mtime, fn, size))
                built += 1
                os.makedirs(outdir, exist_ok=True)
                with atomic_write(state_path) as f:
                    json.dump(done, f, indent=1, sort_keys=True)
                try:
                    conn = store.open_db(os.path.join(outdir, store.DB_NAME))
                    try:
                        n = len(store.list_builds(conn))
                    finally:
                        conn.close()
                except (OSError, ValueError, sqlite3.Error):
                    n = 0
                if n > 1:
                    print("", file=sys.stderr)
                    _main(["diff", args.webapp, "--out", args.out])
            if args.once:
                break
            time.sleep(max(0.2, args.interval))
    except KeyboardInterrupt:
        print("\nwatch: stopped", file=sys.stderr)
    if args.once and not built:
        print("watch: nothing new to build", file=sys.stderr)
    return 0


def _load_watch_state(path: str) -> dict:
    """Which exports were already built. A damaged state file is kept aside rather than read as "nothing
    built yet", which would rebuild every export in the folder as a new build."""
    try:
        with open(path, encoding="utf-8") as f:
            done = json.load(f)
    except FileNotFoundError:
        return {}
    except (OSError, ValueError) as e:
        done = e
    if isinstance(done, dict):
        return done
    try:
        aside = keep_aside(path)
        print(f"watch: {path} was unreadable; kept it aside as {aside}. Exports already built "
              f"will be built again (use --skip-existing to skip them)", file=sys.stderr)
    except OSError:
        pass
    return {}


def cmd_builds(args) -> int:
    dbp = _db_path(args)
    if dbp is None:
        return 2
    try:
        conn = store.open_db(dbp)
        try:
            rows = store.list_builds(conn)
        finally:
            conn.close()
    except (ValueError, sqlite3.Error) as e:
        print(f"could not read {dbp}: {e}", file=sys.stderr)
        return 2
    print(f"{args.webapp}: {len(rows)} build(s) kept in graph.db")
    print(f"  {'id':>3}  {'built (UTC)':<20} {'nodes':>6} {'edges':>6} {'requests':>8}  label")
    for r in rows:
        print(f"  {r['id']:>3}  {r['built_at']:<20} {r['nodes']:>6} {r['edges']:>6} {r['exchanges']:>8}  {r['label']}")
    if len(rows) > 1:
        print(f"\ncompare two:  burp2model diff {args.webapp} {rows[-2]['id']} {rows[-1]['id']}")
    return 0


def cmd_diff(args) -> int:
    dbp = _db_path(args)
    if dbp is None:
        return 2
    try:
        conn = store.open_db(dbp)
    except (ValueError, sqlite3.Error) as e:
        print(f"could not diff: {e}", file=sys.stderr)
        return 2
    try:
        b_ref = args.b if args.b is not None else "latest"
        a_ref = args.a if args.a is not None else "previous"
        newer = store.resolve_build(conn, b_ref)
        if args.a is None and args.b is None:
            older = store.resolve_build(conn, "previous")
        else:
            older = store.resolve_build(conn, a_ref if args.a is not None else "previous")
        if older == newer:
            print(f"build #{older} is compared with itself; pick two different builds "
                  f"(`burp2model builds {args.webapp}` lists them)", file=sys.stderr)
            return 2
        if older > newer:
            older, newer = newer, older
        old, ometa = _snapshot_of(conn, older)
        new, nmeta = _snapshot_of(conn, newer)
        d = diffmod.diff_models(old, new, ometa, nmeta, hist=lambda k, key: store.history(conn, k, key))
    except (ValueError, KeyError, TypeError, OSError, sqlite3.Error) as e:
        print(f"could not diff: {e}", file=sys.stderr)
        return 2
    finally:
        conn.close()
    if args.json:
        print(json.dumps(d, indent=2))
    else:
        print(diffmod.format_text(d))
    return 0
