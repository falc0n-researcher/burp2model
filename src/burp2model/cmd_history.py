"""History commands: what changed between builds, the build list, and watching a folder of exports."""

from __future__ import annotations

import json
import os
import sqlite3
import sys

from . import diff as diffmod
from . import store
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
    try:
        with open(state_path, encoding="utf-8") as f:
            done = json.load(f)
    except (OSError, ValueError):
        done = {}

    def listing():
        found = []
        for fn in os.listdir(folder):
            p = os.path.join(folder, fn)
            if os.path.isfile(p) and any(fnmatch.fnmatch(fn.lower(), x.lower()) for x in pats):
                st = os.stat(p)
                found.append((st.st_mtime_ns, fn, st.st_size))
        return sorted(found)

    sig = lambda t: [t[0], t[2]]                    # noqa: E731
    if args.skip_existing and not done:
        done = {fn: sig((m, fn, sz)) for m, fn, sz in listing()}
    sizes: dict[str, int] = {}
    built = 0
    print(f"watch: {folder}  ({', '.join(pats)}) → {args.webapp}"
          + ("" if args.once else f"  every {args.interval:g}s, Ctrl-C to stop"), file=sys.stderr)
    try:
        while True:
            for mtime, fn, size in listing():
                if done.get(fn) == sig((mtime, fn, size)) or size == 0:
                    continue
                if not args.once and sizes.get(fn) != size:      # still being written: look again next time
                    sizes[fn] = size
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
                if _main(argv) != 0:
                    print(f"watch: could not build from {fn}; will try again if it changes", file=sys.stderr)
                    done[fn] = sig((mtime, fn, size))
                    continue
                done[fn] = sig((mtime, fn, size))
                built += 1
                os.makedirs(outdir, exist_ok=True)
                with open(state_path, "w", encoding="utf-8") as f:
                    json.dump(done, f, indent=1, sort_keys=True)
                conn = store.open_db(os.path.join(outdir, store.DB_NAME))
                try:
                    n = len(store.list_builds(conn))
                finally:
                    conn.close()
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


def cmd_builds(args) -> int:
    dbp = _db_path(args)
    if dbp is None:
        return 2
    conn = store.open_db(dbp)
    try:
        rows = store.list_builds(conn)
    finally:
        conn.close()
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
    conn = store.open_db(dbp)
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
