#!/usr/bin/env python3
"""
cleanup_empty_repos.py

Delete empty directories under data/repos/.

"""

from __future__ import annotations

import argparse
import os
import sys
from typing import List


def remove_empty_dirs(root: str, dry_run: bool = True, verbose: bool = False) -> List[str]:
    """
    Remove only immediate subdirectories of `root` if they are empty.
    """
    root_abs = os.path.abspath(root)
    removed: List[str] = []

    if not os.path.exists(root_abs):
        raise FileNotFoundError(f"Path does not exist: {root}")
    if not os.path.isdir(root_abs):
        raise NotADirectoryError(f"Path is not a directory: {root}")

    try:
        entries = os.listdir(root_abs)
    except OSError:
        if verbose:
            print(f"Cannot access root path: {root_abs}")
        return removed

    for name in entries:
        path = os.path.join(root_abs, name)
        if not os.path.isdir(path):
            continue

        try:
            subentries = os.listdir(path)
        except OSError:
            if verbose:
                print(f"Skipping (access error): {path}")
            continue

        # Only remove the directory if it's completely empty (no files, no dirs)
        if not subentries:
            if dry_run:
                print(f"Would remove: {path}")
            else:
                try:
                    os.rmdir(path)
                    removed.append(path)
                    if verbose:
                        print(f"Removed: {path}")
                except OSError as exc:
                    print(f"Failed to remove {path}: {exc}", file=sys.stderr)

    return removed


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Remove empty directories under data/repos/")
    p.add_argument("--path", default=os.path.join("data", "repos"), help="Root path to scan")
    p.add_argument("--dry-run", action="store_true", help="Show actions without removing")
    p.add_argument("--yes", action="store_true", help="Remove without confirmation")
    p.add_argument("--verbose", action="store_true", help="Verbose output")
    return p.parse_args()


def main() -> int:
    args = parse_args()
    root = args.path
    dry_run = args.dry_run
    verbose = args.verbose

    try:
        # If user didn't request dry-run and didn't pass --yes, prompt for confirmation
        if not dry_run and not args.yes:
            resp = input(f"About to remove empty directories under '{root}'. Proceed? [y/N]: ")
            if resp.strip().lower() not in ("y", "yes"):
                print("Aborted by user.")
                return 2

        removed = remove_empty_dirs(root, dry_run=dry_run, verbose=verbose)

        if not dry_run:
            print(f"Removed {len(removed)} directories.")
        return 0

    except (FileNotFoundError, NotADirectoryError) as exc:
        print(str(exc), file=sys.stderr)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
