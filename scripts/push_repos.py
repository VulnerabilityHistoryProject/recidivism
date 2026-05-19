#!/usr/bin/env python3
"""Push every Git repository under data/repos/ one at a time."""

import argparse
import subprocess
from pathlib import Path


def find_git_repositories(root: Path):
    if not root.exists():
        raise FileNotFoundError(f"Repository root does not exist: {root}")
    if not root.is_dir():
        raise NotADirectoryError(f"Repository root is not a directory: {root}")

    repo_roots = {git_dir.parent for git_dir in root.rglob(".git") if git_dir.is_dir()}
    return sorted(repo_roots)


def push_repository(repo_root: Path, remote: str, refspec: str, no_verify: bool) -> bool:
    command = ["git", "-C", str(repo_root), "push", remote]
    if refspec:
        command.append(refspec)
    if no_verify:
        command.append("--no-verify")

    print(f"Pushing repository: {repo_root}")
    result = subprocess.run(command, capture_output=True, text=True)
    if result.returncode == 0:
        print(f"[✓] Pushed: {repo_root}\n")
        return True

    print(f"[✗] Failed to push: {repo_root}")
    print(result.stdout.strip())
    print(result.stderr.strip())
    print()
    return False


def parse_args():
    parser = argparse.ArgumentParser(
        description="Push every Git repository found under data/repos/.")
    parser.add_argument(
        "--path",
        default=Path("data") / "repos",
        help="Root directory containing repository checkouts.",
    )
    parser.add_argument(
        "--remote",
        default="origin",
        help="Git remote to push to (default: origin).",
    )
    parser.add_argument(
        "--refspec",
        default="",
        help="Optional refspec or branch to push (default: current branch).",
    )
    parser.add_argument(
        "--no-verify",
        action="store_true",
        help="Add --no-verify to the push command.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show the repositories that would be pushed without running git push.",
    )
    return parser.parse_args()


def main():
    args = parse_args()
    repo_root = Path(args.path)
    repositories = find_git_repositories(repo_root)

    if not repositories:
        print(f"No Git repositories found under {repo_root}")
        return

    print(f"Found {len(repositories)} Git repositories under {repo_root}")
    if args.dry_run:
        for repo in repositories:
            print(repo)
        return

    failures = []
    for repo in repositories:
        success = push_repository(repo, args.remote, args.refspec, args.no_verify)
        if not success:
            failures.append(repo)

    print(f"\nProcessed {len(repositories)} repositories.")
    if failures:
        print(f"{len(failures)} repositories failed to push.")
        for failed_repo in failures:
            print(f" - {failed_repo}")
        raise SystemExit(1)


if __name__ == "__main__":
    main()
