#!/usr/bin/env python3
"""Stage, commit, and push every Git repository under data/repos/ one at a time."""

import argparse
import os
import subprocess
from pathlib import Path
from urllib.parse import urlparse


def find_directories(root: Path):
    if not root.exists():
        raise FileNotFoundError(f"Directory root does not exist: {root}")
    if not root.is_dir():
        raise NotADirectoryError(f"Directory root is not a directory: {root}")

    directories = [child for child in root.iterdir() if child.is_dir()]
    return sorted(directories)


def run_git_command(repo_root: Path, args, ssh_key: str = None) -> subprocess.CompletedProcess:
    command = ["git", "-C", str(repo_root)] + args
    env = None
    if ssh_key:
        env = os.environ.copy()
        env["GIT_SSH_COMMAND"] = f"ssh -i {ssh_key} -o StrictHostKeyChecking=no"
    return subprocess.run(command, capture_output=True, text=True, env=env)


def get_remote_url(repo_root: Path, remote: str) -> str:
    result = run_git_command(repo_root, ["remote", "get-url", remote])
    if result.returncode != 0:
        raise RuntimeError(
            f"Failed to get remote URL for {remote} in {repo_root}: {result.stderr.strip()}"
        )
    return result.stdout.strip()


def set_remote_url(repo_root: Path, remote: str, url: str) -> bool:
    result = run_git_command(repo_root, ["remote", "set-url", remote, url])
    if result.returncode != 0:
        print(f"[✗] Failed to set remote URL for {remote} in {repo_root}")
        print(result.stderr.strip())
        print()
        return False
    return True


def https_to_ssh_url(remote_url: str) -> str:
    if remote_url.startswith("git@") or remote_url.startswith("ssh://"):
        return remote_url

    parsed = urlparse(remote_url)
    if parsed.scheme in ("http", "https") and parsed.hostname and parsed.path:
        path = parsed.path.lstrip("/")
        if not path.endswith(".git"):
            path += ".git"
        return f"git@{parsed.hostname}:{path}"

    return remote_url


def ensure_ssh_remote(repo_root: Path, remote: str) -> str:
    try:
        current_url = get_remote_url(repo_root, remote)
    except RuntimeError as error:
        print(error)
        return ""

    ssh_url = https_to_ssh_url(current_url)
    if ssh_url != current_url:
        print(f"[i] Converting remote '{remote}' URL from HTTPS to SSH in {repo_root}")
        if set_remote_url(repo_root, remote, ssh_url):
            return ssh_url
        return current_url

    return ssh_url


def stage_and_commit_directory(repo_root: Path, directory: Path, ssh_key: str = None) -> bool:
    try:
        rel_path = directory.relative_to(repo_root)
    except ValueError:
        rel_path = directory
    print(f"Staging directory in repository: {rel_path}")
    add_result = run_git_command(repo_root, ["add", str(rel_path)], ssh_key)
    if add_result.returncode != 0:
        print(f"[✗] git add failed for {rel_path}")
        print(add_result.stderr.strip())
        print()
        return False

    print(f"[✓] Added changes in {rel_path}")
    commit_message = f"push {directory.name}"
    print(f"Committing {rel_path} with message: '{commit_message}'")
    commit_result = run_git_command(repo_root, ["commit", "-m", commit_message], ssh_key)
    if commit_result.returncode == 0:
        print(f"[✓] Committed {rel_path} with message: '{commit_message}'")
        return True

    stdout = commit_result.stdout.strip()
    stderr = commit_result.stderr.strip()
    if "nothing to commit" in stdout.lower() or "nothing to commit" in stderr.lower():
        print(f"[i] No changes to commit in {repo_root}")
        return True

    print(f"[✗] git commit failed for {repo_root}")
    print(stdout)
    print(stderr)
    print()
    return False


def push_repository(repo_root: Path, remote: str, refspec: str, no_verify: bool, ssh_key: str = None) -> bool:
    refspec_label = f" {refspec}" if refspec else ""
    no_verify_label = " --no-verify" if no_verify else ""
    print(f"Pushing repository: {repo_root} to remote '{remote}'{refspec_label}{no_verify_label}")
    command = ["git", "-C", str(repo_root), "push", remote]
    if refspec:
        command.append(refspec)
    if no_verify:
        command.append("--no-verify")

    env = None
    if ssh_key:
        env = os.environ.copy()
        env["GIT_SSH_COMMAND"] = f"ssh -i {ssh_key} -o StrictHostKeyChecking=no"
    
    result = subprocess.run(command, capture_output=True, text=True, env=env)
    if result.returncode == 0:
        print(f"[✓] Pushed {repo_root} to {remote}{refspec_label}\n")
        return True

    print(f"[✗] Failed to push: {repo_root}")
    print(result.stdout.strip())
    print(result.stderr.strip())
    print()
    return False


def parse_args():
    parser = argparse.ArgumentParser(
        description="Stage and commit directories under data/repos/ in the recidivism repo, then push that repo."
    )
    parser.add_argument(
        "--path",
        default=Path("data") / "repos",
        help="Directory containing the subdirectories to stage and commit.",
    )
    parser.add_argument(
        "--repo-root",
        default=Path("."),
        help="Root git repository to commit and push from (default: current directory).",
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
    parser.add_argument(
        "--ssh-key",
        default=None,
        help="Path to SSH private key for authentication (instead of token-based auth).",
    )
    return parser.parse_args()


def main():
    args = parse_args()
    repo_root = Path(args.repo_root)
    directories = find_directories(Path(args.path))

    print(f"Found {len(directories)} directories under {args.path}")
    if args.dry_run:
        for directory in directories:
            print(directory)
        return

    failures = []
    for directory in directories:
        if not stage_and_commit_directory(repo_root, directory, args.ssh_key):
            failures.append(directory)

    if failures:
        print(f"{len(failures)} directories failed during add/commit.")
        for failed_dir in failures:
            print(f" - {failed_dir}")
        raise SystemExit(1)

    ensure_ssh_remote(repo_root, args.remote)
    success = push_repository(repo_root, args.remote, args.refspec, args.no_verify, args.ssh_key)
    if not success:
        raise SystemExit(1)

    print(f"\nProcessed {len(directories)} directories and pushed repository {repo_root}.")


if __name__ == "__main__":
    main()
