#!/usr/bin/env python3
import argparse
import subprocess
from pathlib import Path
from urllib.parse import urlparse

from osv_common import extract_repo_urls, iter_vulnerability_files, load_vulnerability


def clone_or_update(repo_url: str, target_dir: Path, update_existing: bool) -> None:
    parsed = urlparse(repo_url)
    parts = [part for part in parsed.path.split("/") if part]
    if len(parts) < 2:
        print(f"Warning: skipping malformed repository URL: {repo_url}")
        return
    repo_name = parts[-1][:-4] if parts[-1].endswith(".git") else parts[-1]

    destination = target_dir / repo_name
    if destination.exists():
        if update_existing:
            result = subprocess.run(
                ["git", "-C", str(destination), "pull", "--ff-only"],
                check=False,
                capture_output=True,
                text=True,
            )
            if result.returncode != 0:
                stderr = result.stderr.strip() if result.stderr else f"git pull exited with code {result.returncode}"
                print(f"Warning: failed to update {destination} ({repo_url}): {stderr}")
        return

    result = subprocess.run(
        ["git", "clone", repo_url, str(destination)],
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        stderr = result.stderr.strip() if result.stderr else f"git clone exited with code {result.returncode}"
        print(f"Warning: failed to clone {repo_url}: {stderr}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Clone all repositories referenced by OSV vulnerabilities.")
    parser.add_argument("--osv-dir", default="data/osv_dump", help="Directory containing extracted OSV JSON files")
    parser.add_argument("--target-dir", default="data/repos", help="Directory to place local repository clones")
    parser.add_argument("--max-repos", type=int, default=None, help="Optional limit for number of repositories")
    parser.add_argument("--update-existing", action="store_true", help="Run git pull on existing clones")
    args = parser.parse_args()

    osv_dir = Path(args.osv_dir).resolve()
    target_dir = Path(args.target_dir).resolve()
    target_dir.mkdir(parents=True, exist_ok=True)

    repo_urls = set()
    for path in iter_vulnerability_files(osv_dir):
        vulnerability = load_vulnerability(path)
        repo_urls.update(extract_repo_urls(vulnerability))

    ordered_repos = sorted(repo_urls)
    if args.max_repos is not None:
        ordered_repos = ordered_repos[: args.max_repos]

    for repo_url in ordered_repos:
        clone_or_update(repo_url, target_dir, args.update_existing)

    print(f"Processed {len(ordered_repos)} repositories into {target_dir}")


if __name__ == "__main__":
    main()
