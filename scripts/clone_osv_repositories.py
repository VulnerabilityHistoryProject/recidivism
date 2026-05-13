#!/usr/bin/env python3
import argparse
import subprocess
from datetime import date
from pathlib import Path
from urllib.parse import urlparse

from osv_common import extract_repo_urls, iter_vulnerability_files, load_vulnerability
from recidivism_config import get_required_value, load_config_with_source, resolve_config_path

SKIP_LOG = Path("skipped_repos.txt")

#Logs a skipped repository URL to a text file.
def log_skipped(repo_url: str, reason: str) -> None:
    with open(SKIP_LOG, "a") as f:
        f.write(f"{datetime.now()}::: {repo_url} (Reason: {reason})\n")

def clone_or_update(repo_url: str, target_dir: Path, update_existing: bool) -> None:
    parsed = urlparse(repo_url)
    parts = [part for part in parsed.path.split("/") if part]
    if len(parts) < 2:
        print(f"Warning: skipping malformed repository URL: {repo_url}")
        return
    owner = parts[-2]
    repo_name = parts[-1][:-4] if parts[-1].endswith(".git") else parts[-1]
    destination = target_dir / owner / repo_name
    destination.parent.mkdir(parents=True, exist_ok=True)
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
    config, config_source = load_config_with_source("clone")

    parser = argparse.ArgumentParser(description="Clone all repositories referenced by OSV vulnerabilities.")
    parser.add_argument(
        "--osv-dir",
        help="Directory containing extracted OSV JSON files (overrides clone.osv_dir in recidivism.ini)",
    )
    parser.add_argument(
        "--target-dir",
        help="Directory to place local repository clones (overrides clone.target_dir in recidivism.ini)",
    )
    parser.add_argument(
        "--max-repos",
        type=int,
        default=None,
        help="Optional limit for number of repositories",
    )
    parser.add_argument(
        "--update-existing",
        action=argparse.BooleanOptionalAction,
        default=config.getboolean("update_existing", fallback=False),
        help="Run git pull on existing clones",
    )
    args = parser.parse_args()

    try:
        osv_dir = resolve_config_path(args.osv_dir or get_required_value(config, "clone", "osv_dir"))
        target_dir = resolve_config_path(args.target_dir or get_required_value(config, "clone", "target_dir"))
    except ValueError as error:
        parser.error(f"{error} (config: {config_source})")
    max_repos = args.max_repos
    if max_repos is None:
        max_repos_str = config.get("max_repos", fallback="").strip()
        if max_repos_str:
            try:
                max_repos = int(max_repos_str)
            except ValueError as error:
                parser.error(f"Invalid clone.max_repos value '{max_repos_str}' in {config_source}: {error}")
    target_dir.mkdir(parents=True, exist_ok=True)

    repo_urls = set()
    for path in iter_vulnerability_files(osv_dir):
        vulnerability = load_vulnerability(path)
        repo_urls.update(extract_repo_urls(vulnerability))

    ordered_repos = sorted(repo_urls)
    if max_repos is not None:
        ordered_repos = ordered_repos[:max_repos]

    for repo_url in ordered_repos:
        clone_or_update(repo_url, target_dir, args.update_existing)

    print(f"Processed {len(ordered_repos)} repositories into {target_dir}")


if __name__ == "__main__":
    main()
