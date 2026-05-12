#!/usr/bin/env python3
import argparse
import subprocess
from pathlib import Path

from osv_common import extract_repo_urls, iter_vulnerability_files, load_vulnerability


def clone_or_update(repo_url: str, target_dir: Path, update_existing: bool) -> None:
    repo_name = repo_url.rstrip("/").split("/")[-1]
    if repo_name.endswith(".git"):
        repo_name = repo_name[:-4]

    destination = target_dir / repo_name
    if destination.exists():
        if update_existing:
            subprocess.run(
                ["git", "-C", str(destination), "pull", "--ff-only"],
                check=False,
            )
        return

    subprocess.run(["git", "clone", repo_url, str(destination)], check=False)


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
