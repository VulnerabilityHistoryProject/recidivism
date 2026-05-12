import json
import re
from pathlib import Path
from typing import Dict, Iterator, Optional, Set
from urllib.parse import urlparse


_CWE_RE = re.compile(r"CWE-\d+")
_COMMIT_RE = re.compile(r"/commit/([0-9a-fA-F]{7,40})")
_GITHUB_REPO_RE = re.compile(r"^/([^/]+)/([^/]+)")
_HEX_SHA_RE = re.compile(r"^[0-9a-fA-F]{7,40}$")


def iter_vulnerability_files(root: Path) -> Iterator[Path]:
    for path in root.rglob("*.json"):
        if path.is_file():
            yield path


def load_vulnerability(path: Path) -> Dict:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def extract_cwes(vulnerability: Dict) -> Set[str]:
    cwes: Set[str] = set()

    def add_candidates(value: object) -> None:
        if isinstance(value, str):
            cwes.update(_CWE_RE.findall(value))
        elif isinstance(value, list):
            for item in value:
                add_candidates(item)

    add_candidates(vulnerability.get("database_specific", {}).get("cwe_ids"))
    add_candidates(vulnerability.get("database_specific", {}).get("cwe"))

    for affected in vulnerability.get("affected", []):
        dbs = affected.get("database_specific", {})
        add_candidates(dbs.get("cwe_ids"))
        add_candidates(dbs.get("cwe"))

    return cwes


def github_repo_from_url(url: str) -> Optional[str]:
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"}:
        return None
    if parsed.netloc.lower() != "github.com":
        return None
    match = _GITHUB_REPO_RE.match(parsed.path)
    if not match:
        return None
    owner, repo = match.groups()
    if repo.endswith(".git"):
        repo = repo[:-4]
    return f"https://github.com/{owner}/{repo}.git"


def extract_repo_urls(vulnerability: Dict) -> Set[str]:
    repos: Set[str] = set()
    for ref in vulnerability.get("references", []):
        url = ref.get("url")
        if not isinstance(url, str):
            continue
        repo = github_repo_from_url(url)
        if repo:
            repos.add(repo)
    return repos


def extract_fix_commits(vulnerability: Dict) -> Set[str]:
    commits: Set[str] = set()
    for affected in vulnerability.get("affected", []):
        for range_entry in affected.get("ranges", []):
            for event in range_entry.get("events", []):
                fixed = event.get("fixed")
                if isinstance(fixed, str) and _HEX_SHA_RE.match(fixed):
                    commits.add(fixed.lower())

    for ref in vulnerability.get("references", []):
        url = ref.get("url")
        if not isinstance(url, str):
            continue
        match = _COMMIT_RE.search(url)
        if match:
            commits.add(match.group(1).lower())
    return commits
