import json
import re
from pathlib import Path
from typing import Dict, Iterable, Iterator, List, Optional, Set, Tuple
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


def parse_base_severity(vulnerability: Dict) -> Optional[float]:
    for severity in vulnerability.get("severity", []):
        score = severity.get("score")
        if isinstance(score, str):
            try:
                return float(score)
            except ValueError:
                continue
    return None


def collect_history(
    vulnerabilities: Iterable[Dict],
) -> Tuple[Dict[str, int], Dict[str, int]]:
    cwe_counts: Dict[str, int] = {}
    repo_counts: Dict[str, int] = {}

    for vulnerability in vulnerabilities:
        for cwe in extract_cwes(vulnerability):
            cwe_counts[cwe] = cwe_counts.get(cwe, 0) + 1
        for repo in extract_repo_urls(vulnerability):
            repo_counts[repo] = repo_counts.get(repo, 0) + 1

    return cwe_counts, repo_counts


def recidivism_for_vulnerability(
    vulnerability: Dict,
    cwe_counts: Dict[str, int],
    repo_counts: Dict[str, int],
) -> Dict[str, object]:
    cwes = extract_cwes(vulnerability)
    repos = extract_repo_urls(vulnerability)
    fix_commits = extract_fix_commits(vulnerability)

    cwe_repeat_count = sum(max(cwe_counts.get(cwe, 0) - 1, 0) for cwe in cwes)
    repo_repeat_count = sum(max(repo_counts.get(repo, 0) - 1, 0) for repo in repos)

    recidivism_score = float(cwe_repeat_count + repo_repeat_count)
    base_score = parse_base_severity(vulnerability)
    adjusted_score = min(base_score + recidivism_score, 10.0) if base_score is not None else None

    return {
        "cwes": sorted(cwes),
        "repositories": sorted(repos),
        "fix_commits": sorted(fix_commits),
        "cwe_repeat_count": cwe_repeat_count,
        "repo_repeat_count": repo_repeat_count,
        "score": recidivism_score,
        "base_severity_score": base_score,
        "adjusted_severity_score": adjusted_score,
    }
