import json
import re
from pathlib import Path
from typing import Dict, Iterable, Iterator, List, Optional, Set, Tuple
from urllib.parse import urlparse


_CWE_RE = re.compile(r"CWE-\d+")
_COMMIT_RE = re.compile(r"/commit/([0-9a-fA-F]{7,40})")
_GITHUB_REPO_RE = re.compile(r"^/([^/]+)/([^/]+)")
_HEX_SHA_RE = re.compile(r"^[0-9a-fA-F]{7,40}$")
MAX_SEVERITY_SCORE = 10.0


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


def _infer_package_from_references(vulnerability: Dict) -> Tuple[Optional[str], Optional[str]]:
    for ref in vulnerability.get("references", []):
        url = ref.get("url")
        if not isinstance(url, str):
            continue
        parsed = urlparse(url)
        if parsed.scheme not in {"http", "https"}:
            continue
        if parsed.netloc.lower() != "github.com":
            continue
        parts = [part for part in parsed.path.split("/") if part]
        if len(parts) >= 2:
            return "pip", parts[0]
    return None, None


def extract_affected_ecosystems(vulnerability: Dict) -> Set[str]:
    ecosystems: Set[str] = set()
    for affected in vulnerability.get("affected", []):
        package = affected.get("package", {})
        ecosystem = package.get("ecosystem")
        if isinstance(ecosystem, str) and ecosystem:
            ecosystems.add(ecosystem)
            continue
        inferred_ecosystem, _ = _infer_package_from_references(vulnerability)
        if inferred_ecosystem:
            ecosystems.add(inferred_ecosystem)
    return ecosystems


def extract_affected_package_pairs(vulnerability: Dict) -> Set[Tuple[str, str]]:
    packages: Set[Tuple[str, str]] = set()
    for affected in vulnerability.get("affected", []):
        package = affected.get("package", {})
        ecosystem = package.get("ecosystem")
        name = package.get("name")
        if (
            isinstance(ecosystem, str)
            and ecosystem
            and isinstance(name, str)
            and name
        ):
            packages.add((ecosystem, name))
            continue

        inferred_ecosystem, inferred_name = _infer_package_from_references(vulnerability)
        if inferred_ecosystem and inferred_name:
            packages.add((inferred_ecosystem, inferred_name))
    return packages


def extract_cwe_package_pairs(vulnerability: Dict) -> Set[Tuple[str, str, str]]:
    cwes = extract_cwes(vulnerability)
    package_pairs = extract_affected_package_pairs(vulnerability)
    return {(cwe, ecosystem, name) for cwe in cwes for ecosystem, name in package_pairs}


def _normalize_version(value: Optional[str]) -> Optional[Tuple[int, ...]]:
    if not isinstance(value, str):
        return None
    cleaned = value.strip()
    if not cleaned:
        return None
    if cleaned.startswith(("<", ">", "=", "~", "^")):
        cleaned = cleaned[1:].strip()
    if cleaned.startswith("v") and len(cleaned) > 1 and cleaned[1].isdigit():
        cleaned = cleaned[1:]
    if cleaned in {"*", "latest"}:
        return None

    parts = re.split(r"[^0-9]+", cleaned)
    if not parts or not parts[0]:
        return None

    numbers = []
    for part in parts:
        if part.isdigit():
            numbers.append(int(part))
    if not numbers:
        return None

    while len(numbers) < 3:
        numbers.append(0)
    return tuple(numbers[:3])


def _compare_versions(left: Optional[str], right: Optional[str]) -> Optional[int]:
    left_parts = _normalize_version(left)
    right_parts = _normalize_version(right)
    if left_parts is None or right_parts is None:
        return None
    if left_parts < right_parts:
        return -1
    if left_parts > right_parts:
        return 1
    return 0


def _intervals_overlap(first: Tuple[Optional[str], Optional[str]], second: Tuple[Optional[str], Optional[str]]) -> bool:
    first_start, first_end = first
    second_start, second_end = second

    start = first_start
    if start is None or (second_start is not None and _compare_versions(start, second_start) is not None and _compare_versions(start, second_start) < 0):
        start = second_start

    end = first_end
    if end is None or (second_end is not None and _compare_versions(end, second_end) is not None and _compare_versions(end, second_end) > 0):
        end = second_end

    if start is None or end is None:
        return True

    return _compare_versions(start, end) is not None and _compare_versions(start, end) < 0


def _extract_version_intervals(vulnerability: Dict) -> Dict[Tuple[str, str], List[Tuple[Optional[str], Optional[str]]]]:
    intervals_by_package: Dict[Tuple[str, str], List[Tuple[Optional[str], Optional[str]]]] = {}
    for affected in vulnerability.get("affected", []):
        package = affected.get("package", {})
        ecosystem = package.get("ecosystem")
        name = package.get("name")
        if not isinstance(ecosystem, str) or not ecosystem or not isinstance(name, str) or not name:
            continue

        key = (ecosystem, name)
        intervals = []
        for range_entry in affected.get("ranges", []):
            current_start: Optional[str] = None
            for event in range_entry.get("events", []):
                if isinstance(event, dict) and "introduced" in event:
                    introduced = event.get("introduced")
                    if isinstance(introduced, str):
                        current_start = introduced
                if isinstance(event, dict) and "fixed" in event:
                    fixed = event.get("fixed")
                    if isinstance(fixed, str):
                        intervals.append((current_start, fixed))
                        current_start = None
            if current_start is not None:
                intervals.append((current_start, None))
        if intervals:
            intervals_by_package[key] = intervals
    return intervals_by_package


def parse_base_severity(vulnerability: Dict) -> Optional[float]:
    for severity in vulnerability.get("severity", []):
        if severity.get("type") in {"RECIDIVISM", "RECIDIVISM_ADJUSTED"}:
            continue
        score = severity.get("score")
        if isinstance(score, str):
            try:
                return float(score)
            except ValueError:
                continue
    return None


def collect_history(
    vulnerabilities: Iterable[Dict],
) -> Tuple[Dict[Tuple[str, str, str], int], Dict[str, int]]:
    cwe_package_counts: Dict[Tuple[str, str, str], int] = {}
    repo_counts: Dict[str, int] = {}

    for vulnerability in vulnerabilities:
        for pair in extract_cwe_package_pairs(vulnerability):
            cwe_package_counts[pair] = cwe_package_counts.get(pair, 0) + 1
        for repo in extract_repo_urls(vulnerability):
            repo_counts[repo] = repo_counts.get(repo, 0) + 1

    return cwe_package_counts, repo_counts


def _detect_version_based_recidivism(vulnerability: Dict, vulnerabilities: Iterable[Dict]) -> Dict[str, bool]:
    intervals_by_package = _extract_version_intervals(vulnerability)
    if not intervals_by_package:
        return {"fix_fix": False, "origin_fix": False}

    fix_fix = False
    origin_fix = False
    other_vulnerabilities = list(vulnerabilities)

    for other in other_vulnerabilities:
        if other.get("id") == vulnerability.get("id"):
            continue

        other_intervals = _extract_version_intervals(other)
        for package_key, intervals in intervals_by_package.items():
            other_package_intervals = other_intervals.get(package_key, [])
            if not other_package_intervals:
                continue

            for current_interval in intervals:
                for other_interval in other_package_intervals:
                    if _intervals_overlap(current_interval, other_interval):
                        fix_fix = True
                    if not fix_fix and _compare_versions(current_interval[0], other_interval[1]) is not None and _compare_versions(current_interval[0], other_interval[1]) >= 0:
                        origin_fix = True

    return {"fix_fix": fix_fix, "origin_fix": origin_fix}


def recidivism_for_vulnerability(
    vulnerability: Dict,
    cwe_counts: Dict[Tuple[str, str, str], int],
    repo_counts: Dict[str, int],
    all_vulnerabilities: Optional[Iterable[Dict]] = None,
) -> Dict[str, object]:
    cwes = extract_cwes(vulnerability)
    ecosystems = extract_affected_ecosystems(vulnerability)
    packages = extract_affected_package_pairs(vulnerability)
    repos = extract_repo_urls(vulnerability)
    fix_commits = extract_fix_commits(vulnerability)

    cwe_repeat_count = sum(
        max(cwe_counts.get((cwe, ecosystem, name), 0) - 1, 0)
        for cwe in cwes
        for ecosystem, name in packages
    )
    repo_repeat_count = sum(max(repo_counts.get(repo, 0) - 1, 0) for repo in repos)

    recidivism_score = float(cwe_repeat_count)
    version_recidivism = _detect_version_based_recidivism(vulnerability, all_vulnerabilities or [])
    base_score = parse_base_severity(vulnerability)
    adjusted_score = (
        max(0.0, min(MAX_SEVERITY_SCORE, base_score + recidivism_score))
        if base_score is not None
        else None
    )

    return {
        "cwes": sorted(cwes),
        "affected_ecosystems": sorted(ecosystems),
        "affected_packages": sorted(f"{ecosystem}:{name}" for ecosystem, name in packages),
        "repositories": sorted(repos),
        "fix_commits": sorted(fix_commits),
        "cwe_repeat_count": cwe_repeat_count,
        "repo_repeat_count": repo_repeat_count,
        "score": recidivism_score,
        "base_severity_score": base_score,
        "adjusted_severity_score": adjusted_score,
        "fix_fix_recidivism": version_recidivism["fix_fix"],
        "origin_fix_recidivism": version_recidivism["origin_fix"],
    }
