#!/usr/bin/env python3
import argparse
import json
import re
from pathlib import Path
from typing import Dict, Optional, Set

from osv_common import extract_fix_commits, iter_vulnerability_files, load_vulnerability

_COMMIT_RE = re.compile(r"/commit/([0-9a-fA-F]{7,40})")
_HEX_SHA_RE = re.compile(r"^[0-9a-fA-F]{7,40}$")


def extract_origin_commit(vulnerability: Dict) -> Optional[str]:
    db_specific = vulnerability.get("database_specific", {})
    origin_commit = db_specific.get("origin_commit")
    if isinstance(origin_commit, str) and _HEX_SHA_RE.match(origin_commit):
        return origin_commit.lower()

    for reference in vulnerability.get("references", []):
        if reference.get("type") == "ORIGIN":
            url = reference.get("url")
            if isinstance(url, str):
                match = _COMMIT_RE.search(url)
                if match:
                    return match.group(1).lower()
    return None


def extract_environments(vulnerability: Dict) -> Set[str]:
    environments: Set[str] = set()
    for affected in vulnerability.get("affected", []):
        package = affected.get("package", {})
        ecosystem = package.get("ecosystem")
        if isinstance(ecosystem, str):
            environments.add(ecosystem)
    return environments


def extract_packages(vulnerability: Dict) -> Set[str]:
    packages: Set[str] = set()
    for affected in vulnerability.get("affected", []):
        package = affected.get("package", {})
        name = package.get("name")
        if isinstance(name, str):
            packages.add(name)
    return packages


def extract_fixed_when(vulnerability: Dict) -> Set[str]:
    fixed_when: Set[str] = set()
    for affected in vulnerability.get("affected", []):
        for range_entry in affected.get("ranges", []):
            for event in range_entry.get("events", []):
                fixed_value = event.get("fixed")
                if not isinstance(fixed_value, str):
                    continue
                if _HEX_SHA_RE.match(fixed_value):
                    continue
                fixed_when.add(fixed_value)
    return fixed_when


def extract_cves(vulnerability: Dict) -> Set[str]:
    cves: Set[str] = set()
    for alias in vulnerability.get("aliases", []):
        if isinstance(alias, str) and alias.startswith("CVE-"):
            cves.add(alias)
    return cves


def extract_vulnerability_info(vulnerability: Dict) -> Dict[str, object]:
    return {
        "id": vulnerability.get("id"),
        "packages": sorted(extract_packages(vulnerability)),
        "environments": sorted(extract_environments(vulnerability)),
        "fix_commits": sorted(extract_fix_commits(vulnerability)),
        "fixed_when": sorted(extract_fixed_when(vulnerability)),
        "origin_commit": extract_origin_commit(vulnerability),
        "cves": sorted(extract_cves(vulnerability)),
    }


def write_extracted_jsonl(output_path: Path, records: list[Dict[str, object]]) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8") as handle:
        for record in records:
            handle.write(json.dumps(record, sort_keys=True))
            handle.write("\n")


def print_extracted_info(path: Path, info: Dict[str, object]) -> None:
    print(f"Extracted from {path.name}:")
    print(f"  id: {info['id']}")
    print(f"  packages: {info['packages']}")
    print(f"  environments: {info['environments']}")
    print(f"  fix_commits: {info['fix_commits']}")
    print(f"  fixed_when: {info['fixed_when']}")
    print(f"  origin_commit: {info['origin_commit']}")
    print(f"  cves: {info['cves']}")
    print()


def main() -> None:
    default_root = Path(__file__).resolve().parents[1]
    default_osv_dir = default_root / "testdata" / "osv_dump"
    default_output = default_root / "data" / "extraction" / "osv_extracted.jsonl"

    parser = argparse.ArgumentParser(description="Extract OSV metadata from JSON dump files and write it as JSONL.")
    parser.add_argument(
        "--osv-dir",
        default=str(default_osv_dir),
        help="Directory containing extracted OSV JSON files.",
    )
    parser.add_argument(
        "--output",
        default=str(default_output),
        help="Path to the output JSONL file.",
    )
    args = parser.parse_args()

    osv_dir = Path(args.osv_dir)
    output_path = Path(args.output)

    records: list[Dict[str, object]] = []
    seen_ids: set[str] = set()
    seen_signatures: set[str] = set()

    for path in sorted(iter_vulnerability_files(osv_dir)):
        vulnerability = load_vulnerability(path)
        info = extract_vulnerability_info(vulnerability)

        # attach source file for traceability
        output_record: Dict[str, object] = dict(info)
        output_record["source_file"] = path.name

        vid = output_record.get("id")
        if isinstance(vid, str) and vid:
            if vid in seen_ids:
                print(f"Skipping duplicate vulnerability id {vid} from {path.name}")
                continue
            seen_ids.add(vid)
        else:
            # fallback dedupe by stable JSON signature of extracted fields
            signature = json.dumps({
                k: output_record.get(k) for k in ("packages", "environments", "fix_commits", "fixed_when", "origin_commit", "cves")
            }, sort_keys=True)
            if signature in seen_signatures:
                print(f"Skipping duplicate (no id) from {path.name}")
                continue
            seen_signatures.add(signature)

        print_extracted_info(path, output_record)
        records.append(output_record)

    write_extracted_jsonl(output_path, records)
    print(f"Wrote {len(records)} extracted records to {output_path}")


if __name__ == "__main__":
    main()
