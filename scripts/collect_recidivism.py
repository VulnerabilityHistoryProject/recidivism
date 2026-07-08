#!/usr/bin/env python3
"""Generate recidivism scores for each vulnerability, as available.

Calculates a recidivism score for each vulnerability using
CWE + ecosystem + package recurrence,
then writes results to data/osv_recidivism.jsonl
"""

import argparse
import json
import sys
import zipfile
from pathlib import Path
from typing import Dict, Iterable

from osv_common import collect_history, recidivism_for_vulnerability
from recidivism_config import get_required_value, load_config_with_source, resolve_config_path


def build_output_record(vulnerability: Dict, score_data: Dict) -> Dict:
    """Build a JSONL record matching the sample recidivism format."""
    return {
        "id": vulnerability.get("id"),
        "severity": [{"type": "recidivism", "score": "recidivistic:true"}],
        "score": score_data.get("score"),
        "type_recidivistic": bool(score_data.get("score", 0.0) > 0.0),
        "fix_fix_recidivism": bool(score_data.get("fix_fix_recidivism", False)),
        "origin_fix_recidivism": bool(score_data.get("origin_fix_recidivism", False)),
    }


def load_vulnerabilities_from_zip(zip_path: Path) -> Iterable[Dict]:
    """Load vulnerabilities from a zip file by iterating through JSON files."""
    if not zip_path.exists():
        raise FileNotFoundError(f"Zip file not found: {zip_path}")

    with zipfile.ZipFile(zip_path, "r") as zf:
        for name in zf.namelist():
            if name.endswith(".json"):
                try:
                    with zf.open(name) as f:
                        yield json.load(f)
                except (json.JSONDecodeError, IOError) as e:
                    print(f"Warning: Failed to parse {name}: {e}", file=sys.stderr)


def main() -> None:
    # Load both dump and scores configuration sections
    dump_config, dump_source = load_config_with_source("dump")
    scores_config, scores_source = load_config_with_source("scores")

    parser = argparse.ArgumentParser(
        description="Generate recidivism scores from OSV-all.zip and write to JSONL output."
    )
    parser.add_argument(
        "--archive-path",
        help="Override scores.archive_path from recidivism.ini (path to OSV-all.zip)",
    )
    parser.add_argument(
        "--jsonl-output",
        help="Override scores.jsonl_output from recidivism.ini (destination JSONL file)",
    )
    parser.add_argument(
        "--batch-size",
        type=int,
        default=scores_config.getint("batch_size", fallback=1000),
        help="Number of vulnerabilities to process before reporting progress",
    )
    args = parser.parse_args()

    try:
        archive_path = resolve_config_path(
            args.archive_path or get_required_value(dump_config, "dump", "archive_path")
        )
        output_path = resolve_config_path(
            args.jsonl_output or get_required_value(scores_config, "scores", "jsonl_output")
        )
    except ValueError as error:
        # Prefer showing both config sources if available
        parser.error(f"{error} (config: {dump_source} / {scores_source})")

    # Load all vulnerabilities from zip
    print(f"Loading vulnerabilities from {archive_path}...")
    vulnerabilities = list(load_vulnerabilities_from_zip(archive_path))
    print(f"Loaded {len(vulnerabilities)} vulnerabilities")

    # Collect CWE/ecosystem and repository history
    print("Collecting CWE/ecosystem and repository history...")
    cwe_counts, repo_counts = collect_history(vulnerabilities)
    print(
        f"Found {len(cwe_counts)} unique CWE+ecosystem pairs and {len(repo_counts)} unique repositories"
    )

    # Create output file path
    output_path.parent.mkdir(parents=True, exist_ok=True)

    # Generate JSONL output with only recidivistic vulnerabilities
    print(f"Writing recidivistic vulnerabilities to {output_path}...")
    processed_count = 0
    skipped_count = 0
    error_count = 0

    with output_path.open("w", encoding="utf-8") as output_handle:
        for vulnerability in vulnerabilities:
            try:
                vuln_id = vulnerability.get("id")
                if not vuln_id:
                    skipped_count += 1
                    continue

                # Calculate recidivism score
                score_data = recidivism_for_vulnerability(
                    vulnerability, cwe_counts, repo_counts, vulnerabilities
                )

                # Only write recidivistic vulnerabilities to output
                if score_data.get("score", 0.0) <= 0.0:
                    skipped_count += 1
                    continue

                output_record = build_output_record(vulnerability, score_data)
                output_handle.write(json.dumps(output_record, sort_keys=True))
                output_handle.write("\n")
                processed_count += 1

                if processed_count % args.batch_size == 0:
                    print(f"  Processed {processed_count} recidivistic vulnerabilities...")

            except Exception as e:
                print(f"Error processing vulnerability: {e}", file=sys.stderr)
                error_count += 1

    print(f"\nCompleted!")
    print(f"  Written: {processed_count} recidivistic vulnerabilities")
    print(f"  Skipped: {skipped_count} non-recidivistic or invalid vulnerabilities")
    print(f"  Errors: {error_count}")


if __name__ == "__main__":
    main()
