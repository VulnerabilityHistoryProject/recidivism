#!/usr/bin/env python3
"""Generate recidivism scores for each vulnerability, as available.

Calculates a recidivism score for each vulnerability using
CWE + ecosystem + package recurrence,
then writes results to data/osv_recidivism.jsonl
"""

import argparse
import json
import sys
from pathlib import Path
from typing import Dict, Iterable

from osv_common import collect_history, recidivism_for_vulnerability
from recidivism_config import get_required_value, load_config_with_source, resolve_config_path

def load_vulnerabilities_from_jsonl(jsonl_path: Path) -> Iterable[Dict]:
    """Load vulnerabilities from a JSONL file."""
    if not jsonl_path.exists():
        raise FileNotFoundError(f"JSONL file not found: {jsonl_path}")

    with jsonl_path.open("r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if line:
                yield json.loads(line)


def main() -> None:
    config, config_source = load_config_with_source("scores")

    parser = argparse.ArgumentParser(
        description="Generate individual recidivism score JSON files for each vulnerability."
    )
    parser.add_argument("--archive-path", help="Override dump.archive_path from recidivism.ini")
    parser.add_argument("--jsonl-output", help="Override scores.jsonl_output from recidivism.ini")

    args = parser.parse_args()

    try:
        archive_path = resolve_config_path(
            args.archive_path or get_required_value(config, "dump", "archive_path")
        )
        output_path = resolve_config_path(
            args.jsonl_output or get_required_value(config, "scores", "jsonl_output")
        )
    except ValueError as error:
        parser.error(f"{error} (config: {config_source})")

    # Load all vulnerabilities first
    print(f"Loading vulnerabilities from {archive_path}...")


    # vulnerabilities = list(load_vulnerabilities_from_jsonl())
    vulnerabilities = [] # FIXME - need to update this with our new inputs - the zip file instead
    print(f"Loaded {len(vulnerabilities)} vulnerabilities")

    # Collect CWE/ecosystem and repository history
    print("Collecting CWE/ecosystem and repository history...")
    cwe_counts, repo_counts = collect_history(vulnerabilities)
    print(
        f"Found {len(cwe_counts)} unique CWE+ecosystem pairs and {len(repo_counts)} unique repositories"
    )

    # FIXME - Remove and just do jsonl output
    # # Create output directory
    # output_dir.mkdir(parents=True, exist_ok=True)

    # # Generate score files
    # print(f"Generating score files in {output_dir}...")
    processed_count = 0
    skipped_count = 0
    error_count = 0

    for vulnerability in vulnerabilities:
        try:
            vuln_id = vulnerability.get("id")
            if not vuln_id:
                skipped_count += 1
                continue

            # Calculate recidivism score
            score_data = recidivism_for_vulnerability(
                vulnerability, cwe_counts, repo_counts
            )

            # Only emit JSON for recidivistic vulnerabilities
            if score_data.get("score", 0.0) <= 0.0:
                skipped_count += 1
                continue

            output_file = output_dir / f"{vuln_id}.json"
            with output_file.open("w", encoding="utf-8") as handle:
                json.dump(score_data, handle, indent=2, sort_keys=True)

            processed_count += 1

            if processed_count % args.batch_size == 0:
                print(f"  Processed {processed_count} recidivistic vulnerabilities...")

        except Exception as e:
            print(f"Error processing vulnerability: {e}", file=sys.stderr)
            error_count += 1

    print(f"\nCompleted!")
    print(f"  Generated: {processed_count} recidivistic scores")
    print(f"  Skipped: {skipped_count} non-recidivistic or invalid vulnerabilities")
    print(f"  Errors: {error_count}")


if __name__ == "__main__":
    main()
