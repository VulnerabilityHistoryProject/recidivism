#!/usr/bin/env python3
"""Generate individual recidivism score JSON files for each vulnerability.

This script scans osv_recidivism.jsonl, calculates a recidivism score for each
vulnerability using CWE + ecosystem recurrence, and writes the result to
`data/scores/<vulnerability_id>.json`.
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
    parser.add_argument(
        "--input",
        help="Override scores.input from recidivism.ini (path to osv_recidivism.jsonl)",
    )
    parser.add_argument(
        "--output-dir",
        help="Override scores.output_dir from recidivism.ini (destination directory for score files)",
    )
    parser.add_argument(
        "--batch-size",
        type=int,
        default=config.getint("batch_size", fallback=1000),
        help="Number of vulnerabilities to process before reporting progress",
    )
    args = parser.parse_args()

    try:
        input_path = resolve_config_path(
            args.input or get_required_value(config, "scores", "input")
        )
        output_dir = resolve_config_path(
            args.output_dir or get_required_value(config, "scores", "output_dir")
        )
    except ValueError as error:
        parser.error(f"{error} (config: {config_source})")

    # Load all vulnerabilities first
    print(f"Loading vulnerabilities from {input_path}...")
    vulnerabilities = list(load_vulnerabilities_from_jsonl(input_path))
    print(f"Loaded {len(vulnerabilities)} vulnerabilities")

    # Collect CWE/ecosystem and repository history
    print("Collecting CWE/ecosystem and repository history...")
    cwe_counts, repo_counts = collect_history(vulnerabilities)
    print(
        f"Found {len(cwe_counts)} unique CWE+ecosystem pairs and {len(repo_counts)} unique repositories"
    )

    # Create output directory
    output_dir.mkdir(parents=True, exist_ok=True)

    # Generate score files
    print(f"Generating score files in {output_dir}...")
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
    print(f"  Generated: {processed_count} recidivistic score files")
    print(f"  Skipped: {skipped_count} non-recidivistic or invalid vulnerabilities")
    print(f"  Errors: {error_count}")


if __name__ == "__main__":
    main()
