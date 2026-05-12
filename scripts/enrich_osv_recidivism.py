#!/usr/bin/env python3
import argparse
import json
import shutil
import tarfile
import zipfile
from pathlib import Path
from urllib.request import urlretrieve

from osv_common import collect_history, iter_vulnerability_files, load_vulnerability, recidivism_for_vulnerability
from recidivism_config import load_config, resolve_config_path


def download_dump(url: str, destination: Path, force: bool) -> None:
    if destination.exists() and not force:
        return
    destination.parent.mkdir(parents=True, exist_ok=True)
    urlretrieve(url, destination)


def extract_dump(archive: Path, extract_dir: Path, force: bool) -> None:
    if extract_dir.exists() and force:
        shutil.rmtree(extract_dir)
    extract_dir.mkdir(parents=True, exist_ok=True)

    if archive.suffix == ".zip":
        with zipfile.ZipFile(archive, "r") as zf:
            zf.extractall(extract_dir)
    elif archive.name.endswith(".tar.gz") or archive.suffix == ".tgz":
        with tarfile.open(archive, "r:gz") as tf:
            tf.extractall(extract_dir)
    else:
        raise ValueError(f"Unsupported archive format: {archive}")


def main() -> None:
    config = load_config("enrich")

    parser = argparse.ArgumentParser(description="Download OSV dump and enrich with recidivism metrics.")
    parser.add_argument("--dump-url", default=config.get("dump_url"))
    parser.add_argument("--archive-path", default=config.get("archive_path"))
    parser.add_argument("--extract-dir", default=config.get("extract_dir"))
    parser.add_argument("--output", default=config.get("output"))
    parser.add_argument(
        "--force-download",
        action=argparse.BooleanOptionalAction,
        default=config.getboolean("force_download", fallback=False),
    )
    parser.add_argument(
        "--force-extract",
        action=argparse.BooleanOptionalAction,
        default=config.getboolean("force_extract", fallback=False),
    )
    args = parser.parse_args()

    archive_path = resolve_config_path(args.archive_path)
    extract_dir = resolve_config_path(args.extract_dir)
    output_path = resolve_config_path(args.output)

    download_dump(args.dump_url, archive_path, args.force_download)
    extract_dump(archive_path, extract_dir, args.force_extract)

    vulnerability_files = list(iter_vulnerability_files(extract_dir))
    cwe_counts, repo_counts = collect_history(load_vulnerability(path) for path in vulnerability_files)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    enriched_count = 0
    with output_path.open("w", encoding="utf-8") as handle:
        for path in vulnerability_files:
            vulnerability = load_vulnerability(path)
            metric = recidivism_for_vulnerability(vulnerability, cwe_counts, repo_counts)
            dbs = vulnerability.setdefault("database_specific", {})
            if "recidivism" in dbs:
                print(f"Overwriting existing recidivism metric for vulnerability {vulnerability.get('id', 'UNKNOWN')}")
            dbs["recidivism"] = metric

            severity = [
                item
                for item in vulnerability.setdefault("severity", [])
                if item.get("type") not in {"RECIDIVISM", "RECIDIVISM_ADJUSTED"}
            ]
            severity.append({"type": "RECIDIVISM", "score": f"{metric['score']:.2f}"})
            adjusted = metric["adjusted_severity_score"]
            if adjusted is not None:
                severity.append({"type": "RECIDIVISM_ADJUSTED", "score": f"{adjusted:.2f}"})
            vulnerability["severity"] = severity

            handle.write(json.dumps(vulnerability, sort_keys=True))
            handle.write("\n")
            enriched_count += 1

    print(f"Enriched {enriched_count} vulnerabilities -> {output_path}")


if __name__ == "__main__":
    main()
