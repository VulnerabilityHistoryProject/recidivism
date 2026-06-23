#!/usr/bin/env python3
import argparse
import zipfile
from pathlib import Path
from urllib.request import urlretrieve
from recidivism_config import get_required_value, load_config_with_source, resolve_config_path

def download_dump(url: str, destination: Path, force: bool) -> None:
    if destination.exists() and not force:
        return
    destination.parent.mkdir(parents=True, exist_ok=True)
    urlretrieve(url, destination)

def print_dump_info(archive_path: Path) -> None:
    """Print information about the downloaded dump file."""
    with zipfile.ZipFile(archive_path, "r") as zip_file:
        print(f"Dump contains {len(zip_file.namelist())} files.")

def main() -> None:
    config, config_source = load_config_with_source("dump")
    parser = argparse.ArgumentParser(description="Download OSV dump and copy extracted JSON content into a JSONL file.")
    parser.add_argument("--osv-dump-url", help="Override dump.osv_dump_url from recidivism.ini")
    parser.add_argument("--archive-path", help="Override dump.archive_path from recidivism.ini")
    parser.add_argument(
        "--force-download",
        action=argparse.BooleanOptionalAction,
        default=config.getboolean("force_download", fallback=False),
    )

    args = parser.parse_args()

    try:
        dump_url = args.osv_dump_url or get_required_value(config, "dump", "osv_dump_url")
        archive_path = resolve_config_path(args.archive_path or get_required_value(config, "dump", "archive_path"))
    except ValueError as error:
        parser.error(f"{error} (config: {config_source})")

    download_dump(dump_url, archive_path, args.force_download)

    print(f"Downloaded dump file to  {archive_path}.")
    print_dump_info(archive_path)


if __name__ == "__main__":
    main()

