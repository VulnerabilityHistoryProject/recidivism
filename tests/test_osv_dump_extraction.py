import json
import re
import sys
import unittest
from pathlib import Path
from typing import Optional

sys.path.insert(0, str((Path(__file__).resolve().parents[1] / "scripts")))

from osv_common import extract_fix_commits, iter_vulnerability_files, load_vulnerability  # noqa: E402

_COMMIT_RE = re.compile(r"/commit/([0-9a-fA-F]{7,40})")
_HEX_SHA_RE = re.compile(r"^[0-9a-fA-F]{7,40}$")


def extract_origin_commit(vulnerability: dict) -> Optional[str]:
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


def extract_environments(vulnerability: dict) -> set[str]:
    environments: set[str] = set()
    for affected in vulnerability.get("affected", []):
        package = affected.get("package", {})
        ecosystem = package.get("ecosystem")
        if isinstance(ecosystem, str):
            environments.add(ecosystem)
    return environments


def extract_packages(vulnerability: dict) -> set[str]:
    packages: set[str] = set()
    for affected in vulnerability.get("affected", []):
        package = affected.get("package", {})
        name = package.get("name")
        if isinstance(name, str):
            packages.add(name)
    return packages


def extract_fixed_when(vulnerability: dict) -> set[str]:
    fixed_when: set[str] = set()

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


def extract_cves(vulnerability: dict) -> set[str]:
    cves: set[str] = set()
    for alias in vulnerability.get("aliases", []):
        if isinstance(alias, str) and alias.startswith("CVE-"):
            cves.add(alias)
    return cves


def extract_vulnerability_info(vulnerability: dict) -> dict[str, object]:
    return {
        "id": vulnerability.get("id"),
        "fix_commits": sorted(extract_fix_commits(vulnerability)),
        "origin_commit": extract_origin_commit(vulnerability),
        "fixed_when": sorted(extract_fixed_when(vulnerability)),
        "environments": sorted(extract_environments(vulnerability)),
        "packages": sorted(extract_packages(vulnerability)),
        "cves": sorted(extract_cves(vulnerability)),
    }


def print_vulnerability_info(path: Path, info: dict[str, object]) -> None:
    print(f"Extracted from {path.name}:")
    print(f"  id: {info['id']}")
    print(f"  packages: {info['packages']}")
    print(f"  environments: {info['environments']}")
    print(f"  fix_commits: {info['fix_commits']}")
    print(f"  fixed_when: {info['fixed_when']}")
    print(f"  origin_commit: {info['origin_commit']}")
    print(f"  cves: {info['cves']}")
    print()


class OsvDumpExtractionTests(unittest.TestCase):
    def test_extracts_expected_fields_from_sample_dump(self) -> None:
        dump_dir = Path(__file__).resolve().parents[1] / "testdata" / "osv_dump"
        files = sorted(iter_vulnerability_files(dump_dir))
        self.assertTrue(files, "No OSV dump files found in testdata/osv_dump")

        for path in files:
            vulnerability = load_vulnerability(path)
            info = extract_vulnerability_info(vulnerability)
            print_vulnerability_info(path, info)

            self.assertEqual(info["id"], vulnerability.get("id"))
            self.assertIsInstance(info["fix_commits"], list)
            self.assertIsInstance(info["environments"], list)
            self.assertIsInstance(info["packages"], list)

        ghsa_path = dump_dir / "GHSA-4j5m-wc25-pvh7.json"
        if ghsa_path.exists():
            ghsa = load_vulnerability(ghsa_path)
            ghsa_info = extract_vulnerability_info(ghsa)

            self.assertEqual(ghsa_info["id"], "GHSA-4j5m-wc25-pvh7")
            self.assertIn("onenote_parser", ghsa_info["packages"])
            self.assertIn("crates.io", ghsa_info["environments"])
            self.assertIn("c9267b2c96e2542be7e7b557d67318e81b733585", ghsa_info["fix_commits"])
            self.assertIn("1.1.1", ghsa_info["fixed_when"])
            self.assertIn("CVE-2026-46671", ghsa_info["cves"])
            self.assertIsNone(ghsa_info["origin_commit"])

    def test_origin_commit_is_recorded_when_present(self) -> None:
        vulnerability = {
            "id": "ORIGIN-TEST",
            "aliases": ["CVE-2026-99999"],
            "affected": [
                {
                    "package": {"name": "example", "ecosystem": "npm"},
                }
            ],
            "references": [
                {"type": "ORIGIN", "url": "https://github.com/example/example/commit/abcdef0123456789"}
            ],
        }
        info = extract_vulnerability_info(vulnerability)

        self.assertEqual(info["origin_commit"], "abcdef0123456789")
        self.assertEqual(info["packages"], ["example"])
        self.assertEqual(info["environments"], ["npm"])
        self.assertEqual(info["cves"], ["CVE-2026-99999"])


if __name__ == "__main__":
    unittest.main()
