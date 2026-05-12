import sys
import unittest
from pathlib import Path

sys.path.insert(0, str((Path(__file__).resolve().parents[1] / "scripts")))

from osv_common import (  # noqa: E402
    collect_history,
    extract_cwes,
    extract_fix_commits,
    extract_repo_urls,
    recidivism_for_vulnerability,
)


class OsvCommonTests(unittest.TestCase):
    def test_extractors(self) -> None:
        vulnerability = {
            "database_specific": {"cwe_ids": ["CWE-79"]},
            "affected": [
                {
                    "database_specific": {"cwe_ids": ["CWE-89"]},
                    "ranges": [{"events": [{"fixed": "a1b2c3d4"}]}],
                }
            ],
            "references": [
                {"url": "https://github.com/example/project"},
                {"url": "https://github.com/example/project/commit/deadbeef"},
            ],
        }

        self.assertEqual(extract_cwes(vulnerability), {"CWE-79", "CWE-89"})
        self.assertEqual(extract_repo_urls(vulnerability), {"https://github.com/example/project.git"})
        self.assertEqual(extract_fix_commits(vulnerability), {"a1b2c3d4", "deadbeef"})

    def test_recidivism_metric(self) -> None:
        v1 = {
            "id": "A",
            "database_specific": {"cwe_ids": ["CWE-79"]},
            "severity": [{"type": "CVSS_V3", "score": "7.5"}],
            "references": [{"url": "https://github.com/example/project"}],
        }
        v2 = {
            "id": "B",
            "database_specific": {"cwe_ids": ["CWE-79"]},
            "references": [{"url": "https://github.com/example/project"}],
        }

        cwe_counts, repo_counts = collect_history([v1, v2])
        metric = recidivism_for_vulnerability(v1, cwe_counts, repo_counts)

        self.assertEqual(metric["cwe_repeat_count"], 1)
        self.assertEqual(metric["repo_repeat_count"], 1)
        self.assertEqual(metric["score"], 2.0)
        self.assertEqual(metric["adjusted_severity_score"], 9.5)


if __name__ == "__main__":
    unittest.main()
