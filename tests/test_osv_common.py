import sys
import unittest
from pathlib import Path

sys.path.insert(0, str((Path(__file__).resolve().parents[1] / "scripts")))

from osv_common import (  # noqa: E402
    extract_cwes,
    extract_fix_commits,
    extract_repo_urls,
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

if __name__ == "__main__":
    unittest.main()
