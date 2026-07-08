import sys
import unittest
from pathlib import Path

sys.path.insert(0, str((Path(__file__).resolve().parents[1] / "scripts")))

from collect_recidivism import build_output_record  # noqa: E402


class CollectRecidivismTests(unittest.TestCase):
    def test_build_output_record_matches_example_format(self) -> None:
        vulnerability = {"id": "GHSA-123"}
        score_data = {
            "score": 1.0,
            "fix_fix_recidivism": False,
            "origin_fix_recidivism": True,
        }

        record = build_output_record(vulnerability, score_data)

        self.assertEqual(record["id"], "GHSA-123")
        self.assertEqual(
            record["severity"],
            [{"type": "recidivism", "score": "recidivistic:true"}],
        )
        self.assertTrue(record["type_recidivistic"])
        self.assertFalse(record["fix_fix_recidivism"])
        self.assertTrue(record["origin_fix_recidivism"])


if __name__ == "__main__":
    unittest.main()
