import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str((Path(__file__).resolve().parents[1] / "scripts")))

from generate_recidivism_scores import load_vulnerabilities_from_jsonl, main  # noqa: E402


class GenerateRecidivismScoresTests(unittest.TestCase):
    def test_load_vulnerabilities_from_jsonl(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            jsonl_file = temp_path / "vulnerabilities.jsonl"
            jsonl_file.write_text(
                '{"id": "A"}\n{"id": "B"}\n', encoding="utf-8"
            )

            vulnerabilities = list(load_vulnerabilities_from_jsonl(jsonl_file))

        self.assertEqual(len(vulnerabilities), 2)
        self.assertEqual(vulnerabilities[0]["id"], "A")
        self.assertEqual(vulnerabilities[1]["id"], "B")

    def test_main_writes_only_recidivistic_files(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            input_jsonl = temp_path / "input.jsonl"
            output_dir = temp_path / "scores"

            input_jsonl.write_text(
                "{"
                '"id": "R1", "database_specific": {"cwe_ids": ["CWE-79"]}, '
                '"affected": [{"package": {"ecosystem": "pip", "name": "example"}}], '
                '"references": [{"url": "https://github.com/example/project"}]}'
                "\n"
                "{"
                '"id": "R2", "database_specific": {"cwe_ids": ["CWE-79"]}, '
                '"affected": [{"package": {"ecosystem": "pip", "name": "example"}}], '
                '"references": [{"url": "https://github.com/example/project"}]}'
                "\n"
                "{"
                '"id": "N", "database_specific": {"cwe_ids": ["CWE-200"]}, '
                '"affected": [{"package": {"ecosystem": "npm", "name": "other"}}], '
                '"references": [{"url": "https://github.com/other/project"}]}'
                "\n",
                encoding="utf-8",
            )

            original_argv = sys.argv
            try:
                sys.argv = [
                    "generate_recidivism_scores.py",
                    "--input",
                    str(input_jsonl),
                    "--output-dir",
                    str(output_dir),
                ]
                main()
            finally:
                sys.argv = original_argv

            files = sorted([p.name for p in output_dir.iterdir() if p.is_file()])

            self.assertEqual(files, ["R1.json", "R2.json"])

            output_data = json.loads((output_dir / "R1.json").read_text(encoding="utf-8"))
            self.assertGreater(output_data["score"], 0.0)
