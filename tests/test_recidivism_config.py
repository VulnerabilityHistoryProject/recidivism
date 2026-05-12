import contextlib
import io
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str((Path(__file__).resolve().parents[1] / "scripts")))

from recidivism_config import load_config, resolve_config_path  # noqa: E402


class RecidivismConfigTests(unittest.TestCase):
    def test_loads_default_and_prints_message_when_local_missing(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            default_config = tmp_path / "recidivism.default.ini"
            default_config.write_text("[enrich]\noutput = data/out.jsonl\n", encoding="utf-8")

            output = io.StringIO()
            with patch("recidivism_config.LOCAL_CONFIG_FILE", tmp_path / "recidivism.ini"), patch(
                "recidivism_config.DEFAULT_CONFIG_FILE", default_config
            ), contextlib.redirect_stdout(output):
                section = load_config("enrich")

            self.assertEqual(section.get("output"), "data/out.jsonl")
            self.assertIn("Missing recidivism.ini", output.getvalue())

    def test_resolve_config_path_uses_repo_root_for_relative(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            with patch("recidivism_config.REPO_ROOT", tmp_path):
                resolved = resolve_config_path("data/example.json")
            self.assertEqual(resolved, (tmp_path / "data/example.json").resolve())


if __name__ == "__main__":
    unittest.main()
