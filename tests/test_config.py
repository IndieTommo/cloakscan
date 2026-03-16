from __future__ import annotations

from pathlib import Path
import os
import unittest

from cloakscan.config import ConfigError, load_scan_config


class ConfigTests(unittest.TestCase):
    def test_default_balanced_workers(self) -> None:
        tmp_dir = Path("tests") / "_tmp_config_default"
        tmp_dir.mkdir(parents=True, exist_ok=True)
        old_cwd = Path.cwd()
        os.chdir(tmp_dir)
        try:
            config = load_scan_config(preset="balanced", config_path=None)
        finally:
            os.chdir(old_cwd)

        self.assertEqual(config.concurrency.http_workers, 3)
        self.assertEqual(config.concurrency.headless_workers, 1)

    def test_config_override_applies(self) -> None:
        tmp_dir = Path("tests") / "_tmp_config_override"
        tmp_dir.mkdir(parents=True, exist_ok=True)
        path = tmp_dir / "cloakscan.toml"
        path.write_text(
            "\n".join(
                [
                    "retries = 2",
                    "[concurrency]",
                    "http_workers = 4",
                    "headless_workers = 1",
                    "[thresholds]",
                    "similarity_min = 0.7",
                ]
            ),
            encoding="utf-8",
        )
        config = load_scan_config(preset="balanced", config_path=path)

        self.assertEqual(config.retries, 2)
        self.assertEqual(config.concurrency.http_workers, 4)
        self.assertEqual(config.concurrency.headless_workers, 1)
        self.assertAlmostEqual(config.thresholds.similarity_min, 0.7)

    def test_invalid_preset_raises(self) -> None:
        with self.assertRaises(ConfigError):
            load_scan_config(preset="unknown", config_path=None)


if __name__ == "__main__":
    unittest.main()
