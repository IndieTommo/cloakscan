from __future__ import annotations

from pathlib import Path
import unittest

from cloakscan.input import collect_targets, parse_text_targets


class InputParserTests(unittest.TestCase):
    def test_parses_newline_semicolon_and_standalone_colon(self) -> None:
        text = (
            "https://example.com/\n"
            "example.org;example.net\n"
            "alpha.test : beta.test"
        )
        parsed = parse_text_targets(text)
        self.assertEqual(
            parsed,
            [
                "https://example.com/",
                "example.org",
                "example.net",
                "alpha.test",
                "beta.test",
            ],
        )

    def test_does_not_split_urls_or_ports(self) -> None:
        text = "https://example.com:8443/path : http://two.example/path"
        parsed = parse_text_targets(text)
        self.assertEqual(parsed, ["https://example.com:8443/path", "http://two.example/path"])

    def test_collect_targets_from_cli_and_file(self) -> None:
        tmp_dir = Path("tests") / "_tmp_input"
        tmp_dir.mkdir(parents=True, exist_ok=True)
        path = tmp_dir / "targets.txt"
        path.write_text("foo.test;bar.test\nbaz.test : qux.test", encoding="utf-8")

        targets = collect_targets(
            cli_targets=["https://one.example/", ":", "https://two.example/"],
            input_path=path,
        )

        normalized = [target.normalized_url for target in targets]
        self.assertIn("https://one.example/", normalized)
        self.assertIn("https://two.example/", normalized)
        self.assertIn("https://foo.test/", normalized)
        self.assertIn("https://bar.test/", normalized)
        self.assertIn("https://baz.test/", normalized)
        self.assertIn("https://qux.test/", normalized)

    def test_rejects_unsupported_scheme(self) -> None:
        with self.assertRaises(RuntimeError):
            collect_targets(cli_targets=["ftp://example.com"], input_path=None)


if __name__ == "__main__":
    unittest.main()
