from __future__ import annotations

import ast
from pathlib import Path
import sys
import unittest

ALLOWED_THIRD_PARTY = {"typer", "rich", "httpx", "playwright", "bs4"}


def _iter_python_files(root: Path) -> list[Path]:
    return [path for path in root.rglob("*.py") if "__pycache__" not in path.parts]


def _top_level(module_name: str) -> str:
    return module_name.split(".")[0]


def _is_stdlib(module_name: str) -> bool:
    top = _top_level(module_name)
    return top in sys.stdlib_module_names


class DependencyGuardTests(unittest.TestCase):
    def test_only_approved_third_party_imports(self) -> None:
        root = Path(__file__).resolve().parent.parent / "cloakscan"
        violations: list[str] = []

        for file_path in _iter_python_files(root):
            tree = ast.parse(file_path.read_text(encoding="utf-8"), filename=str(file_path))
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        top = _top_level(alias.name)
                        if top == "cloakscan":
                            continue
                        if top == "__future__":
                            continue
                        if _is_stdlib(top):
                            continue
                        if top not in ALLOWED_THIRD_PARTY:
                            violations.append(f"{file_path}: import {alias.name}")
                elif isinstance(node, ast.ImportFrom):
                    if node.module is None:
                        continue
                    if node.level and node.level > 0:
                        continue
                    top = _top_level(node.module)
                    if top == "cloakscan":
                        continue
                    if top == "__future__":
                        continue
                    if _is_stdlib(top):
                        continue
                    if top not in ALLOWED_THIRD_PARTY:
                        violations.append(f"{file_path}: from {node.module} import ...")

        self.assertEqual(violations, [], "\n".join(violations))


if __name__ == "__main__":
    unittest.main()
