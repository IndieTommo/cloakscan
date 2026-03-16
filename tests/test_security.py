from __future__ import annotations

import unittest

from cloakscan.security import validate_remote_url


class SecurityTests(unittest.TestCase):
    def test_blocks_localhost_hostname(self) -> None:
        error = validate_remote_url("http://localhost/admin")
        self.assertIsNotNone(error)
        self.assertIn("Blocked local hostname", error)

    def test_blocks_private_ip_literal(self) -> None:
        error = validate_remote_url("http://192.168.1.10/")
        self.assertIsNotNone(error)
        self.assertIn("Blocked non-public destination", error)

    def test_blocks_unsupported_scheme(self) -> None:
        error = validate_remote_url("file:///etc/passwd")
        self.assertIsNotNone(error)
        self.assertIn("Blocked unsupported URL scheme", error)

    def test_allow_unsafe_bypasses_checks(self) -> None:
        error = validate_remote_url("http://127.0.0.1/", allow_unsafe=True)
        self.assertIsNone(error)


if __name__ == "__main__":
    unittest.main()
