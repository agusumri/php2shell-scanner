import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scanner import version_verdict  # noqa: E402


class VersionVerdictTest(unittest.TestCase):
    def test_patched_and_unpatched_releases(self):
        cases = {
            "PHP/8.2.34": "VULNERABLE",
            "PHP/8.2.35": "FIXED",
            "PHP/8.3.35": "VULNERABLE",
            "PHP/8.3.36": "FIXED",
            "PHP/8.4.26": "VULNERABLE",
            "PHP/8.4.27": "FIXED",
            "PHP/8.5.11": "VULNERABLE",
            "PHP/8.5.12": "FIXED",
        }
        for header, expected in cases.items():
            with self.subTest(header=header):
                self.assertEqual(version_verdict(header), expected)

    def test_branches_without_a_fixed_release_are_vulnerable(self):
        # Branches older than the oldest patched release never received a fix,
        # so any advertised version on them is unpatched by construction.
        for header in (
            "PHP/5.6.40",
            "PHP/7.4.33",
            "PHP/8.0.30",
            "PHP/8.1.31",
        ):
            with self.subTest(header=header):
                self.assertEqual(version_verdict(header), "VULNERABLE")

    def test_unknown_future_branches_are_not_judged(self):
        for header in ("PHP/8.6.1", "PHP/9.0.0"):
            with self.subTest(header=header):
                self.assertIsNone(version_verdict(header))

    def test_missing_version_is_not_judged(self):
        for header in ("", "PHP", "Apache/2.4.58"):
            with self.subTest(header=header):
                self.assertIsNone(version_verdict(header))


if __name__ == "__main__":
    unittest.main()
