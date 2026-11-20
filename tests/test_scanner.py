import os
import unittest

from apkscan.scanner import mask, scan_apk

DEMO = os.path.join(os.path.dirname(__file__), "..", "samples", "demo.apk")


class ScannerTests(unittest.TestCase):
    def setUp(self):
        self.findings, self.stats = scan_apk(DEMO)
        self.ids = {f["rule_id"] for f in self.findings}

    def test_detects_secrets(self):
        for rule in ("SEC001", "SEC002", "SEC003", "SEC004", "SEC005", "SEC006", "SEC007"):
            self.assertIn(rule, self.ids)

    def test_detects_storage_issues(self):
        for rule in ("STO001", "STO002", "STO003", "STO004", "STO005", "STO006", "STO007"):
            self.assertIn(rule, self.ids)

    def test_secrets_are_masked(self):
        aws = [f for f in self.findings if f["rule_id"] == "SEC001"][0]
        self.assertNotIn("AKIAIOSFODNN7EXAMPLE", aws["match"])

    def test_mask_short_values(self):
        self.assertEqual(mask("abc"), "***")

    def test_abort_stops_scan(self):
        _, stats = scan_apk(DEMO, should_stop=lambda: True)
        self.assertTrue(stats["aborted"])


if __name__ == "__main__":
    unittest.main()
