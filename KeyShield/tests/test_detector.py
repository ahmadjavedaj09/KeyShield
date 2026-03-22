"""
Unit Tests for KeyShield - Keylogger Detection Tool
Run: python -m pytest tests/ -v
"""

import sys
import os
import unittest
import json
import tempfile
from pathlib import Path
from unittest.mock import patch, MagicMock

# Ensure src is importable
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from src.detector import (
    scan_files,
    analyze_risk,
    generate_report,
    SUSPICIOUS_PROCESS_KEYWORDS,
    SUSPICIOUS_FILE_KEYWORDS,
)


class TestAnalyzeRisk(unittest.TestCase):

    def test_clean_system(self):
        risk = analyze_risk([])
        self.assertEqual(risk["level"], "CLEAN")
        self.assertEqual(risk["score"], 0)
        self.assertEqual(risk["total_findings"], 0)

    def test_low_risk(self):
        findings = [{"severity": "INFO"}, {"severity": "WARNING"}]
        risk = analyze_risk(findings)
        self.assertIn(risk["level"], ("CLEAN", "LOW RISK"))

    def test_high_risk(self):
        findings = [{"severity": "HIGH"}] * 5
        risk = analyze_risk(findings)
        self.assertIn(risk["level"], ("MEDIUM RISK", "HIGH RISK"))
        self.assertGreaterEqual(risk["score"], 25)

    def test_counts(self):
        findings = [
            {"severity": "HIGH"},
            {"severity": "HIGH"},
            {"severity": "MEDIUM"},
            {"severity": "INFO"},
        ]
        risk = analyze_risk(findings)
        self.assertEqual(risk["high_count"], 2)
        self.assertEqual(risk["medium_count"], 1)
        self.assertEqual(risk["info_count"], 1)
        self.assertEqual(risk["total_findings"], 4)


class TestGenerateReport(unittest.TestCase):

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()

    def test_generates_both_files(self):
        findings = [{"type": "Test", "severity": "INFO", "message": "unit test"}]
        risk = analyze_risk(findings)
        json_path, txt_path = generate_report(findings, risk, output_dir=self.tmpdir)

        self.assertTrue(Path(json_path).exists(), "JSON report should exist")
        self.assertTrue(Path(txt_path).exists(), "TXT report should exist")

    def test_json_structure(self):
        findings = [{"type": "Test", "severity": "HIGH", "message": "test"}]
        risk = analyze_risk(findings)
        json_path, _ = generate_report(findings, risk, output_dir=self.tmpdir)

        with open(json_path) as f:
            data = json.load(f)

        self.assertIn("tool", data)
        self.assertIn("risk_assessment", data)
        self.assertIn("findings", data)
        self.assertEqual(len(data["findings"]), 1)

    def test_txt_contains_risk_level(self):
        findings = []
        risk = analyze_risk(findings)
        _, txt_path = generate_report(findings, risk, output_dir=self.tmpdir)

        content = Path(txt_path).read_text()
        self.assertIn("RISK LEVEL", content)
        self.assertIn("RECOMMENDATIONS", content)


class TestScanFiles(unittest.TestCase):

    def test_detects_suspicious_file(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create a fake suspicious file
            fake = Path(tmpdir) / "keylog_output.log"
            fake.write_text("fake log data")

            findings = scan_files(search_paths=[Path(tmpdir)])
            types = [f["type"] for f in findings]
            self.assertIn("Suspicious File", types)

    def test_ignores_normal_files(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            normal = Path(tmpdir) / "notes.txt"
            normal.write_text("shopping list")

            findings = scan_files(search_paths=[Path(tmpdir)])
            self.assertEqual(len(findings), 0)

    def test_empty_directory(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            findings = scan_files(search_paths=[Path(tmpdir)])
            self.assertEqual(len(findings), 0)


class TestKeywordLists(unittest.TestCase):

    def test_process_keywords_not_empty(self):
        self.assertGreater(len(SUSPICIOUS_PROCESS_KEYWORDS), 5)

    def test_file_keywords_not_empty(self):
        self.assertGreater(len(SUSPICIOUS_FILE_KEYWORDS), 3)

    def test_keylog_in_process_keywords(self):
        self.assertIn("keylog", SUSPICIOUS_PROCESS_KEYWORDS)

    def test_keylog_in_file_keywords(self):
        self.assertIn("keylog", SUSPICIOUS_FILE_KEYWORDS)


if __name__ == "__main__":
    unittest.main(verbosity=2)
