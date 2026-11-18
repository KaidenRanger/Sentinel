"""
Sentinel Security - Scan History Tests
Version: 0.6.0

Tests for saving and retrieving local scan history.
"""

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from core.scan_history import save_scan, get_scan_history, clear_scan_history

class TestScanHistory(unittest.TestCase):

    def setUp(self):
        """Create a temporary history file for each test."""
        self.temp_dir = tempfile.TemporaryDirectory()
        self.history_file = Path(self.temp_dir.name) / "history.json"

        self.history_patch = patch(
            "core.scan_history.HISTORY_FILE",
            self.history_file
        )
        self.history_patch.start()

    def tearDown(self):
        """Remove temporary test files."""
        self.history_patch.stop()
        self.temp_dir.cleanup()

    def test_save_scan(self):
         """Verify that a scan record is saved."""

         record = save_scan(
             "url",
             "https://example.com",
             "No suspicious indicators"
         )

         self.assertEqual(record["scan_type"], "url")
         self.assertEqual(record["target"], "https://example.com")
         self.assertIn("timestamp", record)

         with self.history_file.open("r", encoding="utf-8") as file:
             history = json.load(file)

         self.assertEqual(len(history), 1)

    def test_get_scan_history(self):
        """Verify that saved scans can be retrieved."""

        save_scan("file", "test.txt", "No known threats")

        history = get_scan_history()

        self.assertEqual(len(history), 1)
        self.assertEqual(history[0]["scan_type"], "file")

    def test_empty_history(self):
        """Verify that missing history returns an empty list."""

        history = get_scan_history()

        self.assertEqual(history, [])

    def test_clear_scan_history(self):
        """Verify that clearing history deletes saved records."""

        save_scan("file", "test.txt", "No known threats")

        self.assertTrue(self.history_file.exists())

        with patch("core.scan_history.HISTORY_FILE", self.history_file):
            result = clear_scan_history()

        self.assertTrue(result)
        self.assertFalse(self.history_file.exists())
        self.assertEqual(get_scan_history(), [])

    def test_clear_empty_history(self):
        """Verify that clearing nonexistent history succeeds."""

        self.assertFalse(self.history_file.exists())

        result = clear_scan_history()

        self.assertTrue(result)
        self.assertEqual(get_scan_history(), [])

if __name__ == "__main__":
    unittest.main()