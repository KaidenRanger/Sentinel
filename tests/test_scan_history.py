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

from core.scan_history import (
    save_scan,
    get_scan_history,
    clear_scan_history,
    sanitize_url,
)

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

    def test_sanitize_query_parameters(self):
        """Verify that sensitive query parameters are removed."""

        url =  "https://example.com/login?token=abc123&api_key=secret456"

        self.assertEqual(
            sanitize_url(url),
            "https://example.com/login"
        )

    def test_sanitize_fragment(self):
        """Verify that URL fragments are removed."""

        url = "https://example.com/login#session123"

        self.assertEqual(
            sanitize_url(url),
            "https://example.com/login"
        )

    def test_sanitize_credentials(self):
        """Verify that embedded credentials are removed."""

        url = "https://admin:password@example.com/login"

        self.assertEqual(
            sanitize_url(url),
            "https://example.com/login"
        )

    def test_sanitize_normal_url(self):
        """Verify that normal URLs remain unchanged."""

        url = "https://example.com:8443/login"

        self.assertEqual(sanitize_url(url), url)

    def test_sanitize_invalid_url(self):
        """Verify that invalid URLs are not stored directly."""

        self.assertEqual(
            sanitize_url("not-a-valid-url"),
            "[Invalid URL]"
        )

    def test_save_sanitized_url(self):
        """Verify that sensitive URL data is not written to disk."""

        url = (
            "https://admin:password@example.com/login"
            "?token=abc123#session456"
        )

        record = save_scan("url", url, "No suspicious indicators")

        self.assertEqual(
            record["target"],
            "https://example.com/login"
        )

        saved_content = self.history_file.read_text(
            encoding="utf-8"
        )

        for secret in ("admin", "password", "abc123", "session456"):
            self.assertNotIn(secret, saved_content)

    def test_file_target_unchanged(self):
        """Verify that file scan targets are not sanitized."""

        target = "test_file.txt"

        record = save_scan("file", target, "no known threats")

        self.assertEqual(record["target"], target)
        self.assertEqual(get_scan_history()[0]["target"], target)

    def test_save_scan_preserves_corrupted_history(self):
         """Verify corrupted JSON is not overwritten."""
         original_content = "{invalid json"

         self.history_file.write_text(
             original_content,encoding="utf-8"
         )

         with self.assertRaises(ValueError):
             save_scan("file", "example.txt", "Clean")

         self.assertEqual(
             self.history_file.read_text(encoding="utf-8"),
             original_content
         )

    def test_save_scan_preserves_invalid_history_format(self):
        """Verify an invalid history format is not overwritten."""
        original_content = '{"invalid": "format"}'

        self.history_file.write_text(
            original_content, encoding="utf-8"
        )

        with self.assertRaises(ValueError):
            save_scan("file", "example.txt", "Clean")

        self.assertEqual(
            self.history_file.read_text(encoding="utf-8"),
            original_content
        )

    def test_save_scan_preserves_history_on_read_error(self):
        """Verify a read error does not cause data loss."""
        original_content = "[]"

        self.history_file.write_text(
            original_content, encoding="utf-8"
        )

        with patch(
            "pathlib.Path.open",
            side_effect=OSError("Simulated read error")
        ):
            with self.assertRaises(ValueError):
                save_scan("file", "example.txt", "Clean")

        self.assertEqual(
            self.history_file.read_text(encoding="utf-8"),
            original_content
        )

    def test_atomic_write_success(self):
        """Verify successful writes preserve previous records."""
        save_scan("file", "first.txt", "Clean")
        save_scan("file", "second.txt", "Clean")

        history = get_scan_history()

        self.assertEqual(len(history), 2)
        self.assertEqual(history[0]["target"], "first.txt")
        self.assertEqual(history[1]["target"], "second.txt")

    def test_atomic_write_preserves_history_on_failure(self):
        """Verify a failed write preserves existing history."""
        save_scan("file", "original.txt", "Clean")

        original_content = self.history_file.read_text(
            encoding="utf-8"
        )

        with patch(
            "core.scan_history.os.replace",
            side_effect=OSError("Simulated replacement failure")
        ):
            with self.assertRaises(OSError):
                save_scan("file", "new.txt", "Clean")

        self.assertEqual(
            self.history_file.read_text(encoding="utf-8"),
            original_content
        )

    def test_atomic_write_cleans_temporary_files(self):
        """Verify temporary files are removed after failure."""
        save_scan("file", "original.txt", "Clean")

        with patch(
            "core.scan_history.os.replace",
            side_effect=OSError("Simulated replacement failure")
        ):
            with self.assertRaises(OSError):
                save_scan("file", "new.txt", "Clean")

        temporary_files = list(
            self.history_file.parent.glob(".scan_history_*.tmp")
        )

        self.assertEqual(temporary_files, [])

if __name__ == "__main__":
    unittest.main()