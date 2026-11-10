import unittest
from unittest.mock import patch

from scanner import check_malware_hash


class TestSentinelScanner(unittest.TestCase):

    @patch("scanner.Path")
    @patch("builtins.open")
    def test_known_threat(self, mock_open_file, mock_path):
        """Check that known malicious hashes are detected."""

        from unittest.mock import mock_open

        fake_database = (
            '{"malicious_hashes": {"abc123": "TEST_THREAT"}}'
        )

        mock_open_file.side_effect = mock_open(
            read_data=fake_database
        )

        result = check_malware_hash("abc123")

        self.assertEqual(result, "TEST_THREAT")

    @patch("builtins.open")
    def test_unknown_hash(self, mock_open_file):
        """Check that unknown hashes are not flagged."""

        from unittest.mock import mock_open

        fake_database = (
            '{"malicious_hashes": {"abc123": "TEST_THREAT"}}'
        )

        mock_open_file.side_effect = mock_open(
            read_data=fake_database
        )

        result = check_malware_hash("unknown")

        self.assertIsNone(result)


if __name__ == "__main__":
    unittest.main()
    
    
    
    
    """
Sentinel Security - Automated Scanner Tests
Version: 0.3.1

This module contains automated tests for Sentinel's malware
hash detection system.

It verifies that known threat hashes are correctly identified
and that unknown hashes return no match.

The tests use simulated threat database entries, allowing
the detection logic to be tested without real malware.
"""