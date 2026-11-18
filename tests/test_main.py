"""
Sentinel Security - Main Menu Tests
Version: 0.6.0

Tests for scan history deletion confirmation.
"""

import unittest
from unittest.mock import patch

from main import main

class TestMainMenu(unittest.TestCase):

    @patch("main.clear_scan_history")
    @patch("builtins.input", side_effect=["4", "NO", "5"])
    def test_clear_history_cancelled(self, mock_input, mock_clear):
        """Canceling deletion must preserve scan history."""

        main()

        mock_clear.assert_not_called()

    @patch("main.clear_scan_history", return_value=True)
    @patch("builtins.input", side_effect=["4", "YES", "5"])
    def test_clear_history_confirmed(self, mock_input, mock_clear):
         """Typing YES must trigger history deletion."""

         main()

         mock_clear.assert_called_once()

    @patch("main.clear_scan_history", return_value=False)
    @patch("builtins.input", side_effect=["4", "YES", "5"])
    def test_clear_history_failure(self, mock_input, mock_clear):
        """A deletion failure must be handled gracefully."""

        main()

        mock_clear.assert_called_once()

if __name__ == "__main__":
    unittest.main()