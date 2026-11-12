"""
Sentinel Security - Threat Intelligence Tests
Version: 0.5.0

Tests the VirusTotal integration without making
real network requests.
"""

import unittest
import json
from unittest.mock import patch
from urllib.error import HTTPError, URLError

from threat_intel import check_url_reputation


class TestThreatIntel(unittest.TestCase):
    """Test Sentinel's threat intelligence module."""

    @patch.dict("os.environ", {}, clear=True)
    def test_missing_api_key(self):
        """Check that a missing API key is handled."""

        result = check_url_reputation("https://example.com")

        self.assertEqual(result["status"], "error")
        self.assertIn("API key", result["message"])

    @patch("threat_intel.urlopen")
    @patch.dict(
        "os.environ",
        {"VT_API_KEY": "fake_test_key"}
    )
    def test_network_error(self, mock_urlopen):
        """Check that connection failures are handled."""

        mock_urlopen.side_effect = URLError(
            "Simulated connection failure"
        )

        result = check_url_reputation("https://example.com")

        self.assertEqual(result["status"], "error")
        self.assertIn(
            "Network error or request timed out", result["message"]
        )

    @patch("threat_intel.urlopen")
    @patch.dict(
        "os.environ",
        {"VT_API_KEY": "fake_test_key"}
    )
    def test_successful_response(self, mock_urlopen):
         """Check that a successful VirusTotal response is parsed."""
         fake_response = {
             "data": {
                 "attributes": {
                     "last_analysis_stats": {
                         "malicious": 2,
                         "suspicious": 1,
                         "harmless": 65,
                         "undetected": 4
                     }
                 }
             }
         }

         mock_urlopen.return_value.__enter__.return_value.read.return_value = (
             json.dumps(fake_response).encode("utf-8")
         )

         result = check_url_reputation("https://example.com")

         self.assertEqual(result["status"], "success")
         self.assertEqual(result["malicious"], 2)
         self.assertEqual(result["suspicious"], 1)
         self.assertEqual(result["harmless"], 65)
         self.assertEqual(result["undetected"], 4)

    @patch("threat_intel.urlopen")
    @patch.dict(
        "os.environ",
        {"VT_API_KEY": "fake_test_key"}
    )
    def test_report_not_found(self, mock_urlopen):
        """Handle a URL with no existing VirusTotal report."""

        mock_urlopen.side_effect = HTTPError(
            url="https://www.virustotal.com",
            code=404,
            msg="Not Found",
            hdrs=None,
            fp=None
        )

        result = check_url_reputation("https://example.com")

        self.assertEqual(result["status"], "error")
        self.assertIn("report", result["message"].lower())
        mock_urlopen.side_effect.close()

    @patch("threat_intel.urlopen")
    @patch.dict(
        "os.environ",
        {"VT_API_KEY": "fake_test_key"}
    )
    def test_rate_limit(self, mock_urlopen):
        """Handle VirusTotal API rate limiting."""

        mock_urlopen.side_effect = HTTPError(
            url="https://www.virustotal.com",
            code=429,
            msg="Too Many Requests",
            hdrs=None,
            fp=None
        )

        result = check_url_reputation("https://example.com")

        self.assertEqual(result["status"], "error")
        self.assertTrue(
            "rate limit" in result["message"].lower()
            or "429" in result["message"]
        )
        mock_urlopen.side_effect.close()



if __name__ == "__main__":
    unittest.main()
