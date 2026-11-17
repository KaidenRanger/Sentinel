"""
Sentinel Security - URL Scanner Tests
Version: 0.5.0

Automated tests for URL validation and security warnings.
"""


import unittest
from contextlib import redirect_stdout
from io import StringIO

from core.url_scanner import scan_url


class TestURLScanner(unittest.TestCase):
    """Test Sentinel's URL scanning functionality."""

    def run_scan(self, url):
         """Capture the scanner's printed output."""
         output = StringIO()


         with redirect_stdout(output):
            scan_url(url)


         return output.getvalue()
    def test_http_warning(self):
        result = self.run_scan("http://example.com")
        self.assertIn("does not use HTTPS", result)

    def test_ip_address_warning(self):
        result = self.run_scan(
            "https://example.com@192.0.2.1/login"
        )
        self.assertIn("user information", result)

    def test_invalid_url(self):
        result = self.run_scan("not-a-url")
        self.assertIn("Invalid", result)

    def test_long_url_warning(self):
        url = "https://example.com/" + "a" * 210
        result = self.run_scan(url)
        self.assertIn("unusually long", result)

    def test_punycode_warning(self):
        result = self.run_scan("https://xn--bcher-kva.example")
        self.assertIn("Punycode", result)

    def test_normal_https_url(self):
        """Check that a normal HTTPS URL has no warnings."""
        result = self.run_scan("https://example.com")
        self.assertIn(
            "No suspicious URL indicators detected", result
        )

    def test_at_symbol_warning(self):
        """Check that URLs containing user information are flagged."""
        result = self.run_scan(
            "https://example.com@192.0.2.1/login"
        )
        self.assertIn("user information", result)


    def test_invalid_hostname_characters(self):
        """Reject invalid characters in a hostname."""
        result = self.run_scan("https://bad_host.example")
        self.assertIn("Invalid hostname characters", result)

    def test_valid_hyphenated_hostname(self):
        """Accept valid hyphenated hostnames."""
        result = self.run_scan("https://my-site.example")
        self.assertNotIn("Invalid hostname characters", result)
        self.assertIn(
            "No suspicious URL indicators detected",
            result
            )

    def test_valid_url_returns_true(self):
        """Valid URLs should return True."""
        result = scan_url("https://example.com")
        self.assertTrue(result)

    def test_invalid_url_returns_false(self):
        """Invalid URLs should return False."""
        result = scan_url("not-a-valid-url")
        self.assertFalse(result)

    def test_suspicious_url_returns_true(self):
        """Suspicious but valid URLs should return True."""

        result = scan_url("http://192.168.1.1/login")

        self.assertTrue(result)
    def test_detailed_safe_result(self):
         """Check detailed results for a normal HTTPS URL."""

         result = scan_url(
            "https://example.com",
            return_details=True
        )

         self.assertIsInstance(result, dict)
         self.assertTrue(result["valid"])
         self.assertEqual(
             result["status"],
             "No suspicious URL indicators detected"
         )
         self.assertEqual(result["warnings"], [])

    def test_detailed_suspicious_url_result(self):
        """Check detailed results for a suspicious URL."""

        result = scan_url(
            "http://192.168.1.1/login",
            return_details=True
        )
        self.assertIsInstance(result, dict)
        self.assertTrue(result["valid"])
        self.assertEqual(
            result["status"],
            "REVIEW RECOMMENDED"
        )
        self.assertIn(
             "URL does not use HTTPS (unencrypted connection)",
             result["warnings"]
        )
        self.assertIn(
            "URL uses an IP address instead of a domain name",
            result["warnings"]
        )



if __name__ == "__main__":
    unittest.main()