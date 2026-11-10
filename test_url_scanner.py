"""
Sentinel Security - URL Scanner Tests
Version: 0.4.0

Automated tests for URL validation and security warnings.
"""
import unittest
from contextlib import redirect_stdout
from io import StringIO

from url_scanner import scan_url


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
            "No immediate security concerns detected", result
        )
    
    def test_at_symbol_warning(self):
        """Check that URLs containing user information are flagged."""
        result = self.run_scan(
            "https://example.com@192.0.2.1/login"
        )
        self.assertIn("user information", result)
        
if __name__ == "__main__":
    unittest.main()