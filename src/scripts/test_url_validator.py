#!/usr/bin/env python3
"""Unit tests for src/scripts/url_validator.py."""

import unittest
from src.scripts.url_validator import is_safe_external_url, parse_url, looks_numeric, is_cloud_metadata_ip
import ipaddress

class TestUrlValidator(unittest.TestCase):

    def test_valid_urls(self):
        valid = [
            "https://example.com",
            "https://api.github.com/v1/repos",
            "https://sub.domain.org:8443/test?query=val",
            "http://8.8.8.8/dns-query"
        ]
        for url in valid:
            safe, reason = is_safe_external_url(url)
            self.assertTrue(safe, f"Expected safe for {url}, got: {reason}")

    def test_ssrf_private_ips(self):
        unsafe_private = [
            "http://127.0.0.1",
            "http://127.0.0.1:8080",
            "https://10.0.0.1/admin",
            "http://172.16.0.5/api",
            "https://192.168.1.1",
            "http://169.254.169.254/latest/meta-data/",
            "http://localhost/status",
            "http://myhost.local",
            "http://service.internal"
        ]
        for url in unsafe_private:
            safe, reason = is_safe_external_url(url)
            self.assertFalse(safe, f"Expected unsafe for private IP {url}, got safe: {reason}")

    def test_cloud_metadata_ipv4_and_ipv6(self):
        cloud_metadata = [
            "http://169.254.169.254/latest/meta-data/",
            "http://169.254.1.1/info",
            "http://[fd00:ec2::254]/latest/meta-data/",
            "http://[fd00:ec2::1]/",
            "http://[fe80::1]/",
            "http://[fe80::a00:27ff:fe4e:66a1]/",
            "http://[::ffff:169.254.169.254]/latest/meta-data/"
        ]
        for url in cloud_metadata:
            safe, reason = is_safe_external_url(url)
            self.assertFalse(safe, f"Expected unsafe for cloud metadata {url}, got: {reason}")
            self.assertIn("metadata", reason.lower(), f"Expected metadata mention in reason for {url}: {reason}")

    def test_cloud_metadata_blocked_even_with_allow_private(self):
        cloud_metadata = [
            "http://169.254.169.254/latest/meta-data/",
            "http://[fd00:ec2::254]/latest/meta-data/",
            "http://[fe80::1]/",
            "http://[::ffff:169.254.169.254]/"
        ]
        for url in cloud_metadata:
            safe, reason = is_safe_external_url(url, allow_private=True)
            self.assertFalse(safe, f"Expected cloud metadata to be blocked even with allow_private for {url}")

    def test_numeric_ip_evasions(self):
        evasions = [
            "http://0x7f000001",
            "http://0177.0.0.1",
            "http://2130706433",
            "http://0x7f.0x0.0x0.0x1"
        ]
        for url in evasions:
            safe, reason = is_safe_external_url(url)
            self.assertFalse(safe, f"Expected unsafe for evasion {url}, got safe: {reason}")

    def test_malformed_and_injections(self):
        malformed = [
            "javascript:alert(1)",
            "file:///etc/passwd",
            "http://user:pass@example.com",
            "http://example.com\r\nHost: evil.com",
            "http://example.com/path#fragment",
            "http://exam ple.com",
            "http://example.com:99999",
            "http://example.com%2Fevil.com"
        ]
        for url in malformed:
            safe, reason = is_safe_external_url(url)
            self.assertFalse(safe, f"Expected unsafe for malformed {url}, got safe: {reason}")

    def test_link_aggregators_blocking(self):
        aggregators = [
            "https://linktr.ee/phishinguser",
            "https://sub.carrd.co/page",
            "https://bio.link/creator"
        ]
        for url in aggregators:
            # Not blocked by default
            safe_default, _ = is_safe_external_url(url)
            self.assertTrue(safe_default)
            # Blocked when block_aggregators=True
            safe_blocked, reason = is_safe_external_url(url, block_aggregators=True)
            self.assertFalse(safe_blocked)
            self.assertIn("link aggregator", reason.lower())

if __name__ == "__main__":

    unittest.main()
