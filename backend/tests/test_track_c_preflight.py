import unittest
import socket
import asyncio
from unittest.mock import patch, AsyncMock, MagicMock
from app.services.track_c_preflight import URLPreflightValidator

class TestTrackCPreflight(unittest.IsolatedAsyncioTestCase):

    async def _validate_with_dns(self, url: str, resolved_ips: list = None, exception=None):
        """Helper to mock the actual running event loop's getaddrinfo."""
        with patch("app.services.track_c_preflight.asyncio.get_running_loop") as mock_get_loop:
            mock_loop = MagicMock()
            if exception:
                mock_loop.getaddrinfo = AsyncMock(side_effect=exception)
            else:
                addr_info = []
                for ip in (resolved_ips or []):
                    # returning mock addr_info structure
                    addr_info.append((socket.AF_INET, socket.SOCK_STREAM, 6, '', (ip, 0)))
                mock_loop.getaddrinfo = AsyncMock(return_value=addr_info)
            
            mock_get_loop.return_value = mock_loop
            return await URLPreflightValidator.validate(url)

    async def test_safe_urls(self):
        safe_cases = [
            "https://example.com",
            "http://example.com",
            "HTTPS://example.com",
            "https://example.com:8443",
            "https://example.com/path?query=1#frag"
        ]
        for url in safe_cases:
            with self.subTest(url=url):
                res = await self._validate_with_dns(url, ["93.184.216.34"])
                self.assertTrue(res["allowed"])
                if "#" in url:
                    self.assertNotIn("frag", res["normalized_url"])

    async def test_credentialed_url(self):
        url = "https://user:password@example.com/path"
        res = await self._validate_with_dns(url, ["93.184.216.34"])
        self.assertTrue(res["allowed"])
        self.assertNotIn("user", res["normalized_url"])
        self.assertNotIn("password", res["normalized_url"])
        self.assertEqual(res["normalized_url"], "https://example.com/path")

    async def test_blocked_schemes(self):
        blocked = [
            "file:///etc/passwd",
            "data:text/html,test",
            "javascript:alert(1)",
            "ftp://example.com",
            "vbscript:MsgBox(1)"
        ]
        for url in blocked:
            with self.subTest(url=url):
                # We don't even need DNS mock for scheme blocks as they fail early,
                # but using the validate directly is fine.
                res = await URLPreflightValidator.validate(url)
                self.assertFalse(res["allowed"])
                self.assertIn("Disallowed URL scheme", res["reason"])

    async def test_malformed_urls(self):
        # Missing hostname
        res = await URLPreflightValidator.validate("http://")
        self.assertFalse(res["allowed"])

        # Malformed port
        res = await URLPreflightValidator.validate("http://example.com:abc")
        self.assertFalse(res["allowed"])
        self.assertEqual(res["reason"], "Malformed port in URL")

        # Empty
        res = await URLPreflightValidator.validate("")
        self.assertFalse(res["allowed"])

        # Non-string
        res = await URLPreflightValidator.validate(None)  # type: ignore
        self.assertFalse(res["allowed"])

    async def test_trailing_dot(self):
        url = "http://localhost./"
        # The DNS will resolve 'localhost', so we mock it as returning loopback
        res = await self._validate_with_dns(url, ["127.0.0.1"])
        self.assertFalse(res["allowed"])
        self.assertIn("unsafe IP", res["reason"])
        self.assertNotIn(".", res["hostname"]) # ensure dot is stripped

    async def test_dns_errors(self):
        # Timeout
        res = await self._validate_with_dns("http://timeout.com", exception=asyncio.TimeoutError())
        self.assertFalse(res["allowed"])
        self.assertIn("timed out", res["reason"])

        # Failed
        res = await self._validate_with_dns("http://fail.com", exception=socket.gaierror("Name or service not known"))
        self.assertFalse(res["allowed"])
        self.assertIn("resolution failed", res["reason"])

    async def test_blocked_ips(self):
        blocked_ips = [
            "127.0.0.1",
            "10.0.0.1",
            "172.16.0.1",
            "192.168.1.1",
            "169.254.169.254",
            "100.64.0.1",
            "198.18.0.1",
            "192.0.0.1",
            "198.51.100.1",
            "203.0.113.1",
            "240.0.0.1",
            "::1",
            "fc00::1",
            "fe80::1",
            "2001:db8::1",
            "::ffff:10.0.0.1",
            "::ffff:127.0.0.1",
            "::ffff:169.254.169.254",
            "::ffff:192.168.1.1"
        ]
        for ip in blocked_ips:
            with self.subTest(ip=ip):
                res = await self._validate_with_dns("http://attacker.com", [ip])
                self.assertFalse(res["allowed"], f"IP {ip} should have been blocked")
                self.assertIn("unsafe IP", res["reason"])

    async def test_mixed_dns(self):
        res = await self._validate_with_dns("http://mixed.com", ["93.184.216.34", "10.0.0.1"])
        self.assertFalse(res["allowed"])
        self.assertIn("unsafe IP", res["reason"])

    async def test_duplicate_dns(self):
        res = await self._validate_with_dns("http://dup.com", ["93.184.216.34", "93.184.216.34"])
        self.assertTrue(res["allowed"])
        self.assertEqual(len(res["resolved_ips"]), 1)

if __name__ == "__main__":
    unittest.main()
