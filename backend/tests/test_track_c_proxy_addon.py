import unittest
import socket
import asyncio
import ipaddress
from unittest.mock import patch, AsyncMock, MagicMock
from app.services.track_c_proxy_addon import ProxySecurityAddon

class MockServer:
    def __init__(self, address):
        self.address = address
        self.peername = None
        self.error = None
        self.sni = "example.com"

class MockData:
    def __init__(self, server=None):
        self.server = server
        self.ignore_connection = False

class TestTrackCProxyAddon(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.addon = ProxySecurityAddon()

    def test_tls_clienthello(self):
        data = MockData()
        self.addon.tls_clienthello(data)
        self.assertTrue(data.ignore_connection)

    async def _run_server_connect(self, host, port, resolved_ips=None, exception=None):
        server = MockServer((host, port))
        data = MockData(server)

        with patch("app.services.track_c_proxy_addon.asyncio.get_running_loop") as mock_get_loop:
            mock_loop = MagicMock()
            if exception:
                mock_loop.getaddrinfo = AsyncMock(side_effect=exception)
            else:
                addr_info = []
                for ip_str in (resolved_ips or []):
                    ip_obj = ipaddress.ip_address(ip_str)
                    if isinstance(ip_obj, ipaddress.IPv4Address):
                        addr_info.append((socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, '', (ip_str, 0)))
                    else:
                        addr_info.append((socket.AF_INET6, socket.SOCK_STREAM, socket.IPPROTO_TCP, '', (ip_str, 0, 0, 0)))
                mock_loop.getaddrinfo = AsyncMock(return_value=addr_info)
            mock_get_loop.return_value = mock_loop
            
            await self.addon.server_connect(data)
            return data

    async def test_01_permitted_public_ipv4(self):
        data = await self._run_server_connect("example.com", 443, ["93.184.216.34"])
        self.assertIsNone(data.server.error)
        self.assertEqual(data.server.address, ("93.184.216.34", 443))

    async def test_02_permitted_public_ipv6(self):
        data = await self._run_server_connect("example.com", 443, ["2606:2800:220:1:248:1893:25c8:1946"])
        self.assertIsNone(data.server.error)
        self.assertEqual(data.server.address, ("2606:2800:220:1:248:1893:25c8:1946", 443))

    async def test_03_loopback_and_private(self):
        blocked = ["127.0.0.1", "10.0.0.1", "192.168.1.1"]
        for ip in blocked:
            with self.subTest(ip=ip):
                data = await self._run_server_connect("example.com", 80, [ip])
                self.assertIsNotNone(data.server.error)
                self.assertIn("unsafe IP", data.server.error)

    async def test_04_link_local_and_metadata(self):
        blocked = ["169.254.169.254", "fe80::1"]
        for ip in blocked:
            with self.subTest(ip=ip):
                data = await self._run_server_connect("example.com", 80, [ip])
                self.assertIsNotNone(data.server.error)
                self.assertIn("unsafe IP", data.server.error)

    async def test_05_ipv4_mapped_ipv6(self):
        # Canonical lowercase form — must be blocked (10.0.0.1 is private)
        data = await self._run_server_connect("example.com", 80, ["::ffff:10.0.0.1"])
        self.assertIsNotNone(data.server.error)
        self.assertIn("unsafe IP", data.server.error)

    async def test_05b_ipv4_mapped_ipv6_extended(self):
        # Dotted-quad AWS metadata IP in mapped form — must be blocked
        data = await self._run_server_connect("example.com", 80, ["::ffff:169.254.169.254"])
        self.assertIsNotNone(data.server.error)
        self.assertIn("unsafe IP", data.server.error)

        # Mapped loopback — must be blocked
        data = await self._run_server_connect("example.com", 80, ["::ffff:127.0.0.1"])
        self.assertIsNotNone(data.server.error)
        self.assertIn("unsafe IP", data.server.error)

        # Mapped private class-C — must be blocked
        data = await self._run_server_connect("example.com", 80, ["::ffff:192.168.1.1"])
        self.assertIsNotNone(data.server.error)
        self.assertIn("unsafe IP", data.server.error)

        # Mapped safe public IP — must be PERMITTED and pinned to the mapped form
        data = await self._run_server_connect("example.com", 443, ["::ffff:93.184.216.34"])
        self.assertIsNone(data.server.error)
        # Address is pinned to whatever string was returned by the mock resolver
        self.assertEqual(data.server.address[1], 443)
        self.assertIn("93.184.216.34", data.server.address[0])

    async def test_06_mixed_dns_results(self):
        data = await self._run_server_connect("example.com", 80, ["93.184.216.34", "10.0.0.1"])
        self.assertIsNotNone(data.server.error)
        self.assertIn("unsafe IP", data.server.error)

    async def test_07_dns_failure_and_timeout(self):
        data = await self._run_server_connect("fail.com", 80, exception=socket.gaierror("failed"))
        self.assertIsNotNone(data.server.error)
        self.assertIn("DNS resolution failed", data.server.error)

        data = await self._run_server_connect("timeout.com", 80, exception=asyncio.TimeoutError())
        self.assertIsNotNone(data.server.error)
        self.assertIn("DNS resolution timed out", data.server.error)

    async def test_08_missing_or_malformed_dest(self):
        # Missing server
        data = MockData(None)
        await self.addon.server_connect(data)
        # Should not crash
        
        # Missing address
        data = MockData(MockServer(None))
        await self.addon.server_connect(data)
        self.assertIsNotNone(data.server.error)
        self.assertIn("Missing destination", data.server.error)

    async def test_09_failure_to_obtain_valid_ip(self):
        data = await self._run_server_connect("example.com", 80, [])
        self.assertIsNotNone(data.server.error)
        self.assertIn("no IPs", data.server.error)

    async def test_10_post_connect_verification(self):
        # Setup pre-connected state correctly
        data = MockData(MockServer(("93.184.216.34", 443)))
        data.server.peername = ("93.184.216.34", 443)
        self.addon.server_connected(data)
        self.assertIsNone(data.server.error)

        # Peername mismatch
        data = MockData(MockServer(("93.184.216.34", 443)))
        data.server.peername = ("10.0.0.1", 443)
        self.addon.server_connected(data)
        self.assertIsNotNone(data.server.error)
        self.assertIn("Security bypass detected", data.server.error)

        # IPv6 compression equivalence
        data = MockData(MockServer(("2606:4700:4700::1111", 443)))
        data.server.peername = ("2606:4700:4700:0:0:0:0:1111", 443)
        self.addon.server_connected(data)
        self.assertIsNone(data.server.error)

        # IPv4-mapped IPv6 equivalence
        data = MockData(MockServer(("93.184.216.34", 443)))
        data.server.peername = ("::ffff:93.184.216.34", 443)
        self.addon.server_connected(data)
        self.assertIsNone(data.server.error)

        # Missing peername
        data = MockData(MockServer(("93.184.216.34", 443)))
        self.addon.server_connected(data)
        self.assertIsNotNone(data.server.error)
        self.assertIn("peername is missing", data.server.error)

        # Peername unsafe (should be caught by mismatch or here)
        data = MockData(MockServer(("10.0.0.1", 443)))
        data.server.peername = ("10.0.0.1", 443)
        self.addon.server_connected(data)
        self.assertIsNotNone(data.server.error)
        self.assertIn("unsafe peer IP", data.server.error)

        # Malformed peername
        data = MockData(MockServer(("93.184.216.34", 443)))
        data.server.peername = ("not-an-ip", 443)
        self.addon.server_connected(data)
        self.assertIsNotNone(data.server.error)
        self.assertIn("Invalid IP format", data.server.error)

if __name__ == "__main__":
    unittest.main()
