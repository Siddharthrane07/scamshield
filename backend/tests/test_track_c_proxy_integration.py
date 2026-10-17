"""
test_track_c_proxy_integration.py — Controlled mitmproxy integration tests.

Tests the ProxySecurityAddon against a real mitmdump subprocess and locally
controlled echo servers.  No external URLs, no Playwright, no AWS.

Test cases (TC):
    TC-01  tls_clienthello hook fires and sets ignore_connection = True
    TC-02a Prohibited IP (loopback) is blocked before any upstream TCP opens
    TC-02b DNS resolution pins the IP; no second DNS lookup
    TC-03  SNI hostname is preserved through the proxy's IP-pinned connection
    TC-04  Unresolvable hostname fails closed; no upstream connection
    TC-05  server_connected detects and rejects a peername mismatch

Isolation guarantees:
  - All upstream traffic is directed to 127.0.0.1 on ephemeral ports.
  - No changes to the OS hosts file, system proxy settings, or registry.
  - The production track_c_proxy_addon.py is never modified.
  - A TestProxyAddon subclass (proxy_shim.py) whitelists 127.0.0.1 for
    TC-01 and TC-03 only; TC-02a uses the unmodified production addon so
    the loopback-block fires correctly.

Dependency note:
  mitmproxy 10.4.x pins h11==0.14.0, which conflicts with httpcore>=1.0.9.
  Both packages still function correctly in practice.  See
  requirements-integration.txt for details.

IMPORTANT: Run from backend/ with:
    venv\\Scripts\\python.exe -m unittest tests/test_track_c_proxy_integration.py
"""
import asyncio
import ipaddress
import json
import os
import pathlib
import socket
import ssl
import subprocess
import sys
import tempfile
import time
import unittest

import requests

# ---------------------------------------------------------------------------
# Path setup: import test helpers relative to this file's directory
# ---------------------------------------------------------------------------
_TESTS_DIR = pathlib.Path(__file__).parent
_BACKEND_DIR = _TESTS_DIR.parent
sys.path.insert(0, str(_BACKEND_DIR))

from tests.helpers.cert_gen import generate_test_certs
from tests.helpers.echo_server import BlackHoleServer, EchoServer
from tests.helpers.tls_echo_server import TLSEchoServer

# Import production addon for TC-02b and TC-05 (unit-level addon shim tests)
from app.services.track_c_proxy_addon import ProxySecurityAddon
from app.services.track_c_preflight import URLPreflightValidator

# ---------------------------------------------------------------------------
# Ports used by the integration tests.  Choose high-numbered ports that are
# unlikely to conflict with existing services.
# ---------------------------------------------------------------------------
PORT_PROXY = 18080        # mitmdump listener
PORT_HTTP_ECHO = 18081    # plain HTTP echo server
PORT_TLS_ECHO = 18443     # TLS HTTPS echo server
PORT_BLACKHOLE = 19001    # black-hole listener (TC-02a)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _wait_for_port(host: str, port: int, timeout: float = 10.0) -> bool:
    """Poll until a TCP port accepts a connection or the timeout expires."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with socket.create_connection((host, port), timeout=0.5):
                return True
        except (ConnectionRefusedError, OSError):
            time.sleep(0.2)
    return False


def _find_mitmdump() -> str:
    """
    Locate the mitmdump binary inside the active venv.

    On Windows the Scripts directory contains mitmdump.exe; on POSIX it is
    a plain executable in bin/.  We derive the path from sys.executable so
    the function works regardless of how the venv is activated.
    """
    scripts_dir = pathlib.Path(sys.executable).parent
    candidates = [
        scripts_dir / "mitmdump.exe",   # Windows
        scripts_dir / "mitmdump",       # POSIX
    ]
    for candidate in candidates:
        if candidate.exists():
            return str(candidate)
    raise FileNotFoundError(
        f"mitmdump binary not found in {scripts_dir}. "
        "Install mitmproxy with: python -m pip install 'mitmproxy>=10.4,<11'"
    )


def _start_mitmdump(
    script_path: str,
    sidecar_path: str,
    proxy_port: int = PORT_PROXY,
    extra_env: dict | None = None,
    log_path: str | None = None,
) -> subprocess.Popen:
    """
    Launch mitmdump (the non-interactive dump binary) in the background,
    loading the given addon script.

    We deliberately use the mitmdump.exe binary rather than
    ``python -m mitmproxy.tools.main``.  The latter is the interactive TUI
    entrypoint and exits immediately when it detects no terminal.
    mitmdump is the headless mode designed for scripted/automated use.

    Returns the Popen object; caller is responsible for termination.
    """
    env = os.environ.copy()
    existing_pp = env.get("PYTHONPATH", "")
    env["PYTHONPATH"] = f"{_BACKEND_DIR}{os.pathsep}{existing_pp}" if existing_pp else str(_BACKEND_DIR)
    env["SCAMSHIELD_BACKEND_DIR"] = str(_BACKEND_DIR)
    env["SCAMSHIELD_SIDECAR_PATH"] = sidecar_path
    if extra_env:
        env.update(extra_env)

    cmd = [
        _find_mitmdump(),
        "--listen-host", "127.0.0.1",
        "--listen-port", str(proxy_port),
        "--quiet",
        "--scripts", script_path,
    ]
    if log_path:
        out_f = open(log_path, "w", encoding="utf-8")
        proc = subprocess.Popen(
            cmd,
            env=env,
            stdout=out_f,
            stderr=subprocess.STDOUT,
            cwd=str(_BACKEND_DIR),
        )
        proc._log_file = out_f
        return proc
    return subprocess.Popen(
        cmd,
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        cwd=str(_BACKEND_DIR),
    )


# ---------------------------------------------------------------------------
# TC-01 and TC-03: subprocess-based integration tests
# These two tests need a real mitmdump subprocess.
# ---------------------------------------------------------------------------

class TestMitmproxySubprocessIntegration(unittest.TestCase):
    """
    Integration tests that spin up a real mitmdump subprocess.

    setUp / tearDown manage the lifecycle of all servers and the proxy.
    """

    @classmethod
    def setUpClass(cls) -> None:
        # --- Temp directory for certs and sidecar file ---
        cls._tmp = tempfile.TemporaryDirectory(prefix="scamshield_integration_")
        cls.tmp_dir = pathlib.Path(cls._tmp.name)

        # --- TLS certificates ---
        cls.certs = generate_test_certs(
            cls.tmp_dir / "certs",
            server_hostname="localhost",
            server_ip="127.0.0.1",
        )

        # --- Sidecar file (written by proxy_shim.py on hook events) ---
        cls.sidecar_path = str(cls.tmp_dir / "proxy_sidecar.json")
        cls.mitmdump_log_path = str(cls.tmp_dir / "mitmdump.log")

        # --- Start echo servers ---
        cls.http_echo = EchoServer(PORT_HTTP_ECHO)
        cls.http_echo.start()

        cls.tls_echo = TLSEchoServer(
            PORT_TLS_ECHO,
            cert_path=cls.certs["server_cert_path"],
            key_path=cls.certs["server_key_path"],
        )
        cls.tls_echo.start()

        # Wait for echo servers to be ready
        assert _wait_for_port("127.0.0.1", PORT_HTTP_ECHO), \
            f"HTTP echo server did not start on port {PORT_HTTP_ECHO}"
        assert _wait_for_port("127.0.0.1", PORT_TLS_ECHO), \
            f"TLS echo server did not start on port {PORT_TLS_ECHO}"

        # --- Start mitmdump with the test shim ---
        shim_path = str(_TESTS_DIR / "helpers" / "proxy_shim.py")
        cls.mitmdump = _start_mitmdump(
            shim_path,
            cls.sidecar_path,
            log_path=cls.mitmdump_log_path,
        )

        ready = _wait_for_port("127.0.0.1", PORT_PROXY, timeout=15.0)
        if not ready:
            err_msg = ""
            if os.path.exists(cls.mitmdump_log_path):
                with open(cls.mitmdump_log_path, "r", encoding="utf-8", errors="replace") as f:
                    err_msg = f.read()
            cls.mitmdump.terminate()
            raise RuntimeError(
                f"mitmdump did not start on port {PORT_PROXY} within 15 s. Log:\n{err_msg}"
            )

    @classmethod
    def tearDownClass(cls) -> None:
        cls.mitmdump.terminate()
        try:
            cls.mitmdump.wait(timeout=5)
        except subprocess.TimeoutExpired:
            cls.mitmdump.kill()
        if hasattr(cls.mitmdump, "_log_file") and cls.mitmdump._log_file:
            cls.mitmdump._log_file.close()

        cls.http_echo.stop()
        cls.tls_echo.stop()
        cls._tmp.cleanup()

    def _read_sidecar(self) -> dict:
        try:
            with open(self.sidecar_path) as f:
                return json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            return {}

    # -----------------------------------------------------------------------
    # TC-01: tls_clienthello hook fires and sets ignore_connection = True
    # -----------------------------------------------------------------------
    def test_tc01_tls_clienthello_fires_and_sets_ignore_connection(self) -> None:
        """
        TC-01: Hook compatibility.

        Make an HTTPS request through the proxy.  The shim records whether
        tls_clienthello fired and whether ignore_connection was set.

        Because ignore_connection = True causes mitmproxy to forward the
        encrypted stream without decrypting it, the proxy cannot present its
        own certificate — the client's ssl.SSLContext (configured to trust our
        test CA) must complete the handshake successfully using the server's
        real certificate.

        If the hook does NOT fire or ignore_connection = True has no effect,
        mitmproxy will attempt to intercept the TLS, present its own CA cert,
        and the connection will fail with an SSLCertVerificationError (our
        test CA is only trusted for the real server cert, not the mitmproxy CA).

        Therefore: a successful HTTPS response proves both that the hook fired
        AND that TLS passthrough is active.
        """
        proxies = {
            "http": f"http://127.0.0.1:{PORT_PROXY}",
            "https": f"http://127.0.0.1:{PORT_PROXY}",
        }
        # Trust our test CA for the server cert; do NOT trust the mitmproxy CA.
        resp = requests.get(
            f"https://127.0.0.1:{PORT_TLS_ECHO}/tc01",
            proxies=proxies,
            verify=str(self.certs["ca_cert_path"]),
            timeout=10,
        )
        self.assertEqual(resp.status_code, 200)
        body = resp.json()
        self.assertEqual(body.get("tls_echo"), "ok")

        # Verify the sidecar confirms the hook fired
        sidecar = self._read_sidecar()
        self.assertTrue(
            sidecar.get("tls_clienthello_fired"),
            "tls_clienthello hook did not fire — hook may not be registered or "
            "the mitmproxy version does not support the hook signature."
        )
        self.assertTrue(
            sidecar.get("ignore_connection_set"),
            "ignore_connection was not set to True in tls_clienthello — "
            "TLS passthrough is not configured."
        )

    # -----------------------------------------------------------------------
    # TC-03: SNI hostname is preserved through the proxy's IP-pinned connection
    # -----------------------------------------------------------------------
    def test_tc03_sni_preserved_through_ip_pinned_connection(self) -> None:
        """
        TC-03: TLS / SNI preservation.

        The proxy shim pins the upstream connection to the literal IP returned
        by DNS.  After pinning, the TLS relay must still forward the original
        hostname ('localhost') as the SNI value in the TLS ClientHello sent to
        the upstream server.

        If the proxy replaces the SNI with the literal IP string ('127.0.0.1'),
        the server will not match its certificate CN/SAN and the handshake will
        fail.  A successful response here proves the SNI is preserved.

        The TLS echo server records the SNI it received; we assert it equals
        'localhost', not '127.0.0.1'.
        """
        proxies = {
            "http": f"http://127.0.0.1:{PORT_PROXY}",
            "https": f"http://127.0.0.1:{PORT_PROXY}",
        }
        # Connect using the hostname 'localhost' so the proxy sees a hostname
        # that it must resolve (to 127.0.0.1) and then PIN.
        resp = requests.get(
            f"https://localhost:{PORT_TLS_ECHO}/tc03",
            proxies=proxies,
            verify=str(self.certs["ca_cert_path"]),
            timeout=10,
        )
        self.assertEqual(resp.status_code, 200)

        # The TLS echo server records the SNI it received in the handshake.
        # Because mitmproxy passes TLS through (ignore_connection = True),
        # the SNI comes directly from the client/proxy TLS relay — it should
        # be 'localhost', not '127.0.0.1'.
        sni = self.tls_echo.last_sni
        self.assertIsNotNone(sni, "No SNI was captured by the TLS echo server")
        self.assertEqual(
            sni, "localhost",
            f"SNI mismatch: expected 'localhost', got '{sni}'. "
            "IP pinning may have corrupted the TLS hostname."
        )


# ---------------------------------------------------------------------------
# TC-02a: Prohibited IP blocked before upstream connection opens
# This test does NOT use the test allow-list shim; it uses the unmodified
# production addon so the loopback block fires.
# ---------------------------------------------------------------------------

class TestFailClosedProhibitedIP(unittest.TestCase):
    """
    TC-02a: A connection to a prohibited IP must be blocked before the
    upstream TCP socket is opened.

    This test uses a real mitmdump subprocess loaded with the *production*
    addon (not the test shim with the allow-list).  The black-hole server
    listens on 127.0.0.1:PORT_BLACKHOLE.  After the test request, we confirm
    that connection_count == 0 — the addon blocked before the socket opened.
    """

    @classmethod
    def setUpClass(cls) -> None:
        cls._tmp = tempfile.TemporaryDirectory(prefix="scamshield_tc02a_")
        cls.tmp_dir = pathlib.Path(cls._tmp.name)
        cls.sidecar_path = str(cls.tmp_dir / "sidecar.json")

        # Black-hole listener
        cls.blackhole = BlackHoleServer(PORT_BLACKHOLE)
        cls.blackhole.start()
        assert _wait_for_port("127.0.0.1", PORT_BLACKHOLE), \
            "Black-hole server did not start"

        # Production addon path (not the shim)
        production_addon = str(_BACKEND_DIR / "app" / "services" / "track_c_proxy_addon.py")
        cls.mitmdump_log_path = str(cls.tmp_dir / "mitmdump.log")
        cls.mitmdump = _start_mitmdump(
            production_addon,
            cls.sidecar_path,
            proxy_port=PORT_PROXY + 10,  # different port to avoid class-level conflict
            log_path=cls.mitmdump_log_path,
        )
        ready = _wait_for_port("127.0.0.1", PORT_PROXY + 10, timeout=15.0)
        if not ready:
            err_msg = ""
            if os.path.exists(cls.mitmdump_log_path):
                with open(cls.mitmdump_log_path, "r", encoding="utf-8", errors="replace") as f:
                    err_msg = f.read()
            cls.mitmdump.terminate()
            raise RuntimeError(f"mitmdump (production addon) did not start. Log:\n{err_msg}")

    @classmethod
    def tearDownClass(cls) -> None:
        cls.mitmdump.terminate()
        try:
            cls.mitmdump.wait(timeout=5)
        except subprocess.TimeoutExpired:
            cls.mitmdump.kill()
        if hasattr(cls.mitmdump, "_log_file") and cls.mitmdump._log_file:
            cls.mitmdump._log_file.close()
        cls.blackhole.stop()
        cls._tmp.cleanup()

    def test_tc02a_prohibited_ip_blocked_before_upstream_connection(self) -> None:
        """
        TC-02a: Request to 127.0.0.1 (loopback — blocked by production addon)
        must fail with an error response and the black-hole must receive
        zero connections.
        """
        proxies = {
            "http": f"http://127.0.0.1:{PORT_PROXY + 10}",
            "https": f"http://127.0.0.1:{PORT_PROXY + 10}",
        }
        before_count = self.blackhole.connection_count

        try:
            resp = requests.get(
                f"http://127.0.0.1:{PORT_BLACKHOLE}/tc02a",
                proxies=proxies,
                timeout=8,
            )
            # If we get a response, it must be an error status (502/503/etc.)
            self.assertGreaterEqual(
                resp.status_code, 400,
                f"Expected a proxy error response, got {resp.status_code}. "
                "The addon may have failed open and let the request through."
            )
        except requests.exceptions.ProxyError:
            # ProxyError means the proxy itself refused/errored — correct behavior
            pass
        except requests.exceptions.ConnectionError:
            # ConnectionError is also acceptable (proxy closed the tunnel)
            pass

        # The black hole must not have accepted any new connections
        after_count = self.blackhole.connection_count
        self.assertEqual(
            after_count, before_count,
            f"Black-hole accepted {after_count - before_count} connection(s). "
            "The addon did not block the request before opening the upstream socket."
        )


# ---------------------------------------------------------------------------
# TC-02b: DNS pinning — unit-level addon shim test (no subprocess needed)
# ---------------------------------------------------------------------------

class TestDNSPinning(unittest.IsolatedAsyncioTestCase):
    """
    TC-02b: After server_connect(), data.server.address must be pinned to the
    literal IP returned by the mock resolver — no second resolution occurs.

    This uses the real mitmproxy Server and ServerConnectionHookData objects
    so that the production code path runs against genuine mitmproxy types.
    The mock resolver is injected via asyncio.get_running_loop().getaddrinfo.
    """

    async def test_tc02b_address_pinned_to_resolved_ip(self) -> None:
        """
        TC-02b: DNS resolution pins the address; mock called exactly once.
        """
        from unittest.mock import AsyncMock, MagicMock, patch
        from mitmproxy.test.tflow import tserver_conn, tclient_conn
        from mitmproxy.proxy.server_hooks import ServerConnectionHookData

        # A safe public IP to return from the mock resolver
        TEST_IP = "93.184.216.34"

        srv = tserver_conn()
        srv.address = ("example.com", 80)
        srv.peername = None
        srv.error = None

        cli = tclient_conn()
        hook_data = ServerConnectionHookData(server=srv, client=cli)

        addon = ProxySecurityAddon()

        getaddrinfo_call_count = 0

        with patch("app.services.track_c_proxy_addon.asyncio.get_running_loop") as mock_get_loop:
            mock_loop = MagicMock()

            async def fake_getaddrinfo(host, port, *args, **kwargs):
                nonlocal getaddrinfo_call_count
                getaddrinfo_call_count += 1
                return [(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", (TEST_IP, 0))]

            mock_loop.getaddrinfo = fake_getaddrinfo
            mock_get_loop.return_value = mock_loop

            await addon.server_connect(hook_data)

        # Error must not be set
        self.assertIsNone(
            srv.error,
            f"server_connect() set an error unexpectedly: {srv.error}"
        )

        # Address must be pinned to the resolved IP
        pinned_host, pinned_port = srv.address
        self.assertEqual(
            pinned_host, TEST_IP,
            f"Address not pinned: expected {TEST_IP!r}, got {pinned_host!r}."
        )
        self.assertEqual(pinned_port, 80)

        # Resolver called exactly once (no second DNS lookup)
        self.assertEqual(
            getaddrinfo_call_count, 1,
            f"DNS resolver was called {getaddrinfo_call_count} time(s); expected 1."
        )

    async def test_tc02b_safe_ip_direct_literal_bypasses_dns(self) -> None:
        """
        TC-02b (corollary): When the client sends a literal public IP as the
        host (e.g., CONNECT 93.184.216.34:80), the addon still runs
        getaddrinfo (since it always resolves the host field) but the result
        is a safe IP that gets pinned.
        """
        from unittest.mock import MagicMock, patch
        from mitmproxy.test.tflow import tserver_conn, tclient_conn
        from mitmproxy.proxy.server_hooks import ServerConnectionHookData

        TEST_IP = "93.184.216.34"

        srv = tserver_conn()
        srv.address = (TEST_IP, 443)
        srv.peername = None
        srv.error = None

        cli = tclient_conn()
        hook_data = ServerConnectionHookData(server=srv, client=cli)
        addon = ProxySecurityAddon()

        with patch("app.services.track_c_proxy_addon.asyncio.get_running_loop") as mock_get_loop:
            mock_loop = MagicMock()

            async def fake_getaddrinfo(host, port, *args, **kwargs):
                return [(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", (TEST_IP, 0))]

            mock_loop.getaddrinfo = fake_getaddrinfo
            mock_get_loop.return_value = mock_loop

            await addon.server_connect(hook_data)

        self.assertIsNone(srv.error)
        self.assertEqual(srv.address[0], TEST_IP)


# ---------------------------------------------------------------------------
# TC-04: Unresolvable hostname — fail closed
# ---------------------------------------------------------------------------

class TestFailClosedUnresolvableHost(unittest.IsolatedAsyncioTestCase):
    """
    TC-04: A request to an unresolvable hostname must fail before any upstream
    connection is opened.

    Uses the real ServerConnectionHookData + production addon.
    The fake resolver raises socket.gaierror to simulate NXDOMAIN.
    """

    async def test_tc04_nxdomain_fails_closed(self) -> None:
        from unittest.mock import MagicMock, patch
        from mitmproxy.test.tflow import tserver_conn, tclient_conn
        from mitmproxy.proxy.server_hooks import ServerConnectionHookData

        srv = tserver_conn()
        srv.address = ("definitely-nonexistent-hostname.invalid", 80)
        srv.peername = None
        srv.error = None

        cli = tclient_conn()
        hook_data = ServerConnectionHookData(server=srv, client=cli)
        addon = ProxySecurityAddon()

        with patch("app.services.track_c_proxy_addon.asyncio.get_running_loop") as mock_get_loop:
            mock_loop = MagicMock()

            async def fail_getaddrinfo(host, port, *args, **kwargs):
                raise socket.gaierror("Name or service not known")

            mock_loop.getaddrinfo = fail_getaddrinfo
            mock_get_loop.return_value = mock_loop

            await addon.server_connect(hook_data)

        self.assertIsNotNone(
            srv.error,
            "server_connect() should set an error for an unresolvable hostname"
        )
        self.assertIn(
            "DNS resolution failed",
            srv.error,
            f"Unexpected error message: {srv.error!r}"
        )

    async def test_tc04_dns_timeout_fails_closed(self) -> None:
        """DNS timeout must also fail closed."""
        from unittest.mock import MagicMock, patch
        from mitmproxy.test.tflow import tserver_conn, tclient_conn
        from mitmproxy.proxy.server_hooks import ServerConnectionHookData

        srv = tserver_conn()
        srv.address = ("slow-dns.invalid", 80)
        srv.peername = None
        srv.error = None

        cli = tclient_conn()
        hook_data = ServerConnectionHookData(server=srv, client=cli)
        addon = ProxySecurityAddon()

        with patch("app.services.track_c_proxy_addon.asyncio.get_running_loop") as mock_get_loop:
            mock_loop = MagicMock()

            async def timeout_getaddrinfo(host, port, *args, **kwargs):
                raise asyncio.TimeoutError()

            mock_loop.getaddrinfo = timeout_getaddrinfo
            mock_get_loop.return_value = mock_loop

            await addon.server_connect(hook_data)

        self.assertIsNotNone(srv.error)
        self.assertIn("DNS resolution timed out", srv.error)


# ---------------------------------------------------------------------------
# TC-05: server_connected detects peername mismatch
# ---------------------------------------------------------------------------

class TestPeernameMismatch(unittest.TestCase):
    """
    TC-05: The server_connected hook must detect when the actual connected IP
    differs from the pinned IP and set an error.

    Uses the real mitmproxy Server objects; the production server_connected()
    method is called directly (no subprocess needed).
    """

    def setUp(self) -> None:
        self.addon = ProxySecurityAddon()

    def _make_server(self, address: tuple, peername: tuple | None) -> object:
        from mitmproxy.test.tflow import tserver_conn
        srv = tserver_conn()
        srv.address = address
        srv.peername = peername
        srv.error = None
        return srv

    def _make_data(self, server) -> object:
        from mitmproxy.test.tflow import tserver_conn, tclient_conn
        from mitmproxy.proxy.server_hooks import ServerConnectionHookData
        cli = tclient_conn()
        hook_data = ServerConnectionHookData(server=server, client=cli)
        return hook_data

    def test_tc05_matching_peername_is_accepted(self) -> None:
        srv = self._make_server(("93.184.216.34", 443), ("93.184.216.34", 443))
        data = self._make_data(srv)
        self.addon.server_connected(data)
        self.assertIsNone(
            srv.error,
            f"Unexpected error for matching peername: {srv.error!r}"
        )

    def test_tc05_mismatched_peername_is_rejected(self) -> None:
        """Security bypass: connected to different IP than pinned."""
        srv = self._make_server(("93.184.216.34", 443), ("10.0.0.1", 443))
        data = self._make_data(srv)
        self.addon.server_connected(data)
        self.assertIsNotNone(srv.error)
        self.assertIn(
            "Security bypass detected",
            srv.error,
            f"Expected 'Security bypass detected' in error, got: {srv.error!r}"
        )

    def test_tc05_ipv4_mapped_ipv6_equivalence(self) -> None:
        """
        ::ffff:93.184.216.34 and 93.184.216.34 are the same address.
        server_connected must normalize and accept this as a match.
        """
        srv = self._make_server(("93.184.216.34", 443), ("::ffff:93.184.216.34", 443))
        data = self._make_data(srv)
        self.addon.server_connected(data)
        self.assertIsNone(
            srv.error,
            f"IPv4-mapped IPv6 equivalence failed: {srv.error!r}"
        )

    def test_tc05_unsafe_peer_ip_is_rejected(self) -> None:
        """Even if peername matches pinned address, an unsafe IP is blocked."""
        srv = self._make_server(("10.0.0.1", 443), ("10.0.0.1", 443))
        data = self._make_data(srv)
        self.addon.server_connected(data)
        self.assertIsNotNone(srv.error)
        self.assertIn(
            "unsafe peer IP",
            srv.error,
            f"Expected 'unsafe peer IP' in error, got: {srv.error!r}"
        )

    def test_tc05_missing_peername_fails_closed(self) -> None:
        """Missing peername (no actual connection) must set an error."""
        srv = self._make_server(("93.184.216.34", 443), None)
        data = self._make_data(srv)
        self.addon.server_connected(data)
        self.assertIsNotNone(srv.error)
        self.assertIn(
            "peername is missing",
            srv.error,
        )

    def test_tc05_malformed_peername_fails_closed(self) -> None:
        """A non-IP string in peername must set an error, not raise."""
        srv = self._make_server(("93.184.216.34", 443), ("not-an-ip", 443))
        data = self._make_data(srv)
        self.addon.server_connected(data)
        self.assertIsNotNone(srv.error)
        self.assertIn(
            "Invalid IP format",
            srv.error,
        )


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    unittest.main(verbosity=2)
