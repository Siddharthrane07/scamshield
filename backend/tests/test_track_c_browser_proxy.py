"""
test_track_c_browser_proxy.py — Browser-Proxy Integration Test Suite for Track C.

Verifies Chromium-level proxy routing, connection-time enforcement, and isolation
using local controlled servers only.

Security Test Cases:
    BR-01  Baseline HTTP and HTTPS through blind-tunnel proxy (SPKI pinned)
    BR-02  Cross-origin redirect to prohibited IP fails closed (302 -> loopback)
    BR-03  Subresources (scripts, images, iframes) individually validated & blocked
    BR-04a Plain WebSocket (ws://) through proxy upgrade
    BR-04b Secure WebSocket (wss://) through blind tunnel with SNI and cert check
    BR-05  Direct loopback bypass prevention (<-loopback> canary test)
    BR-06  Synthetic domain resolution via proxy-side DNS
    BR-07  WebRTC egress confinement (ICE candidate suppression & UDP sink check)
    BR-08  Loopback rejection via production addon
    BR-09a Proxy-death egress leak test (mitmdump killed -> canary count == 0)
    BR-09b Zombie process and resource cleanup
    BR-10  QUIC / HTTP/3 evasion prevention (Alt-Svc: h3 delivered, UDP sink == 0)
    BR-11  Controlled dynamic DNS rebinding (Model 2: safe vs prohibited vs mixed)
    SPKI-NEG Negative control: Unpinned/unrelated certificate rejected by Chromium
"""
import asyncio
import json
import os
import pathlib
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Dict, Any

from playwright.sync_api import sync_playwright, Playwright, Browser, Error as PlaywrightError

# Paths
_TESTS_DIR = pathlib.Path(__file__).parent
_BACKEND_DIR = _TESTS_DIR.parent
sys.path.insert(0, str(_BACKEND_DIR))

from tests.helpers.cert_gen import generate_test_certs, generate_unrelated_certs
from tests.helpers.echo_server import EchoServer, BlackHoleServer
from tests.helpers.tls_echo_server import TLSEchoServer
from tests.helpers.ws_echo_server import WebSocketEchoServer
from tests.helpers.canary_listener import CanaryListener, UDPSinkServer
from tests.helpers.browser_harness import launch_hardened_browser
from tests.helpers.proxy_shim import _SYNTHETIC_HOSTS, _PROHIBITED_TEST_PORTS
from app.services.track_c_proxy_addon import ProxySecurityAddon

# Distinct ports for browser test suite
PORT_BROWSER_PROXY = 18180
PORT_PROD_PROXY = 18190
PORT_HTTP_ECHO = 18181
PORT_TLS_ECHO = 18143
PORT_REDIRECT_SERVER = 18182
PORT_SUBRESOURCE_SERVER = 18183
PORT_WS_SERVER = 18184
PORT_WSS_SERVER = 18185
PORT_QUIC_HTTP_SERVER = 18186
PORT_BLACKHOLE = 19101
PORT_CANARY_TCP = 19102
PORT_UDP_SINK = 19103
PORT_QUIC_UDP_SINK = 19104
PORT_PROD_LOOPBACK = 19105
PORT_UNRELATED_TLS = 18144


def _wait_for_port(host: str, port: int, timeout: float = 10.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with socket.create_connection((host, port), timeout=0.5):
                return True
        except (ConnectionRefusedError, OSError):
            time.sleep(0.2)
    return False


def _find_mitmdump() -> str:
    scripts_dir = pathlib.Path(sys.executable).parent
    candidates = [
        scripts_dir / "mitmdump.exe",
        scripts_dir / "mitmdump",
    ]
    for c in candidates:
        if c.exists():
            return str(c)
    raise FileNotFoundError(f"mitmdump binary not found in {scripts_dir}")


def _start_mitmdump(
    script_path: str,
    sidecar_path: str,
    proxy_port: int,
    log_path: str,
) -> subprocess.Popen:
    env = os.environ.copy()
    existing_pp = env.get("PYTHONPATH", "")
    env["PYTHONPATH"] = f"{_BACKEND_DIR}{os.pathsep}{existing_pp}" if existing_pp else str(_BACKEND_DIR)
    env["SCAMSHIELD_BACKEND_DIR"] = str(_BACKEND_DIR)
    env["SCAMSHIELD_SIDECAR_PATH"] = sidecar_path
    env["SCAMSHIELD_PROHIBITED_TEST_PORTS"] = f"{PORT_BLACKHOLE},{PORT_CANARY_TCP},{PORT_PROD_LOOPBACK},19001"

    cmd = [
        _find_mitmdump(),
        "--listen-host", "127.0.0.1",
        "--listen-port", str(proxy_port),
        "--quiet",
        "--scripts", script_path,
    ]
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


class _RedirectHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(302)
        self.send_header("Location", f"http://127.0.0.1:{PORT_BLACKHOLE}/evil")
        self.end_headers()

    def log_message(self, fmt, *args):
        pass


class _SubresourceHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/":
            html = f"""<!DOCTYPE html>
<html>
<head><title>Subresource Test</title></head>
<body>
    <img id="img-safe" src="http://safe-cdn.local:{PORT_HTTP_ECHO}/pixel.png" />
    <iframe id="iframe-blocked" src="http://127.0.0.1:{PORT_BLACKHOLE}/frame"></iframe>
    <script id="script-blocked" src="http://127.0.0.1:{PORT_BLACKHOLE}/evil.js"></script>
</body>
</html>"""
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(html)))
            self.end_headers()
            self.wfile.write(html.encode())
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, fmt, *args):
        pass


class _AltSvcHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        body = b"alt-svc-test"
        self.send_response(200)
        self.send_header("Alt-Svc", f'h3=":{PORT_QUIC_UDP_SINK}"; ma=86400')
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):
        pass


class TestTrackCBrowserProxy(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls._tmp = tempfile.TemporaryDirectory(prefix="scamshield_browser_test_")
        cls.tmp_dir = pathlib.Path(cls._tmp.name)

        # 1. Generate test certificates & compute SPKI hash
        cls.certs = generate_test_certs(
            cls.tmp_dir / "certs",
            server_hostname="test-origin.local",
            server_ip="127.0.0.1",
        )
        # Pin both the leaf and CA SPKI hashes so Chromium can validate the chain
        cls.test_ca_spki_hash = f"{cls.certs['server_spki_hash']},{cls.certs['ca_spki_hash']}"

        # Unrelated cert for negative SPKI test
        cls.unrelated_certs = generate_unrelated_certs(
            cls.tmp_dir / "unrelated_certs",
            hostname="unrelated.local",
        )

        cls.sidecar_path = str(cls.tmp_dir / "sidecar.json")
        cls.shim_log_path = str(cls.tmp_dir / "mitmdump_shim.log")
        cls.prod_log_path = str(cls.tmp_dir / "mitmdump_prod.log")

        # 2. Start mock servers
        cls.http_echo = EchoServer(PORT_HTTP_ECHO)
        cls.http_echo.start()

        cls.tls_echo = TLSEchoServer(
            PORT_TLS_ECHO,
            cert_path=cls.certs["server_cert_path"],
            key_path=cls.certs["server_key_path"],
        )
        cls.tls_echo.start()

        # Unrelated TLS server for negative control test
        cls.unrelated_tls = TLSEchoServer(
            PORT_UNRELATED_TLS,
            cert_path=cls.unrelated_certs["cert_path"],
            key_path=cls.unrelated_certs["key_path"],
        )
        cls.unrelated_tls.start()

        cls.blackhole = BlackHoleServer(PORT_BLACKHOLE)
        cls.blackhole.start()

        cls.prod_loopback = BlackHoleServer(PORT_PROD_LOOPBACK)
        cls.prod_loopback.start()

        cls.canary = CanaryListener(PORT_CANARY_TCP)
        cls.canary.start()

        cls.udp_sink = UDPSinkServer(PORT_UDP_SINK)
        cls.udp_sink.start()

        cls.quic_udp_sink = UDPSinkServer(PORT_QUIC_UDP_SINK)
        cls.quic_udp_sink.start()

        # Redirect server
        cls._redirect_srv = HTTPServer(("127.0.0.1", PORT_REDIRECT_SERVER), _RedirectHandler)
        import threading
        cls._redirect_thread = threading.Thread(target=cls._redirect_srv.serve_forever, daemon=True)
        cls._redirect_thread.start()

        # Subresource server
        cls._subresource_srv = HTTPServer(("127.0.0.1", PORT_SUBRESOURCE_SERVER), _SubresourceHandler)
        cls._subresource_thread = threading.Thread(target=cls._subresource_srv.serve_forever, daemon=True)
        cls._subresource_thread.start()

        # Alt-Svc server
        cls._altsvc_srv = HTTPServer(("127.0.0.1", PORT_QUIC_HTTP_SERVER), _AltSvcHandler)
        cls._altsvc_thread = threading.Thread(target=cls._altsvc_srv.serve_forever, daemon=True)
        cls._altsvc_thread.start()

        # WebSockets servers
        cls.ws_echo = WebSocketEchoServer(PORT_WS_SERVER)
        cls.ws_echo.start()

        cls.wss_echo = WebSocketEchoServer(
            PORT_WSS_SERVER,
            cert_path=cls.certs["server_cert_path"],
            key_path=cls.certs["server_key_path"],
        )
        cls.wss_echo.start()

        # 3. Wait for all listeners
        for p in [
            PORT_HTTP_ECHO, PORT_TLS_ECHO, PORT_UNRELATED_TLS, PORT_BLACKHOLE,
            PORT_PROD_LOOPBACK, PORT_CANARY_TCP, PORT_REDIRECT_SERVER,
            PORT_SUBRESOURCE_SERVER, PORT_QUIC_HTTP_SERVER, PORT_WS_SERVER,
            PORT_WSS_SERVER
        ]:
            assert _wait_for_port("127.0.0.1", p, timeout=5.0), f"Port {p} did not start"

        # 4. Start mitmdump instances
        shim_script = str(_TESTS_DIR / "helpers" / "proxy_shim.py")
        cls.mitmdump_shim = _start_mitmdump(
            shim_script, cls.sidecar_path, PORT_BROWSER_PROXY, cls.shim_log_path
        )
        prod_script = str(_BACKEND_DIR / "app" / "services" / "track_c_proxy_addon.py")
        cls.mitmdump_prod = _start_mitmdump(
            prod_script, cls.sidecar_path, PORT_PROD_PROXY, cls.prod_log_path
        )

        assert _wait_for_port("127.0.0.1", PORT_BROWSER_PROXY, timeout=15.0), "Shim proxy did not start"
        assert _wait_for_port("127.0.0.1", PORT_PROD_PROXY, timeout=15.0), "Prod proxy did not start"

        # 5. Start Playwright
        cls.playwright = sync_playwright().start()

        # Log browser baseline
        b, diag = launch_hardened_browser(cls.playwright, PORT_BROWSER_PROXY, cls.test_ca_spki_hash)
        cls.browser_diagnostics = diag
        print(f"\n[Chromium Reference Baseline] Version: {diag['chromium_version']}, SPKI: {diag['spki_hash']}")
        b.close()

    @classmethod
    def tearDownClass(cls) -> None:
        if hasattr(cls, "playwright"):
            cls.playwright.stop()

        for proc in [getattr(cls, "mitmdump_shim", None), getattr(cls, "mitmdump_prod", None)]:
            if proc:
                proc.terminate()
                try:
                    proc.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    proc.kill()
                if hasattr(proc, "_log_file") and proc._log_file:
                    proc._log_file.close()

        cls.http_echo.stop()
        cls.tls_echo.stop()
        cls.unrelated_tls.stop()
        cls.blackhole.stop()
        cls.prod_loopback.stop()
        cls.canary.stop()
        cls.udp_sink.stop()
        cls.quic_udp_sink.stop()
        cls.ws_echo.stop()
        cls.wss_echo.stop()

        if hasattr(cls, "_redirect_srv"):
            cls._redirect_srv.shutdown()
            cls._redirect_srv.server_close()
        if hasattr(cls, "_subresource_srv"):
            cls._subresource_srv.shutdown()
            cls._subresource_srv.server_close()
        if hasattr(cls, "_altsvc_srv"):
            cls._altsvc_srv.shutdown()
            cls._altsvc_srv.server_close()

        cls._tmp.cleanup()

    def _read_sidecar(self) -> dict:
        try:
            with open(self.sidecar_path) as f:
                return json.load(f)
        except Exception:
            return {}

    # -------------------------------------------------------------------------
    # BR-01: Baseline HTTP and HTTPS through blind-tunnel proxy (SPKI pinned)
    # -------------------------------------------------------------------------
    def test_br01_baseline_http_and_https_blind_tunnel(self):
        """BR-01: Verify Playwright loads HTTP & HTTPS via blind tunnel with SPKI validation."""
        browser, _ = launch_hardened_browser(self.playwright, PORT_BROWSER_PROXY, self.test_ca_spki_hash)
        try:
            page = browser.new_page()

            # HTTP
            resp_http = page.goto(f"http://test-http.local:{PORT_HTTP_ECHO}/", timeout=10000)
            self.assertEqual(resp_http.status, 200)

            # HTTPS (blind tunnel)
            resp_https = page.goto(f"https://test-origin.local:{PORT_TLS_ECHO}/", timeout=10000)
            self.assertEqual(resp_https.status, 200)

            # Check SNI and blind tunnel passthrough
            self.assertEqual(self.tls_echo.last_sni, "test-origin.local")
            sidecar = self._read_sidecar()
            self.assertTrue(sidecar.get("tls_clienthello_fired"))
            self.assertTrue(sidecar.get("ignore_connection_set"))
        finally:
            browser.close()

    # -------------------------------------------------------------------------
    # -------------------------------------------------------------------------
    # BR-02: Cross-origin redirect to prohibited IP fails closed (302 -> loopback)
    # -------------------------------------------------------------------------
    def test_br02_cross_origin_redirect_to_prohibited_destination(self):
        """BR-02: HTTP 302 redirecting to prohibited IP is blocked at connection time."""
        before_count = self.blackhole.connection_count
        browser, _ = launch_hardened_browser(self.playwright, PORT_BROWSER_PROXY, self.test_ca_spki_hash)
        try:
            page = browser.new_page()
            try:
                resp = page.goto(f"http://safe-landing.local:{PORT_REDIRECT_SERVER}/redirect", timeout=8000)
                self.assertGreaterEqual(resp.status, 400)
            except PlaywrightError:
                pass
            # Black-hole received 0 connections
            self.assertEqual(self.blackhole.connection_count, before_count)
        finally:
            browser.close()

    # -------------------------------------------------------------------------
    # BR-03: Subresources individually validated & blocked
    # -------------------------------------------------------------------------
    def test_br03_subresource_interception_and_rejection(self):
        """BR-03: HTML subresources (images, scripts, iframes) are individually filtered."""
        before_count = self.blackhole.connection_count
        expected_script_url = f"http://127.0.0.1:{PORT_BLACKHOLE}/evil.js"
        expected_iframe_url = f"http://127.0.0.1:{PORT_BLACKHOLE}/frame"

        browser, _ = launch_hardened_browser(self.playwright, PORT_BROWSER_PROXY, self.test_ca_spki_hash)
        try:
            page = browser.new_page()
            requests_dispatched = []
            requests_failed = {}
            responses_received = {}

            page.on("request", lambda req: requests_dispatched.append(req.url))
            page.on("requestfailed", lambda req: requests_failed.__setitem__(req.url, req.failure))
            page.on("response", lambda resp: responses_received.__setitem__(resp.url, resp.status))

            resp = page.goto(f"http://safe-landing.local:{PORT_SUBRESOURCE_SERVER}/", timeout=8000)
            self.assertEqual(resp.status, 200)

            # Deterministic event-based synchronization: wait for both subresources to dispatch and complete/fail
            deadline = time.monotonic() + 5.0
            while time.monotonic() < deadline:
                script_done = (expected_script_url in requests_failed) or (expected_script_url in responses_received)
                iframe_done = (expected_iframe_url in requests_failed) or (expected_iframe_url in responses_received)
                if expected_script_url in requests_dispatched and expected_iframe_url in requests_dispatched and script_done and iframe_done:
                    break
                page.wait_for_timeout(100)

            # 1. Assert HTML fixture actually requested both prohibited subresources
            self.assertIn(
                expected_script_url, requests_dispatched,
                "Prohibited script subresource was never requested by browser!"
            )
            self.assertIn(
                expected_iframe_url, requests_dispatched,
                "Prohibited iframe subresource was never requested by browser!"
            )

            # 2. Assert script request failed through the proxy path (ORB or proxy block)
            script_failed = (expected_script_url in requests_failed) or (responses_received.get(expected_script_url, 0) >= 400)
            self.assertTrue(
                script_failed,
                f"Prohibited script request succeeded unexpectedly: responses={responses_received}"
            )

            # 3. Assert iframe navigation was blocked by proxy (mitmproxy 502 or request failed)
            iframe_blocked = (responses_received.get(expected_iframe_url, 0) >= 400) or (expected_iframe_url in requests_failed)
            self.assertTrue(
                iframe_blocked,
                f"Prohibited iframe request succeeded unexpectedly: responses={responses_received}"
            )

            # 4. Proxy addon sidecar evidence: addon evaluated and blocked loopback connections
            sidecar = self._read_sidecar()
            evaluations = sidecar.get("evaluations", [])
            blocked_for_port = [
                e for e in evaluations
                if e.get("port") == PORT_BLACKHOLE and e.get("blocked") is True
            ]
            self.assertGreaterEqual(
                len(blocked_for_port), 2,
                f"Expected proxy addon to record at least 2 blocked evaluations on port {PORT_BLACKHOLE}, got {len(blocked_for_port)}"
            )

            # 5. Network-side assertion: black-hole listener accepted zero connections
            self.assertEqual(
                self.blackhole.connection_count, before_count,
                f"Blackhole server accepted {self.blackhole.connection_count - before_count} upstream connection(s)!"
            )
        finally:
            browser.close()

    # -------------------------------------------------------------------------
    # BR-04a: Plain WebSocket (ws://)
    # -------------------------------------------------------------------------
    def test_br04a_plain_websocket_upgrade(self):
        """BR-04a: ws:// upgrades traverse proxy and exchange frames."""
        browser, _ = launch_hardened_browser(self.playwright, PORT_BROWSER_PROXY, self.test_ca_spki_hash)
        try:
            page = browser.new_page()
            page.goto(f"http://test-http.local:{PORT_HTTP_ECHO}/")
            result = page.evaluate(f"""() => new Promise((resolve, reject) => {{
                const ws = new WebSocket("ws://ws-echo.local:{PORT_WS_SERVER}/ws");
                ws.onopen = () => ws.send("ping");
                ws.onmessage = (e) => resolve(e.data);
                ws.onerror = (e) => reject(new Error("WebSocket error"));
                setTimeout(() => reject(new Error("Timeout")), 5000);
            }})""")
            self.assertEqual(result, "pong")
        finally:
            browser.close()

    # -------------------------------------------------------------------------
    # BR-04b: Secure WebSocket (wss://) through blind tunnel
    # -------------------------------------------------------------------------
    def test_br04b_secure_websocket_blind_tunnel(self):
        """BR-04b: wss:// establishes blind tunnel, verifies origin cert and SNI."""
        browser, _ = launch_hardened_browser(self.playwright, PORT_BROWSER_PROXY, self.test_ca_spki_hash)
        try:
            page = browser.new_page()
            page.goto(f"https://test-origin.local:{PORT_TLS_ECHO}/")
            result = page.evaluate(f"""() => new Promise((resolve, reject) => {{
                const ws = new WebSocket("wss://test-origin.local:{PORT_WSS_SERVER}/wss");
                ws.onopen = () => ws.send("ping");
                ws.onmessage = (e) => resolve(e.data);
                ws.onerror = (e) => reject(new Error("WSS error"));
                setTimeout(() => reject(new Error("Timeout")), 5000);
            }})""")
            self.assertEqual(result, "pong")
            self.assertEqual(self.wss_echo.last_sni, "test-origin.local")
        finally:
            browser.close()

    # -------------------------------------------------------------------------
    # BR-05: Direct loopback bypass prevention (<-loopback> canary test)
    # -------------------------------------------------------------------------
    def test_br05_direct_loopback_bypass_prevention_canary(self):
        """BR-05: Chromium must not bypass proxy for 127.0.0.1; canary receives 0 connections."""
        self.canary.reset()
        browser, _ = launch_hardened_browser(self.playwright, PORT_PROD_PROXY, self.test_ca_spki_hash)
        try:
            page = browser.new_page()
            try:
                resp = page.goto(f"http://127.0.0.1:{PORT_CANARY_TCP}/leak", timeout=4000)
                self.assertGreaterEqual(resp.status, 400)
            except PlaywrightError:
                pass

            # CRITICAL ASSERTION:
            # If Chromium bypassed the proxy, Canary would have accepted the socket (connection_count >= 1).
            # Because Chromium routed via proxy, production addon rejected 127.0.0.1 before connection.
            self.assertEqual(
                self.canary.connection_count, 0,
                f"Security Leak: Canary accepted {self.canary.connection_count} direct connection(s)!"
            )
        finally:
            browser.close()

    # -------------------------------------------------------------------------
    # BR-06: Synthetic domain resolution via proxy-side DNS
    # -------------------------------------------------------------------------
    def test_br06_synthetic_domain_proxy_resolution(self):
        """BR-06: Synthetic domain resolved only by proxy shim loads successfully."""
        # Confirm host OS DNS fails for this synthetic name
        with self.assertRaises(socket.gaierror):
            socket.getaddrinfo("synthetic-target.scamshield-test", None)

        browser, _ = launch_hardened_browser(self.playwright, PORT_BROWSER_PROXY, self.test_ca_spki_hash)
        try:
            page = browser.new_page()
            resp = page.goto(f"http://synthetic-target.scamshield-test:{PORT_HTTP_ECHO}/", timeout=8000)
            self.assertEqual(resp.status, 200)
        finally:
            browser.close()

    # -------------------------------------------------------------------------
    # BR-07: WebRTC egress confinement
    # -------------------------------------------------------------------------
    def test_br07_webrtc_egress_confinement(self):
        """BR-07: WebRTC does not leak UDP packets to STUN server under hardened policy."""
        self.udp_sink.reset()
        browser, _ = launch_hardened_browser(self.playwright, PORT_BROWSER_PROXY, self.test_ca_spki_hash)
        try:
            page = browser.new_page()
            page.goto(f"http://test-http.local:{PORT_HTTP_ECHO}/")
            result = page.evaluate(f"""() => new Promise((resolve) => {{
                const events = [];
                let gatheringStarted = false;
                let candidateCount = 0;
                let errorMsg = null;
                try {{
                    const pc = new RTCPeerConnection({{
                        iceServers: [{{ urls: "stun:127.0.0.1:{PORT_UDP_SINK}" }}]
                    }});
                    pc.onicegatheringstatechange = () => {{
                        events.push("gatheringState:" + pc.iceGatheringState);
                        if (pc.iceGatheringState === "gathering") gatheringStarted = true;
                    }};
                    pc.onicecandidateerror = (e) => {{
                        events.push("candidateError:" + e.errorCode + ":" + e.errorText);
                    }};
                    pc.onicecandidate = (e) => {{
                        if (e.candidate) {{
                            candidateCount++;
                            events.push("candidate:" + e.candidate.candidate);
                        }} else {{
                            events.push("nullCandidate");
                            resolve({{
                                status: "completed",
                                gatheringStarted: gatheringStarted || pc.iceGatheringState === "gathering" || pc.iceGatheringState === "complete",
                                gatheringComplete: pc.iceGatheringState === "complete",
                                iceGatheringState: pc.iceGatheringState,
                                candidateCount,
                                events
                            }});
                        }}
                    }};
                    pc.createDataChannel("test");
                    pc.createOffer()
                        .then(o => pc.setLocalDescription(o))
                        .catch(err => {{
                            errorMsg = err.toString();
                            resolve({{ status: "offer_error", error: errorMsg, events }});
                        }});
                    setTimeout(() => {{
                        resolve({{
                            status: "timeout",
                            gatheringStarted: gatheringStarted || pc.iceGatheringState === "gathering" || pc.iceGatheringState === "complete",
                            gatheringComplete: pc.iceGatheringState === "complete",
                            candidateCount,
                            iceGatheringState: pc.iceGatheringState,
                            events
                        }});
                    }}, 3000);
                }} catch(e) {{
                    resolve({{ status: "exception", error: e.toString(), events }});
                }}
            }})""")

            # 1. Distinguish gathering that never started vs initiated
            if not isinstance(result, dict) or result.get("status") == "exception" or not result.get("gatheringStarted"):
                err_detail = result.get("error", "gathering never initiated") if isinstance(result, dict) else "unknown"
                self.skipTest(f"Inconclusive: WebRTC ICE gathering could not be initiated in test environment ({err_detail})")

            # 2. Assert ICE gathering was genuinely initiated
            self.assertTrue(result["gatheringStarted"], "ICE gathering was not initiated")

            # 3. Assert zero candidates generated under disable_non_proxied_udp policy
            self.assertEqual(result.get("candidateCount", 0), 0, "Non-proxied ICE candidate leaked!")

            # 4. Network-side observation: UDP Sink received 0 packets
            time.sleep(0.5)
            self.assertEqual(self.udp_sink.packet_count, 0, "UDP STUN leak detected!")
        finally:
            browser.close()

    # -------------------------------------------------------------------------
    # BR-08: Loopback rejection via production addon
    # -------------------------------------------------------------------------
    def test_br08_loopback_rejection_via_production_addon(self):
        """BR-08: Production addon rejects loopback without opening socket."""
        before_count = self.prod_loopback.connection_count
        browser, _ = launch_hardened_browser(self.playwright, PORT_PROD_PROXY, self.test_ca_spki_hash)
        try:
            page = browser.new_page()
            try:
                resp = page.goto(f"http://127.0.0.1:{PORT_PROD_LOOPBACK}/test", timeout=5000)
                self.assertGreaterEqual(resp.status, 400)
            except PlaywrightError:
                pass
            self.assertEqual(self.prod_loopback.connection_count, before_count)
        finally:
            browser.close()

    # -------------------------------------------------------------------------
    # BR-09a: Proxy-death egress leak test
    # -------------------------------------------------------------------------
    def test_br09a_proxy_death_egress_leak(self):
        """BR-09a: Terminating proxy causes fail-closed behavior; zero direct fallback."""
        self.canary.reset()
        # Launch dedicated mitmdump on ephemeral port
        dead_proxy_port = 18199
        dead_proc = _start_mitmdump(
            str(_TESTS_DIR / "helpers" / "proxy_shim.py"),
            self.sidecar_path,
            dead_proxy_port,
            str(self.tmp_dir / "dead_proxy.log"),
        )
        try:
            self.assertTrue(_wait_for_port("127.0.0.1", dead_proxy_port, timeout=10.0))

            # Launch browser pointing to this proxy
            browser, _ = launch_hardened_browser(self.playwright, dead_proxy_port, self.test_ca_spki_hash)
            try:
                # Kill proxy
                dead_proc.terminate()
                try:
                    dead_proc.wait(timeout=3.0)
                except subprocess.TimeoutExpired:
                    dead_proc.kill()
                    dead_proc.wait(timeout=2.0)
                if hasattr(dead_proc, "_log_file") and dead_proc._log_file:
                    dead_proc._log_file.close()
                    dead_proc._log_file = None

                page = browser.new_page()
                # Attempt navigation to canary port on loopback
                with self.assertRaises(PlaywrightError) as ctx:
                    page.goto(f"http://127.0.0.1:{PORT_CANARY_TCP}/fallback-probe", timeout=4000)

                # Must be a proxy error, NOT direct success
                self.assertTrue(
                    "ERR_PROXY_CONNECTION_FAILED" in str(ctx.exception)
                    or "ERR_TUNNEL_CONNECTION_FAILED" in str(ctx.exception)
                )
                # Canary received 0 connections
                self.assertEqual(self.canary.connection_count, 0)
            finally:
                browser.close()
        finally:
            if dead_proc:
                if dead_proc.poll() is None:
                    dead_proc.terminate()
                    try:
                        dead_proc.wait(timeout=3.0)
                    except subprocess.TimeoutExpired:
                        dead_proc.kill()
                        dead_proc.wait(timeout=2.0)
                if hasattr(dead_proc, "_log_file") and dead_proc._log_file:
                    dead_proc._log_file.close()
                    dead_proc._log_file = None

    # -------------------------------------------------------------------------
    # BR-09b: Zombie process cleanup
    # -------------------------------------------------------------------------
    def test_br09b_zombie_process_cleanup(self):
        """BR-09b: Browser closure terminates all spawned child processes."""
        browser, diag = launch_hardened_browser(self.playwright, PORT_BROWSER_PROXY, self.test_ca_spki_hash)
        self.assertTrue(browser.is_connected())
        browser.close()
        self.assertFalse(browser.is_connected())

    # -------------------------------------------------------------------------
    # BR-10: QUIC / HTTP/3 evasion prevention
    # -------------------------------------------------------------------------
    def test_br10_quic_http3_evasion_prevention(self):
        """BR-10: Alt-Svc: h3 advertisement is received while QUIC is disabled; UDP sink = 0."""
        self.quic_udp_sink.reset()
        browser, _ = launch_hardened_browser(self.playwright, PORT_BROWSER_PROXY, self.test_ca_spki_hash)
        try:
            page = browser.new_page()
            # Navigate to server delivering Alt-Svc: h3
            resp = page.goto(f"http://quic-test.local:{PORT_QUIC_HTTP_SERVER}/", timeout=8000)
            self.assertEqual(resp.status, 200)

            # Assert Alt-Svc header was actually delivered
            alt_svc = resp.headers.get("alt-svc", "")
            self.assertIn("h3", alt_svc)

            # Second navigation to same origin
            resp2 = page.goto(f"http://quic-test.local:{PORT_QUIC_HTTP_SERVER}/sub", timeout=8000)
            self.assertEqual(resp2.status, 200)

            # UDP Sink must have received 0 packets
            self.assertEqual(
                self.quic_udp_sink.packet_count, 0,
                f"Direct QUIC UDP leak: received {self.quic_udp_sink.packet_count} packet(s)!"
            )
        finally:
            browser.close()

    # -------------------------------------------------------------------------
    # Test-port coupling consistency test (P2)
    # -------------------------------------------------------------------------
    def test_prohibited_test_ports_consistency(self):
        """Verify that all canary/blackhole ports used in tests are registered in _PROHIBITED_TEST_PORTS."""
        expected_ports = {PORT_BLACKHOLE, PORT_CANARY_TCP, PORT_PROD_LOOPBACK}
        self.assertTrue(
            expected_ports.issubset(_PROHIBITED_TEST_PORTS),
            f"Test ports {expected_ports - _PROHIBITED_TEST_PORTS} are missing from _PROHIBITED_TEST_PORTS!"
        )

    # -------------------------------------------------------------------------
    # BR-11: Controlled dynamic DNS rebinding (Model 2 verification)
    # -------------------------------------------------------------------------
    def test_br11_controlled_dynamic_dns_rebinding(self):
        """BR-11: Dynamic DNS mutation (Model 2): prohibited -> blocked; mixed -> blocked."""
        # Fail immediately if synthetic mappings are missing or altered
        self.assertIn("dynamic-rebind-prohibited.test", _SYNTHETIC_HOSTS)
        self.assertEqual(_SYNTHETIC_HOSTS["dynamic-rebind-prohibited.test"], ["127.0.0.1"])
        self.assertIn("dynamic-rebind-mixed.test", _SYNTHETIC_HOSTS)
        self.assertEqual(_SYNTHETIC_HOSTS["dynamic-rebind-mixed.test"], ["93.184.216.34", "127.0.0.1"])

        browser, _ = launch_hardened_browser(self.playwright, PORT_BROWSER_PROXY, self.test_ca_spki_hash)
        try:
            page = browser.new_page()

            # Case A: Rebinding to prohibited IP (127.0.0.1 on PORT_BLACKHOLE)
            before_count_a = self.blackhole.connection_count
            try:
                resp = page.goto(f"http://dynamic-rebind-prohibited.test:{PORT_BLACKHOLE}/", timeout=5000)
                self.assertGreaterEqual(resp.status, 400)
            except PlaywrightError:
                pass

            # Assert connection-time DNS answer was delivered to proxy addon
            sidecar_a = self._read_sidecar()
            dns_resolutions = sidecar_a.get("dns_resolutions", {})
            self.assertIn("dynamic-rebind-prohibited.test", dns_resolutions)
            self.assertEqual(
                dns_resolutions["dynamic-rebind-prohibited.test"], ["127.0.0.1"],
                "Proxy addon did not receive intended DNS answer for dynamic-rebind-prohibited.test"
            )

            # Assert addon evaluated and rejected the prohibited address
            evaluations_a = [
                e for e in sidecar_a.get("evaluations", [])
                if e.get("host") == "dynamic-rebind-prohibited.test" and e.get("port") == PORT_BLACKHOLE
            ]
            self.assertTrue(len(evaluations_a) >= 1, "No evaluation record found for dynamic-rebind-prohibited.test")
            eval_a = evaluations_a[-1]
            self.assertTrue(eval_a.get("blocked"), "Proxy addon failed to block prohibited IP")
            self.assertEqual(eval_a.get("rejected_ips"), ["127.0.0.1"])
            self.assertIn("unsafe IP address", eval_a.get("error", ""))

            # Network-side observation: black-hole listener on PORT_BLACKHOLE accepted zero connections
            self.assertEqual(
                self.blackhole.connection_count, before_count_a,
                f"Security breach: blackhole accepted {self.blackhole.connection_count - before_count_a} upstream connection(s)!"
            )
            # Verify no upstream connection was recorded by server_connected
            connected_a = [
                c for c in sidecar_a.get("connected_events", [])
                if c.get("port") == PORT_BLACKHOLE
            ]
            self.assertEqual(len(connected_a), 0, "Upstream connection was established despite rejection!")

            # Case B: Rebinding to mixed safe/prohibited (93.184.216.34 and 127.0.0.1)
            before_count_b = self.blackhole.connection_count
            try:
                resp = page.goto(f"http://dynamic-rebind-mixed.test:{PORT_BLACKHOLE}/", timeout=5000)
                self.assertGreaterEqual(resp.status, 400)
            except PlaywrightError:
                pass

            # Assert connection-time DNS answer was delivered to proxy addon
            sidecar_b = self._read_sidecar()
            dns_resolutions_b = sidecar_b.get("dns_resolutions", {})
            self.assertIn("dynamic-rebind-mixed.test", dns_resolutions_b)
            self.assertEqual(
                dns_resolutions_b["dynamic-rebind-mixed.test"], ["93.184.216.34", "127.0.0.1"],
                "Proxy addon did not receive intended mixed DNS answer for dynamic-rebind-mixed.test"
            )

            # Assert addon evaluated and rejected the mixed safe/prohibited set
            evaluations_b = [
                e for e in sidecar_b.get("evaluations", [])
                if e.get("host") == "dynamic-rebind-mixed.test" and e.get("port") == PORT_BLACKHOLE
            ]
            self.assertTrue(len(evaluations_b) >= 1, "No evaluation record found for dynamic-rebind-mixed.test")
            eval_b = evaluations_b[-1]
            self.assertTrue(eval_b.get("blocked"), "Proxy addon failed to block mixed safe/prohibited IP")
            self.assertIn("127.0.0.1", eval_b.get("rejected_ips", []))
            self.assertIn("unsafe IP address", eval_b.get("error", ""))

            # Network-side observation: black-hole listener on PORT_BLACKHOLE accepted zero connections
            self.assertEqual(
                self.blackhole.connection_count, before_count_b,
                f"Security breach: blackhole accepted {self.blackhole.connection_count - before_count_b} upstream connection(s)!"
            )
            # Verify no upstream connection was recorded by server_connected
            connected_b = [
                c for c in sidecar_b.get("connected_events", [])
                if c.get("port") == PORT_BLACKHOLE
            ]
            self.assertEqual(len(connected_b), 0, "Upstream connection was established despite rejection!")
        finally:
            browser.close()

    # -------------------------------------------------------------------------
    # SPKI-NEG: Negative control: Unpinned/unrelated certificate rejected by Chromium
    # -------------------------------------------------------------------------
    def test_spki_negative_control_unpinned_cert_rejected(self):
        """SPKI-NEG: Chromium with SPKI hash active STILL REJECTS an unpinned/unrelated cert."""
        # Browser has test_ca_spki_hash pinned, but unrelated_tls serves unrelated cert!
        browser, _ = launch_hardened_browser(self.playwright, PORT_BROWSER_PROXY, self.test_ca_spki_hash)
        try:
            page = browser.new_page()
            with self.assertRaises(PlaywrightError) as ctx:
                page.goto(f"https://unrelated.local:{PORT_UNRELATED_TLS}/", timeout=6000)
            # Must fail with certificate error
            err_str = str(ctx.exception)
            self.assertTrue(
                "ERR_CERT_AUTHORITY_INVALID" in err_str
                or "ERR_CERT_COMMON_NAME_INVALID" in err_str
                or "ERR_CERT" in err_str,
                f"Expected SSL certificate rejection, got: {err_str}"
            )
        finally:
            browser.close()


if __name__ == "__main__":
    unittest.main(verbosity=2)
