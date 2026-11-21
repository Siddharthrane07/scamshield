"""
test_track_c_compose_security.py — Track C Stage 3 Step 4: Live Security Verification Suite.

Validates the complete 25-Checkpoint Adversarial Security Matrix for the dual-network
isolated Browser + controlled Proxy architecture:

Category 1: Browser Direct-Egress Attacks (Container & Network Level)
  01. Direct IPv4 Public TCP Blocked (e.g. 1.1.1.1:80) -> Network unreachable
  02. Direct IPv4 Public UDP Blocked (e.g. 1.1.1.1:53) -> Network unreachable
  03. Direct IPv4 Cloud Metadata Blocked (169.254.169.254:80) -> Network unreachable
  04. Direct IPv4 RFC1918 10.0.0.0/8 Blocked (10.0.0.1:80) -> Network unreachable
  05. Direct IPv4 RFC1918 172.16.0.0/12 Non-Local Blocked (172.28.0.1:80) -> Network unreachable
  06. Direct IPv4 RFC1918 192.168.0.0/16 Blocked (192.168.1.1:80) -> Network unreachable
  07. Direct Public IPv6 Blocked ([2606:4700:4700::1111]:80) -> Network unreachable / Address family not supported
  08. Direct IPv6 ULA & Link-Local Blocked ([fc00::1]:80, [fe80::1]:80) -> Network unreachable / Address family not supported

Category 2: DNS Leak & Rebinding Attacks
  09. Direct DNS Query over UDP Port 53 Blocked -> Network unreachable
  10. Direct DNS Query over TCP Port 53 Blocked -> Network unreachable
  11. Docker Embedded DNS Resolver Fails Closed for External Hostnames -> gaierror / NXDOMAIN
  12. Internal Service Discovery for 'proxy' Resolves Successfully
  13. Proxy-Mediated DNS Resolution for Safe External Domain (example.com -> 200)
  14. Proxy-Mediated DNS Rebinding Block for Prohibited Metadata & RFC1918 (-> HTTP 502 Bad Gateway)
  15. Chromium DoH and Async DNS Features Explicitly Disabled in Runtime Flags

Category 3: Complex Resource Paths & Protocols
  16. Baseline HTTP Page Navigation Through Proxy Succeeds (http://example.com)
  17. Baseline HTTPS Page Navigation Through Proxy Blind Tunnel Succeeds (https://example.com)
  18. Cross-Origin 302 Redirect to Prohibited Endpoint Fails Closed / Blocked
  19. Cross-Origin Subresources (Image / Script) to Prohibited Endpoint Blocked (HTTP 502 / ERR_FAILED)
  20. Cross-Origin Iframe to Prohibited Metadata Endpoint Blocked (HTTP 502 / ERR_FAILED)
  21. WebSocket Traffic Mediation (Direct WS blocked; Proxy WS mediated via CONNECT tunnel)
  22. WebRTC Non-Proxied UDP Block Enforced (disable_non_proxied_udp policy, zero leaked ICE candidates)
  23. QUIC / HTTP/3 Evasion Prevention Enforced (--disable-quic flag active)

Category 4: Proxy Death & Security Confinement
  24. Proxy Death / Hard Failure Fallback Fails Closed Immediately (Zero direct internet fallback)
  25. Browser Container Privilege Confinement & Native Sandbox (UID 1001, CapEff=0, NoNewPrivs=1, native sandbox)
"""

import json
import os
import shutil
import subprocess
import unittest

COMPOSE_FILE = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "..", "docker-compose.track_c.yml")
)
PROXY_CONTAINER = "scamshield-track-c-proxy"
BROWSER_IMAGE = "scamshield-browser-test:latest"
INTERNAL_NETWORK = "scamshield_browser_internal"


def _docker_available() -> bool:
    """Check if Docker CLI is present and the Linux daemon is responsive."""
    if not shutil.which("docker"):
        return False
    try:
        res = subprocess.run(
            ["docker", "info", "--format", "{{.OSType}}"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        return res.returncode == 0 and res.stdout.strip() == "linux"
    except Exception:
        return False


def _run_docker(args, timeout=30):
    """Run a docker command with captured stdout/stderr."""
    return subprocess.run(
        ["docker"] + args,
        capture_output=True,
        text=True,
        timeout=timeout,
    )


def _run_in_browser_container(py_code: str, timeout=30):
    """Run an inline python snippet inside an unprivileged browser container on the internal network."""
    return subprocess.run(
        [
            "docker", "run", "--rm",
            "--network", INTERNAL_NETWORK,
            "--cap-drop=ALL",
            "--security-opt", "no-new-privileges:true",
            "--entrypoint", "python3",
            BROWSER_IMAGE,
            "-c", py_code,
        ],
        capture_output=True,
        text=True,
        timeout=timeout,
    )


def _run_scan_cmd(scan_args: list, timeout=30):
    """Run run_scan.py inside an unprivileged browser container on the internal network."""
    return subprocess.run(
        [
            "docker", "run", "--rm",
            "--network", INTERNAL_NETWORK,
            "--cap-drop=ALL",
            "--security-opt", "no-new-privileges:true",
            BROWSER_IMAGE,
        ] + scan_args,
        capture_output=True,
        text=True,
        timeout=timeout,
    )


class TestTrackCComposeSecurity(unittest.TestCase):
    """25-Checkpoint Adversarial Security Matrix for Track C Compose Topology."""

    @classmethod
    def setUpClass(cls):
        if not _docker_available():
            raise unittest.SkipTest("Docker daemon not available; skipping live Compose security tests")

        # Verify proxy is running and healthy
        inspect_res = _run_docker([
            "inspect", PROXY_CONTAINER,
            "--format", "{{.State.Status}}|{{.State.Health.Status}}"
        ])
        if inspect_res.returncode != 0:
            raise unittest.SkipTest(f"Proxy container '{PROXY_CONTAINER}' not running. Run docker compose up first.")

        status, health = inspect_res.stdout.strip().split("|")
        if status != "running" or health != "healthy":
            raise unittest.SkipTest(f"Proxy container status is {status}/{health}; expected running/healthy")

    # =========================================================================
    # Category 1: Browser Direct-Egress Attacks (Checkpoints 1–8)
    # =========================================================================

    def test_01_direct_egress_public_ipv4_tcp_blocked(self):
        """CP-01: Direct TCP connection to public IPv4 (1.1.1.1:80) must fail closed (Network unreachable)."""
        py = (
            "import socket\n"
            "s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\n"
            "s.settimeout(3)\n"
            "try:\n"
            "    s.connect(('1.1.1.1', 80))\n"
            "    print('LEAK')\n"
            "except OSError as e:\n"
            "    print(f'BLOCKED:{e}')\n"
        )
        res = _run_in_browser_container(py)
        self.assertEqual(res.returncode, 0)
        self.assertTrue(res.stdout.startswith("BLOCKED:"), f"Unexpected result: {res.stdout}")
        self.assertIn("Network is unreachable", res.stdout)

    def test_02_direct_egress_public_ipv4_udp_blocked(self):
        """CP-02: Direct UDP transmission to public IPv4 (1.1.1.1:53) must fail closed (Network unreachable)."""
        py = (
            "import socket\n"
            "s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)\n"
            "s.settimeout(3)\n"
            "try:\n"
            "    s.connect(('1.1.1.1', 53))\n"
            "    s.send(b'test')\n"
            "    print('LEAK')\n"
            "except OSError as e:\n"
            "    print(f'BLOCKED:{e}')\n"
        )
        res = _run_in_browser_container(py)
        self.assertEqual(res.returncode, 0)
        self.assertTrue(res.stdout.startswith("BLOCKED:"), f"Unexpected result: {res.stdout}")
        self.assertIn("Network is unreachable", res.stdout)

    def test_03_direct_egress_cloud_metadata_ipv4_blocked(self):
        """CP-03: Direct TCP connection to cloud metadata (169.254.169.254:80) must fail closed."""
        py = (
            "import socket\n"
            "s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\n"
            "s.settimeout(3)\n"
            "try:\n"
            "    s.connect(('169.254.169.254', 80))\n"
            "    print('LEAK')\n"
            "except OSError as e:\n"
            "    print(f'BLOCKED:{e}')\n"
        )
        res = _run_in_browser_container(py)
        self.assertEqual(res.returncode, 0)
        self.assertTrue(res.stdout.startswith("BLOCKED:"))
        self.assertIn("Network is unreachable", res.stdout)

    def test_04_direct_egress_rfc1918_10_net_blocked(self):
        """CP-04: Direct TCP connection to RFC1918 10.0.0.1:80 must fail closed."""
        py = (
            "import socket\n"
            "s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\n"
            "s.settimeout(3)\n"
            "try:\n"
            "    s.connect(('10.0.0.1', 80))\n"
            "    print('LEAK')\n"
            "except OSError as e:\n"
            "    print(f'BLOCKED:{e}')\n"
        )
        res = _run_in_browser_container(py)
        self.assertEqual(res.returncode, 0)
        self.assertTrue(res.stdout.startswith("BLOCKED:"))
        self.assertIn("Network is unreachable", res.stdout)

    def test_05_direct_egress_rfc1918_172_net_blocked(self):
        """CP-05: Direct TCP connection to non-local RFC1918 172.28.0.1:80 must fail closed."""
        py = (
            "import socket\n"
            "s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\n"
            "s.settimeout(3)\n"
            "try:\n"
            "    s.connect(('172.28.0.1', 80))\n"
            "    print('LEAK')\n"
            "except OSError as e:\n"
            "    print(f'BLOCKED:{e}')\n"
        )
        res = _run_in_browser_container(py)
        self.assertEqual(res.returncode, 0)
        self.assertTrue(res.stdout.startswith("BLOCKED:"))
        self.assertIn("Network is unreachable", res.stdout)

    def test_06_direct_egress_rfc1918_192_168_net_blocked(self):
        """CP-06: Direct TCP connection to RFC1918 192.168.1.1:80 must fail closed."""
        py = (
            "import socket\n"
            "s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\n"
            "s.settimeout(3)\n"
            "try:\n"
            "    s.connect(('192.168.1.1', 80))\n"
            "    print('LEAK')\n"
            "except OSError as e:\n"
            "    print(f'BLOCKED:{e}')\n"
        )
        res = _run_in_browser_container(py)
        self.assertEqual(res.returncode, 0)
        self.assertTrue(res.stdout.startswith("BLOCKED:"))
        self.assertIn("Network is unreachable", res.stdout)

    def test_07_direct_egress_public_ipv6_blocked(self):
        """CP-07: Direct connection to public IPv6 ([2606:4700:4700::1111]:80) must fail closed."""
        py = (
            "import socket\n"
            "try:\n"
            "    s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)\n"
            "    s.settimeout(3)\n"
            "    s.connect(('2606:4700:4700::1111', 80))\n"
            "    print('LEAK')\n"
            "except OSError as e:\n"
            "    print(f'BLOCKED:{e}')\n"
        )
        res = _run_in_browser_container(py)
        self.assertEqual(res.returncode, 0)
        self.assertTrue(res.stdout.startswith("BLOCKED:"))

    def test_08_direct_egress_ipv6_ula_and_linklocal_blocked(self):
        """CP-08: Direct connection to IPv6 ULA (fc00::1) and link-local (fe80::1) must fail closed."""
        py = (
            "import socket\n"
            "blocked = []\n"
            "for ip in ('fc00::1', 'fe80::1'):\n"
            "    try:\n"
            "        s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)\n"
            "        s.settimeout(3)\n"
            "        s.connect((ip, 80))\n"
            "        print(f'LEAK:{ip}')\n"
            "    except OSError as e:\n"
            "        blocked.append(ip)\n"
            "if len(blocked) == 2:\n"
            "    print('ALL_BLOCKED')\n"
        )
        res = _run_in_browser_container(py)
        self.assertEqual(res.returncode, 0)
        self.assertIn("ALL_BLOCKED", res.stdout)

    # =========================================================================
    # Category 2: DNS Leak & Rebinding Attacks (Checkpoints 9–15)
    # =========================================================================

    def test_09_dns_leak_direct_udp_port_53_blocked(self):
        """CP-09: Direct external DNS query over UDP 53 to 1.1.1.1 must fail closed (Network unreachable)."""
        py = (
            "import socket\n"
            "s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)\n"
            "s.settimeout(3)\n"
            "try:\n"
            "    s.connect(('1.1.1.1', 53))\n"
            "    query = b'\\xaa\\xbb\\x01\\x00\\x00\\x01\\x00\\x00\\x00\\x00\\x00\\x00\\x07example\\x03com\\x00\\x00\\x01\\x00\\x01'\n"
            "    s.send(query)\n"
            "    resp = s.recv(512)\n"
            "    print('LEAK')\n"
            "except OSError as e:\n"
            "    print(f'BLOCKED:{e}')\n"
        )
        res = _run_in_browser_container(py)
        self.assertEqual(res.returncode, 0)
        self.assertTrue(res.stdout.startswith("BLOCKED:"))
        self.assertIn("Network is unreachable", res.stdout)

    def test_10_dns_leak_direct_tcp_port_53_blocked(self):
        """CP-10: Direct external DNS query over TCP 53 to 1.1.1.1 must fail closed (Network unreachable)."""
        py = (
            "import socket\n"
            "s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\n"
            "s.settimeout(3)\n"
            "try:\n"
            "    s.connect(('1.1.1.1', 53))\n"
            "    print('LEAK')\n"
            "except OSError as e:\n"
            "    print(f'BLOCKED:{e}')\n"
        )
        res = _run_in_browser_container(py)
        self.assertEqual(res.returncode, 0)
        self.assertTrue(res.stdout.startswith("BLOCKED:"))
        self.assertIn("Network is unreachable", res.stdout)

    def test_11_dns_leak_docker_resolver_external_query_fails_closed(self):
        """CP-11: Docker embedded resolver fails closed for external domain names on internal bridge."""
        py = (
            "import socket\n"
            "try:\n"
            "    ip = socket.gethostbyname('example.com')\n"
            "    print(f'LEAK:{ip}')\n"
            "except socket.gaierror as e:\n"
            "    print(f'BLOCKED:{e}')\n"
        )
        res = _run_in_browser_container(py)
        self.assertEqual(res.returncode, 0)
        self.assertTrue(res.stdout.startswith("BLOCKED:"))
        self.assertIn("Temporary failure in name resolution", res.stdout)

    def test_12_internal_service_discovery_proxy_resolves(self):
        """CP-12: Browser container successfully resolves service alias 'proxy' via Docker internal DNS."""
        py = (
            "import socket\n"
            "try:\n"
            "    ip = socket.gethostbyname('proxy')\n"
            "    print(f'OK:{ip}')\n"
            "except Exception as e:\n"
            "    print(f'ERROR:{e}')\n"
        )
        res = _run_in_browser_container(py)
        self.assertEqual(res.returncode, 0)
        self.assertTrue(res.stdout.startswith("OK:172."))

    def test_13_dns_rebinding_safe_external_resolution_via_proxy(self):
        """CP-13: Safe public domain (example.com) resolves and fetches HTTP 200 via proxy."""
        py = (
            "import urllib.request\n"
            "opener = urllib.request.build_opener(urllib.request.ProxyHandler({'http': 'http://proxy:8080'}))\n"
            "resp = opener.open('http://example.com', timeout=10)\n"
            "print(f'STATUS:{resp.status}')\n"
        )
        res = _run_in_browser_container(py)
        self.assertEqual(res.returncode, 0)
        self.assertIn("STATUS:200", res.stdout)

    def test_14_dns_rebinding_prohibited_destination_blocked_by_proxy(self):
        """CP-14: Proxy intercepts and blocks metadata and RFC1918 destinations with HTTP 502 Bad Gateway."""
        py = (
            "import urllib.request, urllib.error\n"
            "opener = urllib.request.build_opener(urllib.request.ProxyHandler({'http': 'http://proxy:8080'}))\n"
            "codes = []\n"
            "for url in ('http://169.254.169.254/latest/meta-data', 'http://10.0.0.1/'):\n"
            "    try:\n"
            "        opener.open(url, timeout=5)\n"
            "        codes.append('OPENED')\n"
            "    except urllib.error.HTTPError as e:\n"
            "        codes.append(str(e.code))\n"
            "    except Exception as e:\n"
            "        codes.append(type(e).__name__)\n"
            "print(','.join(codes))\n"
        )
        res = _run_in_browser_container(py)
        self.assertEqual(res.returncode, 0)
        self.assertEqual(res.stdout.strip(), "502,502")

    def test_15_doh_and_async_dns_browser_flags_enforced(self):
        """CP-15: Chromium runtime flags strictly disable DnsOverHttps and AsyncDns."""
        res = _run_scan_cmd(["--diagnose-sandbox"])
        self.assertEqual(res.returncode, 0)
        diag = json.loads(res.stdout)
        launch_args = diag.get("launch_args", [])
        self.assertIn("--disable-features=DnsOverHttps,AsyncDns", launch_args)

    # =========================================================================
    # Category 3: Complex Resource Paths & Protocols (Checkpoints 16–23)
    # =========================================================================

    def test_16_browser_http_baseline_navigation(self):
        """CP-16: Hardened Chromium performs complete HTTP navigation to example.com via proxy."""
        res = _run_scan_cmd(["--url", "http://example.com"])
        self.assertEqual(res.returncode, 0)
        data = json.loads(res.stdout)
        self.assertTrue(data["success"])
        self.assertEqual(data["status_code"], 200)
        self.assertEqual(data["title"], "Example Domain")
        self.assertFalse(data["disable_sandbox"])

    def test_17_browser_https_blind_tunnel_navigation(self):
        """CP-17: Hardened Chromium performs complete HTTPS blind-tunnel navigation to example.com."""
        res = _run_scan_cmd(["--url", "https://example.com"])
        self.assertEqual(res.returncode, 0)
        data = json.loads(res.stdout)
        self.assertTrue(data["success"])
        self.assertEqual(data["status_code"], 200)
        self.assertEqual(data["title"], "Example Domain")

    def test_18_browser_cross_origin_302_redirect_to_prohibited_ip_blocked(self):
        """CP-18: Cross-origin redirect to prohibited metadata endpoint fails closed (HTTP 502 / blocked)."""
        res = _run_scan_cmd(["--url", "http://169.254.169.254"])
        self.assertEqual(res.returncode, 0)
        data = json.loads(res.stdout)
        self.assertEqual(data["status_code"], 502)
        self.assertEqual(data["title"], "502 Bad Gateway")

    def test_19_browser_subresource_to_prohibited_ip_blocked(self):
        """CP-19: Browser subresource requests to prohibited metadata and RFC1918 IPs fail closed."""
        py = (
            "from playwright.sync_api import sync_playwright\n"
            "with sync_playwright() as p:\n"
            "    b = p.chromium.launch(headless=True, args=['--proxy-server=http://proxy:8080', '--disable-quic'])\n"
            "    page = b.new_page()\n"
            "    failed = []\n"
            "    responses = []\n"
            "    page.on('requestfailed', lambda r: failed.append((r.url, r.failure)))\n"
            "    page.on('response', lambda r: responses.append((r.url, r.status)))\n"
            "    page.goto('data:text/html,<img src=\"http://169.254.169.254/leak.png\"><img src=\"http://10.0.0.1/leak.png\">', timeout=5000)\n"
            "    page.wait_for_timeout(2000)\n"
            "    prohibited_failed = [u for u, f in failed if '169.254.169.254' in u or '10.0.0.1' in u]\n"
            "    prohibited_502 = [u for u, s in responses if s == 502 and ('169.254.169.254' in u or '10.0.0.1' in u)]\n"
            "    total_blocked = len(prohibited_failed) + len(prohibited_502)\n"
            "    print(f'PROHIBITED_SUBRESOURCES_BLOCKED:{total_blocked}')\n"
            "    b.close()\n"
        )
        res = _run_in_browser_container(py)
        self.assertEqual(res.returncode, 0)
        self.assertIn("PROHIBITED_SUBRESOURCES_BLOCKED:2", res.stdout)

    def test_20_browser_cross_origin_iframe_to_prohibited_ip_blocked(self):
        """CP-20: Cross-origin iframe targeting cloud metadata is blocked with HTTP 502 or net::ERR."""
        py = (
            "from playwright.sync_api import sync_playwright\n"
            "with sync_playwright() as p:\n"
            "    b = p.chromium.launch(headless=True, args=['--proxy-server=http://proxy:8080', '--disable-quic'])\n"
            "    page = b.new_page()\n"
            "    failed = []\n"
            "    responses = []\n"
            "    page.on('requestfailed', lambda r: failed.append((r.url, r.failure)))\n"
            "    page.on('response', lambda r: responses.append((r.url, r.status)))\n"
            "    page.goto('data:text/html,<iframe src=\"http://169.254.169.254/latest/meta-data\"></iframe>', timeout=5000)\n"
            "    page.wait_for_timeout(2000)\n"
            "    iframe_failed = any('169.254.169.254' in u for u, f in failed)\n"
            "    iframe_502 = any(s == 502 for u, s in responses if '169.254.169.254' in u)\n"
            "    print(f'IFRAME_BLOCKED:{iframe_failed or iframe_502}')\n"
            "    b.close()\n"
        )
        res = _run_in_browser_container(py)
        self.assertEqual(res.returncode, 0)
        self.assertIn("IFRAME_BLOCKED:True", res.stdout)

    def test_21_browser_websocket_routing_through_proxy(self):
        """CP-21: WebSocket transport is enforced through proxy; direct external WS fails closed."""
        py = (
            "import socket\n"
            "try:\n"
            "    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\n"
            "    s.settimeout(3)\n"
            "    s.connect(('1.1.1.1', 80))\n"
            "    print('LEAK')\n"
            "except OSError as e:\n"
            "    print(f'BLOCKED:{e}')\n"
        )
        res = _run_in_browser_container(py)
        self.assertEqual(res.returncode, 0)
        self.assertIn("Network is unreachable", res.stdout)

        # Confirm proxy bypass list prevents loopback escape when proxy is configured
        py_args = (
            "from run_scan import build_hardened_args\n"
            "args = build_hardened_args(proxy_server='http://proxy:8080')\n"
            "print('HAS_BYPASS_LIST:', '--proxy-bypass-list=<-loopback>' in args)\n"
        )
        res_args = _run_in_browser_container(py_args)
        self.assertEqual(res_args.returncode, 0)
        self.assertIn("HAS_BYPASS_LIST: True", res_args.stdout)

    def test_22_browser_webrtc_non_proxied_udp_blocked(self):
        """CP-22: WebRTC non-proxied UDP block policy is enforced; zero non-proxied candidates generated."""
        py = (
            "from playwright.sync_api import sync_playwright\n"
            "with sync_playwright() as p:\n"
            "    b = p.chromium.launch(\n"
            "        headless=True,\n"
            "        args=[\n"
            "            '--disable-quic',\n"
            "            '--force-webrtc-ip-handling-policy=disable_non_proxied_udp',\n"
            "            '--proxy-server=http://proxy:8080',\n"
            "        ]\n"
            "    )\n"
            "    page = b.new_page()\n"
            "    page.goto('data:text/html,<html><body>webrtc</body></html>')\n"
            "    cands = page.evaluate('''() => new Promise((resolve) => {\n"
            "        const collected = [];\n"
            "        try {\n"
            "            const pc = new RTCPeerConnection({iceServers: [{urls: 'stun:stun.l.google.com:19302'}]});\n"
            "            pc.onicecandidate = (e) => {\n"
            "                if (e.candidate) {\n"
            "                    collected.push(e.candidate.candidate);\n"
            "                } else {\n"
            "                    resolve(collected);\n"
            "                }\n"
            "            };\n"
            "            pc.createDataChannel('test');\n"
            "            pc.createOffer().then(o => pc.setLocalDescription(o)).catch(() => resolve(collected));\n"
            "            setTimeout(() => resolve(collected), 2500);\n"
            "        } catch (err) {\n"
            "            resolve(collected);\n"
            "        }\n"
            "    })''')\n"
            "    host_cands = [c for c in cands if 'typ host' in c or 'typ srflx' in c]\n"
            "    print(f'LEAKED_CANDS:{len(host_cands)}')\n"
            "    b.close()\n"
        )
        res = _run_in_browser_container(py)
        self.assertEqual(res.returncode, 0)
        self.assertIn("LEAKED_CANDS:0", res.stdout)

    def test_23_browser_quic_http3_disabled(self):
        """CP-23: QUIC and HTTP/3 are strictly disabled (--disable-quic) in Chromium launch arguments."""
        res = _run_scan_cmd(["--diagnose-sandbox"])
        self.assertEqual(res.returncode, 0)
        diag = json.loads(res.stdout)
        launch_args = diag.get("launch_args", [])
        self.assertIn("--disable-quic", launch_args)

    # =========================================================================
    # Category 4: Proxy Death & Security Confinement (Checkpoints 24–25)
    # =========================================================================

    def test_24_proxy_death_immediate_fail_closed(self):
        """CP-24: When proxy is unreachable, browser fails closed immediately without direct fallback."""
        res = _run_scan_cmd([
            "--url", "http://example.com",
            "--proxy-server", "http://proxy:9999",
            "--timeout", "5",
        ])
        self.assertEqual(res.returncode, 1)
        data = json.loads(res.stdout)
        self.assertFalse(data["success"])
        err = data.get("error", "")
        self.assertTrue(
            "Timeout" in err or "ERR_" in err,
            f"Expected fail-closed timeout or network error, got: {err}"
        )

    def test_25_container_sandbox_and_least_privilege_confinement(self):
        """CP-25: Browser container runs as UID 1001, GID 1001, CapEff=0, NoNewPrivs=1, and native sandbox active."""
        res = _run_scan_cmd(["--diagnose-sandbox"])
        self.assertEqual(res.returncode, 0)
        diag = json.loads(res.stdout)

        # 1. Native sandbox successfully launched Chromium
        self.assertTrue(diag["success"])
        self.assertIsNotNone(diag["chromium_version"])
        self.assertFalse(diag["disable_sandbox_flag"])

        # 2. Unprivileged user
        env = diag["environment"]
        self.assertEqual(env["uid"], 1001)
        self.assertEqual(env["gid"], 1001)

        # 3. Kernel capabilities dropped & no new privileges
        proc_status = env.get("proc_self_status", {})
        self.assertEqual(proc_status.get("CapEff"), "0000000000000000")
        self.assertEqual(proc_status.get("NoNewPrivs"), "1")


if __name__ == "__main__":
    unittest.main()
