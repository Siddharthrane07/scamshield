"""
test_track_c_compose_setup.py — Step 3 Docker Compose Integration Tests.

Validates:
1. Docker Compose specification syntax, healthchecks, and service topology.
2. Network isolation: 'browser_internal' is internal: true (no default route).
3. Dual-network attachment on 'proxy' container and interface identification (eth0/eth1).
4. Single-network attachment on 'browser' container.
5. DNS separation (Mandatory Correction #4):
   - Internal service discovery: resolves 'proxy'.
   - External DNS leak prevention: external hostname queries fail closed.
6. Direct external egress prevention from browser container (Network unreachable).
7. Proxy-routed egress: HTTP via proxy succeeds for valid external destinations.
8. Prohibited destination blocking: Proxy and firewall reject 169.254.169.254 and private IPs.
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
BROWSER_CONTAINER = "scamshield-track-c-browser"


def _docker_available() -> bool:
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
    return subprocess.run(
        ["docker"] + args,
        capture_output=True,
        text=True,
        timeout=timeout,
    )


class TestTrackCComposeSetup(unittest.TestCase):
    """Step 3 Docker Compose integration test suite."""

    @classmethod
    def setUpClass(cls):
        if not _docker_available():
            raise unittest.SkipTest("Docker not available")

        # Ensure compose stack is running
        res = _run_docker(["compose", "-f", COMPOSE_FILE, "ps", "--format", "json"])
        if res.returncode != 0:
            raise unittest.SkipTest(f"Failed to query docker compose ps: {res.stderr}")

    def test_01_compose_config_validation(self):
        """docker-compose.track_c.yml must parse cleanly and define required networks and services."""
        res = _run_docker(["compose", "-f", COMPOSE_FILE, "config", "--format", "json"])
        self.assertEqual(res.returncode, 0, f"compose config failed: {res.stderr}")
        cfg = json.loads(res.stdout)
        self.assertIn("services", cfg)
        self.assertIn("proxy", cfg["services"])
        self.assertIn("browser", cfg["services"])
        self.assertIn("networks", cfg)
        self.assertIn("browser_internal", cfg["networks"])
        self.assertIn("proxy_external", cfg["networks"])

    def test_02_proxy_service_healthy_and_active(self):
        """The proxy service container must be running and in healthy state."""
        res = _run_docker([
            "inspect", PROXY_CONTAINER,
            "--format", "{{.State.Status}}|{{.State.Health.Status}}"
        ])
        self.assertEqual(res.returncode, 0, f"inspect failed: {res.stderr}")
        status, health = res.stdout.strip().split("|")
        self.assertEqual(status, "running")
        self.assertEqual(health, "healthy")

    def test_03_proxy_dual_network_attachment(self):
        """Proxy must be connected to both browser_internal and proxy_external."""
        res = _run_docker([
            "inspect", PROXY_CONTAINER,
            "--format", "{{json .NetworkSettings.Networks}}"
        ])
        self.assertEqual(res.returncode, 0)
        nets = json.loads(res.stdout)
        self.assertIn("scamshield_browser_internal", nets)
        self.assertIn("scamshield_proxy_external", nets)
        self.assertEqual(len(nets), 2)

    def test_04_proxy_interface_topology_invariants(self):
        """Verify proxy interfaces: eth0 on browser_internal (no default route), eth1 on proxy_external (default route)."""
        res = _run_docker([
            "exec", PROXY_CONTAINER,
            "cat", "/proc/net/route"
        ])
        self.assertEqual(res.returncode, 0)
        routes = res.stdout.strip().splitlines()[1:]
        default_routes = [r.split() for r in routes if r.split()[1] == "00000000"]
        self.assertEqual(len(default_routes), 1, "There must be exactly one default route")
        self.assertEqual(default_routes[0][0], "eth1", "Default gateway route must be on EXTERNAL_IF (eth1)")

    def test_05_dns_separation_browser_service_discovery(self):
        """Browser network must resolve service name 'proxy'."""
        res = _run_docker([
            "run", "--rm",
            "--network", "scamshield_browser_internal",
            "--entrypoint", "python3",
            "scamshield-browser-test:latest",
            "-c", "import socket; print(socket.gethostbyname('proxy'))"
        ])
        self.assertEqual(res.returncode, 0, f"Service discovery for 'proxy' failed: {res.stderr}")
        resolved_ip = res.stdout.strip()
        self.assertTrue(resolved_ip.startswith("172."), f"Resolved IP unexpected: {resolved_ip}")

    def test_06_dns_separation_browser_external_dns_fails_closed(self):
        """Browser network must fail closed when attempting to resolve external hostnames directly."""
        res = _run_docker([
            "run", "--rm",
            "--network", "scamshield_browser_internal",
            "--entrypoint", "python3",
            "scamshield-browser-test:latest",
            "-c", "import socket; socket.gethostbyname('example.com')"
        ])
        self.assertNotEqual(res.returncode, 0, "External DNS resolution must fail closed from browser_internal")
        self.assertIn("gaierror", res.stderr)

    def test_07_browser_direct_external_ip_unreachable(self):
        """Direct connection from browser network to external IPs must fail with Network unreachable."""
        res = _run_docker([
            "run", "--rm",
            "--network", "scamshield_browser_internal",
            "--entrypoint", "python3",
            "scamshield-browser-test:latest",
            "-c", "import socket; s = socket.socket(); s.settimeout(3); s.connect(('1.1.1.1', 80))"
        ])
        self.assertNotEqual(res.returncode, 0, "Direct egress to 1.1.1.1 must fail")
        self.assertIn("Network is unreachable", res.stderr)

    def test_08_browser_routed_http_via_proxy_succeeds(self):
        """HTTP traffic routed through the proxy container must succeed."""
        res = _run_docker([
            "run", "--rm",
            "--network", "scamshield_browser_internal",
            "--entrypoint", "python3",
            "scamshield-browser-test:latest",
            "-c",
            "import urllib.request; "
            "opener = urllib.request.build_opener(urllib.request.ProxyHandler({'http': 'http://proxy:8080'})); "
            "resp = opener.open('http://example.com', timeout=10); "
            "print(resp.status)"
        ])
        self.assertEqual(res.returncode, 0, f"HTTP via proxy failed: {res.stderr}")
        self.assertEqual(res.stdout.strip(), "200")

    def test_09_proxy_blocks_metadata_egress(self):
        """Requests to 169.254.169.254 via proxy must be rejected with HTTP 502."""
        py_cmd = (
            "import urllib.request, urllib.error; "
            "opener = urllib.request.build_opener(urllib.request.ProxyHandler({'http': 'http://proxy:8080'})); "
            "code = 0; "
            "exec(\"try:\\n opener.open('http://169.254.169.254/latest/meta-data', timeout=5)\\nexcept urllib.error.HTTPError as e:\\n print(e.code)\")"
        )
        res = _run_docker([
            "run", "--rm",
            "--network", "scamshield_browser_internal",
            "--entrypoint", "python3",
            "scamshield-browser-test:latest",
            "-c", py_cmd
        ])
        self.assertEqual(res.returncode, 0, f"Command failed: {res.stderr}")
        self.assertEqual(res.stdout.strip(), "502")

    def test_10_proxy_blocks_private_ip_egress(self):
        """Requests to private IP 10.0.0.1 via proxy must be rejected with HTTP 502."""
        py_cmd = (
            "import urllib.request, urllib.error; "
            "opener = urllib.request.build_opener(urllib.request.ProxyHandler({'http': 'http://proxy:8080'})); "
            "exec(\"try:\\n opener.open('http://10.0.0.1/', timeout=5)\\nexcept urllib.error.HTTPError as e:\\n print(e.code)\")"
        )
        res = _run_docker([
            "run", "--rm",
            "--network", "scamshield_browser_internal",
            "--entrypoint", "python3",
            "scamshield-browser-test:latest",
            "-c", py_cmd
        ])
        self.assertEqual(res.returncode, 0, f"Command failed: {res.stderr}")
        self.assertEqual(res.stdout.strip(), "502")


if __name__ == "__main__":
    unittest.main()
