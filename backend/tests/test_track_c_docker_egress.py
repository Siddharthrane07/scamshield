"""
test_track_c_docker_egress.py — Controlled Live Docker Egress & Firewall Verification Suite.

Validates that the Track C proxy container enforces kernel-level egress filtering
and fail-closed initialization in a live Linux container environment (Docker Desktop / WSL2):
1. Fail-closed: Container exits nonzero immediately if CAP_NET_ADMIN is missing.
2. Verified startup: Container installs and kernel-verifies all 19 IPv4 rules, then drops
   privileges to unprivileged user 'proxy' (UID 1002, GID 1002).
3. Direct kernel drop (Metadata): Direct TCP connection to 169.254.169.254 is dropped by
   netfilter; kernel rule 1 packet counter increments.
4. Direct kernel drop (RFC1918): Direct TCP connection to 10.0.0.1 is dropped by
   netfilter; kernel rule 3 packet counter increments.
5. Direct kernel drop (UDP): Outbound UDP to non-DNS destinations is blocked by
   netfilter; kernel rule 16 packet counter increments.
6. Intra-container loopback & proxy enforcement: Connection to 127.0.0.1:8080 succeeds on lo;
   proxy addon kills requests to unsafe destinations with 502 before upstream connect.

Host firewalls are never modified. No public internet network access is required.
"""

import json
import logging
import re
import shutil
import subprocess
import time
import unittest

logger = logging.getLogger("scamshield.tests.docker_egress")

IMAGE_NAME = "scamshield-proxy-test:latest"
CONTAINER_NAME = "scamshield-proxy-egress-verify"


def _docker_available() -> bool:
    """Check if Docker CLI is present and the Docker daemon is responsive."""
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


def _run_docker(args, timeout=15):
    """Run a docker command and return the CompletedProcess."""
    return subprocess.run(
        ["docker"] + args,
        capture_output=True,
        text=True,
        timeout=timeout,
    )


class TestTrackCDockerEgressLive(unittest.TestCase):
    """Controlled live Docker container verification for Track C Proxy."""

    @classmethod
    def setUpClass(cls):
        if not _docker_available():
            raise unittest.SkipTest("Docker daemon not accessible; skipping live container verification")

        # Verify target image exists
        inspect_res = _run_docker(["image", "inspect", IMAGE_NAME, "--format", "{{.Id}}"])
        if inspect_res.returncode != 0:
            raise unittest.SkipTest(f"Required Docker image '{IMAGE_NAME}' not found. Build image first.")

        # Ensure no lingering test container
        _run_docker(["rm", "-f", CONTAINER_NAME])

    @classmethod
    def tearDownClass(cls):
        _run_docker(["rm", "-f", CONTAINER_NAME])

    def setUp(self):
        # Clean any running instance before each test
        _run_docker(["rm", "-f", CONTAINER_NAME])

    def tearDown(self):
        _run_docker(["rm", "-f", CONTAINER_NAME])

    def _start_container_with_net_admin(self, wait_seconds=3.0):
        """Start proxy test container with CAP_NET_ADMIN and wait for proxy ready."""
        start_res = _run_docker([
            "run", "-d",
            "--name", CONTAINER_NAME,
            "--cap-add", "NET_ADMIN",
            IMAGE_NAME,
        ])
        self.assertEqual(start_res.returncode, 0, f"Failed to start container: {start_res.stderr}")
        time.sleep(wait_seconds)

        logs_res = _run_docker(["logs", CONTAINER_NAME])
        self.assertIn("Kernel firewall ruleset verified: all 19 required rules active.", logs_res.stdout)
        self.assertIn("HTTP(S) proxy listening at *:8080.", logs_res.stdout)
        return logs_res.stdout

    def _get_iptables_counters(self):
        """Retrieve verbose iptables OUTPUT ruleset with packet and byte counters."""
        res = _run_docker(["exec", "-u", "root", CONTAINER_NAME, "iptables", "-L", "OUTPUT", "-v", "-n"])
        self.assertEqual(res.returncode, 0, f"Failed to query iptables counters: {res.stderr}")
        return res.stdout

    def _parse_rule_packet_count(self, iptables_output, pattern):
        """Extract packet count for the first rule matching regex pattern."""
        for line in iptables_output.splitlines():
            line_str = line.strip()
            if re.search(pattern, line_str):
                parts = line_str.split()
                if parts and parts[0].isdigit():
                    return int(parts[0])
        return 0

    def test_01_fail_closed_without_cap_net_admin(self):
        """Container must fail-closed and exit nonzero when CAP_NET_ADMIN is missing."""
        res = _run_docker(["run", "--rm", IMAGE_NAME])
        self.assertNotEqual(res.returncode, 0, "Container must exit nonzero without CAP_NET_ADMIN")
        combined_output = res.stdout + res.stderr
        self.assertIn("FATAL", combined_output)
        self.assertIn("CAP_NET_ADMIN missing", combined_output)
        self.assertNotIn("HTTP(S) proxy listening", combined_output)

    def test_02_verified_startup_and_unprivileged_user(self):
        """Container starts, verifies all 19 rules in kernel, and runs mitmdump under UID 1002."""
        logs = self._start_container_with_net_admin()
        self.assertIn("Dropping root privileges to user 'proxy' (UID 1002)...", logs)

        # Inspect running process credentials inside container
        proc_status = _run_docker([
            "exec", CONTAINER_NAME,
            "python3", "-c", "print(open('/proc/1/status').read())"
        ])
        self.assertEqual(proc_status.returncode, 0)
        status_text = proc_status.stdout
        self.assertIn("Name:\tmitmdump", status_text)
        # Verify UID and GID are 1002
        self.assertRegex(status_text, r"Uid:\s+1002\s+1002\s+1002\s+1002")
        self.assertRegex(status_text, r"Gid:\s+1002\s+1002\s+1002\s+1002")

    def test_03_kernel_drop_metadata_ip(self):
        """Direct connection to 169.254.169.254 from proxy user is dropped by kernel netfilter."""
        self._start_container_with_net_admin()

        initial_tables = self._get_iptables_counters()
        initial_pkts = self._parse_rule_packet_count(initial_tables, r"DROP\s+all\s+.*\s+169\.254\.169\.254")

        # Attempt direct TCP connection as unprivileged user 'proxy'
        probe_res = _run_docker([
            "exec", "-u", "proxy", CONTAINER_NAME,
            "python3", "-c",
            "import socket; s=socket.socket(); s.settimeout(1.0); s.connect(('169.254.169.254', 80))"
        ])
        # Connection must fail due to packet drop (timed out)
        self.assertNotEqual(probe_res.returncode, 0)
        self.assertIn("TimeoutError", probe_res.stderr)

        # Verify kernel rule counter incremented
        updated_tables = self._get_iptables_counters()
        updated_pkts = self._parse_rule_packet_count(updated_tables, r"DROP\s+all\s+.*\s+169\.254\.169\.254")
        self.assertGreater(updated_pkts, initial_pkts, "Kernel netfilter rule counter for 169.254.169.254 must increment")

    def test_04_kernel_drop_rfc1918_private_ips(self):
        """Direct connection to 10.0.0.1 from proxy user is dropped by kernel netfilter."""
        self._start_container_with_net_admin()

        initial_tables = self._get_iptables_counters()
        initial_pkts = self._parse_rule_packet_count(initial_tables, r"DROP\s+all\s+.*\s+10\.0\.0\.0/8")

        # Attempt direct TCP connection to RFC1918 subnet
        probe_res = _run_docker([
            "exec", "-u", "proxy", CONTAINER_NAME,
            "python3", "-c",
            "import socket; s=socket.socket(); s.settimeout(1.0); s.connect(('10.0.0.1', 80))"
        ])
        self.assertNotEqual(probe_res.returncode, 0)
        self.assertIn("TimeoutError", probe_res.stderr)

        # Verify kernel rule counter incremented
        updated_tables = self._get_iptables_counters()
        updated_pkts = self._parse_rule_packet_count(updated_tables, r"DROP\s+all\s+.*\s+10\.0\.0\.0/8")
        self.assertGreater(updated_pkts, initial_pkts, "Kernel netfilter rule counter for 10.0.0.0/8 must increment")

    def test_05_kernel_drop_unauthorized_udp(self):
        """Direct outbound UDP to public non-DNS destinations is blocked by kernel netfilter."""
        self._start_container_with_net_admin()

        initial_tables = self._get_iptables_counters()
        initial_pkts = self._parse_rule_packet_count(initial_tables, r"DROP\s+udp\s+.*\s+0\.0\.0\.0/0")

        # Attempt sending UDP datagram to non-DNS port (9999)
        probe_res = _run_docker([
            "exec", "-u", "proxy", CONTAINER_NAME,
            "python3", "-c",
            "import socket; s=socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.sendto(b'probe', ('93.184.216.34', 9999))"
        ])
        # Kernel netfilter rejects outbound packet with EPERM (Operation not permitted)
        self.assertNotEqual(probe_res.returncode, 0)
        self.assertIn("PermissionError", probe_res.stderr)

        # Verify kernel rule counter incremented
        updated_tables = self._get_iptables_counters()
        updated_pkts = self._parse_rule_packet_count(updated_tables, r"DROP\s+udp\s+.*\s+0\.0\.0\.0/0")
        self.assertGreater(updated_pkts, initial_pkts, "Kernel netfilter rule counter for UDP DROP must increment")

    def test_06_loopback_acceptance_and_proxy_addon_rejection(self):
        """Intra-container loopback to mitmdump succeeds, and proxy addon rejects unsafe destinations."""
        self._start_container_with_net_admin()

        # 1. Intra-container loopback connects successfully
        loopback_probe = _run_docker([
            "exec", "-u", "proxy", CONTAINER_NAME,
            "python3", "-c",
            "import socket; s=socket.create_connection(('127.0.0.1', 8080), timeout=2); print('LO_OK'); s.close()"
        ])
        self.assertEqual(loopback_probe.returncode, 0)
        self.assertIn("LO_OK", loopback_probe.stdout)

        # 2. HTTP request through proxy to 10.0.0.1 returns 502 Bad Gateway
        req_probe = _run_docker([
            "exec", "-u", "proxy", CONTAINER_NAME,
            "python3", "-c",
            "import urllib.request; req = urllib.request.Request('http://10.0.0.1/'); req.set_proxy('127.0.0.1:8080', 'http'); urllib.request.urlopen(req, timeout=3)"
        ])
        self.assertNotEqual(req_probe.returncode, 0)
        self.assertIn("HTTP Error 502: Bad Gateway", req_probe.stderr)

        # Verify proxy addon logged connection kill before connect
        logs = _run_docker(["logs", CONTAINER_NAME]).stdout
        self.assertIn("server connection to 10.0.0.1:80 killed before connect: Upstream resolves to unsafe IP address: 10.0.0.1", logs)


if __name__ == "__main__":
    unittest.main()

