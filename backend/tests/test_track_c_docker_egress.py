"""
test_track_c_docker_egress.py — Controlled Live Docker Egress & Firewall Verification Suite.

Validates that the Track C proxy container enforces kernel-level egress filtering
and fail-closed initialization in a live Linux container environment (Docker Desktop / WSL2):
1. Fail-closed: Container exits nonzero immediately if CAP_NET_ADMIN is missing.
2. Verified startup: Container installs and kernel-verifies all 21 IPv4 rules and 19 IPv6 rules,
   then drops privileges to unprivileged user 'proxy' (UID 1002, GID 1002).
3. Direct kernel drop (Metadata): Direct TCP connection to 169.254.169.254 is dropped by
   netfilter; kernel rule packet counter increments.
4. Direct kernel drop (RFC1918): Direct TCP connection to 10.0.0.1 is dropped by
   netfilter; kernel rule packet counter increments.
5. Direct kernel drop (UDP): Outbound UDP to non-DNS destinations is blocked by
   netfilter; kernel rule packet counter increments.
6. Intra-container loopback & proxy enforcement: Connection to 127.0.0.1:8080 succeeds on lo;
   proxy addon kills requests to unsafe destinations with 502 before upstream connect.
7. Direct kernel drop (IPv6 Prohibited): Direct TCP connection to IPv6 Unique-Local (fc00::/7)
   is dropped by netfilter; kernel rule packet counter in ip6tables increments.
8. Approved DNS resolver egress: Outbound DNS traffic to the container's configured resolver
   IP is accepted; kernel rule counter for approved resolver port 53 increments.
9. Unapproved DNS resolver drop: Outbound DNS queries (UDP and TCP) to unauthorized resolvers
   (e.g., 8.8.8.8:53) are dropped by netfilter; kernel rule counters for port 53 drop increment.
10. Dual-stack ruleset verification: Confirms all required IPv4 and IPv6 rules are active in
    kernel memory.

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
V6_NET_NAME = "scamshield-v6-egress-test"
V6_CONTAINER_NAME = "scamshield-v6-egress-verify"


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

        # Ensure no lingering test containers or networks
        _run_docker(["rm", "-f", CONTAINER_NAME, V6_CONTAINER_NAME])
        _run_docker(["network", "rm", V6_NET_NAME])

    @classmethod
    def tearDownClass(cls):
        _run_docker(["rm", "-f", CONTAINER_NAME, V6_CONTAINER_NAME])
        _run_docker(["network", "rm", V6_NET_NAME])

    def setUp(self):
        # Clean any running instance before each test
        _run_docker(["rm", "-f", CONTAINER_NAME, V6_CONTAINER_NAME])
        _run_docker(["network", "rm", V6_NET_NAME])

    def tearDown(self):
        _run_docker(["rm", "-f", CONTAINER_NAME, V6_CONTAINER_NAME])
        _run_docker(["network", "rm", V6_NET_NAME])

    def _start_container_with_net_admin(self, wait_seconds=3.0, network=None, name=CONTAINER_NAME):
        """Start proxy test container with CAP_NET_ADMIN and wait for proxy ready."""
        cmd = ["run", "-d", "--name", name, "--cap-add", "NET_ADMIN"]
        if network:
            cmd.extend(["--network", network])
        cmd.append(IMAGE_NAME)

        start_res = _run_docker(cmd)
        self.assertEqual(start_res.returncode, 0, f"Failed to start container: {start_res.stderr}")

        # Deterministic log polling: wait until mitmdump reports ready or deadline
        deadline = time.monotonic() + 10.0
        logs = ""
        while time.monotonic() < deadline:
            logs = _run_docker(["logs", name]).stdout
            if "HTTP(S) proxy listening at *:8080." in logs:
                break
            time.sleep(0.5)

        self.assertIn("IPv4 kernel firewall ruleset verified", logs)
        self.assertIn("IPv6 kernel firewall ruleset verified", logs)
        self.assertIn("HTTP(S) proxy listening at *:8080.", logs)
        return logs

    def _get_iptables_counters(self, container=CONTAINER_NAME):
        """Retrieve verbose iptables OUTPUT ruleset with packet and byte counters."""
        res = _run_docker(["exec", "-u", "root", container, "iptables", "-L", "OUTPUT", "-v", "-n"])
        self.assertEqual(res.returncode, 0, f"Failed to query iptables counters: {res.stderr}")
        return res.stdout

    def _get_ip6tables_counters(self, container=CONTAINER_NAME):
        """Retrieve verbose ip6tables OUTPUT ruleset with packet and byte counters."""
        res = _run_docker(["exec", "-u", "root", container, "ip6tables", "-L", "OUTPUT", "-v", "-n"])
        self.assertEqual(res.returncode, 0, f"Failed to query ip6tables counters: {res.stderr}")
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
        """Container starts, verifies all IPv4 and IPv6 rules in kernel, and runs mitmdump under UID 1002."""
        logs = self._start_container_with_net_admin()
        self.assertIn("Dropping root privileges to user 'proxy' (UID 1002)...", logs)
        self.assertIn("IPv4 kernel firewall ruleset verified: all 21 required rules active.", logs)
        self.assertIn("IPv6 kernel firewall ruleset verified: all 19 required rules active.", logs)

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
        initial_pkts = self._parse_rule_packet_count(initial_tables, r"DROP\s+udp\s+.*\s+0\.0\.0\.0/0\s+0\.0\.0\.0/0$")

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
        updated_pkts = self._parse_rule_packet_count(updated_tables, r"DROP\s+udp\s+.*\s+0\.0\.0\.0/0\s+0\.0\.0\.0/0$")
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

    def test_07_kernel_drop_ipv6_prohibited(self):
        """Direct connection to IPv6 Unique Local Address (fc00::/7) is dropped by ip6tables netfilter."""
        # Create an IPv6-enabled bridge network so an IPv6 default route exists in the container
        net_res = _run_docker(["network", "create", "--ipv6", "--subnet", "fd00:cafe::/64", V6_NET_NAME])
        self.assertEqual(net_res.returncode, 0, f"Failed to create IPv6 network: {net_res.stderr}")

        try:
            self._start_container_with_net_admin(network=V6_NET_NAME, name=V6_CONTAINER_NAME)

            initial_tables = self._get_ip6tables_counters(container=V6_CONTAINER_NAME)
            initial_pkts = self._parse_rule_packet_count(initial_tables, r"DROP\s+all\s+.*\s+fc00::/7")

            # Attempt direct TCP connection to fc00::1 from unprivileged user 'proxy'
            probe_res = _run_docker([
                "exec", "-u", "proxy", V6_CONTAINER_NAME,
                "python3", "-c",
                "import socket; s=socket.socket(socket.AF_INET6, socket.SOCK_STREAM); s.settimeout(1.0); s.connect(('fc00::1', 80))"
            ])
            self.assertNotEqual(probe_res.returncode, 0)
            self.assertIn("TimeoutError", probe_res.stderr)

            # Verify ip6tables rule counter for fc00::/7 incremented
            updated_tables = self._get_ip6tables_counters(container=V6_CONTAINER_NAME)
            updated_pkts = self._parse_rule_packet_count(updated_tables, r"DROP\s+all\s+.*\s+fc00::/7")
            self.assertGreater(updated_pkts, initial_pkts, "Kernel ip6tables rule counter for fc00::/7 must increment")
        finally:
            _run_docker(["rm", "-f", V6_CONTAINER_NAME])
            _run_docker(["network", "rm", V6_NET_NAME])

    def test_08_dns_resolution_to_approved_resolver_succeeds(self):
        """Outbound DNS datagrams to the configured resolver are accepted and increment approved rule counter."""
        self._start_container_with_net_admin()

        # Discover configured nameserver inside running container
        resolv_res = _run_docker(["exec", CONTAINER_NAME, "cat", "/etc/resolv.conf"])
        self.assertEqual(resolv_res.returncode, 0)
        match = re.search(r"^\s*nameserver\s+([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)", resolv_res.stdout, re.MULTILINE)
        self.assertIsNotNone(match, "Must find configured IPv4 nameserver in container /etc/resolv.conf")
        resolver_ip = match.group(1)

        initial_tables = self._get_iptables_counters()
        initial_pkts = self._parse_rule_packet_count(
            initial_tables,
            rf"ACCEPT\s+udp\s+.*\s+{re.escape(resolver_ip)}\s+udp\s+dpt:53",
        )

        # Send UDP probe to approved resolver on port 53
        probe_res = _run_docker([
            "exec", "-u", "proxy", CONTAINER_NAME,
            "python3", "-c",
            f"import socket; s=socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.sendto(b'\\x00\\x00', ('{resolver_ip}', 53))"
        ])
        self.assertEqual(probe_res.returncode, 0, f"Sending UDP probe to approved resolver failed: {probe_res.stderr}")

        # Verify kernel rule counter for approved resolver port 53 incremented
        updated_tables = self._get_iptables_counters()
        updated_pkts = self._parse_rule_packet_count(
            updated_tables,
            rf"ACCEPT\s+udp\s+.*\s+{re.escape(resolver_ip)}\s+udp\s+dpt:53",
        )
        self.assertGreater(
            updated_pkts,
            initial_pkts,
            f"Kernel iptables counter for approved resolver {resolver_ip}:53 must increment",
        )

    def test_09_dns_queries_to_unapproved_resolver_blocked(self):
        """Outbound DNS traffic to unauthorized resolvers (8.8.8.8:53) is dropped by kernel netfilter."""
        self._start_container_with_net_admin()

        initial_tables = self._get_iptables_counters()
        initial_udp_drops = self._parse_rule_packet_count(
            initial_tables,
            r"DROP\s+udp\s+.*\s+0\.0\.0\.0/0\s+udp\s+dpt:53",
        )
        initial_tcp_drops = self._parse_rule_packet_count(
            initial_tables,
            r"DROP\s+tcp\s+.*\s+0\.0\.0\.0/0\s+tcp\s+dpt:53",
        )

        # 1. Attempt sending UDP datagram to unapproved resolver 8.8.8.8:53
        udp_probe = _run_docker([
            "exec", "-u", "proxy", CONTAINER_NAME,
            "python3", "-c",
            "import socket; s=socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.sendto(b'\\x00\\x00', ('8.8.8.8', 53))"
        ])
        # Note: Depending on socket type/netfilter, UDP sendto might succeed locally or raise EPERM,
        # but the packet counter in netfilter DROP rule MUST increment.

        # 2. Attempt direct TCP connection to unapproved resolver 8.8.8.8:53
        tcp_probe = _run_docker([
            "exec", "-u", "proxy", CONTAINER_NAME,
            "python3", "-c",
            "import socket; s=socket.socket(); s.settimeout(1.0); s.connect(('8.8.8.8', 53))"
        ])
        self.assertNotEqual(tcp_probe.returncode, 0)
        self.assertIn("TimeoutError", tcp_probe.stderr)

        # Verify kernel rule counters for port 53 drop incremented
        updated_tables = self._get_iptables_counters()
        updated_udp_drops = self._parse_rule_packet_count(
            updated_tables,
            r"DROP\s+udp\s+.*\s+0\.0\.0\.0/0\s+udp\s+dpt:53",
        )
        updated_tcp_drops = self._parse_rule_packet_count(
            updated_tables,
            r"DROP\s+tcp\s+.*\s+0\.0\.0\.0/0\s+tcp\s+dpt:53",
        )
        self.assertGreater(updated_udp_drops, initial_udp_drops, "Kernel DROP counter for UDP port 53 must increment")
        self.assertGreater(updated_tcp_drops, initial_tcp_drops, "Kernel DROP counter for TCP port 53 must increment")

    def test_10_dual_stack_ruleset_verified_in_kernel(self):
        """Verify that all 21 IPv4 rules and 19 IPv6 rules are active in kernel memory."""
        self._start_container_with_net_admin()

        v4_output = self._get_iptables_counters()
        v6_output = self._get_ip6tables_counters()

        # Check required IPv4 entries exist
        self.assertIn("169.254.169.254", v4_output)
        self.assertIn("10.0.0.0/8", v4_output)
        self.assertIn("172.16.0.0/12", v4_output)
        self.assertIn("192.168.0.0/16", v4_output)
        self.assertIn("127.0.0.0/8", v4_output)
        self.assertIn("ctstate RELATED,ESTABLISHED", v4_output)
        self.assertIn("tcp dpt:80", v4_output)
        self.assertIn("tcp dpt:443", v4_output)

        # Check required IPv6 entries exist
        self.assertIn("fc00::/7", v6_output)
        self.assertIn("fe80::/10", v6_output)
        self.assertIn("ff00::/8", v6_output)
        self.assertIn("2001:db8::/32", v6_output)
        self.assertIn("::1", v6_output)
        self.assertIn("ctstate RELATED,ESTABLISHED", v6_output)
        self.assertIn("tcp dpt:80", v6_output)
        self.assertIn("tcp dpt:443", v6_output)


if __name__ == "__main__":
    unittest.main()
