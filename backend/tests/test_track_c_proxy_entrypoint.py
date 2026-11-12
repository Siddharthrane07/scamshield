"""
test_track_c_proxy_entrypoint.py — Hardened Startup & Firewall Verification Tests for Track C Proxy.

Validates that docker/proxy/entrypoint.sh adheres to fail-closed security invariants:
1. Missing iptables or ip6tables tooling exits nonzero (refuses to start).
2. Insufficient permissions (missing CAP_NET_ADMIN) for iptables or ip6tables exits nonzero.
3. Missing or invalid DNS resolver configuration (/etc/resolv.conf) exits nonzero.
4. Cloud metadata IP (169.254.169.254) or multicast IPv6 configured as resolver exits nonzero.
5. Any IPv4 or IPv6 rule installation failure aborts immediately with nonzero exit code.
6. Ruleset verification failure (rule missing or inactive via -C) aborts before mitmdump.
7. Strict dual-stack rule ordering is enforced:
   - Approved DNS resolver port 53 egress precedes port 53 drop.
   - Port 53 drop precedes prohibited destination drops.
   - Prohibited destination drops strictly precede stateful ESTABLISHED,RELATED acceptance.
   - Intra-container loopback acceptance (-o lo -j ACCEPT) precedes external loopback drop.
   - External loopback drop precedes ESTABLISHED,RELATED acceptance.
   - Default deny (-j DROP) is the final rule in both chains.
8. Successful firewall installation and verification proceeds to unprivileged execution.
9. Missing proxy addon script exits nonzero (refuses to start).
10. Mitmdump CLI arguments in both root and unprivileged execution branches are verified.

All tests use isolated mock binaries in a synthetic PATH.
Host firewalls are never altered and no public network access is required.
"""

import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
import unittest

_BACKEND_DIR = pathlib.Path(__file__).resolve().parent.parent
_REPO_ROOT = _BACKEND_DIR.parent
_ENTRYPOINT_SCRIPT = _REPO_ROOT / "docker" / "proxy" / "entrypoint.sh"

EXPECTED_RULES_V4 = [
    # Phase 1A: Approved IPv4 DNS resolver egress (strictly port 53 to verified resolver IP only)
    "-d 192.168.65.7 -p udp --dport 53 -j ACCEPT",
    "-d 192.168.65.7 -p tcp --dport 53 -j ACCEPT",
    # Phase 1B: Explicit denial of all other IPv4 DNS port 53 egress
    "-p udp --dport 53 -j DROP",
    "-p tcp --dport 53 -j DROP",
    # Phase 1C: Prohibited IPv4 destination drops (unconditional, precedes stateful acceptance)
    "-d 169.254.169.254/32 -j DROP",
    "-d 169.254.0.0/16 -j DROP",
    "-d 10.0.0.0/8 -j DROP",
    "-d 172.16.0.0/12 -j DROP",
    "-d 192.168.0.0/16 -j DROP",
    "-d 100.64.0.0/10 -j DROP",
    "-d 198.18.0.0/15 -j DROP",
    "-d 198.51.100.0/24 -j DROP",
    "-d 203.0.113.0/24 -j DROP",
    "-d 240.0.0.0/4 -j DROP",
    # Phase 2: Intra-container loopback interface communication
    "-o lo -j ACCEPT",
    # Phase 3: Prohibit loopback-addressed traffic on external interfaces
    "-d 127.0.0.0/8 -j DROP",
    # Phase 4: Stateful return traffic acceptance (for permitted public destinations only)
    "-m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT",
    # Phase 5: Permitted outbound transport & port rules (Public destinations only)
    "-p udp -j DROP",
    "-p tcp --dport 80 -j ACCEPT",
    "-p tcp --dport 443 -j ACCEPT",
    # Phase 6: Default deny for all remaining outbound traffic
    "-j DROP",
]

EXPECTED_RULES_V6 = [
    # Phase 1B: Explicit denial of all other IPv6 DNS port 53 egress (no IPv6 resolver by default)
    "-p udp --dport 53 -j DROP",
    "-p tcp --dport 53 -j DROP",
    # Phase 1C: Prohibited IPv6 destination drops (unconditional, precedes stateful acceptance)
    "-d ::/128 -j DROP",
    "-d ::ffff:0:0/96 -j DROP",
    "-d 64:ff9b::/96 -j DROP",
    "-d 100::/64 -j DROP",
    "-d 2001:db8::/32 -j DROP",
    "-d 2001:10::/28 -j DROP",
    "-d 2001:2::/48 -j DROP",
    "-d fc00::/7 -j DROP",
    "-d fe80::/10 -j DROP",
    "-d ff00::/8 -j DROP",
    # Phase 2: Intra-container loopback interface communication
    "-o lo -j ACCEPT",
    # Phase 3: Prohibit loopback-addressed traffic on external interfaces
    "-d ::1/128 -j DROP",
    # Phase 4: Stateful return traffic acceptance (for permitted public destinations only)
    "-m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT",
    # Phase 5: Permitted outbound transport & port rules (Public destinations only)
    "-p udp -j DROP",
    "-p tcp --dport 80 -j ACCEPT",
    "-p tcp --dport 443 -j ACCEPT",
    # Phase 6: Default deny for all remaining outbound traffic
    "-j DROP",
]


def _find_bash() -> str:
    """Locate a POSIX bash interpreter (cross-platform for Windows & Linux)."""
    if sys.platform == "win32":
        candidates = [
            r"E:\Git\bin\bash.exe",
            r"C:\Program Files\Git\bin\bash.exe",
            r"C:\Program Files (x86)\Git\bin\bash.exe",
        ]
        for candidate in candidates:
            if os.path.isfile(candidate):
                return candidate
    bash_path = shutil.which("bash")
    if bash_path:
        return bash_path
    raise unittest.SkipTest("bash executable not available to run entrypoint tests")


class TestTrackCProxyEntrypointHardening(unittest.TestCase):
    """Test suite verifying fail-closed firewall enforcement in docker/proxy/entrypoint.sh."""

    @classmethod
    def setUpClass(cls):
        cls.bash_exe = _find_bash()
        if not _ENTRYPOINT_SCRIPT.is_file():
            raise FileNotFoundError(f"Entrypoint script not found: {_ENTRYPOINT_SCRIPT}")

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.mock_bin_dir = pathlib.Path(self.temp_dir.name) / "bin"
        self.mock_bin_dir.mkdir(parents=True, exist_ok=True)
        self.conf_dir = pathlib.Path(self.temp_dir.name) / "conf"
        self.conf_dir.mkdir(parents=True, exist_ok=True)

        # Create dummy addon script
        self.addon_file = pathlib.Path(self.temp_dir.name) / "mock_addon.py"
        self.addon_file.write_text("# mock addon\n", encoding="utf-8")

        # Invocations log file
        self.log_file = pathlib.Path(self.temp_dir.name) / "mock_invocations.log"
        self.mitm_log = pathlib.Path(self.temp_dir.name) / "mitmdump.log"

        # Default mock resolv.conf
        self.resolv_conf = pathlib.Path(self.temp_dir.name) / "resolv.conf"
        self.resolv_conf.write_text("nameserver 192.168.65.7\n", encoding="utf-8")

    def tearDown(self):
        self.temp_dir.cleanup()

    def _create_mock_script(self, name: str, body: str) -> pathlib.Path:
        target = self.mock_bin_dir / name
        target.write_text(f"#!/bin/sh\n{body}\n", encoding="utf-8", newline="\n")
        try:
            target.chmod(0o755)
        except OSError:
            pass
        return target

    def _create_default_mocks(self):
        """Create standard succeeding mocks for iptables, ip6tables, mitmdump, gosu."""
        iptables_body = """
echo "iptables $*" >> "${INVOCATIONS_LOG}"
exit 0
"""
        self._create_mock_script("iptables", iptables_body)

        ip6tables_body = """
echo "ip6tables $*" >> "${INVOCATIONS_LOG}"
exit 0
"""
        self._create_mock_script("ip6tables", ip6tables_body)

        mitmdump_body = """
echo "mitmdump $*" > "${MITM_LOG}"
exit 0
"""
        self._create_mock_script("mitmdump", mitmdump_body)

        gosu_body = """
echo "gosu $*" >> "${INVOCATIONS_LOG}"
shift
exec "$@"
"""
        self._create_mock_script("gosu", gosu_body)

    def _run_entrypoint(self, env_overrides=None):
        env = dict(os.environ)
        # Prepend mock bin dir to PATH so mocks shadow system binaries
        env["PATH"] = str(self.mock_bin_dir) + os.pathsep + env.get("PATH", "")
        env["CONF_DIR"] = str(self.conf_dir).replace("\\", "/")
        env["ADDON_SCRIPT"] = str(self.addon_file).replace("\\", "/")
        env["RESOLV_CONF"] = str(self.resolv_conf).replace("\\", "/")
        env["INVOCATIONS_LOG"] = str(self.log_file).replace("\\", "/")
        env["MITM_LOG"] = str(self.mitm_log).replace("\\", "/")

        if env_overrides:
            env.update(env_overrides)

        mock_path_str = str(self.mock_bin_dir).replace("\\", "/")
        script_posix = str(_ENTRYPOINT_SCRIPT).replace("\\", "/")
        cmd = [
            self.bash_exe,
            "-c",
            f'export PATH="$(cd "{mock_path_str}" && pwd):$PATH"; exec "{script_posix}"',
        ]
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                env=env,
                timeout=30,
            )
        except subprocess.TimeoutExpired as exc:
            stdout = exc.stdout or ""
            stderr = exc.stderr or ""
            self.fail(f"Entrypoint execution timed out after 30s.\nStdout:\n{stdout}\nStderr:\n{stderr}")
        return result

    # --- Tooling & Privilege Checks ---

    def test_missing_iptables_fails_closed(self):
        """Proxy must exit nonzero if iptables binary is not in PATH."""
        # Only create ip6tables mock, leave iptables missing
        self._create_mock_script("ip6tables", "exit 0\n")
        result = self._run_entrypoint(env_overrides={"PATH": str(self.mock_bin_dir)})

        self.assertNotEqual(result.returncode, 0, "Entrypoint must exit nonzero when iptables is missing")
        output = result.stdout + result.stderr
        self.assertIn("FATAL", output)
        self.assertIn("Required firewall binary 'iptables' not found in PATH", output)
        self.assertFalse(self.mitm_log.exists(), "mitmdump must not be executed when iptables is missing")

    def test_insufficient_privileges_iptables_fails_closed(self):
        """Proxy must exit nonzero if iptables inspection fails (missing CAP_NET_ADMIN)."""
        iptables_body = """
echo "iptables $*" >> "${INVOCATIONS_LOG}"
if [ "$1" = "-L" ] && [ "$2" = "OUTPUT" ] && [ "$3" = "-n" ]; then
    echo "iptables: Permission denied (you must be root)" >&2
    exit 1
fi
exit 0
"""
        self._create_mock_script("iptables", iptables_body)
        self._create_mock_script("ip6tables", "exit 0\n")
        result = self._run_entrypoint()

        self.assertNotEqual(result.returncode, 0, "Entrypoint must exit nonzero on iptables permission failure")
        output = result.stdout + result.stderr
        self.assertIn("FATAL", output)
        self.assertIn("Insufficient permissions to inspect/modify iptables (CAP_NET_ADMIN missing)", output)
        self.assertFalse(self.mitm_log.exists(), "mitmdump must not be executed when permissions are insufficient")

    def test_missing_ip6tables_fails_closed(self):
        """Proxy must exit nonzero if ip6tables binary is not in PATH."""
        # Create iptables mock, leave ip6tables missing
        self._create_mock_script("iptables", "exit 0\n")
        result = self._run_entrypoint(env_overrides={"PATH": str(self.mock_bin_dir)})

        self.assertNotEqual(result.returncode, 0, "Entrypoint must exit nonzero when ip6tables is missing")
        output = result.stdout + result.stderr
        self.assertIn("FATAL", output)
        self.assertIn("Required firewall binary 'ip6tables' not found in PATH", output)
        self.assertFalse(self.mitm_log.exists(), "mitmdump must not be executed when ip6tables is missing")

    def test_insufficient_privileges_ip6tables_fails_closed(self):
        """Proxy must exit nonzero if ip6tables inspection fails (missing CAP_NET_ADMIN)."""
        self._create_mock_script("iptables", "exit 0\n")
        ip6tables_body = """
echo "ip6tables $*" >> "${INVOCATIONS_LOG}"
if [ "$1" = "-L" ] && [ "$2" = "OUTPUT" ] && [ "$3" = "-n" ]; then
    echo "ip6tables: Permission denied (you must be root)" >&2
    exit 1
fi
exit 0
"""
        self._create_mock_script("ip6tables", ip6tables_body)
        result = self._run_entrypoint()

        self.assertNotEqual(result.returncode, 0, "Entrypoint must exit nonzero on ip6tables permission failure")
        output = result.stdout + result.stderr
        self.assertIn("FATAL", output)
        self.assertIn("Insufficient permissions to inspect/modify ip6tables (CAP_NET_ADMIN missing)", output)
        self.assertFalse(self.mitm_log.exists(), "mitmdump must not be executed when ip6tables permissions are insufficient")

    # --- DNS Resolver Inspection Checks ---

    def test_missing_resolv_conf_fails_closed(self):
        """Proxy must exit nonzero if resolv.conf file is missing."""
        self._create_default_mocks()
        result = self._run_entrypoint(env_overrides={"RESOLV_CONF": "/nonexistent/resolv.conf"})

        self.assertNotEqual(result.returncode, 0)
        output = result.stdout + result.stderr
        self.assertIn("FATAL", output)
        self.assertIn("Resolver configuration file '/nonexistent/resolv.conf' not found", output)
        self.assertFalse(self.mitm_log.exists())

    def test_empty_resolv_conf_fails_closed(self):
        """Proxy must exit nonzero if resolv.conf contains no nameservers."""
        self._create_default_mocks()
        self.resolv_conf.write_text("# empty resolv conf\nsearch localdomain\n", encoding="utf-8")
        result = self._run_entrypoint()

        self.assertNotEqual(result.returncode, 0)
        output = result.stdout + result.stderr
        self.assertIn("FATAL", output)
        self.assertIn("No nameserver entries found", output)
        self.assertFalse(self.mitm_log.exists())

    def test_cloud_metadata_as_dns_resolver_fails_closed(self):
        """Proxy must abort immediately if 169.254.169.254 is configured as a DNS resolver."""
        self._create_default_mocks()
        self.resolv_conf.write_text("nameserver 169.254.169.254\n", encoding="utf-8")
        result = self._run_entrypoint()

        self.assertNotEqual(result.returncode, 0)
        output = result.stdout + result.stderr
        self.assertIn("FATAL", output)
        self.assertIn("Cloud metadata IP 169.254.169.254 cannot be used as a DNS resolver", output)
        self.assertFalse(self.mitm_log.exists())

    def test_multicast_ipv6_resolver_fails_closed(self):
        """Proxy must abort immediately if multicast IPv6 is configured as a DNS resolver."""
        self._create_default_mocks()
        self.resolv_conf.write_text("nameserver ff02::1\n", encoding="utf-8")
        result = self._run_entrypoint()

        self.assertNotEqual(result.returncode, 0)
        output = result.stdout + result.stderr
        self.assertIn("FATAL", output)
        self.assertIn("Multicast or unspecified IPv6 address ff02::1 cannot be used as a DNS resolver", output)
        self.assertFalse(self.mitm_log.exists())

    def test_unrecognized_dns_resolver_format_fails_closed(self):
        """Proxy must abort immediately if an invalid nameserver string is in resolv.conf."""
        self._create_default_mocks()
        self.resolv_conf.write_text("nameserver invalid_domain_name\n", encoding="utf-8")
        result = self._run_entrypoint()

        self.assertNotEqual(result.returncode, 0)
        output = result.stdout + result.stderr
        self.assertIn("FATAL", output)
        self.assertIn("Unrecognized nameserver IP format", output)
        self.assertFalse(self.mitm_log.exists())

    # --- Rule Installation and Verification Checks ---

    def test_rule_installation_failure_v4_fails_closed(self):
        """Proxy must exit nonzero immediately if any required IPv4 rule installation fails."""
        iptables_body = """
echo "iptables $*" >> "${INVOCATIONS_LOG}"
if [ "$1" = "-L" ]; then
    exit 0
fi
if [ "$1" = "-A" ]; then
    for arg in "$@"; do
        if [ "$arg" = "169.254.169.254/32" ]; then
            echo "iptables: Memory allocation error / Table locked" >&2
            exit 1
        fi
    done
    exit 0
fi
exit 0
"""
        self._create_mock_script("iptables", iptables_body)
        self._create_mock_script("ip6tables", "exit 0\n")
        self._create_mock_script("mitmdump", "exit 0\n")
        self._create_mock_script("gosu", 'shift; exec "$@"\n')
        result = self._run_entrypoint()

        self.assertNotEqual(result.returncode, 0, "Entrypoint must exit nonzero on IPv4 rule installation failure")
        output = result.stdout + result.stderr
        self.assertIn("FATAL", output)
        self.assertIn("Failed to install required IPv4 rule", output)
        self.assertIn("169.254.169.254/32", output)
        self.assertFalse(self.mitm_log.exists(), "mitmdump must not be executed on rule installation failure")

    def test_rule_installation_failure_v6_fails_closed(self):
        """Proxy must exit nonzero immediately if any required IPv6 rule installation fails."""
        self._create_mock_script("iptables", "exit 0\n")
        ip6tables_body = """
echo "ip6tables $*" >> "${INVOCATIONS_LOG}"
if [ "$1" = "-L" ]; then
    exit 0
fi
if [ "$1" = "-A" ]; then
    for arg in "$@"; do
        if [ "$arg" = "fc00::/7" ]; then
            echo "ip6tables: Memory allocation error / Table locked" >&2
            exit 1
        fi
    done
    exit 0
fi
exit 0
"""
        self._create_mock_script("ip6tables", ip6tables_body)
        self._create_mock_script("mitmdump", "exit 0\n")
        self._create_mock_script("gosu", 'shift; exec "$@"\n')
        result = self._run_entrypoint()

        self.assertNotEqual(result.returncode, 0, "Entrypoint must exit nonzero on IPv6 rule installation failure")
        output = result.stdout + result.stderr
        self.assertIn("FATAL", output)
        self.assertIn("Failed to install required IPv6 rule", output)
        self.assertIn("fc00::/7", output)
        self.assertFalse(self.mitm_log.exists(), "mitmdump must not be executed on rule installation failure")

    def test_verification_failure_v4_fails_closed(self):
        """Proxy must exit nonzero if any required IPv4 rule fails kernel verification (-C)."""
        iptables_body = """
echo "iptables $*" >> "${INVOCATIONS_LOG}"
if [ "$1" = "-L" ] || [ "$1" = "-A" ]; then
    exit 0
fi
if [ "$1" = "-C" ]; then
    for arg in "$@"; do
        if [ "$arg" = "10.0.0.0/8" ]; then
            echo "iptables: Bad rule (does a matching rule exist in that chain?)" >&2
            exit 1
        fi
    done
    exit 0
fi
exit 0
"""
        self._create_mock_script("iptables", iptables_body)
        self._create_mock_script("ip6tables", "exit 0\n")
        self._create_mock_script("mitmdump", "exit 0\n")
        self._create_mock_script("gosu", 'shift; exec "$@"\n')
        result = self._run_entrypoint()

        self.assertNotEqual(result.returncode, 0, "Entrypoint must exit nonzero on IPv4 verification failure")
        output = result.stdout + result.stderr
        self.assertIn("FATAL", output)
        self.assertIn("IPv4 firewall verification failed", output)
        self.assertIn("10.0.0.0/8", output)
        self.assertFalse(self.mitm_log.exists(), "mitmdump must not be executed on verification failure")

    def test_verification_failure_v6_fails_closed(self):
        """Proxy must exit nonzero if any required IPv6 rule fails kernel verification (-C)."""
        self._create_mock_script("iptables", "exit 0\n")
        ip6tables_body = """
echo "ip6tables $*" >> "${INVOCATIONS_LOG}"
if [ "$1" = "-L" ] || [ "$1" = "-A" ]; then
    exit 0
fi
if [ "$1" = "-C" ]; then
    for arg in "$@"; do
        if [ "$arg" = "fc00::/7" ]; then
            echo "ip6tables: Bad rule (does a matching rule exist in that chain?)" >&2
            exit 1
        fi
    done
    exit 0
fi
exit 0
"""
        self._create_mock_script("ip6tables", ip6tables_body)
        self._create_mock_script("mitmdump", "exit 0\n")
        self._create_mock_script("gosu", 'shift; exec "$@"\n')
        result = self._run_entrypoint()

        self.assertNotEqual(result.returncode, 0, "Entrypoint must exit nonzero on IPv6 verification failure")
        output = result.stdout + result.stderr
        self.assertIn("FATAL", output)
        self.assertIn("IPv6 firewall verification failed", output)
        self.assertIn("fc00::/7", output)
        self.assertFalse(self.mitm_log.exists(), "mitmdump must not be executed on verification failure")

    # --- Dual-Stack Ordering & Successful Startup Checks ---

    def test_successful_startup_prerequisites_and_exact_order(self):
        """When firewall rules are installed and verified, proxy completes dual-stack startup in exact security order."""
        self._create_default_mocks()

        result = self._run_entrypoint()

        self.assertEqual(result.returncode, 0, f"Expected successful execution, got: {result.stderr}")
        output = result.stdout + result.stderr
        self.assertIn(f"All {len(EXPECTED_RULES_V4)} required IPv4 firewall rules installed successfully.", output)
        self.assertIn(f"All {len(EXPECTED_RULES_V6)} required IPv6 firewall rules installed successfully.", output)
        self.assertIn(f"IPv4 kernel firewall ruleset verified: all {len(EXPECTED_RULES_V4)} required rules active.", output)
        self.assertIn(f"IPv6 kernel firewall ruleset verified: all {len(EXPECTED_RULES_V6)} required rules active.", output)

        log_lines = self.log_file.read_text(encoding="utf-8").splitlines()

        # Extract installed rules and verified rules in order of execution
        installed_rules_v4 = [
            line[len("iptables -A OUTPUT "):]
            for line in log_lines
            if line.startswith("iptables -A OUTPUT ")
        ]
        verified_rules_v4 = [
            line[len("iptables -C OUTPUT "):]
            for line in log_lines
            if line.startswith("iptables -C OUTPUT ")
        ]

        installed_rules_v6 = [
            line[len("ip6tables -A OUTPUT "):]
            for line in log_lines
            if line.startswith("ip6tables -A OUTPUT ")
        ]
        verified_rules_v6 = [
            line[len("ip6tables -C OUTPUT "):]
            for line in log_lines
            if line.startswith("ip6tables -C OUTPUT ")
        ]

        self.assertEqual(installed_rules_v4, EXPECTED_RULES_V4, "Installed IPv4 rules must match EXPECTED_RULES_V4 exactly in sequence")
        self.assertEqual(verified_rules_v4, EXPECTED_RULES_V4, "Verified IPv4 rules must match EXPECTED_RULES_V4 exactly in sequence")
        self.assertEqual(installed_rules_v6, EXPECTED_RULES_V6, "Installed IPv6 rules must match EXPECTED_RULES_V6 exactly in sequence")
        self.assertEqual(verified_rules_v6, EXPECTED_RULES_V6, "Verified IPv6 rules must match EXPECTED_RULES_V6 exactly in sequence")

        # Verify mitmdump arguments
        self.assertTrue(self.mitm_log.exists(), "mitmdump should have been executed")
        mitm_args = self.mitm_log.read_text(encoding="utf-8")
        self.assertIn("--listen-host 0.0.0.0", mitm_args)
        self.assertIn("--listen-port 8080", mitm_args)
        self.assertIn("--scripts", mitm_args)
        self.assertIn("--set termlog_verbosity=info", mitm_args)
        self.assertNotIn("--termlog-verbosity", mitm_args)

    def test_rule_ordering_prohibits_bypass_before_established_related(self):
        """Security invariant: Prohibited destination drops must strictly precede ESTABLISHED,RELATED acceptance in both v4 and v6."""
        self._create_default_mocks()

        result = self._run_entrypoint()
        self.assertEqual(result.returncode, 0)

        log_lines = self.log_file.read_text(encoding="utf-8").splitlines()

        # --- Check IPv4 Ordering ---
        installed_v4 = [
            line[len("iptables -A OUTPUT "):]
            for line in log_lines
            if line.startswith("iptables -A OUTPUT ")
        ]
        v4_conntrack = "-m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT"
        v4_lo_accept = "-o lo -j ACCEPT"
        v4_lo_drop = "-d 127.0.0.0/8 -j DROP"
        v4_default_drop = "-j DROP"

        self.assertIn(v4_conntrack, installed_v4)
        v4_conntrack_idx = installed_v4.index(v4_conntrack)

        # 1. DNS resolver accept precedes DNS drop
        dns_v4_accept = "-d 192.168.65.7 -p udp --dport 53 -j ACCEPT"
        dns_v4_drop = "-p udp --dport 53 -j DROP"
        self.assertLess(installed_v4.index(dns_v4_accept), installed_v4.index(dns_v4_drop))

        # 2. DNS drop precedes private subnet drops
        self.assertLess(installed_v4.index(dns_v4_drop), installed_v4.index("-d 10.0.0.0/8 -j DROP"))

        # 3. Intra-container loopback acceptance precedes external loopback drop
        self.assertLess(installed_v4.index(v4_lo_accept), installed_v4.index(v4_lo_drop))

        # 4. External loopback drop precedes ESTABLISHED,RELATED acceptance
        self.assertLess(installed_v4.index(v4_lo_drop), v4_conntrack_idx)

        # 5. All prohibited destination drops precede ESTABLISHED,RELATED
        for prefix in ["-d 169.254.", "-d 10.", "-d 172.16.", "-d 192.168.", "-d 100.64.", "-d 198.18.", "-d 240.0.0."]:
            matching = [i for i, r in enumerate(installed_v4) if r.startswith(prefix)]
            self.assertTrue(matching, f"Prefix {prefix} missing in IPv4 rules")
            for idx in matching:
                self.assertLess(idx, v4_conntrack_idx, f"IPv4 rule {installed_v4[idx]} must precede conntrack")

        # 6. Final rule is default deny
        self.assertEqual(installed_v4[-1], v4_default_drop)

        # --- Check IPv6 Ordering ---
        installed_v6 = [
            line[len("ip6tables -A OUTPUT "):]
            for line in log_lines
            if line.startswith("ip6tables -A OUTPUT ")
        ]
        v6_conntrack = "-m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT"
        v6_lo_accept = "-o lo -j ACCEPT"
        v6_lo_drop = "-d ::1/128 -j DROP"
        v6_default_drop = "-j DROP"

        self.assertIn(v6_conntrack, installed_v6)
        v6_conntrack_idx = installed_v6.index(v6_conntrack)

        # Loopback accept precedes external loopback drop
        self.assertLess(installed_v6.index(v6_lo_accept), installed_v6.index(v6_lo_drop))
        # External loopback drop precedes conntrack
        self.assertLess(installed_v6.index(v6_lo_drop), v6_conntrack_idx)

        # All prohibited IPv6 destination drops precede ESTABLISHED,RELATED
        for prefix in ["-d ::/", "-d ::ffff:", "-d fc00::/7", "-d fe80::/10", "-d ff00::/8"]:
            matching = [i for i, r in enumerate(installed_v6) if r.startswith(prefix)]
            self.assertTrue(matching, f"Prefix {prefix} missing in IPv6 rules")
            for idx in matching:
                self.assertLess(idx, v6_conntrack_idx, f"IPv6 rule {installed_v6[idx]} must precede conntrack")

        # Final rule is default deny
        self.assertEqual(installed_v6[-1], v6_default_drop)

    def test_dual_stack_resolver_configuration(self):
        """When resolv.conf contains both IPv4 and IPv6 resolvers, both are permitted on port 53."""
        self._create_default_mocks()
        self.resolv_conf.write_text("nameserver 192.168.65.7\nnameserver 2001:4860:4860::8888\n", encoding="utf-8")

        result = self._run_entrypoint()
        self.assertEqual(result.returncode, 0)

        log_lines = self.log_file.read_text(encoding="utf-8").splitlines()
        installed_v6 = [
            line[len("ip6tables -A OUTPUT "):]
            for line in log_lines
            if line.startswith("ip6tables -A OUTPUT ")
        ]
        self.assertIn("-d 2001:4860:4860::8888 -p udp --dport 53 -j ACCEPT", installed_v6)
        self.assertIn("-d 2001:4860:4860::8888 -p tcp --dport 53 -j ACCEPT", installed_v6)
        # Verify it precedes port 53 drop
        v6_dns_accept_idx = installed_v6.index("-d 2001:4860:4860::8888 -p udp --dport 53 -j ACCEPT")
        v6_dns_drop_idx = installed_v6.index("-p udp --dport 53 -j DROP")
        self.assertLess(v6_dns_accept_idx, v6_dns_drop_idx)

    def test_missing_addon_script_fails_closed(self):
        """Proxy must exit nonzero if addon script does not exist, even if firewall passed."""
        self._create_default_mocks()
        result = self._run_entrypoint(env_overrides={"ADDON_SCRIPT": "/nonexistent/addon_script.py"})

        self.assertNotEqual(result.returncode, 0, "Entrypoint must exit nonzero when addon script is missing")
        output = result.stdout + result.stderr
        self.assertIn("FATAL", output)
        self.assertIn("Proxy addon script not found", output)
        self.assertFalse(self.mitm_log.exists(), "mitmdump must not be executed when addon is missing")

    def test_mitmdump_cli_arguments_both_execution_branches(self):
        """Verify neither execution branch (root vs unprivileged) passes unsupported CLI arguments."""
        self._create_default_mocks()

        # Branch 1: Root execution (id -u returns 0)
        id_root_body = """
if [ "$1" = "-u" ]; then
    echo "0"
    exit 0
fi
exit 0
"""
        self._create_mock_script("id", id_root_body)
        res_root = self._run_entrypoint()
        self.assertEqual(res_root.returncode, 0, f"Root startup branch failed: {res_root.stderr}")
        self.assertTrue(self.mitm_log.exists(), "mitmdump should have executed in root branch")
        mitm_root_args = self.mitm_log.read_text(encoding="utf-8")
        self.assertIn("--set termlog_verbosity=info", mitm_root_args)
        self.assertNotIn("--termlog-verbosity", mitm_root_args)
        invocations_root = self.log_file.read_text(encoding="utf-8")
        self.assertIn("gosu proxy mitmdump", invocations_root)

        # Reset logs for Branch 2
        self.mitm_log.unlink()
        self.log_file.unlink()

        # Branch 2: Unprivileged execution (id -u returns 1002)
        id_unpriv_body = """
if [ "$1" = "-u" ]; then
    echo "1002"
    exit 0
fi
exit 0
"""
        self._create_mock_script("id", id_unpriv_body)
        res_unpriv = self._run_entrypoint()
        self.assertEqual(res_unpriv.returncode, 0, f"Unprivileged startup branch failed: {res_unpriv.stderr}")
        self.assertTrue(self.mitm_log.exists(), "mitmdump should have executed in unprivileged branch")
        mitm_unpriv_args = self.mitm_log.read_text(encoding="utf-8")
        self.assertIn("--set termlog_verbosity=info", mitm_unpriv_args)
        self.assertNotIn("--termlog-verbosity", mitm_unpriv_args)
        invocations_unpriv = self.log_file.read_text(encoding="utf-8") if self.log_file.exists() else ""
        self.assertNotIn("gosu", invocations_unpriv, "gosu should not be called in unprivileged branch")


if __name__ == "__main__":
    unittest.main()
