"""
test_track_c_proxy_entrypoint.py — Hardened Startup & Firewall Verification Tests for Track C Proxy.

Validates that docker/proxy/entrypoint.sh adheres to fail-closed security invariants:
1. Missing iptables tooling exits nonzero (refuses to start).
2. Insufficient permissions (missing CAP_NET_ADMIN) exits nonzero (refuses to start).
3. Any rule installation failure aborts immediately with nonzero exit code.
4. Ruleset verification failure (rule missing or inactive) aborts before mitmdump.
5. Strict rule ordering is enforced:
   - Prohibited destination drops strictly precede stateful ESTABLISHED,RELATED acceptance.
   - Intra-container loopback acceptance (-o lo -j ACCEPT) precedes external loopback drop (-d 127.0.0.0/8 -j DROP).
   - External loopback drop precedes ESTABLISHED,RELATED acceptance.
   - Default deny (-j DROP) is the final rule in the chain.
6. Successful firewall installation and verification proceeds to unprivileged execution.
7. Missing proxy addon script exits nonzero (refuses to start).

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

EXPECTED_RULES = [
    # Phase 1: Prohibited destination drops (unconditional, precedes stateful acceptance)
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
    # Phase 5: Permitted outbound transport & port rules
    "-p udp --dport 53 -j ACCEPT",
    "-p tcp --dport 53 -j ACCEPT",
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

    def _run_entrypoint(self, env_overrides=None):
        env = dict(os.environ)
        # Prepend mock bin dir to PATH so mocks shadow system binaries
        env["PATH"] = str(self.mock_bin_dir) + os.pathsep + env.get("PATH", "")
        env["CONF_DIR"] = str(self.conf_dir).replace("\\", "/")
        env["ADDON_SCRIPT"] = str(self.addon_file).replace("\\", "/")
        env["INVOCATIONS_LOG"] = str(self.log_file).replace("\\", "/")
        env["MITM_LOG"] = str(self.mitm_log).replace("\\", "/")

        if env_overrides:
            env.update(env_overrides)

        cmd = [self.bash_exe, str(_ENTRYPOINT_SCRIPT).replace("\\", "/")]
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            env=env,
        )
        return result

    def test_missing_iptables_fails_closed(self):
        """Proxy must exit nonzero if iptables binary is not in PATH."""
        result = self._run_entrypoint(env_overrides={"PATH": str(self.mock_bin_dir)})

        self.assertNotEqual(result.returncode, 0, "Entrypoint must exit nonzero when iptables is missing")
        output = result.stdout + result.stderr
        self.assertIn("FATAL", output)
        self.assertIn("Required firewall binary 'iptables' not found in PATH", output)
        self.assertFalse(self.mitm_log.exists(), "mitmdump must not be executed when iptables is missing")

    def test_insufficient_privileges_fails_closed(self):
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
        result = self._run_entrypoint()

        self.assertNotEqual(result.returncode, 0, "Entrypoint must exit nonzero on permission check failure")
        output = result.stdout + result.stderr
        self.assertIn("FATAL", output)
        self.assertIn("Insufficient permissions to inspect/modify iptables (CAP_NET_ADMIN missing)", output)
        self.assertFalse(self.mitm_log.exists(), "mitmdump must not be executed when permissions are insufficient")

        if self.log_file.exists():
            log_content = self.log_file.read_text(encoding="utf-8")
            self.assertNotIn("-A OUTPUT", log_content, "No rules should be installed if permission check fails")

    def test_rule_installation_failure_fails_closed(self):
        """Proxy must exit nonzero immediately if any required rule installation fails."""
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
        result = self._run_entrypoint()

        self.assertNotEqual(result.returncode, 0, "Entrypoint must exit nonzero on rule installation failure")
        output = result.stdout + result.stderr
        self.assertIn("FATAL", output)
        self.assertIn("Failed to install required iptables rule", output)
        self.assertIn("169.254.169.254/32", output)
        self.assertFalse(self.mitm_log.exists(), "mitmdump must not be executed on rule installation failure")

    def test_verification_failure_fails_closed(self):
        """Proxy must exit nonzero if any required rule fails kernel verification (-C)."""
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
        result = self._run_entrypoint()

        self.assertNotEqual(result.returncode, 0, "Entrypoint must exit nonzero on verification failure")
        output = result.stdout + result.stderr
        self.assertIn("FATAL", output)
        self.assertIn("Firewall verification failed", output)
        self.assertIn("10.0.0.0/8", output)
        self.assertFalse(self.mitm_log.exists(), "mitmdump must not be executed on verification failure")

    def test_successful_startup_prerequisites_and_exact_order(self):
        """When firewall rules are installed and verified, proxy completes startup in exact security order."""
        iptables_body = """
echo "iptables $*" >> "${INVOCATIONS_LOG}"
exit 0
"""
        self._create_mock_script("iptables", iptables_body)

        mitmdump_body = """
echo "mitmdump $*" > "${MITM_LOG}"
exit 0
"""
        self._create_mock_script("mitmdump", mitmdump_body)

        gosu_body = """
shift
exec "$@"
"""
        self._create_mock_script("gosu", gosu_body)

        result = self._run_entrypoint()

        self.assertEqual(result.returncode, 0, f"Expected successful execution, got: {result.stderr}")
        output = result.stdout + result.stderr
        self.assertIn(f"All {len(EXPECTED_RULES)} required firewall rules installed successfully.", output)
        self.assertIn(f"Kernel firewall ruleset verified: all {len(EXPECTED_RULES)} required rules active.", output)

        log_lines = self.log_file.read_text(encoding="utf-8").splitlines()

        # Extract installed rules and verified rules in order of execution
        installed_rules = [
            line[len("iptables -A OUTPUT "):]
            for line in log_lines
            if line.startswith("iptables -A OUTPUT ")
        ]
        verified_rules = [
            line[len("iptables -C OUTPUT "):]
            for line in log_lines
            if line.startswith("iptables -C OUTPUT ")
        ]

        self.assertEqual(installed_rules, EXPECTED_RULES, "Installed rules must match EXPECTED_RULES exactly in sequence")
        self.assertEqual(verified_rules, EXPECTED_RULES, "Verified rules must match EXPECTED_RULES exactly in sequence")

        # Verify mitmdump arguments
        self.assertTrue(self.mitm_log.exists(), "mitmdump should have been executed")
        mitm_args = self.mitm_log.read_text(encoding="utf-8")
        self.assertIn("--listen-host 0.0.0.0", mitm_args)
        self.assertIn("--listen-port 8080", mitm_args)
        self.assertIn("--scripts", mitm_args)

    def test_rule_ordering_prohibits_bypass_before_established_related(self):
        """Security invariant: Prohibited destination drops must strictly precede ESTABLISHED,RELATED acceptance."""
        iptables_body = """
echo "iptables $*" >> "${INVOCATIONS_LOG}"
exit 0
"""
        self._create_mock_script("iptables", iptables_body)
        self._create_mock_script("mitmdump", "exit 0\n")
        self._create_mock_script("gosu", 'shift; exec "$@"\n')

        result = self._run_entrypoint()
        self.assertEqual(result.returncode, 0)

        log_lines = self.log_file.read_text(encoding="utf-8").splitlines()
        installed_rules = [
            line[len("iptables -A OUTPUT "):]
            for line in log_lines
            if line.startswith("iptables -A OUTPUT ")
        ]

        # Locate critical transition points
        conntrack_rule = "-m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT"
        loopback_accept = "-o lo -j ACCEPT"
        loopback_drop = "-d 127.0.0.0/8 -j DROP"
        default_drop = "-j DROP"

        self.assertIn(conntrack_rule, installed_rules)
        conntrack_idx = installed_rules.index(conntrack_rule)

        self.assertIn(loopback_accept, installed_rules)
        loopback_accept_idx = installed_rules.index(loopback_accept)

        self.assertIn(loopback_drop, installed_rules)
        loopback_drop_idx = installed_rules.index(loopback_drop)

        # 1. Intra-container loopback acceptance must precede external loopback drop
        self.assertLess(
            loopback_accept_idx,
            loopback_drop_idx,
            "-o lo -j ACCEPT must precede -d 127.0.0.0/8 -j DROP so internal IPC succeeds",
        )

        # 2. External loopback drop must precede ESTABLISHED,RELATED acceptance
        self.assertLess(
            loopback_drop_idx,
            conntrack_idx,
            "-d 127.0.0.0/8 -j DROP must precede conntrack acceptance",
        )

        # 3. All prohibited destination drops must precede ESTABLISHED,RELATED
        prohibited_prefixes = [
            "-d 169.254.",
            "-d 10.",
            "-d 172.16.",
            "-d 192.168.",
            "-d 100.64.",
            "-d 198.18.",
            "-d 198.51.100.",
            "-d 203.0.113.",
            "-d 240.0.0.",
        ]
        for prefix in prohibited_prefixes:
            matching_indices = [
                i for i, r in enumerate(installed_rules) if r.startswith(prefix)
            ]
            self.assertTrue(matching_indices, f"Rule with prefix {prefix} must be present in installed rules")
            for idx in matching_indices:
                self.assertLess(
                    idx,
                    conntrack_idx,
                    f"Prohibited rule '{installed_rules[idx]}' (index {idx}) must precede conntrack rule (index {conntrack_idx})",
                )

        # 4. Default drop is the final rule
        self.assertEqual(
            installed_rules[-1],
            default_drop,
            f"The final rule in the chain must be default deny '{default_drop}'",
        )

    def test_missing_addon_script_fails_closed(self):
        """Proxy must exit nonzero if addon script does not exist, even if firewall passed."""
        iptables_body = """
echo "iptables $*" >> "${INVOCATIONS_LOG}"
exit 0
"""
        self._create_mock_script("iptables", iptables_body)
        result = self._run_entrypoint(env_overrides={"ADDON_SCRIPT": "/nonexistent/addon_script.py"})

        self.assertNotEqual(result.returncode, 0, "Entrypoint must exit nonzero when addon script is missing")
        output = result.stdout + result.stderr
        self.assertIn("FATAL", output)
        self.assertIn("Proxy addon script not found", output)
        self.assertFalse(self.mitm_log.exists(), "mitmdump must not be executed when addon is missing")


if __name__ == "__main__":
    unittest.main()
