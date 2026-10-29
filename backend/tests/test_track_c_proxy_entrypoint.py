"""
test_track_c_proxy_entrypoint.py — Hardened Startup & Firewall Verification Tests for Track C Proxy.

Validates that docker/proxy/entrypoint.sh adheres to fail-closed security invariants:
1. Missing iptables tooling exits nonzero (refuses to start).
2. Insufficient permissions (missing CAP_NET_ADMIN) exits nonzero (refuses to start).
3. Any rule installation failure aborts immediately with nonzero exit code.
4. Ruleset verification failure (rule missing or inactive) aborts before mitmdump.
5. Successful firewall installation and verification proceeds to unprivileged execution.
6. Missing proxy addon script exits nonzero (refuses to start).

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
    "-o lo -j ACCEPT",
    "-m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT",
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
    "-d 127.0.0.0/8 -j DROP",
    "-p udp --dport 53 -j ACCEPT",
    "-p tcp --dport 53 -j ACCEPT",
    "-p udp -j DROP",
    "-p tcp --dport 80 -j ACCEPT",
    "-p tcp --dport 443 -j ACCEPT",
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
        # Note: self.mock_bin_dir does NOT contain an iptables script.
        # Ensure system PATH does not provide iptables by overriding PATH to only our mock dir
        # plus standard posix paths (without iptables).
        result = self._run_entrypoint(env_overrides={"PATH": str(self.mock_bin_dir)})

        self.assertNotEqual(result.returncode, 0, "Entrypoint must exit nonzero when iptables is missing")
        output = result.stdout + result.stderr
        self.assertIn("FATAL", output)
        self.assertIn("Required firewall binary 'iptables' not found in PATH", output)
        self.assertFalse(self.mitm_log.exists(), "mitmdump must not be executed when iptables is missing")

    def test_insufficient_privileges_fails_closed(self):
        """Proxy must exit nonzero if iptables inspection fails (missing CAP_NET_ADMIN)."""
        # Mock iptables returning 1 on permission check (-L OUTPUT -n)
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

        # Verify no rule installation was attempted
        if self.log_file.exists():
            log_content = self.log_file.read_text(encoding="utf-8")
            self.assertNotIn("-A OUTPUT", log_content, "No rules should be installed if permission check fails")

    def test_rule_installation_failure_fails_closed(self):
        """Proxy must exit nonzero immediately if any required rule installation fails."""
        # Mock iptables that succeeds on permission check, but fails on a specific rule
        iptables_body = """
echo "iptables $*" >> "${INVOCATIONS_LOG}"
if [ "$1" = "-L" ]; then
    exit 0
fi
if [ "$1" = "-A" ]; then
    # Intentionally fail on the cloud metadata drop rule
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
        # Mock iptables where -L and -A succeed, but -C fails for RFC1918 10.0.0.0/8
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

    def test_successful_startup_prerequisites(self):
        """When firewall rules are installed and verified, proxy completes startup prerequisites."""
        # Mock iptables: succeeds on -L, -A, and -C
        iptables_body = """
echo "iptables $*" >> "${INVOCATIONS_LOG}"
exit 0
"""
        self._create_mock_script("iptables", iptables_body)

        # Mock mitmdump: records call arguments to MITM_LOG and exits cleanly
        mitmdump_body = """
echo "mitmdump $*" > "${MITM_LOG}"
exit 0
"""
        self._create_mock_script("mitmdump", mitmdump_body)

        # Mock gosu: executes the given command
        gosu_body = """
shift
exec "$@"
"""
        self._create_mock_script("gosu", gosu_body)

        result = self._run_entrypoint()

        self.assertEqual(result.returncode, 0, f"Expected successful execution, got: {result.stderr}")
        output = result.stdout + result.stderr
        self.assertIn("All 19 required firewall rules installed successfully.", output)
        self.assertIn("Kernel firewall ruleset verified: all 19 required rules active.", output)

        # Verify that all 19 rules were actually installed and verified
        log_content = self.log_file.read_text(encoding="utf-8")
        for rule in EXPECTED_RULES:
            expected_install = f"iptables -A OUTPUT {rule}"
            expected_verify = f"iptables -C OUTPUT {rule}"
            self.assertIn(expected_install, log_content, f"Missing install command: {expected_install}")
            self.assertIn(expected_verify, log_content, f"Missing verify command: {expected_verify}")

        # Verify mitmdump was launched with correct arguments
        self.assertTrue(self.mitm_log.exists(), "mitmdump should have been executed")
        mitm_args = self.mitm_log.read_text(encoding="utf-8")
        self.assertIn("--listen-host 0.0.0.0", mitm_args)
        self.assertIn("--listen-port 8080", mitm_args)
        self.assertIn("--scripts", mitm_args)

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
