"""
proxy_shim.py — Test-only addon shim for Track C integration tests.

This module is written to a temporary directory at test runtime and loaded
by mitmdump via its ``--scripts`` flag.  It wraps the production
``ProxySecurityAddon`` with a test-specific IP allow-list so that the
integration tests can use local 127.0.0.1 echo servers as upstream targets
without those addresses being blocked by the production ``_is_ip_safe()``
loopback check.

IMPORTANT:
  - This file MUST NOT be imported in production code.
  - ``track_c_proxy_addon.py`` and ``track_c_preflight.py`` are not modified.
  - The allow-list is narrowly scoped to the loopback address used by the
    test servers (127.0.0.1).  All other production blocking rules remain
    active.

The shim is rendered as a Python source string by the integration test and
written to a tempfile.  The integration test also sets the PYTHONPATH so
that the backend ``app`` package is importable from the subprocess.

Hooks recorded for assertion by the integration test:

    tls_clienthello_fired  — set to True when the hook is invoked
    ignore_connection_set  — set to True when ignore_connection is True

These are exported as module-level booleans that the test reads by
inspecting a sidecar JSON file written by the addon on each hook call.
"""
import json
import os
import sys
import asyncio
import socket
import ipaddress

# ---------------------------------------------------------------------------
# Make the backend app package importable (set by the integration test via
# the PYTHONPATH environment variable or via sys.path injection here).
# ---------------------------------------------------------------------------
_backend_dir = os.environ.get("SCAMSHIELD_BACKEND_DIR", "")
if _backend_dir and _backend_dir not in sys.path:
    sys.path.insert(0, _backend_dir)

from app.services.track_c_proxy_addon import ProxySecurityAddon
from app.services.track_c_preflight import URLPreflightValidator

# ---------------------------------------------------------------------------
# Test allow-list: IPs that are permitted in integration tests only.
# We narrow this to 127.0.0.1 exclusively so the real blocking logic still
# fires for all other addresses.
# ---------------------------------------------------------------------------
_TEST_ALLOWED_IPS = frozenset(["127.0.0.1", "::1"])

# Prohibited test ports (canary and black-hole listeners): these MUST never be
# bypassed by the allow-list under any circumstances.
# May be passed via SCAMSHIELD_PROHIBITED_TEST_PORTS env var, falling back
# to the known integration and browser test listener ports.
_env_prohibited = os.environ.get("SCAMSHIELD_PROHIBITED_TEST_PORTS")
if _env_prohibited:
    _PROHIBITED_TEST_PORTS = frozenset(
        int(p.strip()) for p in _env_prohibited.split(",") if p.strip()
    )
else:
    _PROHIBITED_TEST_PORTS = frozenset({
        19001,  # Integration test blackhole (PORT_BLACKHOLE in test_track_c_proxy_integration.py)
        19101,  # Browser test blackhole (PORT_BLACKHOLE in test_track_c_browser_proxy.py)
        19102,  # Browser test TCP canary (PORT_CANARY_TCP in test_track_c_browser_proxy.py)
        19105,  # Browser test prod loopback (PORT_PROD_LOOPBACK in test_track_c_browser_proxy.py)
    })

# Sidecar file path (passed via env var from the test)
_SIDECAR_PATH = os.environ.get("SCAMSHIELD_SIDECAR_PATH", "/tmp/proxy_sidecar.json")

_sidecar: dict = {
    "tls_clienthello_fired": False,
    "ignore_connection_set": False,
    "dns_resolutions": {},
    "evaluations": [],
    "connected_events": [],
}


def _write_sidecar() -> None:
    try:
        tmp_path = f"{_SIDECAR_PATH}.tmp"
        with open(tmp_path, "w", encoding="utf-8") as f:
            json.dump(_sidecar, f)
        os.replace(tmp_path, _SIDECAR_PATH)
    except Exception:
        try:
            with open(_SIDECAR_PATH, "w", encoding="utf-8") as f:
                json.dump(_sidecar, f)
        except Exception:
            pass


# ---------------------------------------------------------------------------
# Test addon subclass
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# Synthetic test hosts mapped directly by the test shim for browser tests.
# This avoids modifying the OS hosts file or requiring public DNS entries.
# ---------------------------------------------------------------------------
_SYNTHETIC_HOSTS = {
    "test-http.local": ["127.0.0.1"],
    "test-origin.local": ["127.0.0.1"],
    "safe-landing.local": ["127.0.0.1"],
    "safe-cdn.local": ["127.0.0.1"],
    "ws-echo.local": ["127.0.0.1"],
    "wss-echo.local": ["127.0.0.1"],
    "quic-test.local": ["127.0.0.1"],
    "synthetic-target.scamshield-test": ["127.0.0.1"],
    "unrelated.local": ["127.0.0.1"],
    # Dynamic DNS test domains for BR-11 (Model 2 evaluation):
    # Case A: Prohibited loopback target, evaluated and tied to blackhole listener on PORT_BLACKHOLE (19101)
    "dynamic-rebind-prohibited.test": ["127.0.0.1"],
    # Model 2 positive control: safe public IP answer (example.com RFC 2606)
    "dynamic-rebind-safe.test": ["93.184.216.35"],
    # Case B: Mixed safe (93.184.216.34) and prohibited (127.0.0.1) answers
    "dynamic-rebind-mixed.test": ["93.184.216.34", "127.0.0.1"],
}

_ALLOWED_SYNTHETIC_HOSTS = frozenset({
    "localhost",
    "127.0.0.1",
    "::1",
    "test-http.local",
    "test-origin.local",
    "safe-landing.local",
    "safe-cdn.local",
    "ws-echo.local",
    "wss-echo.local",
    "quic-test.local",
    "synthetic-target.scamshield-test",
    "unrelated.local",
})


class TestProxyAddon(ProxySecurityAddon):
    """
    Integration-test variant of ProxySecurityAddon.

    Overrides _is_ip_safe at the *usage site* inside server_connect() so
    that 127.0.0.1 and ::1 pass only for explicit allowed test hostnames.
    The production ProxySecurityAddon code is not modified.
    """

    def tls_clienthello(self, data) -> None:
        """Record that the hook fired, then delegate to the production hook."""
        _sidecar["tls_clienthello_fired"] = True
        super().tls_clienthello(data)
        _sidecar["ignore_connection_set"] = bool(
            getattr(data, "ignore_connection", False)
        )
        _write_sidecar()

    async def server_connect(self, data) -> None:
        """
        Resolve DNS and validate IPs, but treat loopback as safe only for test servers.

        We replicate the production server_connect logic here with the
        allow-list applied, rather than monkey-patching _is_ip_safe globally,
        so the production module is untouched and the override is explicit and
        auditable.
        """
        if not getattr(data, "server", None) or not getattr(data.server, "address", None):
            if hasattr(data, "server") and data.server is not None:
                data.server.error = "Missing destination address"
            return

        host, port = data.server.address

        resolved_ips = []
        if host in _SYNTHETIC_HOSTS:
            resolved_ips = list(_SYNTHETIC_HOSTS[host])
        else:
            loop = asyncio.get_running_loop()
            try:
                addr_info = await asyncio.wait_for(
                    loop.getaddrinfo(host, None),
                    timeout=5.0,
                )
            except asyncio.TimeoutError:
                data.server.error = f"DNS resolution timed out for {host}"
                return
            except socket.gaierror as e:
                data.server.error = f"DNS resolution failed for {host}: {e}"
                return
            except Exception as e:
                data.server.error = f"Unexpected DNS error: {e}"
                return

            for info in addr_info:
                ip = info[4][0]
                if ip not in resolved_ips:
                    resolved_ips.append(ip)

        if not resolved_ips:
            data.server.error = f"DNS resolution returned no IPs for {host}"
            return

        # Record delivered DNS resolution in sidecar for verification
        _sidecar.setdefault("dns_resolutions", {})[host] = list(resolved_ips)

        eval_record = {
            "host": host,
            "port": port,
            "resolved_ips": list(resolved_ips),
            "rejected_ips": [],
            "error": None,
            "blocked": False,
            "pinned_ip": None,
        }

        for ip in resolved_ips:
            # Never bypass prohibited canary or black-hole test ports
            if port in _PROHIBITED_TEST_PORTS:
                if not URLPreflightValidator._is_ip_safe(ip):
                    data.server.error = f"Upstream resolves to unsafe IP address: {ip}"
                    eval_record["rejected_ips"].append(ip)
                    eval_record["error"] = data.server.error
                    eval_record["blocked"] = True
                    _sidecar.setdefault("evaluations", []).append(eval_record)
                    _write_sidecar()
                    return
            # Integration-test allow-list: permit local echo server IPs (127.0.0.1, ::1)
            # ONLY for explicitly allowed test hostnames on non-prohibited test ports.
            elif ip in _TEST_ALLOWED_IPS and host in _ALLOWED_SYNTHETIC_HOSTS:
                continue
            elif not URLPreflightValidator._is_ip_safe(ip):
                data.server.error = f"Upstream resolves to unsafe IP address: {ip}"
                eval_record["rejected_ips"].append(ip)
                eval_record["error"] = data.server.error
                eval_record["blocked"] = True
                _sidecar.setdefault("evaluations", []).append(eval_record)
                _write_sidecar()
                return

        # Prefer 127.0.0.1 if available to match our IPv4-bound echo server
        if "127.0.0.1" in resolved_ips:
            pinned_ip = "127.0.0.1"
        else:
            pinned_ip = resolved_ips[0]
        data.server.address = (pinned_ip, port)
        eval_record["pinned_ip"] = pinned_ip
        _sidecar.setdefault("evaluations", []).append(eval_record)
        _write_sidecar()

    def server_connected(self, data) -> None:
        """
        Validate connected peer IP, but allow _TEST_ALLOWED_IPS for integration tests.
        """
        if not getattr(data, "server", None):
            return
        if getattr(data.server, "error", None) is not None:
            return
        peername = getattr(data.server, "peername", None)
        if not peername:
            data.server.error = "Connection established but peername is missing"
            return

        peer_ip_str = peername[0]
        pinned_ip_str = data.server.address[0]
        port = data.server.address[1]

        if port in _PROHIBITED_TEST_PORTS:
            data.server.error = f"Connection to prohibited test port {port} blocked"
            return

        try:
            peer_ip = ipaddress.ip_address(peer_ip_str)
            pinned_ip = ipaddress.ip_address(pinned_ip_str)
            if isinstance(peer_ip, ipaddress.IPv6Address) and peer_ip.ipv4_mapped is not None:
                peer_ip = peer_ip.ipv4_mapped
            if isinstance(pinned_ip, ipaddress.IPv6Address) and pinned_ip.ipv4_mapped is not None:
                pinned_ip = pinned_ip.ipv4_mapped
            if peer_ip != pinned_ip:
                data.server.error = f"Security bypass detected: connected to {peer_ip_str} instead of pinned IP {pinned_ip_str}"
                return
        except ValueError:
            data.server.error = "Invalid IP format in peername or address"
            return

        if (peer_ip_str in _TEST_ALLOWED_IPS or str(peer_ip) in _TEST_ALLOWED_IPS) and port not in _PROHIBITED_TEST_PORTS:
            _sidecar.setdefault("connected_events", []).append({
                "host": pinned_ip_str,
                "port": port,
                "peername": peername,
            })
            _write_sidecar()
            return

        if not URLPreflightValidator._is_ip_safe(str(peer_ip)):
            data.server.error = f"Connected to unsafe peer IP: {peer_ip_str}"
            return

        _sidecar.setdefault("connected_events", []).append({
            "host": pinned_ip_str,
            "port": port,
            "peername": peername,
        })
        _write_sidecar()


addons = [TestProxyAddon()]
