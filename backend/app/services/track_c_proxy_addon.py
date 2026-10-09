import socket
import asyncio
import logging
import ipaddress
from app.services.track_c_preflight import URLPreflightValidator

logger = logging.getLogger("scamshield.track_c.proxy")

class ProxySecurityAddon:
    """
    Mitmproxy addon to enforce IP blocking policy at connection time.
    """

    def tls_clienthello(self, data):
        """
        Force mitmproxy to pass TLS through blindly without decrypting.
        """
        data.ignore_connection = True

    async def server_connect(self, data):
        """
        Hook called by mitmproxy before establishing the upstream connection.
        This hook is async because it awaits DNS resolution. Mitmproxy invokes
        it before the upstream TCP socket is opened, which allows us to mutate
        data.server.address to pin the validated IP before any connection is made.
        """
        if not getattr(data, "server", None) or not getattr(data.server, "address", None):
            if hasattr(data, "server") and data.server is not None:
                data.server.error = "Missing destination address"
            return

        host, port = data.server.address

        loop = asyncio.get_running_loop()
        try:
            # Use None for port so getaddrinfo returns all address records
            # without filtering by service. The destination port is used only
            # when setting the pinned upstream address below.
            addr_info = await asyncio.wait_for(
                loop.getaddrinfo(host, None),
                timeout=5.0
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

        resolved_ips = []
        for info in addr_info:
            ip = info[4][0]
            if ip not in resolved_ips:
                resolved_ips.append(ip)

        if not resolved_ips:
            data.server.error = f"DNS resolution returned no IPs for {host}"
            return

        # Check all resolved IPs to prevent mixed public/private SSRF bypass
        for ip in resolved_ips:
            if not URLPreflightValidator._is_ip_safe(ip):
                data.server.error = f"Upstream resolves to unsafe IP address: {ip}"
                return

        # PIN THE IP
        # We explicitly override the server address to the approved IP.
        # This forces mitmproxy to connect directly to the IP without doing a second DNS lookup.
        # The original hostname is preserved in data.server.sni (for TLS) and client Host headers.
        pinned_ip = resolved_ips[0]
        data.server.address = (pinned_ip, port)

    def server_connected(self, data):
        """
        Hook called by mitmproxy after the upstream connection is established.
        This hook is synchronous because it performs no asynchronous work;
        it only inspects the already-resolved peername attribute.
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

        # Use the already-normalized, IPv4-mapped-unwrapped object for the
        # safety check so the result is consistent with the comparison above.
        # str() is used only because _is_ip_safe accepts a string argument.
        if not URLPreflightValidator._is_ip_safe(str(peer_ip)):
            data.server.error = f"Connected to unsafe peer IP: {peer_ip_str}"

addons = [ProxySecurityAddon()]
