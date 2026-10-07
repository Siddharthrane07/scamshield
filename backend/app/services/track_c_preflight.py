import socket
import asyncio
import logging
from urllib.parse import urlparse
import ipaddress
from typing import List, Dict, Any, Optional

logger = logging.getLogger("scamshield.track_c.preflight")

class PreflightResult:
    def __init__(self, allowed: bool, reason: str, normalized_url: Optional[str] = None, hostname: Optional[str] = None, resolved_ips: Optional[List[str]] = None):
        self.allowed = allowed
        self.reason = reason
        self.normalized_url = normalized_url
        self.hostname = hostname
        self.resolved_ips = resolved_ips or []

    def to_dict(self) -> Dict[str, Any]:
        return {
            "allowed": self.allowed,
            "reason": self.reason,
            "normalized_url": self.normalized_url,
            "hostname": self.hostname,
            "resolved_ips": self.resolved_ips
        }

class URLPreflightValidator:
    """
    Security gatekeeper for Track C (Isolated Browser Sandbox).
    Validates URLs and performs DNS resolution to prevent Server-Side Request Forgery (SSRF)
    and unauthorized access to local/private networks (including AWS Instance Metadata).
    
    IMPORTANT LIMITATION:
    This validator performs time-of-check DNS resolution. It DOES NOT prevent
    DNS rebinding attacks natively. DNS rebinding protection requires the underlying
    sandbox (e.g., Playwright network interceptors or OS-level DNS pinning) to enforce
    that the visited IP matches the validated IP here.
    """
    
    ALLOWED_SCHEMES = {"http", "https"}

    _BLOCKED_NETWORKS = [
        ipaddress.ip_network("100.64.0.0/10"),   # CGNAT
        ipaddress.ip_network("192.0.0.0/24"),    # IETF Protocol Assignments
        ipaddress.ip_network("198.18.0.0/15"),   # Benchmarking
        ipaddress.ip_network("198.51.100.0/24"), # Documentation (TEST-NET-2)
        ipaddress.ip_network("203.0.113.0/24"),  # Documentation (TEST-NET-3)
        ipaddress.ip_network("240.0.0.0/4"),     # Reserved
        ipaddress.ip_network("100::/64"),        # Discard (IPv6)
        ipaddress.ip_network("2001:db8::/32"),   # Documentation (IPv6)
    ]

    @classmethod
    def _is_ip_safe(cls, ip_str: str) -> bool:
        try:
            ip = ipaddress.ip_address(ip_str)
            
            # Unwrap IPv4-mapped IPv6 (e.g. ::ffff:10.0.0.1) to check the embedded IPv4 address
            if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
                ip = ip.ipv4_mapped
                
            # Check for various unsafe network ranges
            if ip.is_loopback:
                return False
            if ip.is_private:
                return False
            if ip.is_link_local:
                return False
            if ip.is_multicast:
                return False
            if ip.is_unspecified:
                return False
            if ip.is_reserved:
                return False
                
            # Check explicit blocked networks
            for network in cls._BLOCKED_NETWORKS:
                if ip in network:
                    return False
                    
            # Explicitly check for AWS Metadata IP
            if str(ip) == "169.254.169.254":
                return False
            
            return True
        except ValueError:
            return False

    @classmethod
    async def validate(cls, url: str) -> Dict[str, Any]:
        """
        Validates the URL for scheme, structure, and safe DNS resolution.
        """
        if not url or not isinstance(url, str):
            return PreflightResult(False, "Empty or invalid URL type").to_dict()

        # Parse URL
        try:
            parsed = urlparse(url)
        except Exception as e:
            return PreflightResult(False, f"Malformed URL parsing error: {e}").to_dict()

        scheme = parsed.scheme.lower()
        if not scheme:
            return PreflightResult(False, "Missing URL scheme").to_dict()

        if scheme not in cls.ALLOWED_SCHEMES:
            return PreflightResult(False, f"Disallowed URL scheme: {scheme}").to_dict()

        hostname = parsed.hostname
        if not hostname:
            return PreflightResult(False, "Missing hostname in URL").to_dict()

        hostname = hostname.lower().rstrip(".")

        # Reconstruct normalized URL for safe downstream consumption
        try:
            port_str = f":{parsed.port}" if parsed.port else ""
        except ValueError:
            return PreflightResult(False, "Malformed port in URL").to_dict()
            
        normalized_url = f"{scheme}://{hostname}{port_str}{parsed.path}"
        if parsed.query:
            normalized_url += f"?{parsed.query}"

        # Resolve DNS
        loop = asyncio.get_running_loop()
        try:
            # getaddrinfo(host, port, family=0, type=0, proto=0, flags=0)
            addr_info = await asyncio.wait_for(
                loop.getaddrinfo(hostname, None),
                timeout=5.0
            )
        except asyncio.TimeoutError:
            return PreflightResult(False, "DNS resolution timed out", normalized_url, hostname).to_dict()
        except socket.gaierror as e:
            return PreflightResult(False, f"DNS resolution failed: {e}", normalized_url, hostname).to_dict()
        except Exception as e:
            return PreflightResult(False, f"Unexpected DNS error: {e}", normalized_url, hostname).to_dict()

        resolved_ips = []
        for info in addr_info:
            # info is a tuple (family, type, proto, canonname, sockaddr)
            # sockaddr is a tuple (address, port) for IPv4 or (address, port, flow info, scope id) for IPv6
            ip = info[4][0]
            if ip not in resolved_ips:
                resolved_ips.append(ip)

        if not resolved_ips:
            return PreflightResult(False, "DNS resolution returned no IP addresses", normalized_url, hostname).to_dict()

        # Check all resolved IPs (mixed public/private rejection)
        for ip in resolved_ips:
            if not cls._is_ip_safe(ip):
                return PreflightResult(
                    False, 
                    f"Hostname resolves to unsafe IP address: {ip}", 
                    normalized_url, 
                    hostname, 
                    resolved_ips
                ).to_dict()

        # All checks passed
        return PreflightResult(True, "URL is safe for sandbox execution", normalized_url, hostname, resolved_ips).to_dict()
