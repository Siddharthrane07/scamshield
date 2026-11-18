"""
dns_egress_tests.py — DNS egress leak investigation tests.

Tests:
 T1: Can a container process reach external DNS (port 53 UDP) to arbitrary IPs?
 T2: Can a container process reach the pinned resolver (192.168.65.7:53)?
 T3: Does 127.0.0.11 (Docker embedded DNS) forward queries externally?
 T4: Can TCP 443 reach a public DoH server (1.1.1.1)?
 T5: Does the loopback iptables rule (#15) allow traffic to 127.0.0.11?
 T6: Does 127.0.0.11 forward through 192.168.65.7 to external servers?
     Evidence: resolv.conf shows ExtServers=[host(192.168.65.7)]

NOTE: This script is meant to be run INSIDE the container, after the entrypoint
has installed iptables rules. It must be called via exec on a running entrypoint container.
To test without iptables rules, run via --entrypoint python3 (bypass entrypoint).
"""

import socket
import struct
import sys
import time

RESULTS = []


def report(test_id, name, result, detail=""):
    sym = "PASS" if result else "FAIL"
    line = f"[{sym}] {test_id}: {name} | {detail}"
    print(line)
    RESULTS.append((test_id, name, result, detail))


def dns_query(server_ip, port, hostname, timeout=3.0):
    """Send a DNS A-record query. Returns (success, rcode, answer_count)."""
    txid = b"\xab\xcd"
    flags = b"\x01\x00"
    qdcount = b"\x00\x01"
    zero = b"\x00\x00"
    header = txid + flags + qdcount + zero + zero + zero
    parts = hostname.encode().split(b".")
    question = b"".join(bytes([len(p)]) + p for p in parts) + b"\x00"
    question += b"\x00\x01\x00\x01"
    pkt = header + question
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(timeout)
        s.sendto(pkt, (server_ip, port))
        resp, _ = s.recvfrom(512)
        s.close()
        rcode = resp[3] & 0x0F
        ancount = struct.unpack_from("!H", resp, 6)[0]
        return True, rcode, ancount
    except socket.timeout:
        return False, None, None
    except OSError as e:
        return False, None, str(e)


def tcp_connect(host, port, timeout=3.0):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((host, port))
        s.close()
        return True, None
    except Exception as e:
        return False, str(e)


def tcp6_connect(host, port, timeout=3.0):
    try:
        s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((host, port, 0, 0))
        s.close()
        return True, None
    except Exception as e:
        return False, str(e)


print("=" * 70)
print("  DNS Egress Leak Investigation — Container-side Tests")
print("=" * 70)

# T1: Arbitrary DNS to 8.8.8.8:53 (should be BLOCKED by rule #3/4 if iptables active)
ok, rcode, ans = dns_query("8.8.8.8", 53, "example.com", timeout=3)
report("T1", "DNS UDP to arbitrary IP 8.8.8.8:53", ok,
       f"rcode={rcode} answers={ans}" if ok else f"blocked/timeout/error")

# T2: DNS to pinned resolver 192.168.65.7:53 (should be ALLOWED by rule #1/2)
ok, rcode, ans = dns_query("192.168.65.7", 53, "example.com", timeout=3)
report("T2", "DNS UDP to pinned resolver 192.168.65.7:53", ok,
       f"rcode={rcode} answers={ans}" if ok else "blocked")

# T3: DNS via 127.0.0.11 (Docker embedded DNS, loopback, should reach internal handler)
ok, rcode, ans = dns_query("127.0.0.11", 53, "example.com", timeout=3)
report("T3", "DNS UDP to Docker embedded resolver 127.0.0.11:53", ok,
       f"rcode={rcode} answers={ans}" if ok else "blocked/timeout/not_loopback_passthrough")

# T4: TCP 443 to 1.1.1.1 (Cloudflare DoH — should be ALLOWED by rule #20)
ok, err = tcp_connect("1.1.1.1", 443, timeout=5)
report("T4", "TCP 443 to 1.1.1.1 (public DoH server)", ok,
       "connected" if ok else f"blocked: {err}")

# T5: TCP 443 to 8.8.8.8 (Google DoH — should be ALLOWED by rule #20)
ok, err = tcp_connect("8.8.8.8", 443, timeout=5)
report("T5", "TCP 443 to 8.8.8.8 (Google DoH server)", ok,
       "connected" if ok else f"blocked: {err}")

# T6: TCP 80 to known public IP (should be ALLOWED by rule #19)
ok, err = tcp_connect("93.184.216.34", 80, timeout=5)
report("T6", "TCP 80 to 93.184.216.34 (example.com public IP)", ok,
       "connected" if ok else f"blocked: {err}")

# T7: TCP 80 to private IP 10.0.0.1 (should be BLOCKED by rule #7)
ok, err = tcp_connect("10.0.0.1", 80, timeout=3)
report("T7", "TCP 80 to private IP 10.0.0.1 (should be BLOCKED)", not ok,
       f"correctly blocked: {err}" if not ok else "LEAK: connected to private IP!")

# T8: TCP 80 to metadata IP 169.254.169.254 (should be BLOCKED by rule #5)
ok, err = tcp_connect("169.254.169.254", 80, timeout=3)
report("T8", "TCP 80 to metadata 169.254.169.254 (should be BLOCKED)", not ok,
       f"correctly blocked: {err}" if not ok else "LEAK: metadata IP reachable!")

# T9: DNS TCP to 8.8.8.8:53 (should be BLOCKED by rule #4)
ok, err = tcp_connect("8.8.8.8", 53, timeout=3)
report("T9", "TCP 53 to 8.8.8.8 (should be BLOCKED)", not ok,
       f"correctly blocked: {err}" if not ok else "LEAK: DNS TCP to arbitrary IP!")

# T10: Can we resolve hostnames via getaddrinfo?
try:
    addrs = socket.getaddrinfo("example.com", 80)
    ips = [a[4][0] for a in addrs]
    report("T10", "getaddrinfo('example.com') — via system resolver", True,
           f"resolved to: {ips[:3]}...")
except Exception as e:
    report("T10", "getaddrinfo('example.com') — via system resolver", False, str(e))

print()
print("=" * 70)
passed = sum(1 for _, _, ok, _ in RESULTS if ok)
failed = sum(1 for _, _, ok, _ in RESULTS if not ok)
print(f"SUMMARY: {passed} passed, {failed} failed out of {len(RESULTS)} tests")
print("=" * 70)

