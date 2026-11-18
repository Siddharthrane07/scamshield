"""
dns_net_inspect.py — Network and DNS inspection tool for the DNS egress investigation.
Runs inside the container via `docker run --entrypoint python3`.
"""
import socket
import struct
import sys
import os


def print_sep(title):
    print(f"\n{'='*60}")
    print(f"  {title}")
    print(f"{'='*60}")


def read_resolv_conf():
    print_sep("1. /etc/resolv.conf")
    try:
        with open("/etc/resolv.conf") as f:
            print(f.read())
    except Exception as e:
        print(f"ERROR: {e}")


def read_interfaces():
    print_sep("2. IPv4 interfaces (/proc/net/if_inet6 for IPv6, /proc/net/fib_trie for IPv4)")
    try:
        with open("/proc/net/if_inet6") as f:
            print("IPv6 interfaces:")
            print(f.read())
    except Exception as e:
        print(f"  No IPv6 interfaces: {e}")

    try:
        with open("/proc/net/dev") as f:
            print("All interfaces:")
            print(f.read())
    except Exception as e:
        print(f"  ERROR reading /proc/net/dev: {e}")


def read_routes():
    print_sep("3. IPv4 Routes (/proc/net/route)")
    try:
        with open("/proc/net/route") as f:
            lines = f.readlines()
        print(lines[0].strip())  # header
        for line in lines[1:]:
            parts = line.strip().split()
            if len(parts) >= 8:
                iface = parts[0]
                dest_hex = parts[1]
                gw_hex = parts[2]
                mask_hex = parts[7]
                dest = socket.inet_ntoa(bytes(reversed(bytes.fromhex(dest_hex.zfill(8)))))
                gw = socket.inet_ntoa(bytes(reversed(bytes.fromhex(gw_hex.zfill(8)))))
                mask = socket.inet_ntoa(bytes(reversed(bytes.fromhex(mask_hex.zfill(8)))))
                print(f"  iface={iface} dest={dest} gw={gw} mask={mask}")
    except Exception as e:
        print(f"  ERROR: {e}")


def read_ipv6_routes():
    print_sep("4. IPv6 Routes (/proc/net/ipv6_route)")
    try:
        with open("/proc/net/ipv6_route") as f:
            content = f.read()
        print(content)
    except Exception as e:
        print(f"  No IPv6 routes: {e}")


def test_dns_udp(resolver_ip, port=53, hostname="example.com"):
    print_sep(f"5. DNS UDP test to {resolver_ip}:{port} for '{hostname}'")
    # Minimal DNS query packet (UDP)
    txid = b"\x12\x34"
    flags = b"\x01\x00"  # standard query, recursion desired
    qdcount = b"\x00\x01"
    zero = b"\x00\x00"
    header = txid + flags + qdcount + zero + zero + zero
    # Encode question: example.com A record
    parts = hostname.encode().split(b".")
    question = b"".join(bytes([len(p)]) + p for p in parts) + b"\x00"
    question += b"\x00\x01\x00\x01"  # QTYPE=A, QCLASS=IN
    pkt = header + question
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(3.0)
        s.sendto(pkt, (resolver_ip, port))
        resp, addr = s.recvfrom(512)
        s.close()
        rcode = resp[3] & 0x0F
        ancount = struct.unpack_from("!H", resp, 6)[0]
        print(f"  SUCCESS: response from {addr}, len={len(resp)}, rcode={rcode}, answers={ancount}")
        # Parse first A record
        if ancount > 0 and rcode == 0:
            # skip question section — find answers after name parse
            off = 12
            # skip name in question
            while off < len(resp) and resp[off] != 0:
                if resp[off] & 0xC0 == 0xC0:
                    off += 2
                    break
                off += resp[off] + 1
            else:
                off += 1
            off += 4  # skip qtype, qclass
            # parse answer RR
            if off + 10 <= len(resp):
                # skip name pointer
                if resp[off] & 0xC0 == 0xC0:
                    off += 2
                rtype, rclass, ttl, rdlen = struct.unpack_from("!HHIH", resp, off)
                off += 10
                if rtype == 1 and rdlen == 4:
                    ip = socket.inet_ntoa(resp[off:off+4])
                    print(f"  RESOLVED: {hostname} -> {ip} (TTL={ttl})")
        return True
    except socket.timeout:
        print(f"  TIMEOUT: No response from {resolver_ip}:{port}")
        return False
    except Exception as e:
        print(f"  ERROR: {e}")
        return False


def test_tcp_connect(host, port, timeout=3):
    print_sep(f"6. TCP connect test to {host}:{port}")
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((host, port))
        s.close()
        print(f"  SUCCESS: TCP connected to {host}:{port}")
        return True
    except Exception as e:
        print(f"  FAILED: {e}")
        return False


def test_hostname_resolution(hostname):
    print_sep(f"7. Hostname resolution test: '{hostname}'")
    try:
        results = socket.getaddrinfo(hostname, 80)
        for r in results:
            print(f"  {hostname} -> {r[4][0]} (family={r[0].name})")
        return True
    except Exception as e:
        print(f"  FAILED: {e}")
        return False


if __name__ == "__main__":
    read_resolv_conf()
    read_interfaces()
    read_routes()
    read_ipv6_routes()
    test_dns_udp("192.168.65.7", 53, "example.com")
    test_dns_udp("192.168.65.7", 53, "scamshield-synthetic-test-domain-xyzzy.invalid")
    test_hostname_resolution("example.com")

