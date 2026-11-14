"""
dns_capture_server.py — Minimal local DNS capture/authoritative server for investigation.

Listens on UDP 5353 (loopback) for DNS queries and logs them.
Responds with NXDOMAIN to all queries by default (authoritative=no data).
Used for: verifying whether Chromium or mitmproxy sends direct DNS queries
independently of the proxy path.

Usage:
    python dns_capture_server.py [--port 5353] [--timeout 30]
"""
import argparse
import socket
import struct
import threading
import time
import logging
import sys

logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] [dns-capture] %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%SZ",
    stream=sys.stdout,
)
logger = logging.getLogger("dns_capture")


def parse_dns_name(data: bytes, offset: int):
    """Parse a DNS name starting at offset. Returns (name_str, new_offset)."""
    labels = []
    visited = set()
    while True:
        if offset in visited:
            break
        visited.add(offset)
        if offset >= len(data):
            break
        length = data[offset]
        if length == 0:
            offset += 1
            break
        elif (length & 0xC0) == 0xC0:
            # Pointer
            if offset + 1 >= len(data):
                break
            ptr = ((length & 0x3F) << 8) | data[offset + 1]
            offset += 2
            suffix, _ = parse_dns_name(data, ptr)
            labels.append(suffix)
            break
        else:
            offset += 1
            labels.append(data[offset : offset + length].decode("ascii", errors="replace"))
            offset += length
    return ".".join(labels), offset


def parse_dns_query(data: bytes):
    """Parse a minimal DNS query packet. Returns list of (qname, qtype) tuples."""
    if len(data) < 12:
        return []
    txid, flags, qdcount = struct.unpack_from("!HHH", data, 0)
    questions = []
    offset = 12
    for _ in range(qdcount):
        try:
            qname, offset = parse_dns_name(data, offset)
            if offset + 4 > len(data):
                break
            qtype, qclass = struct.unpack_from("!HH", data, offset)
            offset += 4
            questions.append((qname, qtype, qclass))
        except Exception:
            break
    return questions


def build_nxdomain_response(query_data: bytes) -> bytes:
    """Build a minimal NXDOMAIN response for the given query."""
    if len(query_data) < 12:
        return b""
    txid = query_data[:2]
    # Flags: QR=1, Opcode=0, AA=1, TC=0, RD=1, RA=0, Z=0, RCODE=3 (NXDOMAIN)
    flags = struct.pack("!H", 0x8403)
    qdcount = query_data[4:6]
    ancount = b"\x00\x00"
    nscount = b"\x00\x00"
    arcount = b"\x00\x00"
    header = txid + flags + qdcount + ancount + nscount + arcount
    # Echo back the question section
    question = query_data[12:]
    return header + question


def run_server(host: str, port: int, timeout: float, queries_received: list):
    """UDP DNS listener. Appends received query info to queries_received list."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.settimeout(1.0)
    sock.bind((host, port))
    logger.info(f"DNS capture server listening on {host}:{port} (timeout={timeout}s)")
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            data, addr = sock.recvfrom(512)
            questions = parse_dns_query(data)
            entry = {"from": addr, "questions": questions, "raw_len": len(data)}
            queries_received.append(entry)
            for qname, qtype, qclass in questions:
                logger.info(f"DNS QUERY from {addr}: name={qname!r} type={qtype} class={qclass}")
            # Send NXDOMAIN
            resp = build_nxdomain_response(data)
            if resp:
                sock.sendto(resp, addr)
        except socket.timeout:
            continue
        except Exception as e:
            logger.warning(f"DNS server error: {e}")
    sock.close()
    logger.info(f"DNS capture server stopped. Total queries received: {len(queries_received)}")


def main():
    parser = argparse.ArgumentParser(description="Minimal DNS capture server for investigation")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=5353)
    parser.add_argument("--timeout", type=float, default=30.0)
    args = parser.parse_args()

    queries = []
    run_server(args.host, args.port, args.timeout, queries)
    print(f"TOTAL_QUERIES_RECEIVED: {len(queries)}")
    for q in queries:
        print(f"  FROM={q['from']} QUESTIONS={q['questions']}")


if __name__ == "__main__":
    main()
