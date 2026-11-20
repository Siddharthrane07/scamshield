"""
inspect_compose_dns.py — Helper to verify DNS and network separation in Docker Compose.
"""
import subprocess
import sys


def run(cmd: str) -> str:
    p = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    out = p.stdout.strip()
    if p.stderr.strip():
        out += "\n[STDERR] " + p.stderr.strip()
    return out


def main():
    print("=== 1. PROXY /etc/resolv.conf ===")
    print(run("docker exec scamshield-track-c-proxy cat /etc/resolv.conf"))

    print("\n=== 2. BROWSER /etc/resolv.conf ===")
    print(run("docker run --rm --network scamshield_browser_internal --entrypoint cat scamshield-browser-test:latest /etc/resolv.conf"))

    print("\n=== 3. BROWSER SERVICE DISCOVERY (resolve 'proxy') ===")
    print(run("docker run --rm --network scamshield_browser_internal --entrypoint python3 scamshield-browser-test:latest -c \"import socket; print('Resolved proxy IP:', socket.gethostbyname('proxy'))\""))

    print("\n=== 4. BROWSER EXTERNAL DNS LEAK ATTEMPT (resolve 'example.com') ===")
    print(run("docker run --rm --network scamshield_browser_internal --entrypoint python3 scamshield-browser-test:latest -c \"import socket; print(socket.gethostbyname('example.com'))\""))

    print("\n=== 5. BROWSER DIRECT EGRESS ATTEMPT (connect to 1.1.1.1:80) ===")
    print(run("docker run --rm --network scamshield_browser_internal --entrypoint python3 scamshield-browser-test:latest -c \"import socket; s = socket.socket(); s.settimeout(3); s.connect(('1.1.1.1', 80))\""))

    print("\n=== 6. PROXY DIRECT RESOLVER CHECK (resolve 'example.com') ===")
    print(run("docker exec scamshield-track-c-proxy python3 -c \"import socket; print('Proxy resolved example.com to:', socket.gethostbyname('example.com'))\""))


if __name__ == "__main__":
    main()
