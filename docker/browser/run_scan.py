#!/usr/bin/env python3
"""
run_scan.py — Containerized Chromium Browser Scanner & Harness for Track C.

Purpose:
  Runs inside the dedicated isolated browser container. Launches Chromium
  via Playwright with hardened network and security flags, routing all external
  traffic through the Track C proxy container.

Security Guarantees:
  - Enforces explicit proxy routing (--proxy-server=http://proxy:8080)
  - Disables loopback bypass exceptions (--proxy-bypass-list=<-loopback>)
  - Disables QUIC / HTTP/3 (--disable-quic)
  - Disables DoH & async DNS (--disable-features=DnsOverHttps,AsyncDns)
  - Enforces WebRTC non-proxied UDP block (--force-webrtc-ip-handling-policy=disable_non_proxied_udp)
  - Respects native Chromium sandbox by default (no automatic --no-sandbox)
  - Supports SPKI leaf and CA certificate pinning (--ignore-certificate-errors-spki-list)
  - Strict navigation timeouts and signal-trapped process cleanup
"""

import argparse
import json
import logging
import os
import signal
import sys
import time
from typing import Any, Dict, List, Optional

from playwright.sync_api import sync_playwright, Browser, BrowserContext, Page, Error as PlaywrightError

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    stream=sys.stderr,
)
logger = logging.getLogger("scamshield.browser.scanner")


def build_hardened_args(
    proxy_server: Optional[str] = "http://proxy:8080",
    spki_pin: Optional[str] = None,
    disable_sandbox: bool = False,
    extra_args: Optional[List[str]] = None,
) -> List[str]:
    """
    Construct security-hardened launch argument list for Chromium.
    Notice: --no-sandbox is omitted by default to preserve native sandbox integrity.
    """
    args = [
        "--disable-quic",
        "--disable-features=DnsOverHttps,AsyncDns",
        "--force-webrtc-ip-handling-policy=disable_non_proxied_udp",
        "--no-first-run",
        "--no-default-browser-check",
    ]

    if proxy_server:
        args.append(f"--proxy-server={proxy_server}")
        args.append("--proxy-bypass-list=<-loopback>")

    if spki_pin:
        args.append(f"--ignore-certificate-errors-spki-list={spki_pin}")

    if disable_sandbox:
        logger.warning("SECURITY NOTICE: Chromium sandbox explicitly disabled via --no-sandbox")
        args.append("--no-sandbox")

    if extra_args:
        args.extend(extra_args)

    return args


def inspect_environment() -> Dict[str, Any]:
    """Inspect current process security context for diagnostics."""
    info: Dict[str, Any] = {
        "uid": os.getuid() if hasattr(os, "getuid") else None,
        "gid": os.getgid() if hasattr(os, "getgid") else None,
        "pid": os.getpid(),
        "unprivileged_userns_clone": None,
        "proc_self_status": {},
    }

    userns_path = "/proc/sys/kernel/unprivileged_userns_clone"
    if os.path.exists(userns_path):
        try:
            with open(userns_path, "r", encoding="utf-8") as f:
                info["unprivileged_userns_clone"] = f.read().strip()
        except Exception as e:
            info["unprivileged_userns_clone"] = f"read_error: {e}"

    status_path = "/proc/self/status"
    if os.path.exists(status_path):
        try:
            with open(status_path, "r", encoding="utf-8") as f:
                for line in f:
                    for key in ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb", "NoNewPrivs", "Seccomp"):
                        if line.startswith(f"{key}:"):
                            info["proc_self_status"][key] = line.split(":", 1)[1].strip()
        except Exception as e:
            info["proc_self_status"]["read_error"] = str(e)

    return info


def run_sandbox_diagnosis(disable_sandbox: bool = False) -> Dict[str, Any]:
    """
    Diagnostic mode: Launch Chromium with native sandbox settings to verify
    whether the sandbox works or capture the exact reason for failure.
    """
    env_info = inspect_environment()
    args = build_hardened_args(
        proxy_server=None,  # No proxy needed for internal sandbox check
        disable_sandbox=disable_sandbox,
    )

    result: Dict[str, Any] = {
        "action": "sandbox_diagnosis",
        "disable_sandbox_flag": disable_sandbox,
        "environment": env_info,
        "launch_args": args,
        "success": False,
        "chromium_version": None,
        "error": None,
        "error_type": None,
    }

    logger.info("Starting Chromium sandbox diagnostic probe (disable_sandbox=%s)...", disable_sandbox)
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(
                headless=True,
                args=args,
            )
            result["chromium_version"] = browser.version
            result["success"] = True
            logger.info("Chromium launched successfully. Version: %s", browser.version)
            browser.close()
    except Exception as exc:
        result["error"] = str(exc)
        result["error_type"] = type(exc).__name__
        logger.error("Chromium launch failed: %s (%s)", type(exc).__name__, exc)

    return result


def execute_scan(
    url: str,
    proxy_server: Optional[str] = "http://proxy:8080",
    spki_pin: Optional[str] = None,
    timeout_sec: int = 30,
    disable_sandbox: bool = False,
    screenshot_path: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Perform a scan navigation against a target URL using hardened Chromium.
    Returns structured result dictionary.
    """
    env_info = inspect_environment()
    args = build_hardened_args(
        proxy_server=proxy_server,
        spki_pin=spki_pin,
        disable_sandbox=disable_sandbox,
    )

    result: Dict[str, Any] = {
        "target_url": url,
        "proxy_server": proxy_server,
        "spki_pin": spki_pin,
        "disable_sandbox": disable_sandbox,
        "environment": {
            "uid": env_info.get("uid"),
            "gid": env_info.get("gid"),
        },
        "success": False,
        "status_code": None,
        "final_url": None,
        "title": None,
        "error": None,
        "error_type": None,
        "console_messages": [],
        "timing_ms": 0,
    }

    start_time = time.time()
    browser: Optional[Browser] = None
    context: Optional[BrowserContext] = None
    page: Optional[Page] = None

    def _cleanup_handler(signum, frame):
        logger.warning("Received signal %d; shutting down browser cleanly.", signum)
        if browser:
            try:
                browser.close()
            except Exception:
                pass
        sys.exit(128 + signum)

    signal.signal(signal.SIGTERM, _cleanup_handler)
    signal.signal(signal.SIGINT, _cleanup_handler)

    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(
                headless=True,
                args=args,
            )
            context = browser.new_context(
                ignore_https_errors=False,  # Enforce strict TLS validation
            )
            page = context.new_page()

            page.on("console", lambda msg: result["console_messages"].append({
                "type": msg.type,
                "text": msg.text,
            }))

            response = page.goto(
                url,
                timeout=timeout_sec * 1000,
                wait_until="load",
            )

            if response:
                result["status_code"] = response.status
                result["final_url"] = page.url
            else:
                result["final_url"] = page.url

            result["title"] = page.title()
            result["success"] = True

            if screenshot_path:
                page.screenshot(path=screenshot_path)
                result["screenshot_path"] = screenshot_path

    except PlaywrightError as pe:
        result["error"] = str(pe)
        result["error_type"] = "PlaywrightError"
        logger.error("Navigation failed: %s", pe)
    except Exception as exc:
        result["error"] = str(exc)
        result["error_type"] = type(exc).__name__
        logger.error("Unexpected error during scan: %s", exc)
    finally:
        result["timing_ms"] = int((time.time() - start_time) * 1000)
        if browser:
            try:
                browser.close()
            except Exception:
                pass

    return result


def main() -> int:
    parser = argparse.ArgumentParser(description="ScamShield Track C Hardened Browser Scanner")
    parser.add_argument("--url", default=None, help="Target URL to inspect")
    parser.add_argument("--proxy-server", default=os.environ.get("PROXY_SERVER", "http://proxy:8080"), help="Proxy server address")
    parser.add_argument("--no-proxy", action="store_true", help="Run without proxy (for direct/internal checks)")
    parser.add_argument("--spki-pin", default=os.environ.get("SPKI_PIN", None), help="Comma-separated SPKI pin hashes")
    parser.add_argument("--timeout", type=int, default=int(os.environ.get("SCAN_TIMEOUT", "30")), help="Timeout in seconds")
    parser.add_argument("--no-sandbox", action="store_true", default=bool(os.environ.get("DISABLE_CHROMIUM_SANDBOX", False)), help="Explicitly disable Chromium sandbox (diagnostic only)")
    parser.add_argument("--diagnose-sandbox", action="store_true", help="Run standalone sandbox diagnosis probe and exit")
    parser.add_argument("--screenshot", default=None, help="Path to save page screenshot")
    parser.add_argument("--format", choices=["json", "text"], default="json", help="Output format")

    args = parser.parse_args()

    if args.diagnose_sandbox:
        diag = run_sandbox_diagnosis(disable_sandbox=args.no_sandbox)
        if args.format == "json":
            print(json.dumps(diag, indent=2))
        else:
            print(f"Sandbox Diagnosis: {'SUCCESS' if diag['success'] else 'FAILED'}")
            print(f"Chromium Version: {diag.get('chromium_version')}")
            if diag.get("error"):
                print(f"Error: {diag['error']}")
        return 0 if diag["success"] else 1

    if not args.url:
        logger.error("Error: --url is required unless --diagnose-sandbox is specified.")
        parser.print_help(sys.stderr)
        return 2

    proxy = None if args.no_proxy else args.proxy_server
    scan_res = execute_scan(
        url=args.url,
        proxy_server=proxy,
        spki_pin=args.spki_pin,
        timeout_sec=args.timeout,
        disable_sandbox=args.no_sandbox,
        screenshot_path=args.screenshot,
    )

    if args.format == "json":
        print(json.dumps(scan_res, indent=2))
    else:
        print(f"Scan URL: {scan_res['target_url']}")
        print(f"Success: {scan_res['success']}")
        print(f"Status Code: {scan_res['status_code']}")
        print(f"Final URL: {scan_res['final_url']}")
        print(f"Title: {scan_res['title']}")
        if scan_res.get("error"):
            print(f"Error: {scan_res['error']}")

    return 0 if scan_res["success"] else 1


if __name__ == "__main__":
    sys.exit(main())
