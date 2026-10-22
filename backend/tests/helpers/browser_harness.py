"""
browser_harness.py — Security-hardened Playwright Chromium launcher for Track C.

Launches Playwright-bundled Chromium with explicit security flags:
- --proxy-server=http://127.0.0.1:<PORT>
- --proxy-bypass-list=<-loopback>
- --disable-quic
- --disable-features=DnsOverHttps,AsyncDns
- --force-webrtc-ip-handling-policy=disable_non_proxied_udp
- --no-first-run
- --no-default-browser-check
- --ignore-certificate-errors-spki-list=<TEST_CA_SPKI_HASH> (when supplied)

Captures and logs browser engine baseline diagnostics:
- Playwright package version
- Bundled Chromium version
- Launch arguments
"""
import logging
from typing import Optional, Dict, Any, List, Tuple
from playwright.sync_api import Playwright, Browser
import playwright

logger = logging.getLogger("scamshield.tests.browser_harness")


def build_hardened_args(
    proxy_port: int,
    test_ca_spki_hash: Optional[str] = None,
    extra_args: Optional[List[str]] = None,
) -> List[str]:
    """Build the standard hardened Chromium argument list."""
    args = [
        f"--proxy-server=http://127.0.0.1:{proxy_port}",
        "--proxy-bypass-list=<-loopback>",
        "--disable-quic",
        "--disable-features=DnsOverHttps,AsyncDns",
        "--force-webrtc-ip-handling-policy=disable_non_proxied_udp",
        "--no-first-run",
        "--no-default-browser-check",
    ]
    if test_ca_spki_hash:
        args.append(f"--ignore-certificate-errors-spki-list={test_ca_spki_hash}")
    if extra_args:
        args.extend(extra_args)
    return args


def launch_hardened_browser(
    playwright_inst: Playwright,
    proxy_port: int,
    test_ca_spki_hash: Optional[str] = None,
    extra_args: Optional[List[str]] = None,
    headless: bool = True,
) -> Tuple[Browser, Dict[str, Any]]:
    """
    Launch Chromium with hardened security flags and capture diagnostic baseline.
    Returns (Browser, diagnostics_dict).
    """
    args = build_hardened_args(proxy_port, test_ca_spki_hash, extra_args)

    browser = playwright_inst.chromium.launch(
        headless=headless,
        args=args,
    )

    diagnostics = {
        "playwright_version": getattr(playwright, "__version__", "unknown"),
        "chromium_version": browser.version,
        "spki_hash": test_ca_spki_hash,
        "launch_args": args,
    }

    logger.info(
        f"[Browser Baseline] Playwright: {diagnostics['playwright_version']} | "
        f"Chromium: {diagnostics['chromium_version']} | SPKI: {test_ca_spki_hash}"
    )

    return browser, diagnostics
