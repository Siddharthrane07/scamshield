import asyncio
import datetime
import sys
import unittest
from unittest.mock import patch, MagicMock
import httpx

sys.path.insert(0, r"e:\scratch\scamshield\backend")

from app.services.track_b_domain import TrackBDomainIntel, validate_domain, _parse_created_date
from app.services.track_a_url import TrackAURLIntel
from app.services.ocr.ocr_postprocess import fix_split_urls, extract_urls


class TestTrackBDomainIntel(unittest.IsolatedAsyncioTestCase):

    # ──────────────────────────────────────────────────────────────────────────
    # TEST 1: Valid domain + WHOIS createdDate available
    # ──────────────────────────────────────────────────────────────────────────
    async def test_01_valid_domain_whois_created_date(self):
        past_date = (datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=95)).strftime("%Y-%m-%dT00:00:00Z")
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "WhoisRecord": {
                "createdDate": past_date
            }
        }

        with patch("app.services.track_b_domain.settings.WHOISXML_API_KEY", "test_key_123"):
            with patch("httpx.AsyncClient.get", return_value=mock_response):
                res = await TrackBDomainIntel.get_domain_age("example.com")
                self.assertEqual(res["status"], "valid")
                self.assertIsNotNone(res["age_days"])
                self.assertTrue(94 <= res["age_days"] <= 96)
                self.assertFalse(res["is_recent_domain"])
                self.assertTrue(res["api_queried"])
                self.assertNotEqual(res["age_days"], 180)

    # ──────────────────────────────────────────────────────────────────────────
    # TEST 2: WHOIS response has no createdDate
    # ──────────────────────────────────────────────────────────────────────────
    async def test_02_whois_response_no_created_date(self):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "WhoisRecord": {
                "createdDate": None
            }
        }

        with patch("app.services.track_b_domain.settings.WHOISXML_API_KEY", "test_key_123"):
            with patch("httpx.AsyncClient.get", return_value=mock_response):
                res = await TrackBDomainIntel.get_domain_age("example.com")
                self.assertEqual(res["status"], "created_date_missing")
                self.assertIsNone(res["age_days"])
                self.assertIsNone(res["is_recent_domain"])
                self.assertIsNone(res["created_date"])
                self.assertEqual(res["reason"], "createdDate_missing")
                self.assertTrue(res["api_queried"])
                self.assertNotEqual(res["age_days"], 180)

    # ──────────────────────────────────────────────────────────────────────────
    # TEST 3: WHOIS HTTP 404
    # ──────────────────────────────────────────────────────────────────────────
    async def test_03_whois_http_404(self):
        mock_response = MagicMock()
        mock_response.status_code = 404
        mock_response.json.return_value = {"error": "Domain not found"}

        with patch("app.services.track_b_domain.settings.WHOISXML_API_KEY", "test_key_123"):
            with patch("httpx.AsyncClient.get", return_value=mock_response):
                res = await TrackBDomainIntel.get_domain_age("nonexistent-domain-xyz.com")
                self.assertEqual(res["status"], "not_found")
                self.assertIsNone(res["age_days"])
                self.assertIsNone(res["is_recent_domain"])
                self.assertEqual(res["reason"], "domain_not_found")
                self.assertNotEqual(res["age_days"], 180)

    # ──────────────────────────────────────────────────────────────────────────
    # TEST 4: WHOIS timeout
    # ──────────────────────────────────────────────────────────────────────────
    async def test_04_whois_timeout(self):
        with patch("app.services.track_b_domain.settings.WHOISXML_API_KEY", "test_key_123"):
            with patch("httpx.AsyncClient.get", side_effect=httpx.TimeoutException("Request timed out")):
                res = await TrackBDomainIntel.get_domain_age("timeout-domain.com")
                self.assertEqual(res["status"], "timeout")
                self.assertIsNone(res["age_days"])
                self.assertIsNone(res["is_recent_domain"])
                self.assertEqual(res["reason"], "whois_timeout")
                self.assertNotEqual(res["age_days"], 180)

    # ──────────────────────────────────────────────────────────────────────────
    # TEST 5: Malformed domain (e.g. bk-bnk-)
    # ──────────────────────────────────────────────────────────────────────────
    async def test_05_malformed_domain(self):
        is_valid, domain_type, reason = validate_domain("bk-bnk-")
        self.assertFalse(is_valid)
        self.assertEqual(domain_type, "invalid")
        self.assertEqual(reason, "hyphen_at_boundary")

        res = await TrackBDomainIntel.get_domain_age("bk-bnk-")
        self.assertEqual(res["status"], "invalid_domain")
        self.assertIsNone(res["age_days"])
        self.assertFalse(res["api_queried"])
        self.assertNotEqual(res["age_days"], 180)

    # ──────────────────────────────────────────────────────────────────────────
    # TEST 6: Valid hyphenated domain
    # ──────────────────────────────────────────────────────────────────────────
    def test_06_valid_hyphenated_domain(self):
        is_valid, domain_type, reason = validate_domain("secure-bank-login.com")
        self.assertTrue(is_valid)
        self.assertEqual(domain_type, "domain")
        self.assertEqual(reason, "valid")

    # ──────────────────────────────────────────────────────────────────────────
    # TEST 7: Valid domain with valid SSL
    # ──────────────────────────────────────────────────────────────────────────
    async def test_07_valid_ssl_no_penalty(self):
        with patch.object(TrackBDomainIntel, "_fetch_ssl_issuer", return_value={
            "ssl_valid": True,
            "status": "valid",
            "reason": "valid_certificate",
            "issuer_org": "DigiCert Inc",
            "issuer_cn": "DigiCert Global",
            "is_lets_encrypt": False,
            "is_cloudflare": False,
            "is_free_ssl": False,
            "error": None
        }):
            res = await TrackBDomainIntel.inspect_ssl("example.com")
            self.assertTrue(res["ssl_valid"])
            self.assertEqual(res["status"], "valid")

    # ──────────────────────────────────────────────────────────────────────────
    # TEST 8: SSL timeout (Infrastructure failure -> 0 risk penalty)
    # ──────────────────────────────────────────────────────────────────────────
    async def test_08_ssl_timeout_no_malicious_penalty(self):
        with patch.object(TrackBDomainIntel, "_fetch_ssl_issuer", return_value={
            "ssl_valid": None,
            "status": "timeout",
            "reason": "ssl_timeout",
            "issuer_org": None,
            "issuer_cn": None,
            "is_lets_encrypt": False,
            "is_cloudflare": False,
            "is_free_ssl": False,
            "error": "timed out"
        }):
            with patch.object(TrackBDomainIntel, "get_domain_age", return_value={
                "created_date": None,
                "age_days": None,
                "is_recent_domain": None,
                "api_queried": False,
                "status": "unknown",
                "reason": "whois_api_not_configured"
            }):
                analysis = await TrackBDomainIntel.analyze(["https://timeout-ssl.com"])
                domain_item = analysis["domains_analyzed"][0]
                self.assertEqual(domain_item["ssl"]["status"], "timeout")
                self.assertIsNone(domain_item["ssl"]["ssl_valid"])
                # Must not add automatic +20 penalty on timeout
                self.assertEqual(domain_item["risk_score"], 0)
                self.assertEqual(domain_item["intelligence_quality"], "unavailable")

    # ──────────────────────────────────────────────────────────────────────────
    # TEST 9: Let's Encrypt / Cloudflare free SSL (Not inherently malicious)
    # ──────────────────────────────────────────────────────────────────────────
    async def test_09_free_ssl_not_malicious(self):
        with patch.object(TrackBDomainIntel, "_fetch_ssl_issuer", return_value={
            "ssl_valid": True,
            "status": "valid",
            "reason": "valid_certificate",
            "issuer_org": "Let's Encrypt",
            "issuer_cn": "R3",
            "is_lets_encrypt": True,
            "is_cloudflare": False,
            "is_free_ssl": True,
            "error": None
        }):
            with patch.object(TrackBDomainIntel, "get_domain_age", return_value={
                "created_date": (datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=200)).isoformat(),
                "age_days": 200,
                "is_recent_domain": False,
                "api_queried": True,
                "status": "valid",
                "reason": "createdDate_retrieved"
            }):
                analysis = await TrackBDomainIntel.analyze(["https://letsencrypt-safe.org"])
                domain_item = analysis["domains_analyzed"][0]
                self.assertTrue(domain_item["ssl"]["is_free_ssl"])
                self.assertEqual(domain_item["risk_score"], 0)
                self.assertEqual(domain_item["intelligence_quality"], "high")

    # ──────────────────────────────────────────────────────────────────────────
    # TEST 10: Multiple URLs with same domain (Deduplication)
    # ──────────────────────────────────────────────────────────────────────────
    async def test_10_multiple_urls_deduplicated(self):
        urls = [
            "https://www.example.com/page1",
            "http://example.com/page2?query=1",
            "https://example.com/login"
        ]
        with patch.object(TrackBDomainIntel, "get_domain_age", return_value={
            "created_date": None,
            "age_days": None,
            "is_recent_domain": None,
            "api_queried": False,
            "status": "unknown",
            "reason": "whois_api_not_configured"
        }):
            with patch.object(TrackBDomainIntel, "inspect_ssl", return_value={
                "ssl_valid": True,
                "status": "valid",
                "reason": "valid_certificate",
                "is_free_ssl": False
            }):
                analysis = await TrackBDomainIntel.analyze(urls)
                self.assertEqual(len(analysis["domains_analyzed"]), 1)
                self.assertEqual(analysis["domains_analyzed"][0]["domain"], "example.com")

    # ──────────────────────────────────────────────────────────────────────────
    # TEST 11: bk-bnk-official.com case (Single line & Wrapped OCR)
    # ──────────────────────────────────────────────────────────────────────────
    def test_11_bk_bnk_official_extraction(self):
        # 11a. Single-line URL extraction
        url1 = "https://www.bk-bnk-official.com/login/otp-update.html"
        domain1 = TrackAURLIntel.extract_domain(url1)
        self.assertEqual(domain1, "bk-bnk-official.com")
        self.assertNotEqual(domain1, "bk-bnk-")

        # 11b. Wrapped OCR lines
        wrapped_ocr = (
            "ALERT: Update KYC via\n"
            "https://www.bk-bnk-\n"
            "official.com/login/otp-\n"
            "update.html immediately"
        )
        stitched = fix_split_urls(wrapped_ocr)
        extracted = extract_urls(stitched)
        self.assertTrue(len(extracted) > 0)
        self.assertEqual(extracted[0], "https://www.bk-bnk-official.com/login/otp-update.html")
        domain_stitched = TrackAURLIntel.extract_domain(extracted[0])
        self.assertEqual(domain_stitched, "bk-bnk-official.com")
        self.assertNotEqual(domain_stitched, "bk-bnk-")


if __name__ == "__main__":
    unittest.main()
