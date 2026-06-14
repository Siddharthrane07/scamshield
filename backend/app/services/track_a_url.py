import logging
import urllib.parse
import base64
import httpx
from typing import List, Dict, Any
from app.core.config import get_settings

logger = logging.getLogger("scamshield.track_a")
settings = get_settings()

TRUSTED_BRANDS = [
    "sbi", "hdfc", "icici", "paytm", "amazon", "flipkart", 
    "netflix", "google", "microsoft", "apple", "paypal", 
    "phonepe", "onlinesbi", "bhim", "yono"
]

HOMOGLYPH_MAP = {
    '0': 'o', '1': 'i', 'l': 'i', 'vv': 'w', 'rn': 'm',
    'cl': 'd', 'cj': 'g', 'i': 'l', 'o': '0'
}

def get_levenshtein_distance(s1: str, s2: str) -> int:
    """
    Computes Levenshtein edit distance between s1 and s2.
    """
    if len(s1) < len(s2):
        return get_levenshtein_distance(s2, s1)
    if len(s2) == 0:
        return len(s1)
    
    previous_row = list(range(len(s2) + 1))
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row
        
    return previous_row[-1]

class TrackAURLIntel:
    @staticmethod
    def extract_domain(url: str) -> str:
        """
        Helper to extract clean hostname/domain from a URL.
        """
        try:
            parsed = urllib.parse.urlparse(url)
            netloc = parsed.netloc or parsed.path
            # Remove port if any
            domain = netloc.split(":")[0].lower()
            if domain.startswith("www."):
                domain = domain[4:]
            return domain
        except Exception:
            return url.lower()

    @classmethod
    def check_typosquatting(cls, domain: str) -> Dict[str, Any]:
        """
        Inspects the domain against trusted brands using edit distance
        and visual homoglyph substitutions to detect typosquatting.
        """
        # Split domain to get the secondary level domain (SLD) e.g., 'hdfcc' from 'hdfcc.com'
        parts = domain.split('.')
        sld = parts[0] if parts else domain

        # 1. Direct contains check
        for brand in TRUSTED_BRANDS:
            # If the brand name is inside the SLD, but is not equal to it (e.g. hdfc-rewards-login.com)
            if brand in sld and sld != brand:
                return {
                    "is_typosquatted": True,
                    "target_brand": brand,
                    "reason": f"Domain contains trusted brand name '{brand}' in suspicious context."
                }

        # 2. Levenshtein edit distance check
        for brand in TRUSTED_BRANDS:
            distance = get_levenshtein_distance(sld, brand)
            if 0 < distance <= 2:
                return {
                    "is_typosquatted": True,
                    "target_brand": brand,
                    "reason": f"Domain SLD '{sld}' is highly similar to brand '{brand}' (edit distance: {distance})."
                }

        # 3. Visual Homoglyph check
        # Attempt to normalize common homoglyphs and check for match
        normalized_sld = sld
        for char, replacement in HOMOGLYPH_MAP.items():
            normalized_sld = normalized_sld.replace(char, replacement)
        
        for brand in TRUSTED_BRANDS:
            if normalized_sld == brand and sld != brand:
                return {
                    "is_typosquatted": True,
                    "target_brand": brand,
                    "reason": f"Domain SLD '{sld}' visually mimics brand '{brand}' using homoglyphs."
                }

        return {
            "is_typosquatted": False,
            "target_brand": None,
            "reason": "No typosquatting detected."
        }

    @classmethod
    async def query_virustotal(cls, url: str) -> Dict[str, Any]:
        """
        Queries VirusTotal API for URL reputation.
        """
        api_key = settings.VIRUSTOTAL_API_KEY
        
        # If API key is not configured, fall back to mock classification based on heuristics
        if not api_key or api_key == "vt_api_key_placeholder":
            logger.warning("VirusTotal API key is a placeholder. Using fallback heuristic.")
            domain = cls.extract_domain(url)
            is_suspicious_domain = any(keyword in domain for keyword in ["free", "reward", "win", "gift", "login", "kyc", "verify", "pay"])
            
            return {
                "malicious_count": 4 if is_suspicious_domain else 0,
                "harmless_count": 65,
                "suspicious_count": 1 if is_suspicious_domain else 0,
                "verdict": "malicious" if is_suspicious_domain else "clean",
                "api_queried": False
            }

        # Format URL ID as base64 without padding for VT API v3
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        vt_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
        headers = {"x-apikey": api_key}

        try:
            async with httpx.AsyncClient(timeout=4.0) as client:
                response = await client.get(vt_url, headers=headers)
                
                if response.status_code == 200:
                    data = response.json()
                    stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                    malicious = stats.get("malicious", 0)
                    suspicious = stats.get("suspicious", 0)
                    harmless = stats.get("harmless", 0)
                    
                    verdict = "clean"
                    if malicious >= 2:
                        verdict = "malicious"
                    elif malicious == 1 or suspicious >= 2:
                        verdict = "suspicious"

                    return {
                        "malicious_count": malicious,
                        "harmless_count": harmless,
                        "suspicious_count": suspicious,
                        "verdict": verdict,
                        "api_queried": True
                    }
                else:
                    logger.error(f"VirusTotal request failed with status: {response.status_code}")
                    return {"error": f"HTTP {response.status_code}", "verdict": "unknown", "api_queried": True}
        except Exception as e:
            logger.error(f"VirusTotal query error: {e}")
            return {"error": str(e), "verdict": "unknown", "api_queried": False}

    @classmethod
    async def analyze(cls, urls: List[str]) -> Dict[str, Any]:
        """
        Executes URL analysis for all extracted links.
        """
        if not urls:
            return {"status": "bypassed", "urls_analyzed": []}

        results = []
        for url in urls:
            domain = cls.extract_domain(url)
            typo_info = cls.check_typosquatting(domain)
            vt_info = await cls.query_virustotal(url)
            
            # Combine scores
            is_malicious = vt_info.get("verdict") == "malicious" or typo_info.get("is_typosquatted")
            risk_score = 0
            if typo_info.get("is_typosquatted"):
                risk_score += 60
            if vt_info.get("malicious_count", 0) > 0:
                risk_score += min(40, vt_info.get("malicious_count", 0) * 15)

            results.append({
                "url": url,
                "domain": domain,
                "typosquatting": typo_info,
                "virustotal": vt_info,
                "risk_score": min(100, risk_score),
                "verdict": "hostile" if is_malicious else "clean"
            })

        # Aggregated URL risk score
        max_risk = max([r["risk_score"] for r in results]) if results else 0
        
        return {
            "status": "completed",
            "max_risk_score": max_risk,
            "urls_analyzed": results
        }
