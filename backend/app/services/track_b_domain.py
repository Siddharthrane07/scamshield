import logging
import datetime
import socket
import ssl
import httpx
import asyncio
from typing import List, Dict, Any
from app.core.config import get_settings

logger = logging.getLogger("scamshield.track_b")
settings = get_settings()

class TrackBDomainIntel:
    @classmethod
    async def get_domain_age(cls, domain: str) -> Dict[str, Any]:
        """
        Queries WhoisXML API to retrieve domain registration date and computes age.
        """
        api_key = settings.WHOISXML_API_KEY

        # Fallback heuristic if API key is not configured
        if not api_key or api_key == "whois_api_key_placeholder":
            logger.warning("WhoisXML API key is a placeholder. Using fallback heuristic.")
            # If domain contains suspicious keywords, simulate a very young domain
            suspicious_keywords = ["free", "reward", "gift", "login", "kyc", "verify", "pay", "bank"]
            is_suspicious = any(kw in domain for kw in suspicious_keywords)
            
            created_date = (
                datetime.datetime.utcnow() - datetime.timedelta(days=2)
                if is_suspicious else
                datetime.datetime.utcnow() - datetime.timedelta(days=450)
            )
            age_days = 2 if is_suspicious else 450
            return {
                "created_date": created_date.isoformat(),
                "age_days": age_days,
                "is_recent_domain": age_days < 30,
                "api_queried": False
            }

        whois_url = f"https://www.whoisxmlapi.com/whoisserver/WhoisService?apiKey={api_key}&domainName={domain}&outputFormat=JSON"
        
        try:
            async with httpx.AsyncClient(timeout=4.0) as client:
                response = await client.get(whois_url)
                if response.status_code == 200:
                    data = response.json()
                    whois_record = data.get("WhoisRecord", {})
                    created_date_str = whois_record.get("createdDate") or whois_record.get("registryData", {}).get("createdDate")
                    
                    if created_date_str:
                        # Extract date part (often ISO e.g., 2026-06-12T12:00:00Z)
                        clean_date = created_date_str.split("T")[0]
                        created_date = datetime.datetime.strptime(clean_date, "%Y-%m-%d")
                        age_days = (datetime.datetime.utcnow() - created_date).days
                        
                        return {
                            "created_date": created_date.isoformat(),
                            "age_days": max(0, age_days),
                            "is_recent_domain": age_days < 30,
                            "api_queried": True
                        }
                    
                    logger.warning(f"Could not extract createdDate for domain: {domain}")
                    return {"age_days": 180, "is_recent_domain": False, "api_queried": True, "warning": "createdDate missing"}
                else:
                    logger.error(f"WhoisXML request failed with status: {response.status_code}")
                    return {"age_days": 180, "is_recent_domain": False, "api_queried": True, "error": f"HTTP {response.status_code}"}
        except Exception as e:
            logger.error(f"WhoisXML query error: {e}")
            return {"age_days": 180, "is_recent_domain": False, "api_queried": False, "error": str(e)}

    @classmethod
    def _fetch_ssl_issuer(cls, domain: str) -> Dict[str, Any]:
        """
        Synchronous helper function to retrieve SSL certificate details.
        Must be run in an executor thread to prevent blocking async event loop.
        """
        context = ssl.create_default_context()
        # Set a short timeout on the socket
        conn = context.wrap_socket(socket.socket(socket.AF_INET), server_hostname=domain)
        conn.settimeout(3.0)
        
        try:
            conn.connect((domain, 443))
            cert = conn.getpeercert()
            
            # Issuer is a tuple of tuples containing key-value pairs
            issuer_tuple = cert.get('issuer', ())
            issuer_info = {}
            for item in issuer_tuple:
                for k, v in item:
                    issuer_info[k] = v
            
            organization = issuer_info.get('organizationName', '')
            common_name = issuer_info.get('commonName', '')
            
            # Identify Let's Encrypt / Cloudflare
            is_lets_encrypt = "Let's Encrypt" in organization or "Let's Encrypt" in common_name
            is_cloudflare = "Cloudflare" in organization or "Cloudflare" in common_name
            
            return {
                "ssl_valid": True,
                "issuer_org": organization,
                "issuer_cn": common_name,
                "is_lets_encrypt": is_lets_encrypt,
                "is_cloudflare": is_cloudflare,
                "is_free_ssl": is_lets_encrypt or is_cloudflare
            }
        except Exception as e:
            logger.warning(f"SSL certificate inspection failed for {domain}: {e}")
            return {
                "ssl_valid": False,
                "issuer_org": None,
                "issuer_cn": None,
                "is_lets_encrypt": False,
                "is_cloudflare": False,
                "is_free_ssl": False,
                "error": str(e)
            }
        finally:
            try:
                conn.close()
            except Exception:
                pass

    @classmethod
    async def inspect_ssl(cls, domain: str) -> Dict[str, Any]:
        """
        Inspects SSL certificate in a non-blocking manner.
        """
        try:
            # Run the synchronous blocking socket code in a separate thread
            return await asyncio.to_thread(cls._fetch_ssl_issuer, domain)
        except Exception as e:
            return {
                "ssl_valid": False,
                "is_free_ssl": False,
                "error": str(e)
            }

    @classmethod
    async def analyze(cls, urls: List[str]) -> Dict[str, Any]:
        """
        Performs WHOIS domain age lookup and SSL issuer check for all domains.
        """
        if not urls:
            return {"status": "bypassed", "domains_analyzed": []}

        # Extract unique domains
        from app.services.track_a_url import TrackAURLIntel
        domains = list(set([TrackAURLIntel.extract_domain(url) for url in urls]))
        
        results = []
        for domain in domains:
            # Check if it's an IP address (if it's an IP, WHOIS/SSL checks are slightly different, but we'll try)
            # Skip localhost or local IPs
            if domain in ["localhost", "127.0.0.1"]:
                continue
                
            age_info = await cls.get_domain_age(domain)
            ssl_info = await cls.inspect_ssl(domain)
            
            # Compute score contributors
            risk_score = 0
            # Recent domains are high risk
            if age_info.get("is_recent_domain"):
                risk_score += 60
            elif age_info.get("age_days", 365) < 90:
                risk_score += 30
                
            # If domain is recent AND uses a free Let's Encrypt / Cloudflare SSL cert, boost risk
            if (age_info.get("is_recent_domain") or age_info.get("age_days", 365) < 90) and ssl_info.get("is_free_ssl"):
                risk_score += 20
                
            # Invalid/expired SSL cert on HTTPS URL is suspicious
            if not ssl_info.get("ssl_valid"):
                risk_score += 20

            results.append({
                "domain": domain,
                "whois": age_info,
                "ssl": ssl_info,
                "risk_score": min(100, risk_score)
            })

        max_risk = max([r["risk_score"] for r in results]) if results else 0

        return {
            "status": "completed",
            "max_risk_score": max_risk,
            "domains_analyzed": results
        }
