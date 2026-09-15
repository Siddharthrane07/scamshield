import logging
import datetime
import ipaddress
import re
import socket
import ssl
import httpx
import asyncio
from typing import List, Dict, Any, Optional, Tuple
from app.core.config import get_settings

logger = logging.getLogger("scamshield.track_b")
settings = get_settings()


def validate_domain(domain: str) -> Tuple[bool, str, str]:
    """
    Validates a domain or host string before sending to WHOIS or SSL inspection.
    Returns: (is_valid, domain_type, reason)
      - domain_type: 'domain', 'ip', or 'invalid'
      - reason: machine-readable reason code
    """
    if not domain or not isinstance(domain, str):
        return False, "invalid", "empty_domain"
    
    clean = domain.strip().lower().rstrip(".")
    if not clean:
        return False, "invalid", "empty_domain"
    
    # Reject whitespace or URL path / query / userinfo characters
    if any(c in clean for c in [" ", "\t", "\n", "\r", "/", "\\", "?", "#", "@", ":"]):
        return False, "invalid", "contains_invalid_characters"

    # Check for IP Address
    try:
        ip = ipaddress.ip_address(clean)
        if ip.is_loopback:
            return False, "ip", "loopback_ip"
        if ip.is_private:
            return False, "ip", "private_ip"
        if ip.is_reserved or ip.is_link_local or ip.is_multicast:
            return False, "ip", "reserved_ip"
        return True, "ip", "public_ip"
    except ValueError:
        pass  # Not an IP address, proceed to domain validation

    # Domain syntax checks
    if clean in ["localhost", "local", "broadcasthost"]:
        return False, "invalid", "localhost"

    if clean.startswith("-") or clean.endswith("-"):
        return False, "invalid", "hyphen_at_boundary"

    labels = clean.split(".")
    if len(labels) < 2:
        return False, "invalid", "missing_tld"

    # Validate each label
    for label in labels:
        if not label:
            return False, "invalid", "empty_label"
        if len(label) > 63:
            return False, "invalid", "label_too_long"
        if label.startswith("-") or label.endswith("-"):
            return False, "invalid", "label_hyphen_boundary"
        if not re.match(r'^[a-z0-9\-]+$', label):
            return False, "invalid", "label_invalid_characters"

    # Validate TLD (must not be all numeric and at least 2 chars)
    tld = labels[-1]
    if tld.isdigit() or len(tld) < 2 or not re.match(r'^[a-z]+$', tld):
        return False, "invalid", "invalid_tld"

    if len(clean) > 253:
        return False, "invalid", "domain_too_long"

    return True, "domain", "valid"


def _parse_created_date(date_val: Any) -> Optional[datetime.datetime]:
    """
    Hardened parser for WHOIS createdDate in various ISO, RFC, and string formats.
    Always returns a timezone-aware UTC datetime or None.
    """
    if not date_val:
        return None
    
    if isinstance(date_val, datetime.datetime):
        if date_val.tzinfo is None:
            return date_val.replace(tzinfo=datetime.timezone.utc)
        return date_val.astimezone(datetime.timezone.utc)

    if isinstance(date_val, (int, float)):
        try:
            return datetime.datetime.fromtimestamp(date_val, tz=datetime.timezone.utc)
        except Exception:
            return None

    if not isinstance(date_val, str):
        return None

    date_str = date_val.strip()
    if not date_str:
        return None

    # 1. ISO format (e.g., '2026-06-12T12:00:00Z', '2026-06-12T12:00:00+00:00')
    try:
        iso_candidate = date_str.replace("Z", "+00:00")
        dt = datetime.datetime.fromisoformat(iso_candidate)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=datetime.timezone.utc)
        return dt.astimezone(datetime.timezone.utc)
    except Exception:
        pass

    # 2. Date only: YYYY-MM-DD or YYYY/MM/DD
    match_ymd = re.match(r'^(\d{4})[/-](\d{1,2})[/-](\d{1,2})', date_str)
    if match_ymd:
        try:
            y, m, d = int(match_ymd.group(1)), int(match_ymd.group(2)), int(match_ymd.group(3))
            return datetime.datetime(y, m, d, tzinfo=datetime.timezone.utc)
        except Exception:
            pass

    # 3. Standard strptime patterns
    patterns = [
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%d %H:%M:%S %Z",
        "%d-%m-%Y",
        "%d/%m/%Y",
        "%b %d %Y",
        "%d-%b-%Y",
        "%d %b %Y"
    ]
    for pat in patterns:
        try:
            dt = datetime.datetime.strptime(date_str, pat)
            return dt.replace(tzinfo=datetime.timezone.utc)
        except Exception:
            continue

    return None


class TrackBDomainIntel:
    @classmethod
    async def get_domain_age(cls, domain: str) -> Dict[str, Any]:
        """
        Queries WhoisXML API to retrieve domain registration date and computes age.
        Explicitly distinguishes between valid, missing date, not found, api error,
        timeout, invalid domain, and unconfigured states. Never fabricates fake age.
        """
        # 1. Validate domain syntax first
        is_valid, domain_type, validation_reason = validate_domain(domain)
        if not is_valid:
            if domain_type == "ip":
                return {
                    "created_date": None,
                    "age_days": None,
                    "is_recent_domain": None,
                    "api_queried": False,
                    "status": "not_applicable",
                    "reason": f"ip_address_{validation_reason}"
                }
            return {
                "created_date": None,
                "age_days": None,
                "is_recent_domain": None,
                "api_queried": False,
                "status": "invalid_domain",
                "reason": validation_reason
            }

        api_key = settings.WHOISXML_API_KEY

        # 2. Handle missing/placeholder API key
        if not api_key or api_key == "whois_api_key_placeholder":
            logger.info(f"WhoisXML API key not configured. Returning unknown status for {domain}.")
            return {
                "created_date": None,
                "age_days": None,
                "is_recent_domain": None,
                "api_queried": False,
                "status": "unknown",
                "reason": "whois_api_not_configured"
            }

        whois_url = f"https://www.whoisxmlapi.com/whoisserver/WhoisService?apiKey={api_key}&domainName={domain}&outputFormat=JSON"
        
        try:
            async with httpx.AsyncClient(timeout=4.0) as client:
                response = await client.get(whois_url)
                
                if response.status_code == 200:
                    data = response.json()
                    whois_record = data.get("WhoisRecord", {})
                    
                    # Extract createdDate candidate
                    created_date_raw = (
                        whois_record.get("createdDate") or 
                        whois_record.get("registryData", {}).get("createdDate") or
                        whois_record.get("createdDateNormalized") or
                        whois_record.get("registryData", {}).get("createdDateNormalized")
                    )
                    
                    dt = _parse_created_date(created_date_raw)
                    if dt:
                        now_utc = datetime.datetime.now(datetime.timezone.utc)
                        age_days = (now_utc - dt).days
                        age_days = max(0, age_days)
                        
                        return {
                            "created_date": dt.isoformat(),
                            "age_days": age_days,
                            "is_recent_domain": age_days < 30,
                            "api_queried": True,
                            "status": "valid",
                            "reason": "createdDate_retrieved"
                        }
                    
                    # Fallback check if estimatedDomainAge is available
                    estimated_age = whois_record.get("estimatedDomainAge")
                    if isinstance(estimated_age, (int, float)) and estimated_age >= 0:
                        age_days = int(estimated_age)
                        return {
                            "created_date": None,
                            "age_days": age_days,
                            "is_recent_domain": age_days < 30,
                            "api_queried": True,
                            "status": "valid",
                            "reason": "estimatedDomainAge_retrieved"
                        }

                    logger.warning(f"Could not extract createdDate for domain: {domain}")
                    return {
                        "created_date": None,
                        "age_days": None,
                        "is_recent_domain": None,
                        "api_queried": True,
                        "status": "created_date_missing",
                        "reason": "createdDate_missing"
                    }
                elif response.status_code == 404:
                    return {
                        "created_date": None,
                        "age_days": None,
                        "is_recent_domain": None,
                        "api_queried": True,
                        "status": "not_found",
                        "reason": "domain_not_found",
                        "error": "HTTP 404"
                    }
                else:
                    logger.error(f"WhoisXML request failed with status: {response.status_code}")
                    return {
                        "created_date": None,
                        "age_days": None,
                        "is_recent_domain": None,
                        "api_queried": True,
                        "status": "api_error",
                        "reason": "whois_http_error",
                        "error": f"HTTP {response.status_code}"
                    }
        except httpx.TimeoutException:
            logger.warning(f"WhoisXML query timed out for domain: {domain}")
            return {
                "created_date": None,
                "age_days": None,
                "is_recent_domain": None,
                "api_queried": True,
                "status": "timeout",
                "reason": "whois_timeout",
                "error": "Request timed out"
            }
        except Exception as e:
            logger.error(f"WhoisXML query error: {e}")
            return {
                "created_date": None,
                "age_days": None,
                "is_recent_domain": None,
                "api_queried": False,
                "status": "unknown",
                "reason": "whois_exception",
                "error": str(e)
            }

    @classmethod
    def _fetch_ssl_issuer(cls, domain: str) -> Dict[str, Any]:
        """
        Synchronous helper function to retrieve SSL certificate details.
        Distinguishes valid certs from expired, mismatch, self-signed, dns failure,
        timeout, and connection failure.
        """
        # Validate domain before socket connection
        is_valid, domain_type, validation_reason = validate_domain(domain)
        if not is_valid:
            return {
                "ssl_valid": None,
                "status": "invalid_domain",
                "reason": validation_reason,
                "issuer_org": None,
                "issuer_cn": None,
                "is_lets_encrypt": False,
                "is_cloudflare": False,
                "is_free_ssl": False,
                "error": f"Invalid domain: {validation_reason}"
            }

        context = ssl.create_default_context()
        conn = context.wrap_socket(socket.socket(socket.AF_INET), server_hostname=domain)
        conn.settimeout(3.0)
        
        try:
            conn.connect((domain, 443))
            cert = conn.getpeercert()
            
            # Issuer details
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
            
            # Check expiry
            not_after = cert.get('notAfter')
            if not_after:
                try:
                    exp_dt = datetime.datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=datetime.timezone.utc)
                    if exp_dt < datetime.datetime.now(datetime.timezone.utc):
                        return {
                            "ssl_valid": False,
                            "status": "expired",
                            "reason": "ssl_certificate_expired",
                            "issuer_org": organization,
                            "issuer_cn": common_name,
                            "is_lets_encrypt": is_lets_encrypt,
                            "is_cloudflare": is_cloudflare,
                            "is_free_ssl": is_lets_encrypt or is_cloudflare,
                            "error": f"Certificate expired on {not_after}"
                        }
                except Exception:
                    pass

            return {
                "ssl_valid": True,
                "status": "valid",
                "reason": "valid_certificate",
                "issuer_org": organization,
                "issuer_cn": common_name,
                "is_lets_encrypt": is_lets_encrypt,
                "is_cloudflare": is_cloudflare,
                "is_free_ssl": is_lets_encrypt or is_cloudflare,
                "error": None
            }
        except socket.gaierror as e:
            logger.info(f"DNS resolution failed during SSL check for {domain}: {e}")
            return {
                "ssl_valid": None,
                "status": "dns_failure",
                "reason": "dns_resolution_failed",
                "issuer_org": None,
                "issuer_cn": None,
                "is_lets_encrypt": False,
                "is_cloudflare": False,
                "is_free_ssl": False,
                "error": str(e)
            }
        except (socket.timeout, TimeoutError) as e:
            logger.info(f"SSL connection timeout for {domain}: {e}")
            return {
                "ssl_valid": None,
                "status": "timeout",
                "reason": "ssl_timeout",
                "issuer_org": None,
                "issuer_cn": None,
                "is_lets_encrypt": False,
                "is_cloudflare": False,
                "is_free_ssl": False,
                "error": str(e)
            }
        except (ConnectionRefusedError, ConnectionResetError) as e:
            logger.info(f"SSL connection refused for {domain}: {e}")
            return {
                "ssl_valid": None,
                "status": "connection_failed",
                "reason": "ssl_connection_refused",
                "issuer_org": None,
                "issuer_cn": None,
                "is_lets_encrypt": False,
                "is_cloudflare": False,
                "is_free_ssl": False,
                "error": str(e)
            }
        except ssl.SSLCertVerificationError as e:
            err_msg = str(e).lower()
            if "expired" in err_msg:
                ssl_status = "expired"
                reason = "ssl_certificate_expired"
            elif "match" in err_msg or "hostname" in err_msg:
                ssl_status = "hostname_mismatch"
                reason = "ssl_hostname_mismatch"
            elif "self-signed" in err_msg or "self signed" in err_msg:
                ssl_status = "self_signed"
                reason = "ssl_self_signed_certificate"
            else:
                ssl_status = "invalid"
                reason = "ssl_certificate_invalid"

            logger.warning(f"SSL certificate verification failed for {domain} ({ssl_status}): {e}")
            return {
                "ssl_valid": False,
                "status": ssl_status,
                "reason": reason,
                "issuer_org": None,
                "issuer_cn": None,
                "is_lets_encrypt": False,
                "is_cloudflare": False,
                "is_free_ssl": False,
                "error": str(e)
            }
        except ssl.SSLError as e:
            logger.warning(f"TLS handshake/protocol error for {domain}: {e}")
            return {
                "ssl_valid": None,
                "status": "tls_error",
                "reason": "tls_handshake_error",
                "issuer_org": None,
                "issuer_cn": None,
                "is_lets_encrypt": False,
                "is_cloudflare": False,
                "is_free_ssl": False,
                "error": str(e)
            }
        except Exception as e:
            logger.warning(f"SSL certificate inspection failed for {domain}: {e}")
            return {
                "ssl_valid": None,
                "status": "unknown",
                "reason": "ssl_inspection_failed",
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
            return await asyncio.to_thread(cls._fetch_ssl_issuer, domain)
        except Exception as e:
            return {
                "ssl_valid": None,
                "status": "unknown",
                "reason": "ssl_executor_error",
                "issuer_org": None,
                "issuer_cn": None,
                "is_lets_encrypt": False,
                "is_cloudflare": False,
                "is_free_ssl": False,
                "error": str(e)
            }

    @classmethod
    def compute_intelligence_quality(cls, whois_status: str, ssl_status: str, is_valid: bool) -> str:
        """
        Calculates transparency score for intelligence availability.
        Returns 'high', 'medium', 'partial', or 'unavailable'.
        """
        if not is_valid:
            return "unavailable"
        
        whois_ok = (whois_status == "valid")
        ssl_ok = (ssl_status == "valid")
        
        if whois_ok and ssl_ok:
            return "high"
        elif whois_ok and not ssl_ok:
            return "medium"
        elif not whois_ok and ssl_ok:
            return "partial"
        else:
            return "unavailable"

    @classmethod
    async def analyze(cls, urls: List[str]) -> Dict[str, Any]:
        """
        Performs evidence-backed WHOIS domain age lookup and SSL certificate inspection
        for all domains, without fabricating intelligence or penalizing unavailable data.
        """
        if not urls:
            return {
                "status": "bypassed",
                "max_risk_score": 0,
                "domains_analyzed": []
            }

        # Extract and deduplicate domains preserving order
        from app.services.track_a_url import TrackAURLIntel
        raw_domains = [TrackAURLIntel.extract_domain(url) for url in urls if url]
        # Remove duplicates while preserving order
        domains = list(dict.fromkeys([d for d in raw_domains if d]))
        
        results = []
        for domain in domains:
            is_valid, domain_type, validation_reason = validate_domain(domain)
            
            # Skip loopback or localhost from external queries
            if domain in ["localhost", "127.0.0.1", "::1"]:
                continue
                
            age_info = await cls.get_domain_age(domain)
            ssl_info = await cls.inspect_ssl(domain)
            
            # Compute evidence-backed score contributors
            risk_score = 0
            
            # 1. Real WHOIS Age: only score if age is confirmed known
            if age_info.get("status") == "valid" and age_info.get("age_days") is not None:
                age = age_info["age_days"]
                if age < 30:
                    risk_score += 60
                elif age < 90:
                    risk_score += 30
            
            # 2. SSL Status: only penalize confirmed invalid/expired/mismatched certificates
            # Infrastructure failures (DNS, timeout, connection reset) do NOT add maliciousness
            if ssl_info.get("status") in ["invalid", "expired", "hostname_mismatch", "self_signed"]:
                risk_score += 20
                
            # 3. Free SSL: Let's Encrypt / Cloudflare alone is +0
            # Kept strictly at +0 by itself.

            # Intelligence Quality
            whois_st = age_info.get("status", "unknown")
            ssl_st = ssl_info.get("status", "unknown")
            intel_quality = cls.compute_intelligence_quality(whois_st, ssl_st, is_valid)
            
            capped_risk = min(100, risk_score)

            logger.info(
                f"[Track B] domain={domain} domain_type={domain_type} "
                f"WHOIS status={whois_st} age_days={age_info.get('age_days')} "
                f"SSL status={ssl_st} risk={capped_risk} intelligence_quality={intel_quality}"
            )

            results.append({
                "domain": domain,
                "domain_type": domain_type,
                "validation_status": "valid" if is_valid else validation_reason,
                "whois": age_info,
                "ssl": ssl_info,
                "risk_score": capped_risk,
                "intelligence_quality": intel_quality
            })

        max_risk = max([r["risk_score"] for r in results]) if results else 0

        return {
            "status": "completed",
            "max_risk_score": max_risk,
            "domains_analyzed": results
        }

