import re
from typing import Dict, List, Tuple
from urllib.parse import urlparse

URL_PATTERN = re.compile(
    r'https?://[^\s]+|www\.[^\s]+|[a-zA-Z0-9\-]+\.[a-zA-Z]{2,}(?:/[^\s]*)?',
    re.IGNORECASE
)

def extract_urls_from_ocr_text(reconstructed_text: str) -> list[str]:
    """
    Reconstructs split URLs without touching any OCR model or bounding box logic.
    Strips whitespace because valid URLs never contain spaces.
    """
    # 1. Remove all whitespace characters (spaces, newlines, tabs)
    collapsed = re.sub(r'\s+', '', reconstructed_text)
    
    # 2. Extract URLs from the collapsed text
    urls_from_collapsed = URL_PATTERN.findall(collapsed)
    
    # 3. Also run on original text
    urls_from_original = URL_PATTERN.findall(reconstructed_text)
    
    # 4. Combine and deduplicate
    all_urls = list(dict.fromkeys(urls_from_collapsed + urls_from_original))
    
    return all_urls

def sanitize_url_token(url: str) -> str:
    """Fix common OCR typos specific to URLs."""
    url = url.replace("https:II", "https://")
    url = url.replace("http:II", "http://")
    url = url.replace("bit.Iy", "bit.ly")
    url = url.replace("bit.IY", "bit.ly")
    return url

def extract_entities(clean_text: str) -> Dict[str, List[str]]:
    # Aadhaar Redaction
    aadhaar_pattern = re.compile(r'\b\d{4}\s\d{4}\s\d{4}\b')
    if aadhaar_pattern.search(clean_text):
        clean_text = aadhaar_pattern.sub("[Aadhaar Redacted]", clean_text)

    # URLs (Non-invasive extraction)
    urls = extract_urls_from_ocr_text(clean_text)
    urls = [sanitize_url_token(url) for url in urls]
    
    # Domains from URLs
    domains = []
    for url in urls:
        if not url.startswith("http"):
            url = "http://" + url
        parsed = urlparse(url)
        if parsed.netloc:
            domains.append(parsed.netloc)
    domains = list(set(domains))

    # UPI IDs
    upi_pattern = re.compile(r'\b[a-zA-Z0-9.\-_]+@[a-zA-Z]{2,}\b')
    upi_ids = list(set(upi_pattern.findall(clean_text)))

    # Phone Numbers (Indian format)
    phone_pattern = re.compile(r'\b(?:\+91|91|0)?[6-9]\d{9}\b')
    phone_numbers = list(set(phone_pattern.findall(clean_text)))

    # OTP Candidates (4-6 digits)
    otp_pattern = re.compile(r'\b\d{4,6}\b')
    # Filter out phones or other known numbers
    all_numbers = otp_pattern.findall(clean_text)
    otp_candidates = [n for n in all_numbers if not any(n in p for p in phone_numbers)]
    otp_candidates = list(set(otp_candidates))

    # Amounts (INR/Rs/₹ followed by numbers)
    amount_pattern = re.compile(r'(?:INR|Rs\.?|₹|rs\.?)\s*(\d+(?:,\d+)*(?:\.\d{1,2})?)', re.IGNORECASE)
    amounts = list(set(amount_pattern.findall(clean_text)))

    # Bank Names
    bank_list = ["HDFC", "SBI", "ICICI", "AXIS", "KOTAK", "PAYTM", "RBI"]
    bank_names = []
    text_upper = clean_text.upper()
    for bank in bank_list:
        if re.search(r'\b' + bank + r'\b', text_upper):
            bank_names.append(bank)

    return {
        "urls": urls,
        "domains": domains,
        "upi_ids": upi_ids,
        "phone_numbers": phone_numbers,
        "otp_candidates": otp_candidates,
        "amounts": amounts,
        "bank_names": bank_names,
        "redacted_text": clean_text
    }
