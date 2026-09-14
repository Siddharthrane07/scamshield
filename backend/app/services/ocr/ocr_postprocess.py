import re
from typing import Dict, List, Tuple, Any
from urllib.parse import urlparse

VALID_TLDS = r'(?:com|org|net|in|gov|edu|xyz|co|io|ly|me|top|site|live|info|biz|online|app|page|ke|ng|ai|ph|cc|club|shop|store|vip|pro|icu)'
URL_PATTERN = re.compile(
    rf'https?://[^\s,;!?"\'\)\]}}]+|www\.[^\s,;!?"\'\)\]}}]+|[a-zA-Z0-9\-]+\.{VALID_TLDS}(?:/[^\s,;!?"\'\)\]}}]*)?',
    re.IGNORECASE
)

def sanitize_url_token(url: str) -> str:
    """Fix common OCR typos specific to URLs."""
    url = url.replace("https:II", "https://")
    url = url.replace("http:II", "http://")
    url = url.replace("https:l/", "https://")
    url = url.replace("http:l/", "http://")
    url = url.replace("https:1/", "https://")
    url = url.replace("http:1/", "http://")
    url = url.replace("https:// ", "https://")
    url = url.replace("http:// ", "http://")
    url = url.replace("bit.Iy", "bit.ly")
    url = url.replace("bit.IY", "bit.ly")
    url = url.replace("bit.lyI", "bit.ly/")
    return url

def _stitch_wrapped_urls(text: str) -> str:
    """
    Robustly stitch URLs split across newlines or spaces.
    Handles:
    - Protocol followed by newline: 'https://\\nfoo.com' -> 'https://foo.com'
    - Line ending with hyphen in domain/path: 'https://foo-\\nbar.com' -> 'https://foo-bar.com'
    - Line ending with slash: 'example.com/\\npath' -> 'example.com/path'
    - Path continuation across lines: 'example.com/path/aa\\ndharnow' -> 'example.com/path/aadharnow'
    - Space inside URL caused by OCR: 'https:// govt-schemes-drop- india- official.net/...'
    """
    # Step 1: Protocol followed by newline or space
    text = re.sub(r'(https?://|www\.)[ \t]*\n[ \t]*', r'\1', text)
    text = re.sub(r'(https?://)[ \t]+', r'\1', text)
    text = re.sub(r'(www\.)[ \t]+', r'\1', text)

    # Step 2: Line ending with hyphen or path fragment after URL start
    for _ in range(5):
        # 2a. Line starts or contains URL prefix and ends with hyphen -> merge next line directly
        new_text = re.sub(
            r'((?:https?://|www\.)[^\n]*?[\w\-/]+-)[ \t]*\n[ \t]*([a-zA-Z0-9])',
            r'\1\2',
            text,
            flags=re.IGNORECASE
        )
        # 2b. Continuation line from previous hyphen-split that ends in hyphen -> merge next line
        new_text = re.sub(
            r'([a-zA-Z0-9\-_./]+-)[ \t]*\n[ \t]*([a-zA-Z0-9])',
            r'\1\2',
            new_text,
            flags=re.IGNORECASE
        )
        # 2c. Line containing URL with path ending in slash or word fragment before newline,
        # where next line starts with lowercase/digit path continuation (e.g. .net/renewal/pandigital/aa\ndharnow)
        new_text = re.sub(
            r'((?:https?://|www\.)[^\n\s]*?/[^\n\s]*?[a-zA-Z0-9])[ \t]*\n[ \t]*([a-zA-Z0-9_\-./]+\.[a-zA-Z0-9]+|[a-zA-Z0-9_\-/]+(?:\s|$))',
            r'\1\2',
            new_text,
            flags=re.IGNORECASE
        )
        if new_text == text:
            break
        text = new_text

    # Step 3: Space around hyphens in domain/URL on same line (e.g. 'govt- schemes- drop- india- official.net')
    for _ in range(5):
        new_text = re.sub(
            r'((?:https?://|www\.)[^\s]*?[\w\-]+-)[ \t]+([\w\-]+)',
            r'\1\2',
            text,
            flags=re.IGNORECASE
        )
        new_text = re.sub(
            r'([\w\-]+-)[ \t]+([\w\-]+(?:\.[\w\-]+|/))',
            r'\1\2',
            new_text,
            flags=re.IGNORECASE
        )
        if new_text == text:
            break
        text = new_text

    # Step 4: Space around slashes in URL paths
    text = re.sub(r'(/[a-zA-Z0-9\-_]+)[ \t]+(/[a-zA-Z0-9\-_]+)', r'\1\2', text)
    text = re.sub(r'([a-zA-Z0-9\-]+\.[a-zA-Z]{2,}/)[ \t]+([a-zA-Z0-9\-_]+)', r'\1\2', text)
    text = re.sub(r'/[ \t]+([a-zA-Z0-9\-_]+)', r'/\1', text)

    return text

def fix_split_urls(text: str) -> str:
    """
    Heals split URL tokens caused by OCR space/hyphen fragmentation
    without touching regular English/Hindi sentences or crossing newlines.
    """
    # 0. Stitch URLs that were line-wrapped across newlines in the source image
    text = _stitch_wrapped_urls(text)

    # 1. Fix missing space after colon: Click:bit.ly -> Click: bit.ly
    text = re.sub(r':(?=[a-zA-Z0-9\-]+\.[a-zA-Z]{2,})', ': ', text)

    # 2. Fix space after protocol: https:// google.com -> https://google.com
    text = re.sub(r'(https?://)[ \t]+', r'\1', text)
    text = re.sub(r'(www\.)[ \t]+', r'\1', text)
    
    # 3. Fix space around slashes in URLs (on same line only): bit.ly/ Safaricomapp -> bit.ly/Safaricomapp
    text = re.sub(r'([a-zA-Z0-9\-]+\.[a-zA-Z]{2,}/)[ \t]+([a-zA-Z0-9\-_]+)', r'\1\2', text)
    text = re.sub(r'/[ \t]+([a-zA-Z0-9\-_]+)', r'/\1', text)
    
    # 4. Fix space around hyphens in domain names (allowing multi-hyphen prefixes):
    # e.g., kbc-lottery-winner- claim.net -> kbc-lottery-winner-claim.net
    for _ in range(3):
        text = re.sub(r'([a-zA-Z0-9\-]+-)[ \t]+([a-zA-Z0-9\-]+(?:\.[a-zA-Z]{2,}))', r'\1\2', text)
        text = re.sub(r'([a-zA-Z0-9\-]+-)[ \t]+([a-zA-Z0-9\-]+(?:/[a-zA-Z0-9\-_]+))', r'\1\2', text)
        text = re.sub(r'([a-zA-Z0-9\-]+-)[ \t]+([a-zA-Z0-9\-]+-)', r'\1\2', text)
    
    return text

def extract_urls(clean_text: str) -> List[str]:
    """
    Extracts structured URLs from OCR text using targeted token healing.
    """
    processed_text = fix_split_urls(clean_text)
    raw_urls = URL_PATTERN.findall(processed_text)
    
    cleaned_urls = []
    for u in raw_urls:
        u = sanitize_url_token(u)
        # Strip common trailing punctuation
        u = re.sub(r'[.,;!?)\]}>]+$', '', u)
        if u:
            cleaned_urls.append(u)
            
    # Deduplicate: prefer longer, more complete URLs
    cleaned_urls.sort(key=len, reverse=True)
    final_urls = []
    for u in cleaned_urls:
        if not any(u == existing or (u in existing and len(existing) > len(u)) for existing in final_urls):
            final_urls.append(u)
            
    return final_urls

def extract_entities(clean_text: str) -> Dict[str, Any]:
    """
    Extracts structured entities from text: URLs, domains, UPI IDs,
    phone numbers, OTP candidates, amounts, and bank names.
    Also handles Aadhaar redaction.
    """
    # 0. Heal URLs in text
    clean_text = fix_split_urls(clean_text)

    # Aadhaar Redaction
    aadhaar_pattern = re.compile(r'\b\d{4}\s\d{4}\s\d{4}\b')
    if aadhaar_pattern.search(clean_text):
        clean_text = aadhaar_pattern.sub("[Aadhaar Redacted]", clean_text)

    # URLs (Targeted token extraction)
    urls = extract_urls(clean_text)
    
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
    all_numbers = otp_pattern.findall(clean_text)
    otp_candidates = [n for n in all_numbers if not any(n in p for p in phone_numbers)]
    otp_candidates = list(set(otp_candidates))

    # Amounts (INR/Rs/₹ followed by numbers)
    amount_pattern = re.compile(r'(?:INR|Rs\.?|₹|rs\.?)\s*(\d+(?:,\d+)*(?:\.\d{1,2})?)', re.IGNORECASE)
    amounts = list(set(amount_pattern.findall(clean_text)))

    # Bank Names
    bank_list = ["HDFC", "SBI", "ICICI", "AXIS", "KOTAK", "PAYTM", "RBI", "PNB", "BOB", "HSBC", "JIO", "AIRTEL"]
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

