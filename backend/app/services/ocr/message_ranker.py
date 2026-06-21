import re
from typing import List, Tuple
from .models import OCRBlock
from .ocr_postprocess import extract_entities

HINGLISH_MAP = {
    "mujs": "mujhse", "kr": "kar", "kro": "karo", "kr do": "kar do", "pls": "please", 
    "plz": "please", "bt": "baat", "msg": "message", "bcz": "because", "abt": "about", 
    "wid": "with", "ur": "your", "r u": "are you", "u r": "you are", "frm": "from", 
    "thn": "then", "nw": "now", "tmrw": "tomorrow", "nd": "and", "dn": "done", 
    "bhejo": "send", "abhi kro": "abhi karo", "help kro": "help karo", "call me": "call me", 
    "turant": "immediately", "jaldi": "quickly", "abhi": "now"
}

URGENCY_WORDS = {"urgent", "immediately", "quickly", "now", "turant", "jaldi", "alert", "warning", "suspend", "block"}
AUTHORITY_WORDS = {"police", "bank", "manager", "rbi", "government", "sbi", "hdfc", "icici", "axis"}

def normalize_text(text: str) -> str:
    words = text.split()
    normalized_words = [HINGLISH_MAP.get(word.lower(), word) for word in words]
    return " ".join(normalized_words)

def rank_message(blocks: List[OCRBlock]) -> Tuple[List[OCRBlock], int]:
    threat_density_score = 0
    full_text = []
    
    # 1. Normalize
    for block in blocks:
        block.text = normalize_text(block.text)
        full_text.append(block.text)
        
    combined_text = " ".join(full_text)
    combined_lower = combined_text.lower()
    
    # 2. Score text-based markers
    for word in URGENCY_WORDS:
        if word in combined_lower:
            threat_density_score += 2
            
    for word in AUTHORITY_WORDS:
        if word in combined_lower:
            threat_density_score += 2
            
    # Use extract_entities from Stage 7 to count entity occurrences
    entities = extract_entities(combined_text)
    
    threat_density_score += len(entities.get("urls", [])) * 3
    threat_density_score += len(entities.get("upi_ids", [])) * 3
    threat_density_score += len(entities.get("phone_numbers", [])) * 2
    threat_density_score += len(entities.get("amounts", [])) * 2
    
    return blocks, threat_density_score
