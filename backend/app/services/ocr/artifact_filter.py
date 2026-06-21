import re
from typing import List

# We will import OCRBlock inline or assume it is passed in as a known protocol to avoid circular imports.
# For simplicity, we import it from ocr_engine, which we will create next.
from .models import OCRBlock

UI_EXACT_MATCHES = {
    "delete", "mark as known", "mark as read", "forward", "copy", "block", "report spam", 
    "sms", "text message", "business account", "voice call", "silenced voice call", 
    "unknown caller", "joined last month", "हटाएं", "ब्लॉक", "रिपोर्ट", "स्पैम"
}

REGEX_FILTERS = [
    re.compile(r'^\d{1,2}:\d{2}$'),  # Time
    re.compile(r'^\d{1,3}%$'),      # Battery
    re.compile(r'^(LTE|4G|5G|VoLTE|SIM\s?\d?)$', re.IGNORECASE) # Network
]

def filter_artifacts(blocks: List[OCRBlock], image_height: int) -> List[OCRBlock]:
    filtered_blocks = []
    top_margin = image_height * 0.10
    bottom_margin = image_height * 0.90
    
    for block in blocks:
        # bbox is List[List[int]]: [[tl_x, tl_y], [tr_x, tr_y], [br_x, br_y], [bl_x, bl_y]]
        tl_y = block.bbox[0][1]
        br_y = block.bbox[2][1]
        
        # 1. Height filtering
        if tl_y < top_margin or br_y > bottom_margin:
            continue
            
        text = block.text.strip()
        
        # 2. Regex filtering
        if any(r.match(text) for r in REGEX_FILTERS):
            continue
            
        # 3. String matches
        text_lower = text.lower()
        if text_lower in UI_EXACT_MATCHES:
            continue
            
        filtered_blocks.append(block)
        
    return filtered_blocks
