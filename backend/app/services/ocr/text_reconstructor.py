import re
import statistics
from typing import List
from .models import OCRBlock

_URL_START = re.compile(r'(?:https?://|www\.|bit\.ly/|tinyurl\.com/|\.com/|\.org/|\.in/|\.net/|\.co/)\S*$', re.IGNORECASE)
_URL_FRAGMENT = re.compile(r'^[A-Za-z0-9\-._~/?#@!$&\'()*+,;=%]+$')
_STOP_WORDS = {'to', 'for', 'in', 'and', 'the', 'is', 'on', 'at', 'or', 'a', 'of', 'from'}

def merge_url_fragments_spatially(blocks: List[OCRBlock]) -> List[OCRBlock]:
    if not blocks:
        return []

    # Sort blocks top-to-bottom, left-to-right
    sorted_blocks = sorted(blocks, key=lambda b: (b.bbox[0][1], b.bbox[0][0]))
    
    # Estimate average line height from median block heights
    heights = [b.bbox[2][1] - b.bbox[0][1] for b in sorted_blocks]
    avg_line_height = statistics.median(heights) if heights else 15
    y_threshold = 2 * avg_line_height
    
    merged_blocks = []
    skip_next = False
    
    for i in range(len(sorted_blocks)):
        if skip_next:
            skip_next = False
            continue
            
        block = sorted_blocks[i]
        
        if i + 1 < len(sorted_blocks) and _URL_START.search(block.text):
            next_block = sorted_blocks[i + 1]
            
            y_gap = next_block.bbox[0][1] - block.bbox[2][1]
            x_diff = next_block.bbox[0][0] - block.bbox[0][0]
            
            # Vertically below within 2x line-height gap
            # Horizontally aligned or slightly indented
            if -avg_line_height <= y_gap <= y_threshold and x_diff >= -20:
                if _URL_FRAGMENT.match(next_block.text) and next_block.text.lower() not in _STOP_WORDS:
                    # Combine their text without a space
                    block.text = block.text + next_block.text
                    block.confidence = (block.confidence + next_block.confidence) / 2
                    
                    # Merge their bounding box coordinates
                    x_min = min(block.bbox[0][0], next_block.bbox[0][0], block.bbox[3][0], next_block.bbox[3][0])
                    y_min = min(block.bbox[0][1], next_block.bbox[0][1], block.bbox[1][1], next_block.bbox[1][1])
                    x_max = max(block.bbox[1][0], next_block.bbox[1][0], block.bbox[2][0], next_block.bbox[2][0])
                    y_max = max(block.bbox[2][1], next_block.bbox[2][1], block.bbox[3][1], next_block.bbox[3][1])
                    
                    block.bbox = [
                        [x_min, y_min],
                        [x_max, y_min],
                        [x_max, y_max],
                        [x_min, y_max]
                    ]
                    
                    merged_blocks.append(block)
                    skip_next = True
                    continue
                    
        merged_blocks.append(block)
        
    return merged_blocks

def reconstruct_text(blocks: List[OCRBlock]) -> str:
    if not blocks:
        return ""
        
    blocks = merge_url_fragments_spatially(blocks)
        
    # Sort by top-left Y (bbox[0][1]), then top-left X (bbox[0][0])
    sorted_blocks = sorted(blocks, key=lambda b: (b.bbox[0][1], b.bbox[0][0]))
    
    lines = []
    current_line = [sorted_blocks[0]]
    
    for block in sorted_blocks[1:]:
        # If difference in top-left Y is < 15px, consider it same line
        if abs(block.bbox[0][1] - current_line[-1].bbox[0][1]) < 15:
            current_line.append(block)
        else:
            # Sort current line by X just to be perfectly sure
            current_line.sort(key=lambda b: b.bbox[0][0])
            line_text = " ".join(b.text.strip() for b in current_line)
            lines.append(line_text)
            current_line = [block]
            
    # Add last line
    if current_line:
        current_line.sort(key=lambda b: b.bbox[0][0])
        line_text = " ".join(b.text.strip() for b in current_line)
        lines.append(line_text)
        
    final_text = "\n".join(lines).strip()
    return final_text
