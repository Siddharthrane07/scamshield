from typing import List
from .models import OCRBlock

def reconstruct_text(blocks: List[OCRBlock]) -> str:
    """
    Reconstruct lines in reading order from OCR blocks.
    Groups blocks into lines based on Y coordinate alignment (<15px),
    sorts line blocks by X coordinate, and joins with single spaces.
    """
    if not blocks:
        return ""

    # Sort by top-left Y (bbox[0][1]), then top-left X (bbox[0][0])
    sorted_blocks = sorted(blocks, key=lambda b: (b.bbox[0][1], b.bbox[0][0]))
    
    lines = []
    current_line = [sorted_blocks[0]]
    
    for block in sorted_blocks[1:]:
        # If difference in top-left Y is < 15px, consider it same line
        if abs(block.bbox[0][1] - current_line[-1].bbox[0][1]) < 15:
            current_line.append(block)
        else:
            # Sort current line by X
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

