from dataclasses import dataclass
from typing import List

@dataclass
class OCRBlock:
    bbox: List[List[int]]
    text: str
    confidence: float
    script: str
    source: str
