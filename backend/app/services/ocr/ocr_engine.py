import time
import re
import cv2
import uuid
import numpy as np
import pytesseract
from dataclasses import dataclass
from typing import List, Dict, Any, Tuple
from paddleocr import PaddleOCR

from .image_preprocess import preprocess_image
from .artifact_filter import filter_artifacts
from .message_ranker import rank_message
from .text_reconstructor import reconstruct_text
from .ocr_postprocess import extract_entities
from .models import OCRBlock

# Module-level singletons
paddle_en = PaddleOCR(lang='en')
paddle_hi = PaddleOCR(lang='hi')

def calculate_iou(boxA: List[List[int]], boxB: List[List[int]]) -> float:
    # box is [[x1, y1], [x2, y1], [x2, y2], [x1, y2]] approx
    xA = max(boxA[0][0], boxB[0][0])
    yA = max(boxA[0][1], boxB[0][1])
    xB = min(boxA[2][0], boxB[2][0])
    yB = min(boxA[2][1], boxB[2][1])
    
    interArea = max(0, xB - xA) * max(0, yB - yA)
    boxAArea = (boxA[2][0] - boxA[0][0]) * (boxA[2][1] - boxA[0][1])
    boxBArea = (boxB[2][0] - boxB[0][0]) * (boxB[2][1] - boxB[0][1])
    
    if float(boxAArea + boxBArea - interArea) == 0:
        return 0.0
    iou = interArea / float(boxAArea + boxBArea - interArea)
    return iou

class OCRPipeline:
    @classmethod
    def run_paddle_engine(cls, img_rgb: np.ndarray) -> List[OCRBlock]:
        result_en = paddle_en.ocr(img_rgb)
        blocks_en = []
        if result_en and result_en[0]:
            for line in result_en[0]:
                bbox, (text, conf) = line
                blocks_en.append(OCRBlock(bbox=bbox, text=text, confidence=conf, script='en', source='paddle'))
                
        # Devnagari scan
        devnagari_pattern = re.compile(r'[\u0900-\u097F]')
        blocks_hi = []
        
        for block in blocks_en:
            if devnagari_pattern.search(block.text):
                # Crop padded region
                tl_x = max(0, int(block.bbox[0][0]) - 10)
                tl_y = max(0, int(block.bbox[0][1]) - 10)
                br_x = min(img_rgb.shape[1], int(block.bbox[2][0]) + 10)
                br_y = min(img_rgb.shape[0], int(block.bbox[2][1]) + 10)
                
                crop = img_rgb[tl_y:br_y, tl_x:br_x]
                if crop.size == 0:
                    continue
                    
                result_hi = paddle_hi.ocr(crop)
                if result_hi and result_hi[0]:
                    for line in result_hi[0]:
                        bbox, (text, conf) = line
                        # Map coordinates back
                        mapped_bbox = [
                            [bbox[0][0] + tl_x, bbox[0][1] + tl_y],
                            [bbox[1][0] + tl_x, bbox[1][1] + tl_y],
                            [bbox[2][0] + tl_x, bbox[2][1] + tl_y],
                            [bbox[3][0] + tl_x, bbox[3][1] + tl_y]
                        ]
                        blocks_hi.append(OCRBlock(bbox=mapped_bbox, text=text, confidence=conf, script='hi', source='paddle'))
                        
        # Merge passes
        final_blocks = []
        # We start with hi blocks, because they are tailored for those regions
        all_blocks = blocks_hi + blocks_en
        
        # O(N^2) merge with IoU
        merged = []
        skip_indices = set()
        for i in range(len(all_blocks)):
            if i in skip_indices:
                continue
            best_block = all_blocks[i]
            for j in range(i + 1, len(all_blocks)):
                if j in skip_indices:
                    continue
                if calculate_iou(best_block.bbox, all_blocks[j].bbox) > 0.50:
                    if all_blocks[j].confidence > best_block.confidence:
                        best_block = all_blocks[j]
                    skip_indices.add(j)
            merged.append(best_block)
            
        # Stage 3: Confidence Filter
        filtered_blocks = [b for b in merged if b.confidence >= 0.60]
        
        # Sort top-left Y then X
        filtered_blocks.sort(key=lambda b: (b.bbox[0][1], b.bbox[0][0]))
        return filtered_blocks

    @classmethod
    def run_tesseract_fallback(cls, img_rgb: np.ndarray) -> List[OCRBlock]:
        # Tesseract wrapper that mimics OCRBlock output
        # Using pytesseract.image_to_data
        data = pytesseract.image_to_data(img_rgb, lang='eng+hin', config='--oem 3 --psm 6', output_type=pytesseract.Output.DICT)
        blocks = []
        for i in range(len(data['text'])):
            text = data['text'][i].strip()
            conf = int(data['conf'][i]) / 100.0
            if text and conf >= 0.60:
                x, y, w, h = data['left'][i], data['top'][i], data['width'][i], data['height'][i]
                bbox = [[x, y], [x+w, y], [x+w, y+h], [x, y+h]]
                blocks.append(OCRBlock(bbox=bbox, text=text, confidence=conf, script='mixed', source='tesseract'))
        return blocks

    @classmethod
    def compute_quality(cls, blocks: List[OCRBlock], entities: Dict[str, Any]) -> float:
        if not blocks:
            return 0.0
        avg_confidence = sum(b.confidence for b in blocks) / len(blocks)
        entity_presence_bool = 1.0 if any(len(entities.get(k, [])) > 0 for k in ["urls", "upi_ids", "phone_numbers"]) else 0.0
        # message_density_ratio: let's say total text length / 100 maxed at 1.0
        total_len = sum(len(b.text) for b in blocks)
        message_density_ratio = min(1.0, total_len / 50.0)
        return (0.4 * avg_confidence) + (0.3 * entity_presence_bool) + (0.3 * message_density_ratio)

    @classmethod
    def process_pipeline(cls, img_rgb: np.ndarray, blocks: List[OCRBlock], image_height: int) -> Tuple[str, Dict[str, Any], float]:
        # Stage 4
        filtered = filter_artifacts(blocks, image_height)
        # Stage 5
        normalized_blocks, threat_score = rank_message(filtered)
        # Stage 6
        clean_text = reconstruct_text(normalized_blocks)
        # Stage 7
        entities = extract_entities(clean_text)
        
        quality = cls.compute_quality(normalized_blocks, entities)
        return clean_text, entities, quality

    @classmethod
    def process_image(cls, image_bytes: bytes) -> Dict[str, Any]:
        start_time = time.perf_counter()
        
        # Stage 1
        prep_res = preprocess_image(image_bytes)
        img_rgb = prep_res["image"]
        image_height = img_rgb.shape[0]
        
        # Stage 2
        blocks = cls.run_paddle_engine(img_rgb)
        
        # Run stages 4-7
        clean_text, entities, quality = cls.process_pipeline(img_rgb, blocks, image_height)
        
        fallback_used = False
        final_blocks = blocks
        
        # Stage 8
        if quality < 0.60:
            fallback_blocks = cls.run_tesseract_fallback(img_rgb)
            fallback_clean, fallback_entities, fallback_quality = cls.process_pipeline(img_rgb, fallback_blocks, image_height)
            if fallback_quality > quality:
                fallback_used = True
                clean_text = fallback_clean
                entities = fallback_entities
                quality = fallback_quality
                final_blocks = fallback_blocks
                
        # Raw text for logging (just dump all blocks before filtering)
        raw_text = "\n".join(b.text for b in (fallback_blocks if fallback_used else blocks))
        
        exec_time_ms = (time.perf_counter() - start_time) * 1000.0
        
        devnagari_detected = bool(re.search(r'[\u0900-\u097F]', raw_text))
        
        avg_conf = sum(b.confidence for b in final_blocks) / len(final_blocks) if final_blocks else 0.0
        
        return {
            "scan_id": str(uuid.uuid4()),
            "raw_text": raw_text,
            "clean_text": entities.get("redacted_text", clean_text),
            "entities": {k:v for k,v in entities.items() if k != "redacted_text"},
            "ocr_quality_score": quality,
            "avg_confidence": avg_conf,
            "dark_mode_detected": prep_res["dark_mode_detected"],
            "devanagari_detected": devnagari_detected,
            "fallback_used": fallback_used,
            "execution_time_ms": exec_time_ms,
            "confidence_statistics": {
                "blocks_count": len(final_blocks),
                "min_conf": min([b.confidence for b in final_blocks]) if final_blocks else 0.0,
                "max_conf": max([b.confidence for b in final_blocks]) if final_blocks else 0.0
            }
        }
