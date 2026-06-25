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
paddle_en = PaddleOCR(lang='en', use_mkldnn=True, show_log=False)
paddle_hi = PaddleOCR(lang='hi', use_mkldnn=True, show_log=False)

# Regex to detect Devanagari Unicode characters
DEVANAGARI_RE = re.compile(r'[\u0900-\u097F]')


def calculate_iou(boxA: List[List[int]], boxB: List[List[int]]) -> float:
    """Calculate Intersection over Union between two bounding boxes."""
    xA = max(boxA[0][0], boxB[0][0])
    yA = max(boxA[0][1], boxB[0][1])
    xB = min(boxA[2][0], boxB[2][0])
    yB = min(boxA[2][1], boxB[2][1])

    interArea = max(0, xB - xA) * max(0, yB - yA)
    boxAArea = (boxA[2][0] - boxA[0][0]) * (boxA[2][1] - boxA[0][1])
    boxBArea = (boxB[2][0] - boxB[0][0]) * (boxB[2][1] - boxB[0][1])

    denom = float(boxAArea + boxBArea - interArea)
    if denom == 0:
        return 0.0
    return interArea / denom


def has_devanagari(text: str) -> bool:
    """Check if text contains any Devanagari Unicode characters."""
    return bool(DEVANAGARI_RE.search(text))


def parse_paddle_result(result, script: str) -> List[OCRBlock]:
    """Parse PaddleOCR result into a list of OCRBlock objects."""
    blocks = []
    if result and result[0]:
        for line in result[0]:
            bbox, (text, conf) = line
            blocks.append(OCRBlock(
                bbox=bbox, text=text, confidence=conf,
                script=script, source='paddle'
            ))
    return blocks


class OCRPipeline:
    @classmethod
    def run_paddle_engine(cls, img_rgb: np.ndarray) -> List[OCRBlock]:
        """
        Stage 2: Dual-model OCR with intelligent script-based merging.
        
        Strategy:
        1. Run English model on full image → captures all Latin/numeric text
        2. Run Hindi (Devanagari) model on full image → captures Devanagari script
        3. Merge by IoU overlap:
           - If both models detect the same region (IoU > 0.50):
             * Prefer Hindi block if it contains actual Devanagari Unicode
             * Prefer English block otherwise (better accuracy for Latin text)
           - Non-overlapping blocks are kept from both models
        """
        # --- Pass 1: English OCR on full image ---
        result_en = paddle_en.ocr(img_rgb)
        blocks_en = parse_paddle_result(result_en, 'en')

        # --- Pass 2: Hindi (Devanagari) OCR on full image ---
        result_hi = paddle_hi.ocr(img_rgb)
        blocks_hi = parse_paddle_result(result_hi, 'hi')

        # --- Pass 3: Script-aware merge ---
        # Mark which Hindi blocks overlap with English blocks
        en_matched = set()   # indices of English blocks that overlap with a Hindi block
        hi_matched = set()   # indices of Hindi blocks that overlap with an English block
        
        merged = []
        
        # For each Hindi block, find best overlapping English block
        for hi_idx, hi_block in enumerate(blocks_hi):
            best_en_idx = -1
            best_iou = 0.0
            
            for en_idx, en_block in enumerate(blocks_en):
                iou = calculate_iou(hi_block.bbox, en_block.bbox)
                if iou > best_iou:
                    best_iou = iou
                    best_en_idx = en_idx
            
            if best_iou > 0.50 and best_en_idx >= 0:
                # Both models detected same region — pick by script
                en_block = blocks_en[best_en_idx]
                en_matched.add(best_en_idx)
                hi_matched.add(hi_idx)
                
                if has_devanagari(hi_block.text):
                    # Hindi model produced actual Devanagari — prefer it
                    merged.append(hi_block)
                else:
                    # Hindi model produced Latin text — prefer English (more accurate)
                    merged.append(en_block)
            # else: non-overlapping Hindi block handled below
        
        # Add non-overlapping English blocks (not matched to any Hindi block)
        for en_idx, en_block in enumerate(blocks_en):
            if en_idx not in en_matched:
                merged.append(en_block)
        
        # Add non-overlapping Hindi blocks that contain Devanagari
        # (Hindi model detected text that English model missed entirely)
        for hi_idx, hi_block in enumerate(blocks_hi):
            if hi_idx not in hi_matched and has_devanagari(hi_block.text):
                merged.append(hi_block)

        # --- Stage 3: Confidence Filter ---
        filtered_blocks = [b for b in merged if b.confidence >= 0.55]

        # Sort by Y position (top to bottom), then X (left to right)
        filtered_blocks.sort(key=lambda b: (b.bbox[0][1], b.bbox[0][0]))
        return filtered_blocks

    @classmethod
    def run_tesseract_fallback(cls, img_rgb: np.ndarray) -> List[OCRBlock]:
        """Tesseract fallback when PaddleOCR quality is insufficient."""
        data = pytesseract.image_to_data(
            img_rgb, lang='eng+hin',
            config='--oem 3 --psm 6',
            output_type=pytesseract.Output.DICT
        )
        blocks = []
        for i in range(len(data['text'])):
            text = data['text'][i].strip()
            conf = int(data['conf'][i]) / 100.0
            if text and conf >= 0.55:
                x, y, w, h = data['left'][i], data['top'][i], data['width'][i], data['height'][i]
                bbox = [[x, y], [x+w, y], [x+w, y+h], [x, y+h]]
                script = 'hi' if has_devanagari(text) else 'en'
                blocks.append(OCRBlock(
                    bbox=bbox, text=text, confidence=conf,
                    script=script, source='tesseract'
                ))
        return blocks

    @classmethod
    def compute_quality(cls, blocks: List[OCRBlock], entities: Dict[str, Any]) -> float:
        """Compute OCR quality score based on confidence, entities, and text density."""
        if not blocks:
            return 0.0
        avg_confidence = sum(b.confidence for b in blocks) / len(blocks)
        entity_presence = 1.0 if any(
            len(entities.get(k, [])) > 0
            for k in ["urls", "upi_ids", "phone_numbers"]
        ) else 0.0
        total_len = sum(len(b.text) for b in blocks)
        density = min(1.0, total_len / 50.0)
        return (0.4 * avg_confidence) + (0.3 * entity_presence) + (0.3 * density)

    @classmethod
    def process_pipeline(cls, img_rgb: np.ndarray, blocks: List[OCRBlock], image_height: int) -> Tuple[str, Dict[str, Any], float]:
        """Run stages 4-7: filter artifacts, rank, reconstruct, extract entities."""
        # Stage 4: Artifact filtering
        filtered = filter_artifacts(blocks, image_height)
        # Stage 5: Message ranking
        normalized_blocks, threat_score = rank_message(filtered)
        # Stage 6: Text reconstruction
        clean_text = reconstruct_text(normalized_blocks)
        # Stage 7: Entity extraction
        entities = extract_entities(clean_text)

        quality = cls.compute_quality(normalized_blocks, entities)
        return clean_text, entities, quality

    @classmethod
    def process_image(cls, image_bytes: bytes) -> Dict[str, Any]:
        """
        Full 9-stage OCR pipeline.
        Stage 1: Preprocess → Stage 2: Dual PaddleOCR → Stage 3: Filter low-conf
        Stage 4: Artifact filter → Stage 5: Rank → Stage 6: Reconstruct
        Stage 7: Entity extraction → Stage 8: Tesseract fallback → Stage 9: Output
        """
        start_time = time.perf_counter()

        # Stage 1: Image preprocessing (dark mode inversion, CLAHE, sharpen)
        prep_res = preprocess_image(image_bytes)
        img_rgb = prep_res["image"]
        image_height = img_rgb.shape[0]

        # Stage 2: Dual-model PaddleOCR
        blocks = cls.run_paddle_engine(img_rgb)

        # Run stages 4-7
        clean_text, entities, quality = cls.process_pipeline(img_rgb, blocks, image_height)

        fallback_used = False
        final_blocks = blocks

        # Stage 8: Tesseract fallback if quality is poor
        if quality < 0.55:
            fallback_blocks = cls.run_tesseract_fallback(img_rgb)
            fallback_clean, fallback_entities, fallback_quality = cls.process_pipeline(
                img_rgb, fallback_blocks, image_height
            )
            if fallback_quality > quality:
                fallback_used = True
                clean_text = fallback_clean
                entities = fallback_entities
                quality = fallback_quality
                final_blocks = fallback_blocks

        # Raw text for logging
        raw_text = "\n".join(b.text for b in final_blocks)

        exec_time_ms = (time.perf_counter() - start_time) * 1000.0

        devnagari_detected = has_devanagari(raw_text)

        avg_conf = (
            sum(b.confidence for b in final_blocks) / len(final_blocks)
            if final_blocks else 0.0
        )

        return {
            "scan_id": str(uuid.uuid4()),
            "raw_text": raw_text,
            "clean_text": entities.get("redacted_text", clean_text),
            "entities": {k: v for k, v in entities.items() if k != "redacted_text"},
            "ocr_quality_score": quality,
            "avg_confidence": avg_conf,
            "dark_mode_detected": prep_res["dark_mode_detected"],
            "devanagari_detected": devnagari_detected,
            "fallback_used": fallback_used,
            "execution_time_ms": exec_time_ms,
            "confidence_statistics": {
                "blocks_count": len(final_blocks),
                "min_conf": min(b.confidence for b in final_blocks) if final_blocks else 0.0,
                "max_conf": max(b.confidence for b in final_blocks) if final_blocks else 0.0,
            },
        }
