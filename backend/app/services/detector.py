import re
import logging
from typing import Dict, Any, List
from app.core.exceptions import MarathiLanguageException
from app.services.ocr.ocr_postprocess import fix_split_urls, extract_entities, extract_urls

logger = logging.getLogger("scamshield.detector")

# Words unique to Marathi language (not used in Hindi)
MARATHI_ONLY_WORDS = {
    "आहे", "नाही", "आहेत", "करून", "केले", "साठी", "यांनी", 
    "त्यांनी", "केला", "केली", "झाला", "झाली", "भेटला", "बघून"
}

class DetectorService:
    @staticmethod
    def check_marathi_exclusion(text: str) -> None:
        """
        Scans text for Marathi language characteristics:
        1. Checks for the letter 'ळ' (Unicode codepoint U+0933), which is unique to Marathi in Devnagari.
        2. Checks for highly frequent Marathi-only words that do not exist in Hindi.
        Raises MarathiLanguageException if detected.
        """
        # 1. Unicode Check for Devnagari letter LLA (ळ)
        if "\u0933" in text:
            logger.warning("Marathi character 'ळ' detected in input. Rejects request.")
            raise MarathiLanguageException("Marathi language processing is strictly EXCLUDED from normalization, analysis, and reporting.")

        # 2. Token-based word match
        # Clean text punctuation for accurate token split
        clean_devnagari = re.sub(r'[^\w\s\u0900-\u097F]', ' ', text)
        words = set(clean_devnagari.split())
        
        detected_marathi_words = words.intersection(MARATHI_ONLY_WORDS)
        if detected_marathi_words:
            logger.warning(f"Marathi words detected: {detected_marathi_words}. Rejects request.")
            raise MarathiLanguageException("Marathi language processing is strictly EXCLUDED from normalization, analysis, and reporting.")

    @classmethod
    def clean_text(cls, text: str) -> str:
        """
        Cleans and normalizes text: checks Marathi exclusion,
        stitches broken/wrapped URLs, strips trailing/leading whitespaces,
        and normalizes multiple spaces to single space.
        """
        # Intercept and block Marathi immediately
        cls.check_marathi_exclusion(text)
        
        # Stitch any URLs split across newlines or spaces before flattening whitespace
        text = fix_split_urls(text)
        
        # Strip trailing/leading spaces
        text = text.strip()
        # Replace multiple spaces/newlines with a single space
        text = re.sub(r'\s+', ' ', text)
        
        return text

    @classmethod
    def extract_entities(cls, text: str) -> Dict[str, List[str]]:
        """
        Extracts structured arrays: URLs, Phone numbers, and UPI IDs.
        """
        ent = extract_entities(text)
        return {
            "urls": ent.get("urls", []),
            "phones": ent.get("phone_numbers", []),
            "upis": ent.get("upi_ids", [])
        }

    @classmethod
    def process(cls, text: str) -> Dict[str, Any]:
        """
        Runs the full detoxification, URL healing, normalization, and entity extraction pipeline.
        Returns a clean JSON metadata packet.
        """
        cls.check_marathi_exclusion(text)
        
        # 1. Heal URLs while line breaks and hyphens are intact
        stitched_text = fix_split_urls(text)
        
        # 2. Extract full structured entities
        entities = extract_entities(stitched_text)
        
        # 3. Normalize whitespace for ML text input
        normalized_text = re.sub(r'\s+', ' ', stitched_text).strip()
        
        return {
            "normalized_text": normalized_text,
            "urls": entities.get("urls", []),
            "domains": entities.get("domains", []),
            "phones": entities.get("phone_numbers", []),
            "upis": entities.get("upi_ids", []),
            "entities": entities
        }

