import re
import logging
from typing import Dict, Any, List
from app.core.exceptions import MarathiLanguageException

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
        Cleans and normalizes text: strips trailing/leading whitespaces,
        normalizes multiple spaces to single space, and checks Marathi exclusion.
        """
        # Intercept and block Marathi immediately
        cls.check_marathi_exclusion(text)
        
        # Strip trailing/leading spaces
        text = text.strip()
        # Replace multiple spaces/newlines with a single space
        text = re.sub(r'\s+', ' ', text)
        
        return text

    @classmethod
    def extract_entities(cls, text: str) -> Dict[str, List[str]]:
        """
        Extracts structured arrays: URLs, Phone numbers, and UPI IDs using regex.
        """
        # Regex Patterns
        # URLs beginning with http/https
        url_pattern = re.compile(
            r'https?://(?:www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b(?:[-a-zA-Z0-9()@:%_\+.~#?&//=]*)',
            re.IGNORECASE
        )
        
        # Indian phone numbers: +91, 91, 0 prefix, followed by 10 digits starting with 6-9
        phone_pattern = re.compile(r'\b(?:\+91|91|0)?[6-9]\d{9}\b')
        
        # UPI IDs: standard format username@bank (commonly 2 or more characters for VPA handle)
        upi_pattern = re.compile(r'\b[a-zA-Z0-9.\-_]+@[a-zA-Z]{2,}\b')

        urls = list(set(url_pattern.findall(text)))
        phones = list(set(phone_pattern.findall(text)))
        upis = list(set(upi_pattern.findall(text)))

        return {
            "urls": urls,
            "phones": phones,
            "upis": upis
        }

    @classmethod
    def process(cls, text: str) -> Dict[str, Any]:
        """
        Runs the full detoxification, normalization, and entity extraction pipeline.
        Returns a clean JSON metadata packet.
        """
        normalized_text = cls.clean_text(text)
        entities = cls.extract_entities(normalized_text)
        
        return {
            "normalized_text": normalized_text,
            "urls": entities["urls"],
            "phones": entities["phones"],
            "upis": entities["upis"]
        }
