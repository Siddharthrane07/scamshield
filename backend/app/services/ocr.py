import cv2
import numpy as np
import logging
import pytesseract
from app.core.exceptions import ScamShieldException

logger = logging.getLogger("scamshield.ocr")

class OCRService:
    @staticmethod
    def preprocess_image(image_bytes: bytes) -> np.ndarray:
        """
        Ingests image bytes, decodes, and applies OpenCV preprocessing
        (Adaptive Thresholding) to enhance OCR readiness.
        """
        try:
            # Decode bytes to numpy array
            nparr = np.frombuffer(image_bytes, np.uint8)
            img = cv2.imdecode(nparr, cv2.IMREAD_COLOR)
            if img is None:
                raise ScamShieldException("Could not decode image bytes.")

            # Convert to grayscale
            gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)

            # Apply Adaptive Thresholding
            processed = cv2.adaptiveThreshold(
                gray,
                255,
                cv2.ADAPTIVE_THRESH_GAUSSIAN_C,
                cv2.THRESH_BINARY,
                11,
                2
            )
            return processed
        except Exception as e:
            logger.error(f"Image preprocessing failed: {e}")
            raise ScamShieldException(f"Image preprocessing failed: {str(e)}")

    @classmethod
    def extract_text(cls, image_bytes: bytes) -> str:
        """
        Processes image and runs PyTesseract OCR.
        """
        try:
            processed_img = cls.preprocess_image(image_bytes)
            
            # Execute PyTesseract
            text = pytesseract.image_to_string(processed_img, lang='eng+hin')
            return text.strip()
        except pytesseract.TesseractNotFoundError:
            logger.warning("PyTesseract is not installed or not in PATH. Falling back to dry-run mock OCR.")
            # For demonstration in local development environment without tesseract binary:
            return "[MOCK OCR RESULT: Please pay Rs 5000 urgently to keep your electricity running. UPI: pay@electricity, Phone: 9876543210, URL: http://fake-electricity-bill.in]"
        except Exception as e:
            logger.error(f"OCR extraction failed: {e}")
            raise ScamShieldException(f"OCR extraction failed: {str(e)}")
