import logging
from sqlalchemy.ext.asyncio import AsyncSession
from app.models.db_models import ScanRecord
from app.services.cache_service import CacheService

logger = logging.getLogger("scamshield.reporting")

class ReportingService:
    @staticmethod
    async def persist_scan(
        db: AsyncSession,
        scan_id: str,
        input_type: str,
        raw_input: str,
        extracted_text: str,
        risk_score: int,
        risk_category: str,
        explanation_en: str,
        explanation_hi: str,
        metadata_json: dict,
        screenshot_base64: str = None
    ) -> ScanRecord:
        """
        Creates and persists a ScanRecord in the database.
        """
        # Calculate text hash for cache identification in subsequent requests
        text_hash = CacheService.calculate_hash(extracted_text)
        
        logger.info(f"Persisting scan record {scan_id} with hash {text_hash}...")
        
        try:
            record = ScanRecord(
                scan_id=scan_id,
                input_type=input_type,
                raw_input=raw_input,
                extracted_text=extracted_text,
                hash=text_hash,
                risk_score=risk_score,
                risk_category=risk_category,
                explanation_en=explanation_en,
                explanation_hi=explanation_hi,
                metadata_json=metadata_json,
                screenshot_base64=screenshot_base64
            )
            
            db.add(record)
            await db.commit()
            await db.refresh(record)
            
            logger.info(f"Scan record {scan_id} persisted successfully.")
            return record
        except Exception as e:
            # If persistence fails, log it but don't fail the whole user request
            await db.rollback()
            logger.error(f"Failed to persist scan record {scan_id}: {e}")
            # Return an unpersisted record so user still gets their scan results
            return ScanRecord(
                scan_id=scan_id,
                input_type=input_type,
                raw_input=raw_input,
                extracted_text=extracted_text,
                hash=text_hash,
                risk_score=risk_score,
                risk_category=risk_category,
                explanation_en=explanation_en,
                explanation_hi=explanation_hi,
                metadata_json=metadata_json,
                screenshot_base64=screenshot_base64
            )
patch = """
"""
