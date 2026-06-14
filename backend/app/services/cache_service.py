import hashlib
import datetime
import logging
from sqlalchemy.future import select
from sqlalchemy.ext.asyncio import AsyncSession
from app.models.db_models import ScanRecord
from app.core.config import get_settings

logger = logging.getLogger("scamshield.cache")
settings = get_settings()

class CacheService:
    @staticmethod
    def calculate_hash(text: str) -> str:
        """
        Computes the SHA-256 hash of the normalized input text.
        """
        return hashlib.sha256(text.encode("utf-8")).hexdigest()

    @classmethod
    async def get_cached_scan(cls, text: str, db: AsyncSession) -> ScanRecord or None:
        """
        Checks the database for an existing ScanRecord matching the SHA-256 hash
        of the text that was created within the last CACHE_TTL_HOURS.
        """
        scan_hash = cls.calculate_hash(text)
        time_threshold = datetime.datetime.utcnow() - datetime.timedelta(hours=settings.CACHE_TTL_HOURS)
        
        logger.info(f"Checking cache gatekeeper for hash: {scan_hash}")
        try:
            # Query the database
            query = select(ScanRecord).where(
                ScanRecord.hash == scan_hash,
                ScanRecord.created_at >= time_threshold
            ).order_by(ScanRecord.created_at.desc())

            result = await db.execute(query)
            record = result.scalars().first()

            if record:
                logger.info(f"Cache hit! Found scan {record.scan_id} with latency < 50ms.")
                return record
            
            logger.info("Cache miss. Routing to parallel scan engines.")
            return None
        except Exception as e:
            # Log error but don't block the request; let it proceed to engine tracks
            logger.error(f"Error querying cache: {e}")
            return None
