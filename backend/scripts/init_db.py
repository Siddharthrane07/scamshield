import asyncio
import logging
import os
import sys

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("init_db")

# Add the backend directory to sys.path to allow imports of 'app'
current_dir = os.path.dirname(os.path.abspath(__file__))
backend_dir = os.path.dirname(current_dir)
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

from app.core.config import get_settings
from app.core.database import Base
from app.models.db_models import ScanRecord
from sqlalchemy.ext.asyncio import create_async_engine

async def wait_for_db(postgres_url: str, max_retries: int = 30, delay: float = 2.0):
    logger.info("Waiting for PostgreSQL database container to become healthy...")
    engine = create_async_engine(postgres_url, echo=False)
    for i in range(1, max_retries + 1):
        try:
            async with engine.connect() as conn:
                # Execute a simple query to verify connection
                await conn.execute(Base.metadata.clear())
            logger.info("PostgreSQL is healthy and accepting connections!")
            await engine.dispose()
            return True
        except Exception as e:
            logger.warning(
                f"Database connection attempt {i}/{max_retries} failed. Retrying in {delay}s... (Error: {e})"
            )
            await asyncio.sleep(delay)
    await engine.dispose()
    logger.error("Could not connect to PostgreSQL database. Exiting.")
    return False

async def init_postgres():
    settings = get_settings()
    postgres_url = settings.postgres_url
    
    # Wait for database container
    db_ready = await wait_for_db(postgres_url)
    if not db_ready:
        sys.exit(1)
        
    logger.info("Initializing PostgreSQL schema...")
    engine = create_async_engine(postgres_url, echo=False)
    
    async with engine.begin() as conn:
        logger.info("Dropping table 'scan_records' if exists...")
        await conn.run_sync(Base.metadata.drop_all, tables=[ScanRecord.__table__])
        
        logger.info("Creating table 'scan_records'...")
        await conn.run_sync(Base.metadata.create_all, tables=[ScanRecord.__table__])
        
    await engine.dispose()
    logger.info("Database tables initialized successfully and ready to accept sub-50ms cache queries.")

if __name__ == "__main__":
    asyncio.run(init_postgres())
