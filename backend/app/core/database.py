import logging
from typing import AsyncGenerator
from sqlalchemy import text
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession
from sqlalchemy.orm import declarative_base
from app.core.config import get_settings


logger = logging.getLogger("scamshield.database")
settings = get_settings()

Base = declarative_base()

# We will initialize engine and sessionmaker dynamically to handle fallback gracefully
engine = None
async_session_maker = None

async def init_db_engine():
    global engine, async_session_maker
    if engine is not None:
        return

    # Try connecting to PostgreSQL
    postgres_url = settings.postgres_url
    logger.info(f"Attempting to connect to PostgreSQL at {settings.POSTGRES_HOST}...")
    try:
        # Create Postgres Engine with a short connection timeout
        temp_engine = create_async_engine(
            postgres_url,
            connect_args={"timeout": 5}, # 5 second timeout
            echo=False
        )
        # Verify connectivity
        async with temp_engine.connect() as conn:
            # Check basic connection
            await conn.execute(text("SELECT 1"))
        
        engine = temp_engine
        logger.info("Successfully connected to PostgreSQL.")
    except Exception as e:
        logger.warning(
            f"Failed to connect to PostgreSQL: {e}. "
            f"Falling back to local SQLite at {settings.sqlite_url}"
        )
        engine = create_async_engine(
            settings.sqlite_url,
            echo=False
        )

    async_session_maker = async_sessionmaker(
        bind=engine,
        class_=AsyncSession,
        expire_on_commit=False,
        autocommit=False,
        autoflush=False
    )

async def init_tables():
    await init_db_engine()
    async with engine.begin() as conn:
        # Import models here to ensure they are registered with Base
        from app.models.db_models import ScanRecord # noqa
        await conn.run_sync(Base.metadata.create_all)
    logger.info("Database tables verified/created successfully.")

async def get_db() -> AsyncGenerator[AsyncSession, None]:
    if async_session_maker is None:
        await init_db_engine()
    
    async with async_session_maker() as session:
        try:
            yield session
        finally:
            await session.close()
