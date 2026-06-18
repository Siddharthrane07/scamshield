import asyncio
import os
import sys

# Add the backend directory to sys.path to allow imports of 'app'
current_dir = os.path.dirname(os.path.abspath(__file__))
backend_dir = os.path.dirname(current_dir)
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

from app.core.config import get_settings
from app.core.database import Base
from app.models.db_models import ScanRecord
from sqlalchemy import text
from sqlalchemy.ext.asyncio import create_async_engine

async def init_local_db():
    settings = get_settings()
    postgres_url = settings.postgres_url
    
    print(f"Connecting to local PostgreSQL database at {settings.POSTGRES_HOST}:{settings.POSTGRES_PORT} (DB: {settings.POSTGRES_DB})...")
    
    try:
        # Create async engine for PostgreSQL
        engine = create_async_engine(postgres_url, echo=False)
        
        # Test connection
        async with engine.connect() as conn:
            # Check connection with a simple text query
            await conn.execute(text("SELECT 1"))
            print("Successfully connected to the local PostgreSQL database!")
            
        # Drop and recreate tables
        async with engine.begin() as conn:
            print("Dropping existing 'scan_records' table (if it exists)...")
            await conn.run_sync(Base.metadata.drop_all, tables=[ScanRecord.__table__])
            
            print("Creating 'scan_records' table...")
            await conn.run_sync(Base.metadata.create_all, tables=[ScanRecord.__table__])
            
        await engine.dispose()
        print("Database tables initialized successfully! Layer 3 cache gatekeeper infrastructure is ready.")
        
    except Exception as e:
        print(f"Error initializing local PostgreSQL database: {e}", file=sys.stderr)
        print("Please verify that PostgreSQL is running locally and the credentials in backend/.env are correct.", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    asyncio.run(init_local_db())
