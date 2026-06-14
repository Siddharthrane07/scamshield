import datetime
from sqlalchemy import Column, String, Integer, DateTime, JSON, Text
from app.core.database import Base

class ScanRecord(Base):
    __tablename__ = "scan_records"

    scan_id = Column(String(50), primary_key=True, index=True)
    input_type = Column(String(10), nullable=False) # "text" or "image"
    raw_input = Column(Text, nullable=False)        # The raw text or filename/path of the image
    extracted_text = Column(Text, nullable=False)   # Normalized and pre-processed text
    hash = Column(String(64), nullable=False, index=True) # SHA-256 for caching
    risk_score = Column(Integer, nullable=False)    # 0-100
    risk_category = Column(String(20), nullable=False) # "Safe", "Suspicious", "High Risk"
    explanation_en = Column(Text, nullable=False)   # Safety narrative in English
    explanation_hi = Column(Text, nullable=False)   # Safety narrative in Hindi
    metadata_json = Column(JSON, nullable=False)    # Structured logs from engine tracks
    screenshot_base64 = Column(Text, nullable=True) # Full page PNG base64 representation from Sandbox
    created_at = Column(DateTime, default=datetime.datetime.utcnow, nullable=False)
