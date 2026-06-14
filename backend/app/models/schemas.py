from pydantic import BaseModel, Field
from typing import Dict, Any, Optional
from datetime import datetime

class ScanTextRequest(BaseModel):
    text: str = Field(..., description="Text content to be scanned for potential scams")

class ScanResponse(BaseModel):
    scan_id: str = Field(..., description="Unique identifier for the scan")
    input_type: str = Field(..., description="'text' or 'image'")
    extracted_text: str = Field(..., description="Preprocessed and normalized text used for analysis")
    risk_score: int = Field(..., description="Aggregated risk score (0-100)")
    risk_category: str = Field(..., description="'Safe' (0-30), 'Suspicious' (31-60), or 'High Risk' (61-100)")
    explanations: Dict[str, str] = Field(..., description="Safety narratives mapping language codes to templates")
    metadata: Dict[str, Any] = Field(..., description="Detailed payload containing outputs from each engine track and timings")
    screenshot_base64: Optional[str] = Field(None, description="Base64 encoded string of Fargate sandbox screenshot (if sandbox ran)")
    created_at: datetime = Field(..., description="Timestamp of scan execution")

    class Config:
        from_attributes = True
