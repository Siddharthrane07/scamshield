import uuid
import datetime
import logging
from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, status
from sqlalchemy.ext.asyncio import AsyncSession
from app.core.database import get_db
from app.core.exceptions import MarathiLanguageException, ScamShieldException
from app.models.schemas import ScanTextRequest, ScanResponse
from app.services.ocr.ocr_engine import OCRPipeline
from app.services.detector import DetectorService
from app.services.cache_service import CacheService
from app.services.scoring import ScoringService
from app.services.explanation import ExplanationEngine
from app.services.reporting import ReportingService

logger = logging.getLogger("scamshield.router")
router = APIRouter(prefix="/scan", tags=["Scams Ingestion & Detection"])

def generate_scan_id() -> str:
    """
    Generates a unique scan identifier (e.g. scam_2026_ab89).
    """
    current_year = datetime.datetime.utcnow().year
    random_hex = uuid.uuid4().hex[:4]
    return f"scam_{current_year}_{random_hex}"

async def execute_scan_pipeline(
    raw_input: str,
    input_type: str,
    extracted_text: str,
    db: AsyncSession
) -> ScanResponse:
    """
    Executes the shared ingestion pipeline logic starting from Layer 3 (Cache Gatekeeper).
    """
    scan_id = generate_scan_id()
    logger.info(f"Initiating scan pipeline for {scan_id} ({input_type})")
    
    # Layer 3: Gatekeeper Cache check
    cached_record = await CacheService.get_cached_scan(extracted_text, db)
    if cached_record:
        logger.info(f"Cache hit! Fast-forwarding to reporting layer for scan_id {scan_id}")
        return ScanResponse(
            scan_id=cached_record.scan_id,
            input_type=cached_record.input_type,
            extracted_text=cached_record.extracted_text,
            risk_score=cached_record.risk_score,
            risk_category=cached_record.risk_category,
            explanations={
                "en": cached_record.explanation_en,
                "hi": cached_record.explanation_hi
            },
            metadata=cached_record.metadata_json,
            screenshot_base64=cached_record.screenshot_base64,
            created_at=cached_record.created_at
        )

    # Layer 2 details: Extract entities from normalized text
    detection_packet = DetectorService.process(extracted_text)
    normalized_text = detection_packet["normalized_text"]
    urls = detection_packet["urls"]
    
    # Layer 4, 5 & 6: Parallel Engine execution and risk aggregation
    pipeline_result = await ScoringService.run_pipeline(normalized_text, urls)
    
    # Layer 7: Explanation templates matching
    narratives = ExplanationEngine.generate_narrative(pipeline_result)
    
    # Layer 8: Persistent logger
    saved_record = await ReportingService.persist_scan(
        db=db,
        scan_id=scan_id,
        input_type=input_type,
        raw_input=raw_input,
        extracted_text=normalized_text,
        risk_score=pipeline_result["risk_score"],
        risk_category=pipeline_result["risk_category"],
        explanation_en=narratives["en"],
        explanation_hi=narratives["hi"],
        metadata_json={
            "track_details": pipeline_result["tracks"],
            "scoring_details": pipeline_result["scores_summary"],
            "redistribution_applied": pipeline_result["redistribution_applied"],
            "applied_weights": pipeline_result["applied_weights"],
            "execution_time_seconds": pipeline_result["execution_time_seconds"]
        },
        screenshot_base64=pipeline_result["screenshot_base64"]
    )
    
    return ScanResponse(
        scan_id=saved_record.scan_id,
        input_type=saved_record.input_type,
        extracted_text=saved_record.extracted_text,
        risk_score=saved_record.risk_score,
        risk_category=saved_record.risk_category,
        explanations={
            "en": saved_record.explanation_en,
            "hi": saved_record.explanation_hi
        },
        metadata=saved_record.metadata_json,
        screenshot_base64=saved_record.screenshot_base64,
        created_at=saved_record.created_at
    )


@router.post("/text", response_model=ScanResponse, status_code=status.HTTP_200_OK)
async def scan_text_endpoint(
    payload: ScanTextRequest,
    db: AsyncSession = Depends(get_db)
):
    """
    Ingests raw text message queries, detects scam probability,
    and returns localized safety reports.
    """
    try:
        # Preprocess text and enforce Marathi exclusion
        normalized_input = DetectorService.clean_text(payload.text)
        
        # Execute Pipeline
        return await execute_scan_pipeline(
            raw_input=payload.text,
            input_type="text",
            extracted_text=normalized_input,
            db=db
        )
    except MarathiLanguageException as mle:
        logger.error(f"Rejection: {mle}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(mle)
        )
    except ScamShieldException as sse:
        logger.error(f"ScamShield pipeline error: {sse}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(sse)
        )
    except Exception as e:
        logger.error(f"Unexpected endpoint error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"An unexpected system error occurred: {str(e)}"
        )


@router.post("/image", response_model=ScanResponse, status_code=status.HTTP_200_OK)
async def scan_image_endpoint(
    file: UploadFile = File(..., description="Mobile screenshot image file to run OCR and scan"),
    db: AsyncSession = Depends(get_db)
):
    """
    Ingests mobile screenshots, pre-processes image using OpenCV,
    performs Tesseract OCR, normalizes extracted text, and runs threat intelligence.
    """
    try:
        # Read uploaded image bytes
        image_bytes = await file.read()
        
        # Layer 2: OpenCV + PaddleOCR + Tesseract OCR extraction
        ocr_pipeline = getattr(scan_image_endpoint, "pipeline", None)
        if not ocr_pipeline:
            scan_image_endpoint.pipeline = OCRPipeline()
            ocr_pipeline = scan_image_endpoint.pipeline
            
        ocr_result = ocr_pipeline.process_image(image_bytes)
        extracted_ocr_text = ocr_result["clean_text"]
        
        if not extracted_ocr_text.strip():
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="OCR failed to extract any readable text from the uploaded screenshot."
            )
            
        # Clean and run Marathi check
        normalized_ocr_text = DetectorService.clean_text(extracted_ocr_text)

        # Execute Pipeline
        return await execute_scan_pipeline(
            raw_input=file.filename,
            input_type="image",
            extracted_text=normalized_ocr_text,
            db=db
        )
    except MarathiLanguageException as mle:
        logger.error(f"Rejection: {mle}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(mle)
        )
    except ScamShieldException as sse:
        logger.error(f"ScamShield pipeline error: {sse}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(sse)
        )
    except Exception as e:
        logger.error(f"Unexpected endpoint error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"An unexpected system error occurred: {str(e)}"
        )
