import logging
import asyncio
import time
from typing import List, Dict, Any
from app.services.track_a_url import TrackAURLIntel
from app.services.track_b_domain import TrackBDomainIntel
from app.services.track_c_sandbox import TrackCSandbox
from app.services.track_d_ml import ml_engine

logger = logging.getLogger("scamshield.scoring")

class ScoringService:
    @classmethod
    async def run_pipeline(cls, normalized_text: str, urls: List[str]) -> Dict[str, Any]:
        """
        Layer 5 (Sync Core) & Layer 6 (Weighted Risk score computation).
        Coordinates parallel tracks A, B, C, D, aggregates results,
        handles Fargate timeouts, and computes weighted risk score.
        """
        start_time = time.time()
        
        # 1. Routing Decision (Layer 3 Condition 2)
        has_url = len(urls) > 0
        
        track_a_res = None
        track_b_res = None
        track_c_res = None
        track_d_res = None
        
        # Layer 5: Asynchronous Gather Barrier
        if not has_url:
            logger.info("No URL present in input. Bypassing Tracks A, B, C. Routing only to Track D (ML).")
            # Only run ML engine
            track_d_res = await ml_engine.analyze(normalized_text)
            track_a_res = {"status": "bypassed", "max_risk_score": 0}
            track_b_res = {"status": "bypassed", "max_risk_score": 0}
            track_c_res = {"status": "bypassed", "sandbox_status": "skipped", "risk_weight": 0}
        else:
            logger.info(f"URLs found: {urls}. Fanning out to Tracks A, B, C, D in parallel.")
            # Execute all tracks in parallel
            results = await asyncio.gather(
                TrackAURLIntel.analyze(urls),
                TrackBDomainIntel.analyze(urls),
                TrackCSandbox.analyze(urls),
                ml_engine.analyze(normalized_text),
                return_exceptions=True
            )
            
            # Extract results, handling exceptions gracefully
            track_a_res = results[0] if not isinstance(results[0], Exception) else {"status": "failed", "max_risk_score": 50, "error": str(results[0])}
            track_b_res = results[1] if not isinstance(results[1], Exception) else {"status": "failed", "max_risk_score": 50, "error": str(results[1])}
            track_c_res = results[2] if not isinstance(results[2], Exception) else {"status": "failed", "sandbox_status": "failed", "risk_weight": 40, "error": str(results[2])}
            track_d_res = results[3] if not isinstance(results[3], Exception) else {"status": "failed", "risk_score": 50, "error": str(results[3])}

            if isinstance(results[2], Exception):
                logger.error(f"Track C (Sandbox) threw an unhandled exception: {results[2]}")

        # Layer 6: Weighted Risk Score Computation
        ml_score = track_d_res.get("risk_score", 0)
        
        # Extract risk components
        url_score = track_a_res.get("max_risk_score", 0) if isinstance(track_a_res, dict) else 0
        domain_score = track_b_res.get("max_risk_score", 0) if isinstance(track_b_res, dict) else 0
        
        # Sandbox status evaluation
        sandbox_status = track_c_res.get("sandbox_status", "skipped")
        sandbox_screenshot = track_c_res.get("screenshot_base64")
        
        sandbox_failed = sandbox_status in ["hostile_timeout", "failed", "skipped"]
        
        # Base weights: ML (40%), URL (25%), Domain (20%), Sandbox (15%)
        # Scoring logic with dynamic redistribution
        if not has_url:
            # 100% ML Engine
            aggregated_score = ml_score
            redistribution_active = False
            applied_weights = {"ML": 1.0, "URL": 0.0, "Domain": 0.0, "Sandbox": 0.0}
            sandbox_score = 0
            timeout_penalty = 0
        elif sandbox_failed:
            # 15% sandbox weight is redistributed proportionally to active tracks:
            # ML: 40/85 = ~47% | URL: 25/85 = ~29% | Domain: 20/85 = ~24%
            w_ml = 40 / 85
            w_url = 25 / 85
            w_domain = 20 / 85
            
            weighted_score = (ml_score * w_ml) + (url_score * w_url) + (domain_score * w_domain)
            
            # Apply fallback penalty for hostile timeout or failure
            timeout_penalty = 0
            if sandbox_status == "hostile_timeout":
                # Apply penalty: timeout penalty weight is 40. We add a flat risk penalty of 15% * 40 = 6 points
                # or add +15 to represent sandbox's max risk contribution under timeout
                timeout_penalty = int(0.15 * track_c_res.get("risk_weight", 40)) # 6 points
                logger.info(f"Applying sandbox hostile timeout penalty: +{timeout_penalty} risk points")
            
            aggregated_score = int(weighted_score) + timeout_penalty
            redistribution_active = True
            applied_weights = {"ML": round(w_ml, 3), "URL": round(w_url, 3), "Domain": round(w_domain, 3), "Sandbox": 0.0}
            sandbox_score = 0
        else:
            # Normal weights: ML (40%), URL (25%), Domain (20%), Sandbox (15%)
            # Sandbox score: 100 if auth/payment tags detected, 0 otherwise
            sandbox_signals = track_c_res.get("dom_signals", {})
            sandbox_score = 100 if (sandbox_signals.get("has_auth_inputs") or sandbox_signals.get("has_payment_forms")) else 0
            
            weighted_score = (ml_score * 0.40) + (url_score * 0.25) + (domain_score * 0.20) + (sandbox_score * 0.15)
            aggregated_score = int(weighted_score)
            redistribution_active = False
            applied_weights = {"ML": 0.40, "URL": 0.25, "Domain": 0.20, "Sandbox": 0.15}
            timeout_penalty = 0

        # Cap score at 100
        final_score = min(100, max(0, aggregated_score))
        
        # Risk classification thresholds
        if final_score <= 30:
            category = "Safe"
        elif final_score <= 60:
            category = "Suspicious"
        else:
            category = "High Risk"
            
        execution_time = time.time() - start_time
        logger.info(f"Pipeline executed in {execution_time:.3f}s. Aggregated risk score: {final_score} ({category})")
        
        return {
            "risk_score": final_score,
            "risk_category": category,
            "execution_time_seconds": round(execution_time, 3),
            "redistribution_applied": redistribution_active,
            "applied_weights": applied_weights,
            "screenshot_base64": sandbox_screenshot,
            "tracks": {
                "track_a_url_intel": track_a_res,
                "track_b_domain_intel": track_b_res,
                "track_c_sandbox": track_c_res,
                "track_d_ml_engine": track_d_res
            },
            "scores_summary": {
                "ml_score": ml_score,
                "url_score": url_score,
                "domain_score": domain_score,
                "sandbox_score": sandbox_score if not sandbox_failed else None,
                "timeout_penalty_applied": timeout_penalty
            }
        }
