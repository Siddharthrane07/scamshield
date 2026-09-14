import os
import logging
import asyncio
from typing import Dict, Any
from app.core.config import get_settings

logger = logging.getLogger("scamshield.track_d")
settings = get_settings()

# Keywords for rule-based fallback classification (Hindi, English, Hinglish)
KEYWORDS_SOCIAL = {
    "social_urgency": ["urgent", "immediately", "quick", "hurry", "expire", "action required", "deadline", "जल्दी", "तुरंत", "अभी", "jaldi", "turant"],
    "social_fear": ["arrest", "court", "police", "cbi", "jail", "suspend", "penalty", "fine", "पुलिस", "जेल", "अदालत", "जुर्माना", "court", "band", "arrest"],
    "social_authority_impersonation": ["electricity board", "power department", "sbi bank", "manager", "support desk", "official", "बैंक", "मैनेजर", "बिजली विभाग", "सरकारी", "bijli"],
    "social_reward_bait": ["won", "lottery", "draw", "gift card", "reward points", "free cashback", "congratulations", "जीता", "इनाम", "लॉटरी", "मुफ्त", "jeeta", "inam", "lottery", "free"],
    "social_financial_pressure": ["bill due", "pay now", "pending payment", "unpaid", "arrears", "electricity bill", "बिल", "भुगतान", "बकाया", "पैसे", "paisa", "payment"]
}

KEYWORDS_INTENT = {
    "fake_kyc": ["kyc", "verify", "pan card", "aadhaar", "verification", "अपडेट", "सत्यापन", "update"],
    "otp_theft": ["otp", "one time password", "code", "pin", "ओटीपी", "पासवर्ड"],
    "upi_fraud": ["upi", "gpay", "phonepe", "paytm", "send money", "request money", "पैसे भेजें", "UPI"],
    "job_scams": ["job offer", "work from home", "salary", "part time", "earn money", "नौकरी", "रोजगार", "kamao"],
    "delivery_scams": ["delivery", "courier", "package", "post office", "tracking", "डिलिवरी", "पार्सल", "post"]
}

class TrackDMLMachine:
    """
    Track D Machine Learning Service.
    Wraps the frozen multi-task XLM-RoBERTa ScamShieldPredictor singleton with
    async non-blocking threadpool execution and heuristic fallback.
    """
    def __init__(self):
        self.predictor = None
        self.use_mock = True
        
        try:
            from app.services.ml_engine import ScamShieldPredictor
            self.predictor = ScamShieldPredictor()
            self.use_mock = False
            logger.info("✅ Track D successfully loaded ScamShieldPredictor (Frozen XLM-RoBERTa).")
        except Exception as e:
            logger.warning(
                f"⚠️ Could not load production ScamShieldPredictor ({e}). "
                f"Falling back to deterministic rule-based ML."
            )
            self.use_mock = True

    def _run_mock_inference(self, text: str) -> Dict[str, Any]:
        """
        Runs a smart, deterministic keyword-based mock classifier
        for Head 1 and Head 2 if the transformer model is not present.
        """
        text_lower = text.lower()
        
        # Head 1 (Multi-label Social Engineering facets)
        social_scores = {}
        for facet, keywords in KEYWORDS_SOCIAL.items():
            matches = sum(1 for kw in keywords if kw in text_lower)
            prob = min(0.95, matches * 0.45) if matches > 0 else 0.05
            social_scores[facet] = prob
            clean_name = facet.replace("social_", "")
            social_scores[clean_name] = prob
            
        # Head 2 (Multi-class Scam Intent)
        intent_scores = {}
        detected_intent = "Legitimate / Benign"
        max_matches = 0
        
        for intent, keywords in KEYWORDS_INTENT.items():
            matches = sum(1 for kw in keywords if kw in text_lower)
            intent_scores[intent] = matches
            if matches > max_matches:
                max_matches = matches
                detected_intent = intent
                
        # Format Head 2 probabilities
        intent_probs = {}
        if max_matches > 0:
            total = sum(intent_scores.values()) + 1
            for intent in KEYWORDS_INTENT.keys():
                intent_probs[intent] = round(intent_scores[intent] / total, 3)
            intent_probs["Legitimate / Benign"] = round(1 / total, 3)
            is_scam = True
        else:
            for intent in KEYWORDS_INTENT.keys():
                intent_probs[intent] = 0.02
            intent_probs["Legitimate / Benign"] = 0.90
            detected_intent = "Legitimate / Benign"
            is_scam = False
            
        max_social = max(social_scores.values())
        scam_prob = 1.0 - intent_probs.get("Legitimate / Benign", 1.0)
        ml_risk = int(max(max_social, scam_prob) * 100)
        
        return {
            "model_type": "heuristic_fallback_ml",
            "risk_score": ml_risk,
            "is_scam": is_scam,
            "social_engineering": social_scores,
            "social_engineering_triggers": [k for k, v in social_scores.items() if v >= 0.5 and not k.startswith("social_")],
            "scam_intent": {
                "detected_intent": detected_intent,
                "confidence": round(intent_probs.get(detected_intent, 0.9), 3),
                "probabilities": intent_probs
            }
        }

    async def analyze(self, text: str) -> Dict[str, Any]:
        """
        Runs asynchronous ML analysis on normalized text.
        Executes transformer inference in a separate worker thread to avoid blocking the FastAPI event loop.
        """
        if self.use_mock or self.predictor is None:
            return self._run_mock_inference(text)
            
        try:
            loop = asyncio.get_running_loop()
            result = await loop.run_in_executor(None, self.predictor.predict, text)
            
            return {
                "model_type": "xlm_roberta_multitask_frozen",
                "risk_score": result["risk_score"],
                "is_scam": result["is_scam"],
                "social_engineering": result["social_engineering_scores"],
                "social_engineering_triggers": result["social_engineering_triggers"],
                "scam_intent": {
                    "detected_intent": result["predicted_intent"],
                    "confidence": result["intent_confidence"],
                    "probabilities": result["intent_distribution"]
                }
            }
        except Exception as e:
            logger.error(f"Transformer inference failed during execution: {e}. Falling back to mock ML.")
            return self._run_mock_inference(text)

# Singleton ML engine instance
ml_engine = TrackDMLMachine()
