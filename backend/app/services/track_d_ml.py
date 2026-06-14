import os
import logging
import numpy as np
from typing import Dict, Any
from app.core.config import get_settings

# Try importing onnxruntime and tokenizers
try:
    import onnxruntime as ort
    from tokenizers import Tokenizer
    ONNX_LIBS_AVAILABLE = True
except ImportError:
    ONNX_LIBS_AVAILABLE = False

logger = logging.getLogger("scamshield.track_d")
settings = get_settings()

MODEL_PATH = os.path.join(os.path.dirname(__file__), "..", "resources", "model.onnx")
TOKENIZER_PATH = os.path.join(os.path.dirname(__file__), "..", "resources", "tokenizer.json")

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
    def __init__(self):
        self.session = None
        self.tokenizer = None
        self.use_mock = True
        
        if ONNX_LIBS_AVAILABLE:
            if os.path.exists(MODEL_PATH) and os.path.exists(TOKENIZER_PATH):
                try:
                    # Initialize ONNX session
                    # Set intra_op_num_threads to 1-2 to optimize CPU memory usage under 8GB RAM limits
                    sess_options = ort.SessionOptions()
                    sess_options.intra_op_num_threads = 2
                    sess_options.execution_mode = ort.ExecutionMode.ORT_SEQUENTIAL
                    
                    self.session = ort.InferenceSession(MODEL_PATH, sess_options)
                    self.tokenizer = Tokenizer.from_file(TOKENIZER_PATH)
                    self.use_mock = False
                    logger.info("Successfully loaded ONNX model and Tokenizer.")
                except Exception as e:
                    logger.error(f"Error loading ONNX model/tokenizer: {e}. Falling back to mock ML.")
            else:
                logger.warning("ONNX model or tokenizer file not found in resources. Using deterministic rule-based ML.")
        else:
            logger.warning("ONNX Runtime or Tokenizers libraries not available. Using deterministic rule-based ML.")

    def _run_mock_inference(self, text: str) -> Dict[str, Any]:
        """
        Runs a smart, deterministic keyword-based mock classifier
        for Head 1 and Head 2 if the ONNX model is not present.
        """
        text_lower = text.lower()
        
        # Head 1 (Multi-label Social Engineering facets - 0.0 to 1.0 probability)
        social_scores = {}
        for facet, keywords in KEYWORDS_SOCIAL.items():
            matches = sum(1 for kw in keywords if kw in text_lower)
            # Logarithmic probability scaling
            prob = min(0.95, matches * 0.45)
            if matches == 0:
                prob = 0.05
            social_scores[facet] = prob
            
        # Head 2 (Multi-class Scam Intent)
        intent_scores = {}
        detected_intent = "legitimate"
        max_matches = 0
        
        for intent, keywords in KEYWORDS_INTENT.items():
            matches = sum(1 for kw in keywords if kw in text_lower)
            intent_scores[intent] = matches
            if matches > max_matches:
                max_matches = matches
                detected_intent = intent
                
        # Format Head 2 probabilities (Softmax simulation)
        intent_probs = {}
        if max_matches > 0:
            # Distribute probability mass
            total = sum(intent_scores.values()) + 1 # add 1 for other/legit
            for intent in KEYWORDS_INTENT.keys():
                intent_probs[intent] = round(intent_scores[intent] / total, 3)
            intent_probs["legitimate"] = round(1 / total, 3)
        else:
            # Default to clean/legitimate
            for intent in KEYWORDS_INTENT.keys():
                intent_probs[intent] = 0.02
            intent_probs["legitimate"] = 0.90
            detected_intent = "legitimate"
            
        # Overall ML risk calculation (max social score + non-legit intent probability)
        max_social = max(social_scores.values())
        scam_prob = 1.0 - intent_probs.get("legitimate", 1.0)
        
        ml_risk = int(max(max_social, scam_prob) * 100)
        
        return {
            "model_type": "heuristic_fallback_ml",
            "risk_score": ml_risk,
            "social_engineering": social_scores,
            "scam_intent": {
                "detected_intent": detected_intent,
                "probabilities": intent_probs
            }
        }

    async def analyze(self, text: str) -> Dict[str, Any]:
        """
        Runs ML analysis on normalized text. Uses async-compatible execution.
        """
        if self.use_mock:
            # Return rule-based classification
            return self._run_mock_inference(text)
            
        # Real ONNX Inference Path
        try:
            # Tokenize input text (padding to 128 max length is standard for latency)
            encoded = self.tokenizer.encode(text)
            # Limit sequence length
            input_ids = encoded.ids[:128]
            attention_mask = encoded.attention_mask[:128]
            
            # Pad sequences
            if len(input_ids) < 128:
                padding_len = 128 - len(input_ids)
                input_ids += [self.tokenizer.token_to_id("<pad>") or 1] * padding_len
                attention_mask += [0] * padding_len
                
            # Convert to numpy arrays
            input_ids_np = np.array([input_ids], dtype=np.int64)
            attention_mask_np = np.array([attention_mask], dtype=np.int64)
            
            # Prepare inputs
            # XML-RoBERTa expects input_ids and attention_mask
            inputs = {
                "input_ids": input_ids_np,
                "attention_mask": attention_mask_np
            }
            
            # Execute ONNX session (run in executor to avoid blocking CPU)
            loop = asyncio.get_running_loop()
            outputs = await loop.run_in_executor(
                None, 
                lambda: self.session.run(None, inputs)
            )
            
            # Extract Head 1 and Head 2 outputs
            # Assuming output 0 = Social Engineering Logits, output 1 = Intent Logits
            social_logits = outputs[0][0]
            intent_logits = outputs[1][0]
            
            # Sigmoid for Head 1
            social_probs = 1 / (1 + np.exp(-social_logits))
            # Softmax for Head 2
            exp_logits = np.exp(intent_logits - np.max(intent_logits))
            intent_probs = exp_logits / exp_logits.sum()
            
            social_labels = ["social_urgency", "social_fear", "social_authority_impersonation", "social_reward_bait", "social_financial_pressure"]
            intent_labels = ["fake_kyc", "otp_theft", "upi_fraud", "job_scams", "delivery_scams", "normal_spam", "legitimate"]
            
            social_results = {label: float(social_probs[i]) for i, label in enumerate(social_labels)}
            intent_prob_results = {label: float(intent_probs[i]) for i, label in enumerate(intent_labels)}
            
            detected_idx = int(np.argmax(intent_probs))
            detected_intent = intent_labels[detected_idx]
            
            # Calculate overall ML risk score
            max_social = max(social_probs)
            scam_prob = 1.0 - intent_prob_results["legitimate"]
            ml_risk = int(max(max_social, scam_prob) * 100)
            
            return {
                "model_type": "onnx_xlm_roberta",
                "risk_score": ml_risk,
                "social_engineering": social_results,
                "scam_intent": {
                    "detected_intent": detected_intent,
                    "probabilities": intent_prob_results
                }
            }
        except Exception as e:
            logger.error(f"ONNX inference failed during execution: {e}. Falling back to mock ML.")
            return self._run_mock_inference(text)

# Singleton ML engine instance
ml_engine = TrackDMLMachine()
