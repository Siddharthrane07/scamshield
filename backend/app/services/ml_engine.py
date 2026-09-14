import os
import json
import logging
from typing import Dict, Any, List, Optional
import numpy as np
import torch
import torch.nn as nn
from transformers import AutoTokenizer, AutoModel

logger = logging.getLogger("scamshield.ml_engine")

# ---------------------------------------------------------------------------
# Multi-Task PyTorch Model Definition (Matching Frozen Architecture)
# ---------------------------------------------------------------------------
class ScamShieldMultiTaskModel(nn.Module):
    """
    Production Multi-Task Architecture:
    - Backbone: XLM-RoBERTa Base (shared cross-lingual transformer)
    - CLS Representation (768-dim) + Dropout (0.2)
    - Head 1: Multi-label classification for Social Engineering Triggers (BCEWithLogits)
    - Head 2: Multi-class classification for Scam Scenarios (CrossEntropy)
    """
    def __init__(self, model_backbone: str, num_head1: int, num_head2: int, dropout_prob: float = 0.2):
        super().__init__()
        self.transformer = AutoModel.from_pretrained(model_backbone)
        hidden_size = self.transformer.config.hidden_size

        self.dropout = nn.Dropout(dropout_prob)
        self.head1_classifier = nn.Linear(hidden_size, num_head1)
        self.head2_classifier = nn.Linear(hidden_size, num_head2)

        self.register_buffer("head2_class_weights", torch.ones(num_head2))
        self.loss_fn_head1 = nn.BCEWithLogitsLoss()
        self.head2_loss_weight = 1.5

    def forward(self, input_ids: torch.Tensor, attention_mask: torch.Tensor):
        outputs = self.transformer(input_ids=input_ids, attention_mask=attention_mask)
        cls_rep = outputs.last_hidden_state[:, 0, :]
        cls_rep = self.dropout(cls_rep)

        head1_logits = self.head1_classifier(cls_rep)
        head2_logits = self.head2_classifier(cls_rep)
        return head1_logits, head2_logits


# ---------------------------------------------------------------------------
# Self-Contained Production Predictor
# ---------------------------------------------------------------------------
class ScamShieldPredictor:
    """
    Self-contained inference engine for ScamShield AI.
    Loads frozen weights, tokenizer, and label mappings from backend/models/v1_xlmr_frozen/.
    """
    def __init__(self, model_dir: Optional[str] = None):
        if model_dir is None:
            # Default to backend/models/v1_xlmr_frozen/
            base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
            model_dir = os.path.join(base_dir, "models", "v1_xlmr_frozen")
        
        self.model_dir = model_dir
        if not os.path.exists(self.model_dir):
            raise FileNotFoundError(f"❌ Model package directory not found at: {self.model_dir}")

        # 1. Load Configurations and Label Mappings
        self._load_metadata()

        # 2. Select Compute Device (CUDA if available, else CPU)
        self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        logger.info(f"ScamShieldPredictor initializing on device: {self.device}")

        # 3. Load Frozen Tokenizer
        logger.info(f"Loading tokenizer from: {self.model_dir}")
        self.tokenizer = AutoTokenizer.from_pretrained(self.model_dir)

        # 4. Instantiate Architecture & Load Frozen Checkpoint Weights
        self.num_head1 = len(self.head1_tags)
        self.num_head2 = len(self.id2intent)
        
        weights_path = os.path.join(self.model_dir, "model_weights.pt")
        if not os.path.exists(weights_path):
            raise FileNotFoundError(f"❌ Checkpoint file missing: {weights_path}")

        logger.info(f"Instantiating model architecture with backbone '{self.model_backbone}'...")
        self.model = ScamShieldMultiTaskModel(
            model_backbone=self.model_dir if os.path.exists(os.path.join(self.model_dir, "config.json")) else self.model_backbone,
            num_head1=self.num_head1,
            num_head2=self.num_head2,
            dropout_prob=0.2
        )

        logger.info(f"Loading weights strictly from: {weights_path}...")
        state_dict = torch.load(weights_path, map_location=self.device)
        self.model.load_state_dict(state_dict, strict=True)
        self.model.to(self.device)
        self.model.eval()
        logger.info("✅ ScamShieldPredictor successfully initialized and ready for inference.")

    def _load_metadata(self):
        """Loads deployment config, label mappings, and intent dictionary."""
        config_path = os.path.join(self.model_dir, "deployment_config.json")
        with open(config_path, "r", encoding="utf-8") as f:
            self.deployment_config = json.load(f)

        self.model_backbone = self.deployment_config.get("model_backbone", "xlm-roberta-base")
        self.max_seq_length = int(self.deployment_config.get("max_seq_length", 256))
        self.head1_global_threshold = float(self.deployment_config.get("head1_global_threshold", 0.50))
        self.head1_per_tag_thresholds = self.deployment_config.get("head1_per_tag_optimal_thresholds", {})

        # Load Intent Mappings (Head 2)
        id2intent_path = os.path.join(self.model_dir, "id2intent.json")
        with open(id2intent_path, "r", encoding="utf-8") as f:
            raw_id2intent = json.load(f)
            self.id2intent = {int(k): v for k, v in raw_id2intent.items()}

        intent2id_path = os.path.join(self.model_dir, "intent2id.json")
        with open(intent2id_path, "r", encoding="utf-8") as f:
            self.intent2id = json.load(f)

        # Identify Benign Intent dynamically
        self.benign_intent_name = next(
            (name for name in self.intent2id.keys() if "legitimate" in name.lower() or "benign" in name.lower() or "ham" in name.lower()),
            self.id2intent[0]
        )
        self.benign_id = self.intent2id[self.benign_intent_name]

        # Load Head 1 Trigger Mappings
        head1_path = os.path.join(self.model_dir, "head1_mapping.json")
        with open(head1_path, "r", encoding="utf-8") as f:
            raw_h1 = json.load(f)
            if isinstance(raw_h1, dict):
                self.head1_tags = sorted(raw_h1.keys(), key=lambda k: raw_h1[k])
            else:
                self.head1_tags = list(raw_h1)

    def predict(self, text: str) -> Dict[str, Any]:
        """
        Executes real-time multi-task inference for a single input text.
        Returns:
            Dict containing binary is_scam verdict, risk_score, detected_intent,
            social engineering trigger lists, and full probability distributions.
        """
        if not text or not text.strip():
            # Graceful empty input response
            return {
                "is_scam": False,
                "risk_score": 0,
                "predicted_intent": self.benign_intent_name,
                "intent_confidence": 1.0,
                "social_engineering_triggers": [],
                "social_engineering_scores": {tag: 0.0 for tag in self.head1_tags},
                "intent_distribution": {name: (1.0 if name == self.benign_intent_name else 0.0) for name in self.intent2id.keys()},
                "model_version": "v1_xlmr_frozen",
                "device": str(self.device)
            }

        # 1. Tokenize text
        encoding = self.tokenizer(
            text,
            truncation=True,
            padding="max_length",
            max_length=self.max_seq_length,
            return_tensors="pt"
        )
        input_ids = encoding["input_ids"].to(self.device)
        attention_mask = encoding["attention_mask"].to(self.device)

        # 2. Forward pass under no_grad
        with torch.no_grad():
            h1_logits, h2_logits = self.model(input_ids, attention_mask)
            h1_probs = torch.sigmoid(h1_logits).squeeze(0).cpu().numpy()
            h2_probs = torch.softmax(h2_logits, dim=-1).squeeze(0).cpu().numpy()

        # 3. Process Head 1: Social Engineering Triggers
        social_scores = {}
        triggered_tags = []
        for idx, tag in enumerate(self.head1_tags):
            prob = float(h1_probs[idx])
            threshold = float(self.head1_per_tag_thresholds.get(tag, self.head1_global_threshold))
            social_scores[tag] = round(prob, 4)
            # Also provide 'social_' prefixed key for backward compatibility
            social_scores[f"social_{tag}"] = round(prob, 4)
            if prob >= threshold:
                triggered_tags.append(tag)

        # 4. Process Head 2: Scenario Intent
        top_idx = int(np.argmax(h2_probs))
        predicted_intent = self.id2intent.get(top_idx, "Unknown")
        intent_confidence = float(h2_probs[top_idx])

        intent_distribution = {
            self.id2intent[idx]: round(float(prob), 4)
            for idx, prob in enumerate(h2_probs)
        }

        # 5. Security Decision Logic
        # is_scam is True if the model predicts ANY scenario other than Benign
        is_scam = (top_idx != self.benign_id)

        # Compute continuous risk score (0 - 100)
        benign_prob = float(h2_probs[self.benign_id])
        scam_prob = max(0.0, 1.0 - benign_prob)
        max_social = max(float(np.max(h1_probs)), 0.0)
        
        # Risk score incorporates both the non-benign probability and social triggers
        risk_score = int(round(max(scam_prob, max_social) * 100))

        return {
            "is_scam": is_scam,
            "risk_score": risk_score,
            "predicted_intent": predicted_intent,
            "intent_confidence": round(intent_confidence, 4),
            "social_engineering_triggers": triggered_tags,
            "social_engineering_scores": social_scores,
            "intent_distribution": intent_distribution,
            "model_version": "v1_xlmr_frozen",
            "device": str(self.device)
        }
