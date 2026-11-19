"""
ML Classifier for Phishing Detection.

Uses Linear SVC (best performer from project evaluation at 91% accuracy)
with a fallback heuristic scorer when no trained model is available.
Supports training, saving, loading, and prediction.
"""

import logging
import numpy as np
import joblib
from pathlib import Path

from config import (
    ML_MODEL_PATH,
    SCALER_PATH,
    PHISHING_THRESHOLD,
    HIGH_RISK_THRESHOLD,
    WARNING_THRESHOLD,
)
from models.url_features import extract_features, get_feature_names, features_to_vector

logger = logging.getLogger(__name__)


class PhishingClassifier:
    """
    Phishing URL classifier.

    When a trained LSVC model is on disk, it loads and uses it.
    Otherwise, falls back to a deterministic heuristic scorer
    so the extension works out of the box.
    """

    def __init__(self):
        self.model = None
        self.scaler = None
        self.is_ml_loaded = False
        self._load_model()

    # ── Model persistence ────────────────────────────────────────────────

    def _load_model(self):
        """Attempt to load a pre-trained model from disk."""
        if ML_MODEL_PATH.exists() and SCALER_PATH.exists():
            try:
                self.model = joblib.load(ML_MODEL_PATH)
                self.scaler = joblib.load(SCALER_PATH)
                self.is_ml_loaded = True
                logger.info("ML model loaded from %s", ML_MODEL_PATH)
            except Exception as exc:
                logger.warning("Failed to load ML model: %s", exc)
                self.is_ml_loaded = False
        else:
            logger.info(
                "No trained model found. Using heuristic fallback. "
                "Run train.py to train the ML model."
            )

    def reload_model(self):
        """Hot-reload the model (e.g. after retraining)."""
        self._load_model()

    # ── Prediction ───────────────────────────────────────────────────────

    def predict(self, url: str) -> dict:
        """
        Classify a URL as phishing or legitimate.

        Returns:
            dict with keys:
                - is_phishing (bool)
                - confidence (float 0-1)
                - risk_level (str: safe / warning / phishing / high_risk)
                - method (str: ml_model / heuristic)
                - features (dict of extracted features)
                - breakdown (list of human-readable risk factors)
        """
        features = extract_features(url)
        breakdown = self._explain_features(features)

        if self.is_ml_loaded:
            result = self._predict_ml(features)
            result["method"] = "ml_model"
        else:
            result = self._predict_heuristic(features)
            result["method"] = "heuristic"

        result["features"] = features
        result["breakdown"] = breakdown
        return result

    def _predict_ml(self, features: dict) -> dict:
        """Run prediction through the trained LSVC model."""
        vector = np.array([features_to_vector(features)])
        scaled = self.scaler.transform(vector)

        # LSVC uses decision_function; convert to pseudo-probability via sigmoid
        decision = self.model.decision_function(scaled)[0]
        probability = 1.0 / (1.0 + np.exp(-decision))

        return self._build_result(float(probability))

    def _predict_heuristic(self, features: dict) -> dict:
        """
        Rule-based fallback scorer.
        Assigns weighted risk scores based on known phishing indicators.
        Works without any trained model so the extension is usable immediately.
        """
        score = 0.0
        max_score = 10.0

        # High-risk signals
        if features["has_ip_address"]:
            score += 2.0
        if features["has_at_sign"]:
            score += 1.5
        if features["has_suspicious_tld"]:
            score += 1.5
        if features["has_double_slash_redirect"]:
            score += 1.0
        if features["has_non_standard_port"]:
            score += 1.0

        # Moderate-risk signals
        if features["suspicious_keyword_count"] >= 2:
            score += min(features["suspicious_keyword_count"] * 0.5, 2.0)
        if features["num_subdomains"] >= 3:
            score += 1.0
        if features["url_length"] > 75:
            score += 0.5
        if features["url_length"] > 150:
            score += 0.5
        if features["hostname_length"] > 30:
            score += 0.5
        if features["domain_has_digits"]:
            score += 0.3
        if features.get("is_tunnel_or_free_host"):
            score += 2.0
        if features.get("is_tunnel_or_free_host"):
            breakdown.append("⚠️ Uses dynamic tunnel or free hosting domain (e.g. trycloudflare, webnode)")
        if features["is_shortened"]:
            score += 0.5
        if features["url_entropy"] > 4.5:
            score += 0.5

        # Protective signals (reduce score)
        if features["has_https"]:
            score -= 0.5

        probability = min(max(score / max_score, 0.0), 1.0)
        return self._build_result(probability)

    # ── Helpers ──────────────────────────────────────────────────────────

    @staticmethod
    def _build_result(probability: float) -> dict:
        """Map a phishing probability to a risk level."""
        if probability >= HIGH_RISK_THRESHOLD:
            risk_level = "high_risk"
        elif probability >= PHISHING_THRESHOLD:
            risk_level = "phishing"
        elif probability >= WARNING_THRESHOLD:
            risk_level = "warning"
        else:
            risk_level = "safe"

        return {
            "is_phishing": probability >= PHISHING_THRESHOLD,
            "confidence": round(probability, 4),
            "risk_level": risk_level,
        }

    @staticmethod
    def _explain_features(features: dict) -> list[str]:
        """Generate human-readable explanations for notable features."""
        breakdown = []

        if features["has_ip_address"]:
            breakdown.append("⚠️ URL uses an IP address instead of a domain name")
        if features["has_at_sign"]:
            breakdown.append("⚠️ URL contains @ symbol (possible redirect trick)")
        if features["has_suspicious_tld"]:
            breakdown.append("⚠️ Uses a commonly abused top-level domain")
        if not features["has_https"]:
            breakdown.append("⚠️ No HTTPS encryption")
        if features["suspicious_keyword_count"] >= 2:
            breakdown.append(
                f"⚠️ Contains {features['suspicious_keyword_count']} suspicious keywords "
                f"(e.g., login, verify, secure)"
            )
        if features["num_subdomains"] >= 3:
            breakdown.append(
                f"⚠️ Excessive subdomains ({features['num_subdomains']})"
            )
        if features["url_length"] > 75:
            breakdown.append(f"⚠️ Unusually long URL ({features['url_length']} chars)")
        if features["has_double_slash_redirect"]:
            breakdown.append("⚠️ Double-slash redirect detected in path")
        if features["has_non_standard_port"]:
            breakdown.append("⚠️ Non-standard port number in URL")
        if features.get("is_tunnel_or_free_host"):
            score += 2.0
        if features.get("is_tunnel_or_free_host"):
            breakdown.append("⚠️ Uses dynamic tunnel or free hosting domain (e.g. trycloudflare, webnode)")
        if features["is_shortened"]:
            breakdown.append("⚠️ URL shortened — destination hidden")
        if features["domain_has_digits"]:
            breakdown.append("ℹ️ Domain contains digits")
        if features["url_entropy"] > 4.5:
            breakdown.append("ℹ️ High randomness in URL (possible obfuscation)")

        if not breakdown:
            breakdown.append("✅ No major risk indicators found in URL structure")

        return breakdown
