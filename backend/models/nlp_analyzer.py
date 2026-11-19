"""
NLP Analyzer — DistilBERT-based webpage content classifier.

Analyzes the visible text content of a webpage to detect phishing
language patterns (urgency, credential requests, impersonation).
Uses Hugging Face transformers with DistilBERT.
"""

import logging
from config import NLP_MODEL_NAME

logger = logging.getLogger(__name__)

# Global model/tokenizer — loaded lazily on first use
_model = None
_tokenizer = None
_device = None
_available = None  # None = not checked yet


def _ensure_loaded() -> bool:
    """Lazily load DistilBERT model and tokenizer."""
    global _model, _tokenizer, _device, _available

    if _available is not None:
        return _available

    try:
        import torch
        from transformers import DistilBertTokenizer, DistilBertForSequenceClassification

        _device = "cuda" if torch.cuda.is_available() else "cpu"
        logger.info("Loading DistilBERT model (%s) on %s…", NLP_MODEL_NAME, _device)

        _tokenizer = DistilBertTokenizer.from_pretrained(NLP_MODEL_NAME)
        # Using 2-class classification: 0=legitimate, 1=phishing
        _model = DistilBertForSequenceClassification.from_pretrained(
            NLP_MODEL_NAME, num_labels=2
        )
        _model.to(_device)
        _model.eval()
        _available = True
        logger.info("DistilBERT model loaded successfully")
    except Exception as exc:
        logger.warning(
            "DistilBERT unavailable (install torch + transformers to enable): %s", exc
        )
        _available = False

    return _available


# ── Phishing language patterns for keyword-based fallback ────────────────────

_PHISHING_PATTERNS = {
    "high": [
        "verify your account", "confirm your identity", "update your payment",
        "suspended", "unauthorized access", "click here immediately",
        "your account will be closed", "confirm your password",
        "verify your information", "unusual activity detected",
        "security alert", "action required immediately",
        "your account has been compromised", "reset your password now",
    ],
    "medium": [
        "dear customer", "dear user", "valued customer",
        "click the link below", "log in to your account",
        "expire", "within 24 hours", "within 48 hours",
        "limited time", "act now", "don't ignore",
        "failure to", "will result in",
    ],
    "low": [
        "congratulations", "you have won", "selected winner",
        "claim your prize", "free gift", "lottery",
        "inheritance", "beneficiary",
    ],
}


def analyze_content(text: str) -> dict:
    """
    Analyze webpage text content for phishing indicators.

    Args:
        text: Cleaned plaintext from the webpage (see preprocessor.clean_page_text).

    Returns:
        dict with:
            - nlp_score (float 0-1): phishing probability from NLP
            - nlp_method (str): 'distilbert' or 'keyword'
            - phishing_phrases (list): detected suspicious phrases
            - content_risk_level (str): safe / warning / phishing
    """
    if not text or len(text.strip()) < 20:
        return {
            "nlp_score": 0.0,
            "nlp_method": "skipped",
            "phishing_phrases": [],
            "content_risk_level": "safe",
            "detail": "Insufficient text content for analysis",
        }

    if _ensure_loaded():
        return _analyze_with_distilbert(text)
    else:
        return _analyze_with_keywords(text)


def _analyze_with_distilbert(text: str) -> dict:
    """Run DistilBERT inference on page content."""
    import torch

    # Truncate to 512 tokens (DistilBERT limit)
    truncated = text[:2048]  # rough char limit before tokenization

    inputs = _tokenizer(
        truncated,
        return_tensors="pt",
        truncation=True,
        max_length=512,
        padding=True,
    )
    inputs = {k: v.to(_device) for k, v in inputs.items()}

    with torch.no_grad():
        outputs = _model(**inputs)
        probs = torch.softmax(outputs.logits, dim=1)
        phishing_prob = probs[0][1].item()  # class 1 = phishing

    # Also run keyword detection for explainability
    keyword_result = _analyze_with_keywords(text)

    risk_level = (
        "phishing" if phishing_prob >= 0.6
        else "warning" if phishing_prob >= 0.3
        else "safe"
    )

    return {
        "nlp_score": round(phishing_prob, 4),
        "nlp_method": "distilbert",
        "phishing_phrases": keyword_result["phishing_phrases"],
        "content_risk_level": risk_level,
    }


def _analyze_with_keywords(text: str) -> dict:
    """
    Keyword-based fallback when DistilBERT is not available.
    Scans for known phishing language patterns.
    """
    text_lower = text.lower()
    detected = []
    score = 0.0

    for phrase in _PHISHING_PATTERNS["high"]:
        if phrase in text_lower:
            detected.append(f"🔴 {phrase}")
            score += 3.0

    for phrase in _PHISHING_PATTERNS["medium"]:
        if phrase in text_lower:
            detected.append(f"🟡 {phrase}")
            score += 1.5

    for phrase in _PHISHING_PATTERNS["low"]:
        if phrase in text_lower:
            detected.append(f"🟠 {phrase}")
            score += 1.0

    # Normalize to 0-1
    max_possible = 15.0
    probability = min(score / max_possible, 1.0)

    risk_level = (
        "phishing" if probability >= 0.5
        else "warning" if probability >= 0.2
        else "safe"
    )

    return {
        "nlp_score": round(probability, 4),
        "nlp_method": "keyword",
        "phishing_phrases": detected[:10],  # top 10
        "content_risk_level": risk_level,
    }
