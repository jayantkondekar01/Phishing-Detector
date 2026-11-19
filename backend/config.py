"""
Configuration settings for the Phishing Detection Backend.
All environment-specific settings are centralized here.
"""

import os
from pathlib import Path

# ─── Paths ────────────────────────────────────────────────────────────────────
BASE_DIR = Path(__file__).resolve().parent
TRAINED_MODELS_DIR = BASE_DIR / "trained_models"
TRAINED_MODELS_DIR.mkdir(exist_ok=True)

# ─── Model file paths ────────────────────────────────────────────────────────
ML_MODEL_PATH = TRAINED_MODELS_DIR / "phishing_classifier.joblib"
VECTORIZER_PATH = TRAINED_MODELS_DIR / "url_vectorizer.joblib"
SCALER_PATH = TRAINED_MODELS_DIR / "feature_scaler.joblib"
NLP_MODEL_NAME = "distilbert-base-uncased"

# ─── Server ───────────────────────────────────────────────────────────────────
API_HOST = os.getenv("API_HOST", "127.0.0.1")
API_PORT = int(os.getenv("API_PORT", "8000"))
CORS_ORIGINS = ["chrome-extension://*", "http://localhost:*"]

# ─── Detection thresholds ────────────────────────────────────────────────────
PHISHING_THRESHOLD = 0.5          # probability above this → phishing
HIGH_RISK_THRESHOLD = 0.8         # probability above this → high risk
WARNING_THRESHOLD = 0.3           # probability above this → suspicious

# ─── Feature extraction ──────────────────────────────────────────────────────
SUSPICIOUS_TLDS = {
    "tk", "ml", "ga", "cf", "gq", "top", "xyz", "work", "click",
    "link", "info", "online", "site", "website", "space", "pw",
    "buzz", "surf", "rest", "fit", "icu", "cam", "monster",
    "live", "sbs", "cfd", "vip", "cc", "pro", "shop", "lat",
    "quest", "cyou", "beauty", "bond", "hair", "skin", "makeup",
    "uno", "fun", "press", "host", "club", "app",
}

SUSPICIOUS_KEYWORDS = {
    "login", "signin", "sign-in", "verify", "verification", "secure",
    "account", "update", "confirm", "banking", "paypal", "ebay",
    "amazon", "apple", "microsoft", "google", "facebook", "netflix",
    "password", "credential", "suspend", "restrict", "unlock",
    "wallet", "crypto", "expire", "urgent", "alert", "unusual",
    "activity", "support", "helpdesk", "authenticate", "validate",
    "portal", "auth", "suporte", "bonus", "reward", "billing",
    "att", "chase", "wellsfargo", "bankofamerica", "citi",
}

FREE_TUNNELS_AND_HOSTS = {
    "trycloudflare.com", "webnode.page", "firebaseapp.com",
    "pages.dev", "workers.dev", "ngrok-free.app", "github.io",
    "vercel.app", "netlify.app", "glitch.me", "000webhostapp.com",
}

SHORTENER_DOMAINS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "buff.ly",
    "ow.ly", "adf.ly", "rb.gy", "cutt.ly", "shorturl.at",
}

# ─── Logging ──────────────────────────────────────────────────────────────────
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")
