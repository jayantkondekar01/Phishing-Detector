"""
FastAPI Backend — Real-Time Phishing Website Detection API.

Endpoints:
    POST /api/analyze        → Full analysis (URL + optional page content)
    GET  /api/health         → Health check
    POST /api/reload-model   → Hot-reload ML model after retraining

Privacy: No user browsing data is stored. All analysis is stateless.
"""

import logging
import time
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from config import API_HOST, API_PORT, CORS_ORIGINS, LOG_LEVEL
from models.ml_classifier import PhishingClassifier
from models.nlp_analyzer import analyze_content
from utils.domain_checker import get_domain_metadata
from utils.preprocessor import clean_url, clean_page_text

# ─── Logging ──────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=getattr(logging, LOG_LEVEL),
    format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
)
logger = logging.getLogger("phishing-api")

# ─── Global classifier instance ──────────────────────────────────────────────
classifier: PhishingClassifier = None


def get_classifier() -> PhishingClassifier:
    """Get or lazily initialize the classifier."""
    global classifier
    if classifier is None:
        logger.info("Initializing Phishing Classifier...")
        classifier = PhishingClassifier()
    return classifier


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Initialize the classifier on startup."""
    get_classifier()
    logger.info(
        "Classifier ready (ML model: %s)",
        "loaded" if classifier.is_ml_loaded else "heuristic fallback",
    )
    yield
    logger.info("Shutting down...")


# ─── FastAPI app ──────────────────────────────────────────────────────────────
app = FastAPI(
    title="Phishing Website Detection API",
    description="Real-time phishing detection using NLP & ML",
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],       # Chrome extensions send opaque origins
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ─── Request / Response models ───────────────────────────────────────────────

class AnalyzeRequest(BaseModel):
    url: str = Field(..., description="The URL to analyze")
    page_content: str = Field(
        None, description="Optional: raw HTML or text of the webpage"
    )
    check_domain: bool = Field(
        True, description="Whether to perform domain metadata checks (SSL, DNS)"
    )


class AnalyzeResponse(BaseModel):
    url: str
    is_phishing: bool
    confidence: float
    risk_level: str
    method: str
    breakdown: list
    url_features: dict
    domain_info: dict = None
    nlp_analysis: dict = None
    analysis_time_ms: float


# ─── Endpoints ───────────────────────────────────────────────────────────────

def fetch_page_content_sync(url: str) -> str:
    """Fetch live HTML with a fast 1.5s timeout for pasted URLs."""
    import urllib.request
    try:
        req = urllib.request.Request(
            url,
            headers={
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
            }
        )
        with urllib.request.urlopen(req, timeout=1.5) as resp:
            raw = resp.read(60000)
            return raw.decode("utf-8", errors="ignore")
    except Exception:
        return ""


@app.post("/api/analyze", response_model=AnalyzeResponse)
async def analyze_url(request: AnalyzeRequest):
    """
    Analyze a URL for phishing indicators.

    Combines:
    1. URL feature extraction → ML classifier (LSVC or heuristic)
    2. Domain metadata checks (SSL, DNS)
    3. Page content NLP analysis (DistilBERT or keyword-based)

    Returns a comprehensive risk assessment with confidence score.
    """
    start = time.perf_counter()

    if not request.url or len(request.url.strip()) < 4:
        raise HTTPException(status_code=400, detail="Invalid URL provided")

    url = clean_url(request.url)

    # 1. URL-based ML classification
    clf = get_classifier()
    ml_result = clf.predict(url)

    # 2. Domain metadata (optional)
    domain_info = None
    if request.check_domain:
        try:
            domain_info = get_domain_metadata(url)
        except Exception as exc:
            logger.warning("Domain check failed: %s", exc)
            domain_info = {"error": str(exc)}

    # 3. NLP content analysis
    raw_content = request.page_content
    # If no content provided by extension (e.g. user pasted URL manually), fetch it
    if not raw_content and domain_info and domain_info.get("dns", {}).get("resolves"):
        try:
            import asyncio
            loop = asyncio.get_event_loop()
            raw_content = await loop.run_in_executor(None, fetch_page_content_sync, url)
        except Exception:
            raw_content = None

    nlp_result = None
    if raw_content:
        cleaned_text = clean_page_text(raw_content)
        nlp_result = analyze_content(cleaned_text)

    # ── Combine scores ───────────────────────────────────────────────────
    final_confidence = ml_result["confidence"]
    combined_breakdown = list(ml_result["breakdown"])

    # Boost confidence if domain has risk signals
    if domain_info and isinstance(domain_info, dict) and "risk_signals" in domain_info:
        domain_risk_count = domain_info.get("risk_signal_count", 0)
        if domain_risk_count > 0:
            boost = domain_risk_count * 0.08
            final_confidence = min(final_confidence + boost, 1.0)
            for signal in domain_info.get("risk_signals", []):
                combined_breakdown.append(
                    "Domain: " + signal.replace("_", " ")
                )

    # If domain doesn't resolve at all (dead/taken-down phishing domain)
    if domain_info and not domain_info.get("dns", {}).get("resolves", True):
        final_confidence = max(final_confidence, 0.45)
        combined_breakdown.append("⚠️ Domain does not resolve (frequently indicates expired or taken-down phishing infrastructure)")

    # Boost confidence if NLP detects phishing content
    if nlp_result and nlp_result["nlp_score"] > 0.3:
        nlp_boost = nlp_result["nlp_score"] * 0.25
        final_confidence = min(final_confidence + nlp_boost, 1.0)
        for phrase in nlp_result.get("phishing_phrases", [])[:3]:
            combined_breakdown.append("Content: " + phrase)

    # Determine final risk level
    if final_confidence >= 0.8:
        risk_level = "high_risk"
    elif final_confidence >= 0.5:
        risk_level = "phishing"
    elif final_confidence >= 0.3:
        risk_level = "warning"
    else:
        risk_level = "safe"

    elapsed = (time.perf_counter() - start) * 1000

    return AnalyzeResponse(
        url=url,
        is_phishing=final_confidence >= 0.5,
        confidence=round(final_confidence, 4),
        risk_level=risk_level,
        method=ml_result["method"],
        breakdown=combined_breakdown,
        url_features=ml_result["features"],
        domain_info=domain_info,
        nlp_analysis=nlp_result,
        analysis_time_ms=round(elapsed, 2),
    )


@app.get("/api/health")
async def health_check():
    """Health check endpoint."""
    clf = get_classifier()
    return {
        "status": "healthy",
        "ml_model_loaded": clf.is_ml_loaded if clf else False,
        "version": "1.0.0",
    }


@app.post("/api/reload-model")
async def reload_model():
    """Hot-reload the ML model after retraining."""
    clf = get_classifier()
    clf.reload_model()
    return {
        "status": "reloaded",
        "ml_model_loaded": clf.is_ml_loaded,
    }


# ─── Run ──────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host=API_HOST, port=API_PORT)
