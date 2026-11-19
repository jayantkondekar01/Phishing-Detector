"""
URL Feature Extractor.
Extracts 27 numerical features from a URL for ML classification.
Based on the feature engineering approach from the project presentation.
"""

import re
import math
from urllib.parse import urlparse
from collections import Counter

from utils.preprocessor import clean_url, calculate_entropy, extract_domain_parts
from config import SUSPICIOUS_TLDS, SUSPICIOUS_KEYWORDS, SHORTENER_DOMAINS, FREE_TUNNELS_AND_HOSTS


# ─── Regex patterns ──────────────────────────────────────────────────────────
_IP_PATTERN = re.compile(
    r"^(?:\d{1,3}\.){3}\d{1,3}$"           # IPv4
    r"|^\[?[0-9a-fA-F:]+\]?$"              # IPv6
)
_DIGIT_PATTERN = re.compile(r"\d")
_LETTER_PATTERN = re.compile(r"[a-zA-Z]")


def extract_features(url: str) -> dict:
    """
    Extract a comprehensive set of numerical features from a URL.

    Returns a dictionary of 27 features used by the ML classifier.
    Every value is numeric (int or float) so it can be fed directly
    into scikit-learn models.
    """
    url = clean_url(url)
    parsed = urlparse(url)
    hostname = parsed.hostname or ""
    path = parsed.path or ""
    query = parsed.query or ""
    full = parsed.geturl()

    domain_info = extract_domain_parts(url)

    features = {}

    # ── Length-based features ─────────────────────────────────────────────
    features["url_length"] = len(full)
    features["hostname_length"] = len(hostname)
    features["path_length"] = len(path)
    features["query_length"] = len(query)

    # ── Character count features ──────────────────────────────────────────
    features["num_dots"] = full.count(".")
    features["num_hyphens"] = full.count("-")
    features["num_underscores"] = full.count("_")
    features["num_slashes"] = full.count("/")
    features["num_question_marks"] = full.count("?")
    features["num_equals"] = full.count("=")
    features["num_at_signs"] = full.count("@")
    features["num_ampersands"] = full.count("&")
    features["num_percent"] = full.count("%")
    features["num_digits"] = len(_DIGIT_PATTERN.findall(full))

    # ── Ratio features ────────────────────────────────────────────────────
    total_len = max(len(full), 1)
    features["digit_ratio"] = round(features["num_digits"] / total_len, 4)
    num_letters = len(_LETTER_PATTERN.findall(full))
    features["letter_ratio"] = round(num_letters / total_len, 4)

    # ── Entropy ───────────────────────────────────────────────────────────
    features["url_entropy"] = calculate_entropy(full)
    features["hostname_entropy"] = calculate_entropy(hostname)

    # ── Binary / boolean features (as 0/1) ────────────────────────────────
    features["has_https"] = 1 if parsed.scheme == "https" else 0
    features["has_ip_address"] = 1 if _IP_PATTERN.match(hostname) else 0
    features["has_at_sign"] = 1 if "@" in full else 0
    features["has_double_slash_redirect"] = 1 if "//" in path else 0
    features["has_non_standard_port"] = (
        1 if parsed.port and parsed.port not in (80, 443) else 0
    )

    # ── Domain structure features ─────────────────────────────────────────
    features["num_subdomains"] = domain_info["num_subdomains"]
    features["domain_has_digits"] = 1 if _DIGIT_PATTERN.search(
        domain_info["registered_domain"]
    ) else 0

    # ── Suspicious content features ───────────────────────────────────────
    tld = domain_info["tld"].lower()
    features["has_suspicious_tld"] = 1 if tld in SUSPICIOUS_TLDS else 0

    lower_url = full.lower()
    keyword_count = sum(1 for kw in SUSPICIOUS_KEYWORDS if kw in lower_url)
    features["suspicious_keyword_count"] = keyword_count

    features["is_tunnel_or_free_host"] = (
        1 if any(th in hostname.lower() for th in FREE_TUNNELS_AND_HOSTS) else 0
    )

    # ── Shortened URL detection ───────────────────────────────────────────
    features["is_shortened"] = (
        1 if any(sd in hostname.lower() for sd in SHORTENER_DOMAINS) else 0
    )

    # ── Path token analysis ───────────────────────────────────────────────
    path_tokens = re.split(r"[/\-_.?=&#]", path)
    path_tokens = [t for t in path_tokens if t]
    features["longest_path_token"] = max((len(t) for t in path_tokens), default=0)

    return features


def get_feature_names() -> list[str]:
    """Return ordered feature names matching the extract_features output."""
    sample = extract_features("https://example.com")
    return list(sample.keys())


def features_to_vector(features: dict) -> list[float]:
    """Convert a feature dict to an ordered numeric vector for ML models."""
    return [float(features[name]) for name in get_feature_names()]
