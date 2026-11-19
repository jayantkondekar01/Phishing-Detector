"""
Text and URL preprocessing utilities.
Handles tokenization, cleaning, and normalization of URLs and webpage content.
"""

import re
import math
from urllib.parse import urlparse, unquote
from collections import Counter


def clean_url(url: str) -> str:
    """Normalize and decode a URL for analysis."""
    url = url.strip()
    url = unquote(url)
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    return url


def tokenize_url(url: str) -> list[str]:
    """
    Split a URL into meaningful tokens.
    Breaks on dots, slashes, hyphens, underscores, and query separators.
    """
    parsed = urlparse(clean_url(url))
    raw = f"{parsed.netloc}{parsed.path}{parsed.query}{parsed.fragment}"
    tokens = re.split(r"[./\-_?=&#@:~%+]", raw)
    return [t.lower() for t in tokens if t and len(t) > 1]


def calculate_entropy(text: str) -> float:
    """Calculate Shannon entropy of a string — high entropy signals randomness."""
    if not text:
        return 0.0
    counter = Counter(text)
    length = len(text)
    entropy = -sum(
        (count / length) * math.log2(count / length)
        for count in counter.values()
    )
    return round(entropy, 4)


def clean_page_text(html_text: str) -> str:
    """
    Strip HTML tags and normalize whitespace from raw page content.
    Returns plain text suitable for NLP analysis.
    """
    text = re.sub(r"<script[^>]*>.*?</script>", "", html_text, flags=re.DOTALL | re.IGNORECASE)
    text = re.sub(r"<style[^>]*>.*?</style>", "", text, flags=re.DOTALL | re.IGNORECASE)
    text = re.sub(r"<[^>]+>", " ", text)
    text = re.sub(r"&[a-zA-Z]+;", " ", text)
    text = re.sub(r"\s+", " ", text)
    return text.strip()


def extract_domain_parts(url: str) -> dict:
    """Parse a URL into its structural components."""
    parsed = urlparse(clean_url(url))
    hostname = parsed.hostname or ""
    parts = hostname.split(".")
    
    # Determine TLD and registered domain
    tld = parts[-1] if parts else ""
    registered_domain = ".".join(parts[-2:]) if len(parts) >= 2 else hostname
    subdomain = ".".join(parts[:-2]) if len(parts) > 2 else ""
    
    return {
        "scheme": parsed.scheme,
        "hostname": hostname,
        "subdomain": subdomain,
        "registered_domain": registered_domain,
        "tld": tld,
        "port": parsed.port,
        "path": parsed.path,
        "query": parsed.query,
        "fragment": parsed.fragment,
        "num_subdomains": len(parts) - 2 if len(parts) > 2 else 0,
    }
