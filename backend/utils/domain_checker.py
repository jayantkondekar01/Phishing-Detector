"""
Domain metadata checker.
Extracts domain reputation signals: age, SSL, WHOIS data, and DNS records.
Works without external API keys — uses only public data.
"""

import ssl
import socket
import logging
from datetime import datetime, timezone
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

# ─── Timeout for network lookups (seconds) ────────────────────────────────────
_SOCKET_TIMEOUT = 1.5


def check_ssl_certificate(hostname: str) -> dict:
    """
    Retrieve basic SSL certificate information for a hostname.
    Returns issuer, validity dates, and whether the cert is valid.
    """
    result = {
        "has_ssl": False,
        "issuer": None,
        "valid_from": None,
        "valid_to": None,
        "is_valid": False,
        "days_remaining": None,
    }
    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=_SOCKET_TIMEOUT) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                result["has_ssl"] = True
                # Issuer
                issuer_parts = dict(x[0] for x in cert.get("issuer", []))
                result["issuer"] = issuer_parts.get("organizationName", "Unknown")
                # Validity
                not_before = cert.get("notBefore", "")
                not_after = cert.get("notAfter", "")
                if not_before and not_after:
                    fmt = "%b %d %H:%M:%S %Y %Z"
                    valid_from = datetime.strptime(not_before, fmt)
                    valid_to = datetime.strptime(not_after, fmt)
                    result["valid_from"] = valid_from.isoformat()
                    result["valid_to"] = valid_to.isoformat()
                    now = datetime.now(timezone.utc).replace(tzinfo=None)
                    result["is_valid"] = valid_from <= now <= valid_to
                    result["days_remaining"] = (valid_to - now).days
    except Exception as exc:
        logger.debug("SSL check failed for %s: %s", hostname, exc)
    return result


def check_domain_resolution(hostname: str) -> dict:
    """Check if the domain resolves to an IP and if it uses an IP directly."""
    result = {
        "resolves": False,
        "ip_address": None,
        "is_ip_based": False,
    }
    # Check if hostname is already an IP
    try:
        socket.inet_aton(hostname)
        result["is_ip_based"] = True
        result["resolves"] = True
        result["ip_address"] = hostname
        return result
    except socket.error:
        pass
    # DNS resolution
    try:
        ip = socket.gethostbyname(hostname)
        result["resolves"] = True
        result["ip_address"] = ip
    except socket.gaierror:
        logger.debug("Domain %s does not resolve", hostname)
    return result


def get_domain_metadata(url: str) -> dict:
    """
    Aggregate all available domain metadata for a URL.
    Returns SSL info, DNS resolution, and risk indicators.
    Privacy-preserving: no user data is stored or transmitted.
    """
    parsed = urlparse(url if url.startswith("http") else f"http://{url}")
    hostname = parsed.hostname or ""

    # Check DNS resolution first
    dns_info = check_domain_resolution(hostname)

    # Only attempt SSL connection if domain resolves
    if dns_info["resolves"] and not dns_info["is_ip_based"]:
        ssl_info = check_ssl_certificate(hostname)
    else:
        ssl_info = {
            "has_ssl": False,
            "issuer": None,
            "valid_from": None,
            "valid_to": None,
            "is_valid": False,
            "days_remaining": None,
        }

    # Calculate domain-level risk signals
    risk_signals = []
    if not ssl_info["has_ssl"]:
        risk_signals.append("no_ssl")
    if dns_info["is_ip_based"]:
        risk_signals.append("ip_based_url")
    if ssl_info["has_ssl"] and ssl_info["days_remaining"] is not None:
        if ssl_info["days_remaining"] < 30:
            risk_signals.append("ssl_expiring_soon")
    if not dns_info["resolves"]:
        risk_signals.append("domain_not_resolving")

    return {
        "hostname": hostname,
        "ssl": ssl_info,
        "dns": dns_info,
        "risk_signals": risk_signals,
        "risk_signal_count": len(risk_signals),
    }
