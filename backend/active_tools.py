"""
active_tools.py
---------------
Active probing utility functions for MSME Shield.

Each function is self-contained with a safe fallback so the API never
crashes during a live demo if the external service is unreachable.

Tools implemented:
    check_password  — zxcvbn password strength estimator (0–4 score)
    check_ssl       — CertSpotter SSL certificate days-remaining check
"""

from __future__ import annotations

from datetime import datetime, timezone

import requests

# ---------------------------------------------------------------------------
# Password Strength (zxcvbn)
# ---------------------------------------------------------------------------

def check_password(password: str) -> int:
    """
    Estimate password strength using the zxcvbn algorithm.

    zxcvbn scores passwords on a scale of 0–4:
        0 — Too guessable (e.g., "password", "123456")
        1 — Very guessable
        2 — Somewhat guessable
        3 — Safely unguessable
        4 — Very unguessable

    MSME Shield policy: scores < 3 are considered weak and trigger a
    -10 point penalty on the Governance Score.

    Args:
        password: The plaintext password to evaluate.

    Returns:
        Integer score in range [0, 4]. Returns 0 (worst case) on error.
    """
    try:
        from zxcvbn import zxcvbn  # lazy import — not needed at module load
        result = zxcvbn(password)
        return int(result["score"])
    except Exception:
        return 0  # fail-secure: treat as weak on any error


# ---------------------------------------------------------------------------
# SSL Expiry (CertSpotter API)
# ---------------------------------------------------------------------------

_CERTSPOTTER_URL = (
    "https://api.certspotter.com/v1/issuances"
    "?domain={domain}&include_subdomains=false&expand=dns_names&expand=cert"
)
_SSL_SAFE_FALLBACK = 45   # days — treat as healthy when API is unreachable
_SSL_TIMEOUT_SEC   = 8


def check_ssl(domain: str) -> int:
    """
    Query CertSpotter for the SSL certificate expiry of *domain* and return
    the number of days until the certificate expires.

    Uses the first issuance returned by the API. Only certificates whose
    ``not_after`` date is in the future are considered.

    MSME Shield policy: <= 30 days remaining triggers a +15 Technical
    Score penalty (expiring cert = unmanaged attack surface).

    Args:
        domain: Apex domain to inspect (e.g., "example.com").

    Returns:
        Days remaining as int. Returns ``_SSL_SAFE_FALLBACK`` (45) on any
        network or parse error so the demo never crashes.
    """
    try:
        url = _CERTSPOTTER_URL.format(domain=domain)
        response = requests.get(url, timeout=_SSL_TIMEOUT_SEC)
        response.raise_for_status()
        issuances = response.json()

        if not issuances:
            return _SSL_SAFE_FALLBACK   # no cert found → assume healthy

        # Pick the soonest-expiring cert from the returned issuances
        min_days = _SSL_SAFE_FALLBACK
        now = datetime.now(tz=timezone.utc)

        for issuance in issuances:
            not_after_str = (
                issuance.get("cert", {}).get("not_after")
                or issuance.get("not_after")
            )
            if not not_after_str:
                continue
            # CertSpotter uses ISO-8601 with 'Z' suffix
            not_after = datetime.fromisoformat(
                not_after_str.replace("Z", "+00:00")
            )
            days_left = (not_after - now).days
            if days_left < min_days:
                min_days = days_left

        return max(min_days, 0)   # clamp negative (already expired) to 0

    except Exception:
        return _SSL_SAFE_FALLBACK
