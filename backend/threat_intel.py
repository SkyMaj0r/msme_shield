"""
threat_intel.py
---------------
External threat-intelligence layer for MSME Shield.

Responsibilities:
    - Fetch CVE data from NVD API v2.0 (with CVSS scores).
    - Fetch exploit probability from EPSS API (FIRST.org).
    - Check End-of-Life status from endoflife.date API.
    - Combine all three sources into an enriched software inventory.

STRICT CONSTRAINTS (never violate):
    - Zero math logic in this file — return raw enriched data only.
    - Zero database calls in this file.
    - Zero Pydantic models in this file.
    - All API keys/URLs come from constants defined at the top of this file.
    - Every function fails gracefully — network errors never crash the pipeline.
    - All imports are absolute (uvicorn runs from backend/).

Pillar alignment:
    Output feeds into risk_engine.calculate_technical_score() which
    applies the MRQM formula:
        MRQM = (0.45 × tech) + (0.35 × gov) + (0.20 × exp)
    ref: NIST SP 800-30 Rev 1, Tables G-2/G-3
"""

from __future__ import annotations

import logging
import time
from datetime import date, datetime
from typing import Optional

import requests

# ---------------------------------------------------------------------------
# Logger
# ---------------------------------------------------------------------------
log = logging.getLogger("msme_shield.threat_intel")

# ---------------------------------------------------------------------------
# API Constants — no magic literals anywhere else in this file
# ---------------------------------------------------------------------------
NVD_BASE_URL            = "https://services.nvd.nist.gov/rest/json/cves/2.0"
EPSS_BASE_URL           = "https://api.first.org/data/v1/epss"
EOL_BASE_URL            = "https://endoflife.date/api"

NVD_RESULTS_PER_PAGE    = 5       # top 5 most recent CVEs per software
NVD_SLEEP_WITH_KEY      = 0.2     # seconds between NVD calls with API key
NVD_SLEEP_WITHOUT_KEY   = 0.6     # seconds between NVD calls without API key
NVD_REQUEST_TIMEOUT     = 15      # seconds
EPSS_REQUEST_TIMEOUT    = 10      # seconds
EOL_REQUEST_TIMEOUT     = 8       # seconds

DEFAULT_CVSS_FALLBACK   = 5.0     # used when NVD reports no CVSS score
DEFAULT_EPSS_FALLBACK   = 0.0     # used when EPSS has no record for a CVE

# ---------------------------------------------------------------------------
# EOL slug mapping — common software names → endoflife.date product slugs
# Longer / more-specific keys must come first so substring matches work.
# ---------------------------------------------------------------------------
_EOL_SLUG_MAP: dict[str, str] = {
    "apache http server":  "apache",
    "windows server":      "windows-server",
    "node.js":             "nodejs",
    "nodejs":              "nodejs",
    "spring boot":         "spring-boot",
    "python":              "python",
    "php":                 "php",
    "mysql":               "mysql",
    "postgresql":          "postgresql",
    "nginx":               "nginx",
    "ubuntu":              "ubuntu",
    "java":                "java",
}


# ===========================================================================
# 1. NVD CVE Fetcher
# ===========================================================================

def fetch_nvd_cves(software_name: str, api_key: Optional[str]) -> list[dict]:
    """
    Query NVD API v2.0 for CVEs matching *software_name*.

    Fetches the top ``NVD_RESULTS_PER_PAGE`` (5) most recent CVEs.
    CVSS scoring precedence: v3.1 base score → v2.0 base score →
    ``DEFAULT_CVSS_FALLBACK`` (5.0).

    Rate limiting:
        - With API key:    ``NVD_SLEEP_WITH_KEY``    seconds after each call.
        - Without API key: ``NVD_SLEEP_WITHOUT_KEY`` seconds after each call.

    Args:
        software_name: Plain-English software name (e.g. "Apache HTTP Server").
        api_key:       NVD API key from .env, or None.

    Returns:
        List of CVE dicts:
            [{"cve_id": str, "cvss_score": float, "description": str}, ...]
        Returns [] on any network/parse error.
    """
    log.info("NVD query: software=%r  resultsPerPage=%d", software_name, NVD_RESULTS_PER_PAGE)

    headers: dict[str, str] = {}
    if api_key:
        headers["apiKey"] = api_key

    params = {
        "keywordSearch": software_name,
        "resultsPerPage": NVD_RESULTS_PER_PAGE,
    }

    try:
        response = requests.get(
            NVD_BASE_URL,
            params=params,
            headers=headers,
            timeout=NVD_REQUEST_TIMEOUT,
        )
        response.raise_for_status()
        data = response.json()
    except Exception as exc:
        log.warning("NVD API call failed for %r: %s", software_name, exc)
        return []
    finally:
        # Always sleep to respect rate limits, even if the call failed.
        sleep_secs = NVD_SLEEP_WITH_KEY if api_key else NVD_SLEEP_WITHOUT_KEY
        time.sleep(sleep_secs)

    vulnerabilities = data.get("vulnerabilities", [])
    if not vulnerabilities:
        log.warning("NVD returned 0 CVEs for software=%r", software_name)

    cve_list: list[dict] = []
    for item in vulnerabilities:
        cve_block = item.get("cve", {})
        cve_id: str = cve_block.get("id", "UNKNOWN")

        # --- CVSS score extraction (v3.1 preferred, v2.0 fallback) ----------
        cvss_score: float = DEFAULT_CVSS_FALLBACK
        metrics = cve_block.get("metrics", {})

        # v3.1 path
        for entry in metrics.get("cvssMetricV31", []):
            try:
                cvss_score = float(entry["cvssData"]["baseScore"])
                break
            except (KeyError, TypeError, ValueError):
                continue

        # v2.0 fallback (only if no v3.1 found)
        if cvss_score == DEFAULT_CVSS_FALLBACK:
            for entry in metrics.get("cvssMetricV2", []):
                try:
                    cvss_score = float(entry["cvssData"]["baseScore"])
                    break
                except (KeyError, TypeError, ValueError):
                    continue

        # --- Description (first 200 chars, English preferred) ---------------
        description: str = ""
        for desc_entry in cve_block.get("descriptions", []):
            if desc_entry.get("lang") == "en":
                description = desc_entry.get("value", "")[:200]
                break

        cve_list.append({
            "cve_id":      cve_id,
            "cvss_score":  cvss_score,
            "description": description,
        })

    log.info("NVD: %d CVE(s) found for %r", len(cve_list), software_name)
    return cve_list


# ===========================================================================
# 2. EPSS Batch Fetcher
# ===========================================================================

def fetch_epss_scores(cve_ids: list[str]) -> dict[str, float]:
    """
    Fetch EPSS exploit-probability scores for a batch of CVE IDs.

    EPSS (Exploit Prediction Scoring System) from FIRST.org estimates
    the probability that a CVE will be exploited in the wild within 30 days.
    Source: Jacobs et al., IEEE S&P 2021 / FIRST.org.

    Sends a single API call with all CVE IDs comma-joined (up to 100).
    CVEs absent from the response are assigned ``DEFAULT_EPSS_FALLBACK`` (0.0).

    Args:
        cve_ids: List of CVE IDs to look up (e.g. ["CVE-2021-41773", ...]).

    Returns:
        Dict mapping cve_id → epss_probability (float, 0.0–1.0).
        Returns {} on any network/parse error.
    """
    if not cve_ids:
        log.info("EPSS: no CVE IDs to look up — skipping batch call.")
        return {}

    log.info("EPSS batch fetch: %d CVE ID(s)", len(cve_ids))

    params = {"cve": ",".join(cve_ids)}

    try:
        response = requests.get(
            EPSS_BASE_URL,
            params=params,
            timeout=EPSS_REQUEST_TIMEOUT,
        )
        response.raise_for_status()
        data = response.json()
    except Exception as exc:
        log.warning("EPSS API call failed: %s", exc)
        return {}

    epss_map: dict[str, float] = {}
    for entry in data.get("data", []):
        try:
            cve_id = entry["cve"]
            prob   = float(entry["epss"])
            epss_map[cve_id] = prob
        except (KeyError, TypeError, ValueError) as exc:
            log.warning("EPSS: could not parse entry %r — %s", entry, exc)

    log.info("EPSS: received scores for %d / %d CVE(s)", len(epss_map), len(cve_ids))
    return epss_map


# ===========================================================================
# 3. EOL Status Checker
# ===========================================================================

def _resolve_eol_slug(software_name: str) -> str:
    """
    Map a human-readable software name to an endoflife.date product slug.

    Checks ``_EOL_SLUG_MAP`` first (longest-key match wins), then falls
    back to lowercasing and replacing spaces with hyphens.

    Args:
        software_name: e.g. "Apache HTTP Server", "Python".

    Returns:
        Slug string, e.g. "apache", "python".
    """
    normalized = software_name.lower().strip()
    # Iterate from longest key to shortest for best specificity
    for key in sorted(_EOL_SLUG_MAP, key=len, reverse=True):
        if key in normalized:
            return _EOL_SLUG_MAP[key]
    # Fallback: lowercase with spaces replaced by hyphens
    return normalized.replace(" ", "-")


def check_eol_status(software_name: str, version: str) -> bool:
    """
    Determine whether a given software version is End-of-Life (EOL).

    Queries the endoflife.date public API. EOL precedence:
        - If the ``eol`` field is False → actively maintained → return False.
        - If the ``eol`` field is a date string and that date is in the past
          → return True (EOL confirmed).
        - If the product slug is not found (HTTP 404) → return False (unknown;
          fail-open — do not penalise for unknown products).
        - On any other exception → return False (fail-open).

    EOL penalty is applied in risk_engine.py (EOL_PENALTY = 20.0).
    Basis: CISA KEV catalog — 300+ entries for post-EOL software.

    Args:
        software_name: e.g. "Apache HTTP Server".
        version:       e.g. "2.4.49".

    Returns:
        True if EOL confirmed, False otherwise.
    """
    slug = _resolve_eol_slug(software_name)
    url  = f"{EOL_BASE_URL}/{slug}.json"
    log.info("EOL check: software=%r  slug=%r  version=%r", software_name, slug, version)

    try:
        response = requests.get(url, timeout=EOL_REQUEST_TIMEOUT)

        if response.status_code == 404:
            log.info("EOL: product slug %r not found (404) — treating as supported.", slug)
            return False

        response.raise_for_status()
        cycles: list[dict] = response.json()
    except requests.exceptions.HTTPError as exc:
        log.warning("EOL API HTTP error for slug=%r: %s", slug, exc)
        return False
    except Exception as exc:
        log.warning("EOL API call failed for slug=%r: %s", slug, exc)
        return False

    # Normalize version for prefix matching (e.g. "2.7.18" matches cycle "2.7")
    version_str = str(version).strip()

    for cycle in cycles:
        cycle_label = str(cycle.get("cycle", "")).strip()
        # Match if version starts with the cycle label (e.g. "2.7" in "2.7.18")
        if not (version_str == cycle_label or version_str.startswith(cycle_label + ".")):
            continue

        eol_field = cycle.get("eol", False)

        # eol = False means still actively supported
        if eol_field is False:
            log.info("EOL: %r %r  → actively supported (eol=False).", software_name, version)
            return False

        # eol = True means EOL with no specific date
        if eol_field is True:
            log.info("EOL: %r %r  → EOL confirmed (eol=True).", software_name, version)
            return True

        # eol = "YYYY-MM-DD" — compare to today
        if isinstance(eol_field, str):
            try:
                eol_date = date.fromisoformat(eol_field)
                is_eol   = eol_date <= date.today()
                log.info(
                    "EOL: %r %r  eol_date=%s  is_eol=%s",
                    software_name, version, eol_date, is_eol,
                )
                return is_eol
            except ValueError:
                log.warning("EOL: could not parse date %r for %r.", eol_field, software_name)
                return False

    # No matching cycle found — version not in database; treat as supported
    log.info("EOL: no matching cycle for %r %r  slug=%r — treating as supported.", software_name, version, slug)
    return False


# ===========================================================================
# 4. Master Enrichment Orchestrator
# ===========================================================================

def enrich_software_inventory(
    software_list: list[dict],
    api_key: Optional[str],
) -> dict:
    """
    Orchestrate NVD + EPSS + EOL enrichment for a full software inventory.

    Pipeline:
        1. Call ``fetch_nvd_cves()`` for each software item (sequential,
           rate-limited). Collect all CVE IDs across all software.
        2. ONE batched call to ``fetch_epss_scores()`` for all CVE IDs.
        3. For each software item:
            a. Call ``check_eol_status()``.
            b. Merge EPSS probabilities into each CVE finding.
            c. Compute ``per_cve_risk = cvss_score × epss_probability``.
            d. Compute ``software_risk = max(per_cve_risk, default=0.0)``.
            e. Build the software finding dict.

    Args:
        software_list: List of dicts from agent:
                       [{"name": str, "version": str}, ...]
        api_key:       NVD API key (None if unavailable).

    Returns:
        {
            "findings":    [list of per-software finding dicts],
            "any_eol":     bool,        # True if ANY software is EOL
            "all_cve_ids": [str, ...]   # flat list of all CVE IDs discovered
        }

        Per-software finding dict structure:
        {
            "software_name": str,
            "version":       str,
            "is_eol":        bool,
            "cves":          [{"cve_id", "cvss_score", "epss_probability",
                               "description", "per_cve_risk"}, ...],
            "software_risk": float   # max per_cve_risk across this software's CVEs
        }

    Note:
        This function contains NO math — it returns raw enriched data.
        The MRQM formula (tech_score computation) lives entirely in
        risk_engine.py.
    """
    if not software_list:
        log.info("enrich_software_inventory: empty inventory — returning defaults.")
        return {"findings": [], "any_eol": False, "all_cve_ids": []}

    log.info("Starting enrichment for %d software item(s).", len(software_list))

    # -----------------------------------------------------------------------
    # Phase 1 — NVD queries (one per software, rate-limited)
    # -----------------------------------------------------------------------
    # intermediate structure: list of (software_item, raw_cve_list)
    nvd_results: list[tuple[dict, list[dict]]] = []
    all_cve_ids: list[str] = []

    for item in software_list:
        name    = item.get("name", "unknown")
        version = item.get("version", "")
        raw_cves = fetch_nvd_cves(name, api_key)
        nvd_results.append((item, raw_cves))
        for cve in raw_cves:
            cve_id = cve.get("cve_id", "")
            if cve_id and cve_id not in all_cve_ids:
                all_cve_ids.append(cve_id)

    # -----------------------------------------------------------------------
    # Phase 2 — EPSS batch call (single call for ALL CVE IDs)
    # -----------------------------------------------------------------------
    epss_map: dict[str, float] = fetch_epss_scores(all_cve_ids)

    # -----------------------------------------------------------------------
    # Phase 3 — EOL check + merge + per-software finding assembly
    # -----------------------------------------------------------------------
    findings: list[dict] = []
    any_eol:  bool       = False

    for (item, raw_cves) in nvd_results:
        name    = item.get("name", "unknown")
        version = item.get("version", "")

        # EOL check
        is_eol = check_eol_status(name, version)
        if is_eol:
            any_eol = True

        # Merge EPSS into CVE findings
        enriched_cves: list[dict] = []
        for cve in raw_cves:
            cve_id          = cve.get("cve_id", "")
            cvss_score      = cve.get("cvss_score", DEFAULT_CVSS_FALLBACK)
            epss_probability = epss_map.get(cve_id, DEFAULT_EPSS_FALLBACK)
            per_cve_risk    = round(cvss_score * epss_probability, 4)

            enriched_cves.append({
                "cve_id":           cve_id,
                "cvss_score":       cvss_score,
                "epss_probability": epss_probability,
                "description":      cve.get("description", ""),
                "per_cve_risk":     per_cve_risk,
            })

        # software_risk = max per_cve_risk (0.0 if no CVEs found)
        software_risk: float = (
            max(c["per_cve_risk"] for c in enriched_cves)
            if enriched_cves
            else 0.0
        )

        findings.append({
            "software_name": name,
            "version":       version,
            "is_eol":        is_eol,
            "cves":          enriched_cves,
            "software_risk": round(software_risk, 4),
        })

        log.info(
            "Enriched: %r %r  is_eol=%s  cves=%d  software_risk=%.4f",
            name, version, is_eol, len(enriched_cves), software_risk,
        )

    result = {
        "findings":    findings,
        "any_eol":     any_eol,
        "all_cve_ids": all_cve_ids,
    }

    log.info(
        "Enrichment complete: %d software item(s)  any_eol=%s  total_cve_ids=%d",
        len(findings), any_eol, len(all_cve_ids),
    )
    return result
