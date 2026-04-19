"""
risk_engine.py
--------------
Pure math layer for the MSME Shield Master Risk Quantification Metric (MRQM).

STRICT CONSTRAINTS (never violate):
    - Zero HTTP calls in this file.
    - Zero database calls in this file.
    - Zero Pydantic models in this file.
    - No imports from threat_intel, api, schemas, or models.
    - All penalty/weight constants are named. No magic numbers anywhere.
    - Every function is stateless and side-effect-free.

MRQM Formula:
    MRQM = (0.45 × tech_score) + (0.35 × gov_score) + (0.20 × exp_score)

Pillar weights grounded in:
    NIST SP 800-30 Rev 1, Tables G-2/G-3 (threat likelihood × impact weighting)

Governance framework hybrid rule:
    CERT-In statutory directives take precedence and carry the highest raw_weight.
    Where no CERT-In directive exists, NIST CSF 2.0 applies as best-practice.
    References:
        - CERT-In Directions April 28 2022 (MeitY / IT Act 2000, Section 70B)
        - NIST Cybersecurity Framework 2.0 (NIST, Feb 2024)
"""

from __future__ import annotations

import logging
from typing import Any

# ---------------------------------------------------------------------------
# Logger — pure; never writes to DB or makes HTTP calls
# ---------------------------------------------------------------------------
log = logging.getLogger("msme_shield.risk_engine")


# ===========================================================================
# CONSTANTS — All penalty values are named. Zero magic numbers below.
# ===========================================================================

# ---------------------------------------------------------------------------
# Technical score penalties
# ---------------------------------------------------------------------------

EOL_PENALTY: float = 20.0
# Basis: CISA KEV catalog — 300+ actively exploited vulnerabilities in post-EOL
# software. Flat additive penalty because EOL risk is categorical, not
# probabilistic: no security patch will ever be issued. A single known CVE
# against unsupported software is permanently weaponisable.

SSL_EXPIRY_PENALTY: float = 15.0
# Basis: Industry standard (Google, Mozilla, Cloudflare). Certificates expiring
# within 30 days represent an active infrastructure failure: broken API trust
# chains, browser warnings, and potential MITM exposure from cert mis-issuance.

SSL_EXPIRY_THRESHOLD_DAYS: int = 30
# The 30-day boundary is the Google/Mozilla/CA-Browser Forum recommended
# minimum renewal window. Below this, cert management is in breach of
# operational hygiene policies.

MAX_TECH_SCORE: float = 100.0
# Hard cap: MRQM pillar scores are bounded [0, 100] by design.

MAX_EXPOSURE_SCORE: float = 100.0
# Hard cap for perimeter exposure score.

# ---------------------------------------------------------------------------
# Governance tier registries
# Weights follow the hybrid CERT-In + NIST CSF 2.0 rule:
#   statutory CERT-In controls → raw_weight 5 (sole) or 4 (joint citation)
#   NIST best-practice controls → raw_weight 3 (operational) or 2 (awareness)
# Normalisation happens at runtime — adding controls never breaks the formula.
# ---------------------------------------------------------------------------

TIER_1_REGISTRY: list[dict] = [
    {
        "key": "log_retention",
        "label": "180-Day Log Retention",
        "raw_weight": 5,
        "citation": "CERT-In Directions April 2022, Section 6(ii)",
        "statutory": True,
        "tier": 1,
        "remediation": (
            "Configure centralised log aggregation and retain all system, "
            "network, and application logs for minimum 180 days. "
            "Non-compliance attracts penalties under IT Act 2000, Section 70B."
        ),
    },
    {
        "key": "incident_reporting",
        "label": "6-Hour Incident Reporting to CERT-In",
        "raw_weight": 5,
        "citation": "CERT-In Directions April 2022, Section 4",
        "statutory": True,
        "tier": 1,
        "remediation": (
            "Designate a CERT-In nodal officer. Document the 6-hour reporting "
            "procedure. Register on CERT-In portal: https://www.cert-in.org.in"
        ),
    },
    {
        "key": "incident_plan",
        "label": "Incident Response Plan",
        "raw_weight": 4,
        "citation": "CERT-In/GEN-2/2022 + NIST CSF 2.0 RS.RP-1",
        "statutory": True,
        "tier": 1,
        "remediation": (
            "Document an IRP covering: detection triggers, escalation contacts, "
            "containment steps, and CERT-In 6-hour reporting procedure."
        ),
    },
    {
        "key": "mfa_enabled",
        "label": "MFA on Critical Systems",
        "raw_weight": 4,
        "citation": "CERT-In Directions April 2022, Section 6(v) + NIST PR.AC-7",
        "statutory": True,
        "tier": 1,
        "remediation": (
            "Enable MFA on all admin and remote-access accounts. "
            "Google Workspace MFA: \u20b90 additional cost. Setup time: 2-4 hours."
        ),
    },
    {
        "key": "ntp_sync",
        "label": "NTP Time Synchronisation",
        "raw_weight": 3,
        "citation": "CERT-In Directions April 2022, Section 6(i)",
        "statutory": True,
        "tier": 1,
        "remediation": (
            "Configure all systems to sync with NTP servers. "
            "Recommended: time.google.com or pool.ntp.org. "
            "Accurate timestamps are required for CERT-In incident evidence."
        ),
    },
    {
        "key": "offline_backup",
        "label": "Offline / Air-Gapped Backup",
        "raw_weight": 3,
        "citation": "NIST CSF 2.0 PR.IP-4",
        "statutory": False,
        "tier": 1,
        "remediation": (
            "Implement 3-2-1 backup policy: 3 copies, 2 different media, "
            "1 offsite or offline. Test restoration quarterly. "
            "Primary defence against ransomware."
        ),
    },
    {
        "key": "least_privilege",
        "label": "Least Privilege Access Control",
        "raw_weight": 3,
        "citation": "NIST CSF 2.0 PR.AC-4",
        "statutory": False,
        "tier": 1,
        "remediation": (
            "Audit all user accounts. Remove admin rights from standard users. "
            "Use separate admin accounts for privileged operations only."
        ),
    },
    {
        "key": "patch_management",
        "label": "Patch Management Cadence",
        "raw_weight": 3,
        "citation": "NIST CSF 2.0 PR.IP-12",
        "statutory": False,
        "tier": 1,
        "remediation": (
            "Establish a monthly patching cycle for all software and OS. "
            "Critical patches (CVSS \u2265 9.0) must be applied within 72 hours."
        ),
    },
    {
        "key": "phishing_training",
        "label": "Phishing Awareness Training",
        "raw_weight": 2,
        "citation": "NIST CSF 2.0 PR.AT-1",
        "statutory": False,
        "tier": 1,
        "remediation": (
            "Conduct annual phishing awareness training for all staff. "
            "Free resources: CERT-In awareness portal, Google Phishing Quiz."
        ),
    },
    {
        "key": "firewall_segmentation",
        "label": "Firewall / Network Segmentation",
        "raw_weight": 2,
        "citation": "NIST CSF 2.0 PR.PT-3",
        "statutory": False,
        "tier": 1,
        "remediation": (
            "Enable and configure the OS firewall on all machines. "
            "Segment guest WiFi from business network. "
            "Document and review firewall rules annually."
        ),
    },
]

TIER_2_REGISTRY: list[dict] = [
    {
        "key": "asset_inventory",
        "label": "Asset Inventory",
        "raw_weight": 3,
        "citation": "NIST CSF 2.0 ID.AM-1",
        "statutory": False,
        "tier": 2,
        "remediation": (
            "Maintain a documented inventory of all hardware and software assets. "
            "Update whenever a new device or application is added."
        ),
    },
    {
        "key": "vulnerability_disclosure",
        "label": "Vulnerability Disclosure Policy",
        "raw_weight": 3,
        "citation": "NIST CSF 2.0 DE.AE-1",
        "statutory": False,
        "tier": 2,
        "remediation": (
            "Publish a responsible disclosure policy on your website. "
            "Designate a security contact email (e.g. security@yourdomain.in)."
        ),
    },
    {
        "key": "privileged_access_ws",
        "label": "Privileged Access Workstations",
        "raw_weight": 3,
        "citation": "NIST CSF 2.0 PR.AC-5",
        "statutory": False,
        "tier": 2,
        "remediation": (
            "Designate separate workstations for administrative tasks. "
            "Admin workstations should not be used for email or browsing."
        ),
    },
    {
        "key": "security_logging",
        "label": "Security Logging / SIEM Configured",
        "raw_weight": 3,
        "citation": "NIST CSF 2.0 DE.CM-1",
        "statutory": False,
        "tier": 2,
        "remediation": (
            "Configure centralised security event logging. "
            "Open-source options: Graylog, Wazuh. "
            "Alert on failed logins, privilege escalations, and port scans."
        ),
    },
    {
        "key": "vendor_risk",
        "label": "Third-Party Vendor Risk Assessment",
        "raw_weight": 2,
        "citation": "NIST CSF 2.0 ID.SC-2",
        "statutory": False,
        "tier": 2,
        "remediation": (
            "Assess security posture of key vendors with access to your data. "
            "Require vendors to confirm basic security controls annually."
        ),
    },
]

TIER_3_REGISTRY: list[dict] = [
    {
        "key": "penetration_testing",
        "label": "Annual Penetration Testing",
        "raw_weight": 3,
        "citation": "NIST CSF 2.0 PR.IP-10",
        "statutory": False,
        "tier": 3,
        "remediation": (
            "Conduct annual penetration testing by a CERT-In empanelled auditor. "
            "List: https://www.cert-in.org.in/s2cMainServlet?pageid=SERVCERTIN"
        ),
    },
    {
        "key": "data_classification",
        "label": "Data Classification Policy",
        "raw_weight": 3,
        "citation": "NIST CSF 2.0 PR.DS-1",
        "statutory": False,
        "tier": 3,
        "remediation": (
            "Classify all business data as Public, Internal, Confidential, "
            "or Restricted. Apply handling controls per classification level."
        ),
    },
    {
        "key": "bcp_drp_tested",
        "label": "BCP / DRP Documented and Tested",
        "raw_weight": 3,
        "citation": "NIST CSF 2.0 RC.RP-1",
        "statutory": False,
        "tier": 3,
        "remediation": (
            "Document Business Continuity and Disaster Recovery plans. "
            "Conduct tabletop exercises at least annually."
        ),
    },
    {
        "key": "vapt_remediation",
        "label": "VAPT Results Tracked and Remediated",
        "raw_weight": 2,
        "citation": "NIST CSF 2.0 RS.AN-1",
        "statutory": False,
        "tier": 3,
        "remediation": (
            "Track all VAPT findings in a risk register. "
            "Critical findings must be remediated within 30 days."
        ),
    },
    {
        "key": "dedicated_ir_team",
        "label": "Dedicated Incident Response Team",
        "raw_weight": 2,
        "citation": "NIST CSF 2.0 RS.CO-1",
        "statutory": False,
        "tier": 3,
        "remediation": (
            "Form a dedicated IR team with defined roles: "
            "Incident Commander, Technical Lead, Communications Lead. "
            "Conduct IR drills quarterly."
        ),
    },
]

# Combined registry for convenience — order is Tier 1 → 2 → 3
ALL_CONTROLS: list[dict] = TIER_1_REGISTRY + TIER_2_REGISTRY + TIER_3_REGISTRY

# ---------------------------------------------------------------------------
# Port risk weights
# Source: CISA/FBI StopRansomware Advisory 2022 (RDP/SMB) +
#         NSA/CISA Network Infrastructure Security Guide 2022 (Telnet/FTP)
# ---------------------------------------------------------------------------

PORT_RISK_WEIGHTS: dict[int, float] = {
    3389: 85.0,   # RDP  — #1 ransomware initial access vector (CISA/FBI 2022)
    23:   90.0,   # Telnet — plaintext credentials; never acceptable in any env
    21:   70.0,   # FTP  — plaintext transfer; anonymous login risk
    22:   40.0,   # SSH  — encrypted but brute-forced; risk depends on config
    445:  80.0,   # SMB  — WannaCry / NotPetya entry vector
    1433: 75.0,   # MSSQL — direct DB exposure
    3306: 75.0,   # MySQL — direct DB exposure
    5432: 70.0,   # PostgreSQL — direct DB exposure
    8080: 30.0,   # HTTP alt — often unencrypted dev servers left open
    8443: 15.0,   # HTTPS alt — lower risk but unexpected exposure
}
DEFAULT_PORT_RISK_WEIGHT: float = 5.0

# ---------------------------------------------------------------------------
# MRQM composite weights (must sum to 1.0)
# Grounded in: NIST SP 800-30 Rev 1, Tables G-2/G-3
# ---------------------------------------------------------------------------
MRQM_WEIGHTS: dict[str, float] = {
    "tech":       0.45,
    "governance": 0.35,
    "exposure":   0.20,
}


# ===========================================================================
# FUNCTION 1 — Tier selector
# ===========================================================================

def get_applicable_controls(it_maturity: str) -> list[dict]:
    """
    Return the governance control registry applicable to an organisation's
    self-declared IT maturity level.

    Maturity → tier mapping (per CERT-In + NIST CSF 2.0 hybrid framework):
        "basic"        → Tier 1 only  (10 controls)
        "intermediate" → Tier 1 + 2   (15 controls)
        "advanced"     → Tier 1 + 2 + 3 (20 controls)

    Fail-secure default: unknown maturity values resolve to Tier 1, matching
    the most conservative (micro/basic) regulatory burden. This prevents
    over-scoping the governance checklist for organisations that have not
    completed onboarding.

    Args:
        it_maturity: Self-selected maturity string from Organisation record.

    Returns:
        List of control dicts from the appropriate tier registry combination.
    """
    maturity = it_maturity.lower().strip() if it_maturity else "basic"

    if maturity == "advanced":
        controls = TIER_1_REGISTRY + TIER_2_REGISTRY + TIER_3_REGISTRY
        log.debug("Maturity=advanced → %d controls (Tier 1+2+3)", len(controls))
    elif maturity == "intermediate":
        controls = TIER_1_REGISTRY + TIER_2_REGISTRY
        log.debug("Maturity=intermediate → %d controls (Tier 1+2)", len(controls))
    else:
        # "basic" or any unrecognised value → Tier 1 only (fail-secure)
        if maturity not in ("basic",):
            log.warning(
                "Unrecognised it_maturity=%r — defaulting to Tier 1 (fail-secure).",
                it_maturity,
            )
        controls = TIER_1_REGISTRY
        log.debug("Maturity=basic → %d controls (Tier 1 only)", len(controls))

    return controls


# ===========================================================================
# FUNCTION 2 — Weight normaliser
# ===========================================================================

def normalize_governance_weights(controls: list[dict]) -> dict[str, float]:
    """
    Compute normalised governance weights for a given set of applicable controls.

    Ensures the total weight always sums to exactly 100.0, regardless of how
    many controls are in scope. This makes the MRQM formula robust to control
    additions or tier changes — no manual rebalancing is ever required.

    Normalisation formula (per control):
        total_raw       = sum(control["raw_weight"] for all controls)
        normalized_w    = (control["raw_weight"] / total_raw) × 100

    Verification: sum of all normalised weights must be within ±0.1 of 100.0.
    A WARNING is logged if this invariant is violated (indicates a data error
    in the registry, not a formula error).

    Args:
        controls: List of control dicts from get_applicable_controls().

    Returns:
        Dict mapping control key → normalised weight (float).
        Returns {} if controls is empty.
    """
    if not controls:
        log.warning("normalize_governance_weights called with empty controls list.")
        return {}

    total_raw: float = sum(float(c["raw_weight"]) for c in controls)

    if total_raw == 0.0:
        log.error(
            "All controls have raw_weight=0 — cannot normalise. Returning zero weights."
        )
        return {c["key"]: 0.0 for c in controls}

    weights: dict[str, float] = {
        c["key"]: round((float(c["raw_weight"]) / total_raw) * 100.0, 6)
        for c in controls
    }

    # Invariant check
    total_normalised = sum(weights.values())
    if abs(total_normalised - 100.0) > 0.1:
        log.warning(
            "Normalised weight sum=%.4f deviates from 100.0 by more than 0.1. "
            "Check registry raw_weight values.",
            total_normalised,
        )
    else:
        log.debug(
            "Weight normalisation OK: %d controls, sum=%.4f",
            len(controls),
            total_normalised,
        )

    return weights


# ===========================================================================
# FUNCTION 3 — Technical score (from enriched threat-intel findings)
# ===========================================================================

def calculate_technical_score(
    enriched_findings: list[dict],
    any_eol: bool,
    ssl_days: int = 45,
) -> float:
    """
    Compute the Technical pillar score (0–100) from enriched CVE/EOL findings.

    Input ``enriched_findings`` is the ``"findings"`` list produced by
    ``threat_intel.enrich_software_inventory()``. Each element contains:
        software_name (str), version (str), is_eol (bool),
        cves (list), software_risk (float).

    Formula:
        software_count = len(enriched_findings)
        if software_count == 0: return 0.0

        total_risk = sum(f["software_risk"] for f in enriched_findings)
        raw_tech   = (total_risk / software_count) × 10

        if any_eol:    raw_tech += EOL_PENALTY       (20.0)
        if ssl_days ≤  SSL_EXPIRY_THRESHOLD_DAYS:
                       raw_tech += SSL_EXPIRY_PENALTY (15.0)

        tech_score = min(raw_tech, MAX_TECH_SCORE)

    Important methodological note:
        NVD keyword search returns historic CVE matches, not version-pinned
        results. ``software_risk`` is therefore a relative risk signal
        calibrated against known, published threat data — not an exact
        vulnerability count for a specific installed version. This is
        consistent with how CVSS base scores are employed in risk models
        (NIST SP 800-30 Rev 1, Section 2.3): as comparative severity
        signals used to rank and prioritise, not as absolute counts.

    EOL penalty basis: CISA KEV catalog — 300+ actively exploited entries
    in post-EOL software. Source: cisa.gov/known-exploited-vulnerabilities.

    SSL penalty basis: Industry standard (Google, Mozilla, Cloudflare, CAB
    Forum) — 30-day expiry window marks cert management failure, exposing
    trust chains and enabling opportunistic MITM.

    Args:
        enriched_findings: List of per-software dicts from threat_intel.
        any_eol:           True if ANY software in inventory is EOL.
        ssl_days:          Days remaining on SSL certificate. Default 45
                           (healthy — no penalty triggered).

    Returns:
        Technical score as float rounded to 2 decimal places, in [0.0, 100.0].
    """
    software_count: int = len(enriched_findings)

    if software_count == 0:
        log.info("calculate_technical_score: empty inventory, returning 0.0.")
        return 0.0

    total_risk: float = sum(
        float(f.get("software_risk", 0.0)) for f in enriched_findings
    )
    raw_tech: float = (total_risk / software_count) * 10.0

    log.debug(
        "Tech score base: total_risk=%.4f  count=%d  raw_tech=%.4f",
        total_risk, software_count, raw_tech,
    )

    if any_eol:
        raw_tech += EOL_PENALTY
        log.debug("EOL penalty applied: +%.1f  →  raw_tech=%.4f", EOL_PENALTY, raw_tech)

    if ssl_days <= SSL_EXPIRY_THRESHOLD_DAYS:
        raw_tech += SSL_EXPIRY_PENALTY
        log.debug(
            "SSL expiry penalty applied (ssl_days=%d <= %d): +%.1f  →  raw_tech=%.4f",
            ssl_days, SSL_EXPIRY_THRESHOLD_DAYS, SSL_EXPIRY_PENALTY, raw_tech,
        )

    tech_score: float = round(min(raw_tech, MAX_TECH_SCORE), 2)
    log.info("Technical score computed: %.2f", tech_score)
    return tech_score


# ===========================================================================
# FUNCTION 4 — Governance score (tiered, normalised, with breakdown)
# ===========================================================================

def calculate_governance_score(
    answers: dict[str, bool],
    it_maturity: str = "basic",
) -> tuple[float, dict[str, Any]]:
    """
    Compute the Governance pillar score (0–100) and a per-control breakdown.

    Framework hybrid rule (applied via the tiered registry):
        - CERT-In statutory directives: highest raw_weight; always in Tier 1.
        - NIST CSF 2.0 best-practice controls: included by maturity tier.
        Where CERT-In and NIST overlap, CERT-In takes precedence (citation
        reflects both: e.g. "CERT-In Section 6(v) + NIST PR.AC-7").

    Scoring pipeline:
        1. Determine applicable controls via ``get_applicable_controls()``.
        2. Normalise weights via ``normalize_governance_weights()``.
        3. For each applicable control:
               if answers.get(key, False) is True → add normalised weight.
        4. Fail-secure: any missing key treated as False (non-compliant).

    Args:
        answers:     Dict of {control_key: bool} from the governance checklist.
                     Missing keys default to False (non-compliant).
        it_maturity: Maturity tier string ("basic" | "intermediate" | "advanced").

    Returns:
        Tuple of:
            (float)  governance_score — rounded to 2 decimal places, [0.0, 100.0]
            (dict)   breakdown — per-control detail dict for dashboard display.

    Breakdown dict structure:
        {
            "log_retention": {
                "label":        str,
                "compliant":    bool,
                "weight":       float,   ← normalised weight for this control
                "contribution": float,   ← weight if compliant, 0.0 if not
                "citation":     str,
                "statutory":    bool,
                "remediation":  str,
                "tier":         int,
            },
            ...
        }
    """
    controls = get_applicable_controls(it_maturity)
    weights  = normalize_governance_weights(controls)

    score: float = 0.0
    breakdown: dict[str, Any] = {}

    for control in controls:
        key        = control["key"]
        norm_w     = weights.get(key, 0.0)
        compliant  = bool(answers.get(key, False))   # fail-secure default
        contribution = norm_w if compliant else 0.0

        score += contribution

        breakdown[key] = {
            "label":        control["label"],
            "compliant":    compliant,
            "weight":       round(norm_w, 4),
            "contribution": round(contribution, 4),
            "citation":     control["citation"],
            "statutory":    control["statutory"],
            "remediation":  control["remediation"],
            "tier":         control["tier"],
        }

    gov_score = round(score, 2)
    log.info(
        "Governance score: %.2f  maturity=%r  controls=%d",
        gov_score, it_maturity, len(controls),
    )
    return gov_score, breakdown


# ===========================================================================
# FUNCTION 5 — Exposure score (from psutil port scan)
# ===========================================================================

def calculate_exposure_score(open_ports: list[dict]) -> float:
    """
    Compute the Perimeter Exposure pillar score (0–100) from port telemetry.

    Input is the list of port dicts produced by the edge agent (sensor.py via
    psutil). Each dict contains: port (int), state (str), service (str),
    risk_weight (float).

    Weight resolution (per port, in priority order):
        1. Use ``port["risk_weight"]`` if present and > 0.
        2. Otherwise look up ``PORT_RISK_WEIGHTS`` by port number.
        3. Fall back to ``DEFAULT_PORT_RISK_WEIGHT`` (5.0) for unknown ports.

    Port weights are grounded in:
        - RDP (3389) / SMB (445): CISA/FBI StopRansomware Advisory 2022
        - Telnet (23) / FTP (21): NSA/CISA Network Infrastructure Security Guide 2022
        - SSH (22): Conservative weight; encrypted but frequently brute-forced.

    Only ports with state == "open" contribute to the score. Other states
    ("closed", "filtered") are ignored.

    Raw score is capped at MAX_EXPOSURE_SCORE (100.0).

    Args:
        open_ports: List of port dicts from the edge agent sensor.

    Returns:
        Exposure score as float rounded to 2 decimal places, in [0.0, 100.0].
    """
    raw_score: float = 0.0

    for port_entry in open_ports:
        state = port_entry.get("state", "").lower()
        if state != "open":
            continue

        port_num   = int(port_entry.get("port", 0))
        agent_w    = float(port_entry.get("risk_weight", 0.0))

        # Weight resolution: agent-provided → registry lookup → default
        if agent_w > 0.0:
            weight = agent_w
        else:
            weight = PORT_RISK_WEIGHTS.get(port_num, DEFAULT_PORT_RISK_WEIGHT)

        raw_score += weight
        log.debug("Port %d (state=open): weight=%.1f  running_total=%.1f", port_num, weight, raw_score)

    exposure_score = round(min(raw_score, MAX_EXPOSURE_SCORE), 2)
    log.info(
        "Exposure score: %.2f  (raw=%.2f, %d open port(s) evaluated)",
        exposure_score, raw_score, len(open_ports),
    )
    return exposure_score


# ===========================================================================
# FUNCTION 6 — MRQM composite formula
# ===========================================================================

def calculate_mrqm(
    tech_score: float,
    gov_score: float,
    exp_score: float,
) -> float:
    """
    Compute the Master Risk Quantification Metric (MRQM).

    Applies the weighted composite formula:
        MRQM = (0.45 × tech_score) + (0.35 × gov_score) + (0.20 × exp_score)

    Weights are defined in MRQM_WEIGHTS and grounded in risk literature
    from NIST SP 800-30 Rev 1, Tables G-2/G-3, which assign the highest
    impact factors to technical vulnerability severity, followed by
    governance posture as a risk amplifier/mitigator, and external
    exposure as the attack surface multiplier.

    All input scores should be in [0.0, 100.0]. By design of the weights
    (which sum to 1.0), the output is naturally bounded in the same range.

    Args:
        tech_score:  Technical vulnerability pillar score (weight: 45%).
        gov_score:   Governance compliance pillar score  (weight: 35%).
        exp_score:   Perimeter exposure pillar score     (weight: 20%).

    Returns:
        MRQM float rounded to 2 decimal places.

    Example:
        >>> calculate_mrqm(72.0, 30.0, 85.0)
        # (0.45 × 72.0) + (0.35 × 30.0) + (0.20 × 85.0)
        # = 32.40 + 10.50 + 17.00 = 59.90
        59.9
    """
    mrqm: float = (
        MRQM_WEIGHTS["tech"]       * tech_score
        + MRQM_WEIGHTS["governance"] * gov_score
        + MRQM_WEIGHTS["exposure"]   * exp_score
    )
    result = round(mrqm, 2)
    log.info(
        "MRQM: (0.45×%.2f) + (0.35×%.2f) + (0.20×%.2f) = %.2f",
        tech_score, gov_score, exp_score, result,
    )
    return result


# ===========================================================================
# FUNCTION 7 — Risk band classifier
# ===========================================================================

def get_risk_band(mrqm_score: float) -> str:
    """
    Map a numeric MRQM score to a categorical risk band label.

    Risk bands:
        LOW      : mrqm_score <  40  — Acceptable baseline risk; monitor quarterly.
        MEDIUM   : mrqm_score <  70  — Elevated risk; remediation plan within 30 days.
        CRITICAL : mrqm_score >= 70  — Imminent threat; immediate action required.

    Band thresholds are derived from the operational risk tolerance framework
    used in NIST SP 800-30 Rev 1, Table H-3 (Very Low/Low/Moderate/High/Very High
    mapped to a 0–100 normalised scale with 40/70 as the inflection points
    for escalation in the MSME context).

    Args:
        mrqm_score: The computed composite MRQM float.

    Returns:
        One of "LOW", "MEDIUM", or "CRITICAL".
    """
    if mrqm_score < 40.0:
        band = "LOW"
    elif mrqm_score < 70.0:
        band = "MEDIUM"
    else:
        band = "CRITICAL"

    log.info("Risk band: %s  (mrqm=%.2f)", band, mrqm_score)
    return band


# ===========================================================================
# FUNCTION 8 — Remediation priority sorter
# ===========================================================================

def get_remediation_priorities(breakdown: dict[str, Any]) -> list[dict]:
    """
    Derive an ordered list of remediation actions for non-compliant controls.

    Takes the breakdown dict produced by ``calculate_governance_score()``
    and returns all non-compliant controls sorted as follows:
        Primary key:   statutory=True controls first (boolean sort descending)
        Secondary key: normalised weight descending (highest priority = highest weight)

    This ordering ensures CERT-In statutory obligations always surface above
    NIST best-practice controls of equal weight, prioritising legal compliance
    risk over operational risk.

    Args:
        breakdown: Per-control breakdown dict from calculate_governance_score().

    Returns:
        List of dicts for non-compliant controls, sorted priority-descending.
        Each dict structure:
            {
                "key":        str,
                "label":      str,
                "citation":   str,
                "statutory":  bool,
                "weight":     float,
                "remediation": str,
                "tier":       int,
            }
        Returns [] if all controls are compliant.
    """
    non_compliant: list[dict] = []

    for key, detail in breakdown.items():
        if not detail.get("compliant", False):
            non_compliant.append({
                "key":         key,
                "label":       detail["label"],
                "citation":    detail["citation"],
                "statutory":   detail["statutory"],
                "weight":      detail["weight"],
                "remediation": detail["remediation"],
                "tier":        detail["tier"],
            })

    # Statutory-first, then by weight descending
    non_compliant.sort(
        key=lambda c: (not c["statutory"], -c["weight"])
    )

    log.info(
        "Remediation priorities: %d non-compliant control(s) identified.",
        len(non_compliant),
    )
    return non_compliant
