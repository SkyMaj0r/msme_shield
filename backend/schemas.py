"""
schemas.py
----------
Pydantic data contracts for the MSME Shield platform.

STRICT CONSTRAINTS (never violate):
    - This is the ONLY file in the codebase that defines Pydantic models.
    - Zero logic, zero math, zero HTTP calls — pure data validation only.
    - All governance boolean fields default to False (fail-secure / non-compliant).
    - All imports are absolute (uvicorn runs from backend/).

TWO-STEP SCAN FLOW:
    Step 1 — Edge agent POSTs telemetry:
        AgentPayload → POST /api/agent/submit
        ← AgentSubmitResponse (scan_id + tech_score, status=pending_governance)

    Step 2 — Owner submits governance answers via dashboard:
        GovernanceSubmission → POST /api/scans/{scan_id}/governance
        ← FullScanResponse (complete MRQM + pillar breakdown + remediation list)
"""

from __future__ import annotations

from typing import Any, Optional

from pydantic import BaseModel, EmailStr, Field


# ===========================================================================
# SUB-MODELS — reusable building blocks
# ===========================================================================

class SoftwareItem(BaseModel):
    """
    A single software entry from the agent's installed-software inventory.

    Collected on Mac from /Applications/<App>.app/Contents/Info.plist
    (CFBundleName + CFBundleShortVersionString).
    Collected on Windows from HKLM\\SOFTWARE\\Microsoft\\Windows\\
    CurrentVersion\\Uninstall registry keys.

    Fed into threat_intel.enrich_software_inventory() which queries
    NVD v2.0, EPSS (FIRST.org), and endoflife.date per item.
    """

    name: str = Field(
        ...,
        description="Software name as reported by the OS.",
        examples=["Apache HTTP Server"],
    )
    version: str = Field(
        ...,
        description="Installed version string.",
        examples=["2.4.49"],
    )


class PortResult(BaseModel):
    """
    A single TCP listening port discovered by psutil on the agent machine.

    risk_weight resolution in risk_engine.calculate_exposure_score():
        1. Use this field if > 0.0 (agent-provided).
        2. Else look up PORT_RISK_WEIGHTS by port number.
        3. Else fall back to DEFAULT_PORT_RISK_WEIGHT (5.0).
    """

    port: int = Field(
        ...,
        ge=1,
        le=65535,
        description="TCP port number.",
        examples=[3389],
    )
    state: str = Field(
        ...,
        description="Port state as reported by psutil (e.g. 'open').",
        examples=["open"],
    )
    service: str = Field(
        default="unknown",
        description="Service name associated with the port, if known.",
        examples=["ms-wbt-server (RDP)"],
    )
    risk_weight: float = Field(
        default=5.0,
        ge=0.0,
        le=100.0,
        description=(
            "Pre-assigned danger score for this port. "
            "If 0.0, risk_engine will look up PORT_RISK_WEIGHTS by port number."
        ),
        examples=[85.0],
    )


# ===========================================================================
# STEP 1 — AGENT SUBMISSION
# ===========================================================================

class AgentPayload(BaseModel):
    """
    Master inbound payload from the MSME Shield edge agent.

    POSTed to: POST /api/agent/submit

    The agent collects this data locally and transmits it in a single call.
    The backend then:
        1. Upserts the organisation record by organization_name.
        2. Calls threat_intel.enrich_software_inventory() for NVD/EPSS/EOL data.
        3. Calls active_tools.check_ssl() for SSL certificate days remaining.
        4. Calls risk_engine.calculate_technical_score() and
           risk_engine.calculate_exposure_score().
        5. Persists a ScanHistory row with status="pending_governance".
        6. Returns AgentSubmitResponse with scan_id and partial scores.
    """

    organization_name: str = Field(
        default="Test MSME",
        description=(
            "Organisation name used to upsert the organisations table. "
            "For first-time users, a record is auto-created with basic defaults."
        ),
        examples=["Sharma Textiles Pvt Ltd"],
    )
    software_list: list[SoftwareItem] = Field(
        default_factory=list,
        description="All installed software collected by the agent inventory scan.",
    )
    open_ports: list[PortResult] = Field(
        default_factory=list,
        description="All TCP listening ports discovered by psutil on the agent machine.",
    )
    os_name: str = Field(
        default="",
        description="Operating system name as returned by platform.system().",
        examples=["Windows 10 Pro"],
    )
    os_version: str = Field(
        default="",
        description="OS version string as returned by platform.version().",
        examples=["10.0.19044"],
    )
    domain_name: str = Field(
        default="",
        description=(
            "Primary apex domain for SSL certificate expiry check via CertSpotter. "
            "Leave empty to skip SSL check (ssl_days will default to safe value)."
        ),
        examples=["sharmatextiles.in"],
    )
    it_maturity: str = Field(
        default="basic",
        description=(
            "Self-selected IT maturity level: basic | intermediate | advanced. "
            "Determines which governance tier is applied in the checklist (Step 2)."
        ),
        examples=["basic"],
    )


class AgentSubmitResponse(BaseModel):
    """
    Response returned to the edge agent after POST /api/agent/submit is processed.

    Contains the scan_id needed to correlate Step 2 governance submission,
    along with partial pillar scores so the agent can write them to its log.

    Status at this point: "pending_governance" — MRQM is NOT yet computed.
    """

    scan_id: int = Field(
        ...,
        description="Database primary key of the created scan_history row.",
        examples=[42],
    )
    tech_score: float = Field(
        ...,
        description="Technical pillar score computed from NVD / EPSS / EOL pipeline.",
        examples=[63.5],
    )
    risk_band_preview: str = Field(
        ...,
        description=(
            "Preliminary risk band based on tech + exposure scores only. "
            "Will be recalculated to final MRQM after governance is submitted."
        ),
        examples=["MEDIUM"],
    )
    software_count: int = Field(
        ...,
        description="Number of software items received and processed from the agent.",
        examples=[12],
    )
    cve_count: int = Field(
        ...,
        description="Total number of CVEs found across all software items.",
        examples=[7],
    )
    any_eol: bool = Field(
        ...,
        description="True if any software item in the inventory is confirmed End-of-Life.",
        examples=[False],
    )
    ssl_days: int = Field(
        ...,
        description="Days remaining until the organisation's SSL certificate expires.",
        examples=[87],
    )
    message: str = Field(
        ...,
        description="Human-readable status message written to the agent log.",
        examples=["Scan created. Open dashboard to complete governance assessment."],
    )


# ===========================================================================
# STEP 2 — GOVERNANCE SUBMISSION
# ===========================================================================

class GovernanceSubmission(BaseModel):
    """
    Payload for POST /api/scans/{scan_id}/governance.

    The MSME owner completes this checklist in the Streamlit dashboard.
    The backend uses it_maturity to determine which controls are in scope,
    then calls risk_engine.calculate_governance_score() to produce gov_score.

    Tiered control scope:
        basic:        Tier 1 only  (10 controls: log_retention … firewall_segmentation)
        intermediate: Tier 1 + 2   (15 controls, adds asset_inventory … vendor_risk)
        advanced:     Tier 1+2+3   (20 controls, adds penetration_testing … dedicated_ir_team)

    Fail-secure design: ALL governance booleans default to False.
    This means unanswered questions are always treated as non-compliant,
    which is the correct and conservative posture for an MSME risk model.

    admin_password:
        Used only for zxcvbn in-memory password strength check.
        Never persisted to the database. Evaluated in api.py and discarded.

    to_answers_dict() extracts only the 20 boolean governance fields,
    excluding it_maturity and admin_password. This dict is passed directly
    to risk_engine.calculate_governance_score(answers, it_maturity).
    """

    it_maturity: str = Field(
        default="basic",
        description=(
            "Maturity tier determines which governance controls are in scope. "
            "basic | intermediate | advanced"
        ),
        examples=["basic"],
    )
    admin_password: str = Field(
        default="",
        description=(
            "Admin/privileged account password for zxcvbn strength check. "
            "Evaluated in-process only. Never stored, logged, or returned."
        ),
        examples=[""],
    )

    # --- Tier 1 controls (all maturities) -----------------------------------
    log_retention: bool = Field(
        default=False,
        description="Logs retained ≥ 180 days. CERT-In Directions April 2022, Section 6(ii).",
    )
    incident_reporting: bool = Field(
        default=False,
        description="6-hour incident reporting to CERT-In in place. Section 4.",
    )
    incident_plan: bool = Field(
        default=False,
        description="Documented Incident Response Plan exists. CERT-In/GEN-2/2022 + NIST RS.RP-1.",
    )
    mfa_enabled: bool = Field(
        default=False,
        description="MFA enforced on all admin and remote-access accounts. CERT-In Section 6(v) + NIST PR.AC-7.",
    )
    ntp_sync: bool = Field(
        default=False,
        description="All systems synced to NTP. CERT-In Section 6(i).",
    )
    offline_backup: bool = Field(
        default=False,
        description="Offline or air-gapped backups maintained. NIST CSF 2.0 PR.IP-4.",
    )
    least_privilege: bool = Field(
        default=False,
        description="Least-privilege access model implemented. NIST CSF 2.0 PR.AC-4.",
    )
    patch_management: bool = Field(
        default=False,
        description="Monthly patch cadence in place; critical patches within 72 h. NIST CSF 2.0 PR.IP-12.",
    )
    phishing_training: bool = Field(
        default=False,
        description="Annual phishing awareness training conducted. NIST CSF 2.0 PR.AT-1.",
    )
    firewall_segmentation: bool = Field(
        default=False,
        description="OS firewall enabled; guest WiFi segmented. NIST CSF 2.0 PR.PT-3.",
    )

    # --- Tier 2 controls (intermediate + advanced) --------------------------
    asset_inventory: bool = Field(
        default=False,
        description="Documented hardware and software asset inventory maintained. NIST CSF 2.0 ID.AM-1.",
    )
    vulnerability_disclosure: bool = Field(
        default=False,
        description="Responsible disclosure policy published. NIST CSF 2.0 DE.AE-1.",
    )
    privileged_access_ws: bool = Field(
        default=False,
        description="Dedicated workstations used for admin tasks only. NIST CSF 2.0 PR.AC-5.",
    )
    security_logging: bool = Field(
        default=False,
        description="Centralised security event logging / SIEM configured. NIST CSF 2.0 DE.CM-1.",
    )
    vendor_risk: bool = Field(
        default=False,
        description="Third-party vendor security posture assessed annually. NIST CSF 2.0 ID.SC-2.",
    )

    # --- Tier 3 controls (advanced only) ------------------------------------
    penetration_testing: bool = Field(
        default=False,
        description="Annual penetration test by CERT-In empanelled auditor. NIST CSF 2.0 PR.IP-10.",
    )
    data_classification: bool = Field(
        default=False,
        description="Data classification policy in place (Public/Internal/Confidential/Restricted). NIST CSF 2.0 PR.DS-1.",
    )
    bcp_drp_tested: bool = Field(
        default=False,
        description="BCP and DRP documented and tested via tabletop exercise. NIST CSF 2.0 RC.RP-1.",
    )
    vapt_remediation: bool = Field(
        default=False,
        description="VAPT findings tracked in risk register; critical issues remediated within 30 days. NIST CSF 2.0 RS.AN-1.",
    )
    dedicated_ir_team: bool = Field(
        default=False,
        description="Dedicated IR team with defined roles (Commander / Tech / Comms). NIST CSF 2.0 RS.CO-1.",
    )

    # Canonical set of governance control field names — used by to_answers_dict()
    _GOVERNANCE_FIELDS: list[str] = [
        "log_retention",
        "incident_reporting",
        "incident_plan",
        "mfa_enabled",
        "ntp_sync",
        "offline_backup",
        "least_privilege",
        "patch_management",
        "phishing_training",
        "firewall_segmentation",
        "asset_inventory",
        "vulnerability_disclosure",
        "privileged_access_ws",
        "security_logging",
        "vendor_risk",
        "penetration_testing",
        "data_classification",
        "bcp_drp_tested",
        "vapt_remediation",
        "dedicated_ir_team",
    ]

    def to_answers_dict(self) -> dict[str, bool]:
        """
        Extract all 20 governance boolean fields as a plain dict.

        Explicitly excludes ``it_maturity`` and ``admin_password`` — these
        are control metadata and credentials, not governance answers.

        Returns:
            Dict of {control_key: bool} with exactly 20 entries.
            Passed directly to risk_engine.calculate_governance_score().
        """
        return {field: getattr(self, field) for field in self._GOVERNANCE_FIELDS}


# ===========================================================================
# RESPONSE MODELS
# ===========================================================================

class FullScanResponse(BaseModel):
    """
    Complete scan result returned by:
        GET  /api/scans/{scan_id}
        GET  /api/scans/latest   (when status = "complete")

    Contains all three pillar scores, the final MRQM, the enriched CVE
    findings, and the full remediation priority list. Used by the dashboard
    to render the scorecard and by the PDF generator to build the report.
    """

    scan_id: int = Field(..., description="Database primary key of this scan.", examples=[42])
    organization_name: str = Field(..., description="Name of the scanned organisation.", examples=["Sharma Textiles Pvt Ltd"])
    status: str = Field(..., description="Scan lifecycle status: pending_governance | complete | failed.", examples=["complete"])
    timestamp: str = Field(..., description="ISO-8601 datetime string of when the scan was created.", examples=["2026-04-04T10:36:55+05:30"])

    # Pillar scores
    tech_score: float = Field(..., description="Technical pillar score (0–100). Weight: 45% of MRQM.", examples=[63.5])
    governance_score: float = Field(..., description="Governance pillar score (0–100). Weight: 35% of MRQM.", examples=[41.2])
    exposure_score: float = Field(..., description="Perimeter exposure pillar score (0–100). Weight: 20% of MRQM.", examples=[85.0])
    mrqm_score: float = Field(..., description="Master Risk Quantification Metric (0–100).", examples=[61.87])
    risk_band: str = Field(..., description="Risk band: LOW | MEDIUM | CRITICAL.", examples=["MEDIUM"])

    # Active-probe outputs
    ssl_days: int = Field(..., description="Days until SSL certificate expires.", examples=[87])
    password_score: int = Field(..., description="zxcvbn password strength score (0–4). 0=weakest.", examples=[3])
    any_eol: bool = Field(..., description="True if any installed software is confirmed EOL.", examples=[False])

    # JSONB payloads (raw lists/dicts)
    software_inventory: list[Any] = Field(
        default_factory=list,
        description="Raw [{name, version}, ...] list from agent inventory.",
    )
    cve_findings: list[Any] = Field(
        default_factory=list,
        description="Enriched CVE data: [{software_name, version, is_eol, cves, software_risk}, ...].",
    )
    governance_answers: dict[str, Any] = Field(
        default_factory=dict,
        description="Submitted governance checklist answers: {control_key: bool, ...}.",
    )
    remediation_priorities: list[Any] = Field(
        default_factory=list,
        description="Ordered list of non-compliant controls from risk_engine.get_remediation_priorities().",
    )
    open_ports: list[Any] = Field(
        default_factory=list,
        description="Open port list from agent psutil scan.",
    )
    allowlisted_ports: list[Any] = Field(
        default_factory=list,
        description="Ports the organisation has explicitly allowlisted (excluded from exposure score).",
    )


class ScanHistoryItem(BaseModel):
    """
    Lightweight scan summary row for the history trend chart.

    Returned by GET /api/scans/history as a list.
    Only scalar fields — no heavy JSONB payloads — to keep the chart
    response fast.
    """

    scan_id: int = Field(..., description="Database primary key.", examples=[42])
    timestamp: str = Field(..., description="ISO-8601 datetime string.", examples=["2026-04-04T10:36:55+05:30"])
    mrqm_score: Optional[float] = Field(None, description="MRQM score, null if scan is pending.", examples=[61.87])
    tech_score: Optional[float] = Field(None, description="Technical pillar score, null if pending.", examples=[63.5])
    governance_score: Optional[float] = Field(None, description="Governance pillar score, null if pending.", examples=[41.2])
    exposure_score: Optional[float] = Field(None, description="Exposure pillar score, null if pending.", examples=[85.0])
    risk_band: Optional[str] = Field(None, description="Risk band label, null if pending.", examples=["MEDIUM"])
    status: str = Field(..., description="Scan lifecycle status.", examples=["complete"])


# ===========================================================================
# PORT ALLOWLIST
# ===========================================================================

class PortAllowlistEntry(BaseModel):
    """
    Inbound payload for POST /api/organizations/{org_id}/allowlist.

    Allowlisted ports are excluded from the exposure score calculation.
    Useful for organisations that legitimately operate services on
    high-risk ports (e.g. a managed SSH bastion on port 22).
    """

    port: int = Field(
        ...,
        ge=1,
        le=65535,
        description="Port number to allowlist.",
        examples=[8888],
    )
    description: str = Field(
        ...,
        description="Human-readable justification for this allowlist entry.",
        examples=["Company webapp on custom port"],
    )


class PortAllowlistResponse(BaseModel):
    """
    Response returned after successfully adding a port to the allowlist.
    """

    id: int = Field(..., description="Database primary key of the allowlist entry.", examples=[1])
    port: int = Field(..., description="The allowlisted port number.", examples=[8888])
    description: str = Field(..., description="Justification for the allowlist entry.", examples=["Company webapp on custom port"])
    added_at: str = Field(..., description="ISO-8601 datetime the entry was created.", examples=["2026-04-04T10:36:55+05:30"])


# ===========================================================================
# AUTH — registration + login contracts
# ===========================================================================

class RegisterRequest(BaseModel):
    """POST /api/auth/register — new MSME organisation sign-up."""

    business_name:  str      = Field(..., description="Trading / business name of the MSME.")
    email:          EmailStr = Field(..., description="Contact email — used as login credential.")
    password:       str      = Field(..., min_length=8, description="Plaintext password (hashed server-side, never stored).")
    sector:         str      = Field(default="other", description="Industry sector.")
    employee_count: int      = Field(default=1, ge=1, description="Headcount.")
    gst_number:     str      = Field(default="", description="GST / Udyam registration number (optional).")


class LoginRequest(BaseModel):
    """POST /api/auth/login — existing organisation sign-in."""

    email:    EmailStr = Field(..., description="Registered email address.")
    password: str      = Field(..., description="Account password.")


class AuthResponse(BaseModel):
    """Returned by both /register and /login on success."""

    access_token:  str = Field(..., description="Bearer JWT for subsequent API calls.")
    token_type:    str = Field(default="bearer")
    org_id:        str = Field(..., description="String representation of the organisation's integer PK.")
    business_name: str = Field(..., description="Registered business name.")
