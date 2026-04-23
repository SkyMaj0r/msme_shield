"""
api.py
------
FastAPI application, route definitions, and request orchestration for
MSME Shield.

Run locally (from backend/ directory):
    uvicorn api:app --reload --port 8000

STRICT CONSTRAINTS (never violate):
    - Absolute imports only. No relative imports.
    - This file is the ONLY place that knows about HTTP, DB, and routing.
    - Zero math logic — all calculations delegated to risk_engine.
    - Zero Pydantic model definitions — all imported from schemas.
    - Zero threat-intel logic — delegated to threat_intel.
    - database.py is never modified under any circumstances.
    - NVD_API_KEY loaded from environment. Never hardcoded.
    - admin_password is NEVER stored, logged, or persisted anywhere.
    - DB failures for non-critical paths are logged and execution continues.

IMPORT NOTE — active tools:
    check_ssl() and check_password() live in backend/active_tools.py.
    scripts/active_scanners.py is the Phase 3 DAST placeholder (all stubs).
    Imports are taken from active_tools (absolute, uvicorn CWD = backend/).
"""

from __future__ import annotations

import logging
import os
from contextlib import asynccontextmanager

from dotenv import load_dotenv
from fastapi import Depends, FastAPI, HTTPException, Query, status
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from active_tools import check_password, check_ssl
from auth import create_access_token, get_password_hash, verify_password
from database import engine, get_db
import models
from risk_engine import (
    calculate_exposure_score,
    calculate_governance_score,
    calculate_mrqm,
    calculate_technical_score,
    get_remediation_priorities,
    get_risk_band,
)
from schemas import (
    AgentPayload,
    AgentSubmitResponse,
    AuthResponse,
    FullScanResponse,
    GovernanceSubmission,
    LoginRequest,
    PortAllowlistEntry,
    PortAllowlistResponse,
    RegisterRequest,
    ScanHistoryItem,
)
from threat_intel import enrich_software_inventory

# ---------------------------------------------------------------------------
# Environment
# ---------------------------------------------------------------------------
load_dotenv()
NVD_API_KEY: str | None = os.getenv("NVD_API_KEY")

# ---------------------------------------------------------------------------
# Logger
# ---------------------------------------------------------------------------
logger = logging.getLogger("msme_shield.api")

# ---------------------------------------------------------------------------
# SSL safe-fallback: returned when no domain is provided
# ---------------------------------------------------------------------------
_SSL_SAFE_FALLBACK: int = 45  # days — healthy cert, no penalty triggered


# ===========================================================================
# Startup — auto-migrate auth columns
# ===========================================================================

@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Run on every server start. Adds email / password_hash columns to the
    organizations table if they don't exist yet (idempotent — safe to run
    repeatedly). This removes the need to manually run a migration script.
    """
    with engine.connect() as conn:
        conn.execute(text("""
            ALTER TABLE organizations
                ADD COLUMN IF NOT EXISTS email
                VARCHAR(255) NOT NULL DEFAULT ''
        """))
        conn.execute(text("""
            ALTER TABLE organizations
                ADD COLUMN IF NOT EXISTS password_hash
                VARCHAR(255) NOT NULL DEFAULT ''
        """))
        # Partial unique index: allows many rows with email='' (agent-created
        # orgs) while still enforcing uniqueness for real email addresses.
        conn.execute(text("""
            CREATE UNIQUE INDEX IF NOT EXISTS uq_organizations_email
                ON organizations (email)
                WHERE email <> ''
        """))
        conn.commit()
    logger.info("Auth columns ensured on organizations table.")
    yield


# ===========================================================================
# App initialisation
# ===========================================================================

app = FastAPI(
    lifespan=lifespan,
    title="MSME Shield — Cyber Risk Quantification API",
    description=(
        "Passive-Hybrid Cyber Risk Quantification Platform for Indian MSMEs. "
        "MRQM = (0.45 × Technical) + (0.35 × Governance) + (0.20 × Exposure). "
        "Aligned to CERT-In Directions April 2022 + NIST CSF 2.0. "
        "SDG 9: Industry, Innovation & Infrastructure."
    ),
    version="2.0.0",
    contact={
        "name": "MSME Shield Team",
        "email": "support@msmeshield.in",
    },
    license_info={"name": "MIT"},
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],          # TODO: restrict to specific origins in prod
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ===========================================================================
# HELPERS
# ===========================================================================

def get_or_create_org(db: Session, name: str) -> models.Organization:
    """
    Upsert an Organisation record by name.

    If no organisation exists with this name, one is created with safe
    defaults (micro / basic / active_scanning_enabled=False).

    This is a placeholder until the full registration flow (POST /api/auth/register)
    is implemented. At that point, organisation creation will be gated behind
    identity verification and Udyam registration number validation.

    Args:
        db:   Active SQLAlchemy session from get_db().
        name: Organisation name string from the agent payload.

    Returns:
        The Organisation ORM object (freshly refreshed from DB).
    """
    org = (
        db.query(models.Organization)
        .filter(models.Organization.name == name)
        .first()
    )
    if org is None:
        logger.info("Creating new organisation: %r", name)
        org = models.Organization(
            name=name,
            udyam_size="micro",
            it_maturity="basic",
            active_scanning_enabled=False,
        )
        db.add(org)
        db.commit()
        db.refresh(org)
    return org


def get_org_allowlisted_ports(db: Session, org_id: int) -> list[int]:
    """
    Return a flat list of allowlisted port numbers for an organisation.

    Allowlisted ports are excluded from calculate_exposure_score() so that
    intentionally-open, business-justified ports do not unfairly inflate the
    perimeter exposure score.

    Args:
        db:     Active SQLAlchemy session.
        org_id: Primary key of the Organisation record.

    Returns:
        List of integer port numbers on the allowlist (may be empty).
    """
    entries = (
        db.query(models.OrgPortAllowlist)
        .filter(models.OrgPortAllowlist.organization_id == org_id)
        .all()
    )
    return [e.port for e in entries]


def _build_full_scan_response(
    scan: models.ScanHistory,
    org: models.Organization,
    allowlisted_ports: list[dict],
    remediation_priorities: list[dict],
) -> FullScanResponse:
    """
    Assemble a FullScanResponse from a ScanHistory ORM row.

    Centralises the mapping logic so both GET /api/scans/latest and
    GET /api/scans/{scan_id} produce identical response shapes.

    Pending scans (status='pending_governance') return 0.0 for uncomputed
    scores and "PENDING" for risk_band. The ``status`` field signals to the
    dashboard that governance has not been submitted yet.

    Args:
        scan:                   ScanHistory ORM row.
        org:                    Organization ORM row (for name field).
        allowlisted_ports:      List of {port, description} dicts.
        remediation_priorities: Output of get_remediation_priorities().

    Returns:
        Populated FullScanResponse Pydantic model.
    """
    # Extract any_eol from the stored intel result dict
    cve_findings_raw = scan.cve_findings or {}
    any_eol: bool = False
    findings_list: list = []
    if isinstance(cve_findings_raw, dict):
        any_eol      = bool(cve_findings_raw.get("any_eol", False))
        findings_list = cve_findings_raw.get("findings", [])
    elif isinstance(cve_findings_raw, list):
        findings_list = cve_findings_raw

    # Extract open_ports from raw_payload if present
    raw_payload = scan.raw_payload or {}
    open_ports_raw: list = raw_payload.get("open_ports", [])

    # Timestamp → ISO string
    ts_str = scan.timestamp.isoformat() if scan.timestamp else ""

    return FullScanResponse(
        scan_id=scan.id,
        organization_name=org.name if org else "Unknown",
        status=scan.status,
        timestamp=ts_str,
        tech_score=scan.tech_score or 0.0,
        governance_score=scan.gov_score or 0.0,
        exposure_score=scan.exp_score or 0.0,
        mrqm_score=scan.mrqm_score or 0.0,
        risk_band=scan.risk_band or "PENDING",
        ssl_days=scan.ssl_days or _SSL_SAFE_FALLBACK,
        password_score=scan.password_score or 0,
        any_eol=any_eol,
        software_inventory=scan.software_inventory or [],
        cve_findings=findings_list,
        governance_answers=scan.governance_answers or {},
        remediation_priorities=remediation_priorities,
        open_ports=open_ports_raw,
        allowlisted_ports=allowlisted_ports,
    )


# ===========================================================================
# ENDPOINT 1 — Health check
# ===========================================================================

@app.get(
    "/api/check-ssl",
    tags=["Utility"],
    summary="Check SSL certificate expiry for a domain",
)
def check_ssl_endpoint(domain: str) -> dict:
    """Return days remaining on the SSL certificate for *domain*."""
    clean = domain.strip().lower()
    for prefix in ("https://", "http://"):
        if clean.startswith(prefix):
            clean = clean[len(prefix):]
    clean = clean.split("/")[0]
    days = check_ssl(clean)
    return {"ssl_days": days, "domain": clean}


@app.get(
    "/health",
    tags=["Utility"],
    summary="Liveness probe",
)
def health_check() -> dict:
    """
    Instant liveness probe. No DB call. Used by uptime monitors and CI checks.
    Returns service name and API version for basic sanity verification.
    """
    return {
        "status": "ok",
        "service": "msme-shield-api",
        "version": "2.0.0",
    }


# ===========================================================================
# ENDPOINT 2 — Step 1: Agent submits telemetry
# ===========================================================================

@app.post(
    "/api/agent/submit",
    response_model=AgentSubmitResponse,
    status_code=status.HTTP_200_OK,
    tags=["Scan — Step 1"],
    summary="Edge agent submits system telemetry (Step 1 of 2)",
)
def agent_submit(
    payload: AgentPayload,
    db: Session = Depends(get_db),
) -> AgentSubmitResponse:
    """
    Receives system telemetry from the MSME Shield edge agent (.exe) and runs
    the full threat-intelligence pipeline to produce a Technical pillar score.

    The agent double-clicks to run this. No web interaction is required.

    Pipeline:
        1. Upsert organisation record (name-based).
        2. Fetch org's port allowlist.
        3. SSL certificate check (active_tools.check_ssl).
        4. NVD + EPSS + EOL enrichment (threat_intel.enrich_software_inventory).
        5. Technical score (risk_engine.calculate_technical_score).
        6. Exposure score with allowlist filtering (risk_engine.calculate_exposure_score).
        7. Preview MRQM (governance=0 placeholder).
        8. Persist ScanHistory row with status="pending_governance".
        9. Return scan_id + partial scores to agent for logging.

    After this call the scan is in status="pending_governance". The owner must
    open the dashboard and submit governance answers to complete the MRQM.
    """
    try:
        # ── a. Upsert organisation ──────────────────────────────────────────
        org = get_or_create_org(db, payload.organization_name)
        if payload.it_maturity and payload.it_maturity != org.it_maturity:
            org.it_maturity = payload.it_maturity
            db.commit()
            db.refresh(org)
        logger.info(
            "Agent submit: org=%r  it_maturity=%r  software=%d  ports=%d",
            org.name, org.it_maturity,
            len(payload.software_list), len(payload.open_ports),
        )

        # ── b. Port allowlist ───────────────────────────────────────────────
        allowlisted: list[int] = get_org_allowlisted_ports(db, org.id)
        logger.info("Allowlisted ports for org %d: %s", org.id, allowlisted)

        # ── c. SSL check ────────────────────────────────────────────────────
        domain = payload.domain_name.strip()
        if domain and domain.lower() not in ("", "localhost", "127.0.0.1"):
            ssl_days: int = check_ssl(domain)
            logger.info("SSL check: domain=%r  days_remaining=%d", domain, ssl_days)
        else:
            ssl_days = _SSL_SAFE_FALLBACK
            logger.info("No domain provided — ssl_days defaulting to %d", ssl_days)

        # ── d. Threat intel pipeline ────────────────────────────────────────
        software_list = [s.model_dump() for s in payload.software_list]
        logger.info("Starting threat-intel enrichment for %d software items.", len(software_list))
        intel_result: dict = enrich_software_inventory(software_list, NVD_API_KEY)
        findings:     list = intel_result.get("findings", [])
        any_eol:      bool = intel_result.get("any_eol", False)
        all_cve_ids:  list = intel_result.get("all_cve_ids", [])
        logger.info(
            "Threat intel complete: findings=%d  any_eol=%s  cves=%d",
            len(findings), any_eol, len(all_cve_ids),
        )

        # ── e. Technical score ──────────────────────────────────────────────
        tech_score: float = calculate_technical_score(
            enriched_findings=findings,
            any_eol=any_eol,
            ssl_days=ssl_days,
        )
        logger.info("Technical score: %.2f", tech_score)

        # ── f. Exposure score (allowlist-filtered) ──────────────────────────
        open_ports = [p.model_dump() for p in payload.open_ports]
        # Filter allowlisted ports before passing to the risk engine.
        # This is data filtering, not math logic — allowlisted ports are
        # business-justified exceptions that should not penalise the org.
        non_allowlisted_ports = [p for p in open_ports if p["port"] not in allowlisted]
        exposure_score: float = calculate_exposure_score(
            open_ports=non_allowlisted_ports,
        )
        logger.info(
            "Exposure score: %.2f  (%d ports evaluated, %d allowlisted)",
            exposure_score, len(non_allowlisted_ports), len(open_ports) - len(non_allowlisted_ports),
        )

        # ── ACTIVE SCANNING HOOK — Phase 3 (Post-Demo) ──────────────────────
        # Enabled only for intermediate/advanced maturity orgs
        # that have explicitly opted in via dashboard settings.
        # Requires written authorization from the org owner.
        #
        # When org.active_scanning_enabled == True:
        #   from scripts.active_scanners import run_active_scan
        #   active_findings = run_active_scan(
        #       domain=payload.domain_name,
        #       scan_type="full"  # sqli, xss, port_scan
        #   )
        #   exposure_score = merge_passive_and_active(
        #       passive_score=exposure_score,
        #       active_findings=active_findings,
        #   )
        # ────────────────────────────────────────────────────────────────────

        # ── g. Preview MRQM (governance=0 placeholder) ──────────────────────
        preview_mrqm: float = calculate_mrqm(
            tech_score=tech_score,
            gov_score=0.0,
            exp_score=exposure_score,
        )
        risk_band_preview: str = get_risk_band(preview_mrqm)
        logger.info(
            "Preview MRQM (no governance): %.2f  band=%s",
            preview_mrqm, risk_band_preview,
        )

        # ── h. Persist scan ─────────────────────────────────────────────────
        # admin_password is explicitly excluded — it must never be persisted.
        scan_raw_payload = payload.model_dump(exclude={"admin_password"})
        scan = models.ScanHistory(
            organization_id=org.id,
            status="pending_governance",
            tech_score=tech_score,
            exp_score=exposure_score,
            ssl_days=ssl_days,
            software_inventory=findings,   # per-software enriched list
            cve_findings=intel_result,     # full intel result dict (findings + any_eol + all_cve_ids)
            raw_payload=scan_raw_payload,
        )
        db.add(scan)
        db.commit()
        db.refresh(scan)
        logger.info("ScanHistory row created: id=%d  org_id=%d", scan.id, org.id)

        # ── i. Return response ───────────────────────────────────────────────
        return AgentSubmitResponse(
            scan_id=scan.id,
            tech_score=tech_score,
            risk_band_preview=risk_band_preview,
            software_count=len(findings),
            cve_count=len(all_cve_ids),
            any_eol=any_eol,
            ssl_days=ssl_days,
            message=(
                "Scan created. Open dashboard to complete governance assessment."
            ),
        )

    except Exception as exc:
        logger.exception("agent_submit pipeline failed: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Scan pipeline error: {exc}",
        ) from exc


# ===========================================================================
# ENDPOINT 3 — Step 2: Owner submits governance answers
# ===========================================================================

@app.post(
    "/api/scans/{scan_id}/governance",
    response_model=FullScanResponse,
    status_code=status.HTTP_200_OK,
    tags=["Scan — Step 2"],
    summary="Dashboard submits governance checklist (Step 2 of 2)",
)
def submit_governance(
    scan_id: int,
    payload: GovernanceSubmission,
    db: Session = Depends(get_db),
) -> FullScanResponse:
    """
    Receives governance checklist answers from the Streamlit dashboard and
    computes the final MRQM score, completing the two-step scan flow.

    Pipeline:
        1. Fetch and validate the scan (must be pending_governance).
        2. Evaluate admin_password strength in-process (never persisted).
        3. Compute governance score + per-control breakdown.
        4. Build remediation priority list (statutory controls first).
        5. Compute final MRQM using stored tech + exposure scores.
        6. Update ScanHistory row to status="complete".
        7. Return the full FullScanResponse for dashboard rendering.

    The admin_password field is evaluated by zxcvbn in-memory and then
    immediately discarded. It is never stored, logged, or included in
    any persisted payload.
    """
    try:
        # ── a. Fetch and validate scan ──────────────────────────────────────
        scan = (
            db.query(models.ScanHistory)
            .filter(models.ScanHistory.id == scan_id)
            .first()
        )
        if scan is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Scan {scan_id} not found.",
            )
        if scan.status == "complete":
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Governance already submitted for scan {scan_id}.",
            )
        logger.info(
            "Governance submission: scan_id=%d  it_maturity=%r",
            scan_id, payload.it_maturity,
        )

        # ── b. Password strength check (in-process, never persisted) ────────
        password_score: int = check_password(payload.admin_password)
        logger.info("Password strength evaluated: score=%d  (string discarded)", password_score)
        # admin_password is now discarded — payload.admin_password is never
        # accessed again, written to DB, or included in any log message.

        # ── c. Governance score + breakdown ─────────────────────────────────
        answers: dict[str, bool] = payload.to_answers_dict()
        gov_score, breakdown = calculate_governance_score(
            answers=answers,
            it_maturity=payload.it_maturity,
        )
        logger.info("Governance score: %.2f  maturity=%r", gov_score, payload.it_maturity)

        # ── d. Remediation priorities ────────────────────────────────────────
        priorities = get_remediation_priorities(breakdown)
        logger.info("Remediation priorities: %d non-compliant controls", len(priorities))

        # ── e. Final MRQM ────────────────────────────────────────────────────
        tech_score: float  = scan.tech_score  or 0.0
        exp_score:  float  = scan.exp_score   or 0.0
        mrqm_score: float  = calculate_mrqm(
            tech_score=tech_score,
            gov_score=gov_score,
            exp_score=exp_score,
        )
        risk_band: str = get_risk_band(mrqm_score)
        logger.info("Final MRQM: %.2f  band=%s", mrqm_score, risk_band)

        # ── f. Persist updated scan ─────────────────────────────────────────
        scan.status         = "complete"
        scan.gov_score      = gov_score
        scan.mrqm_score     = mrqm_score
        scan.risk_band      = risk_band
        scan.password_score = password_score
        scan.governance_answers = answers
        db.commit()
        db.refresh(scan)
        logger.info("ScanHistory %d updated to status=complete", scan_id)

        # ── g. Fetch org for response ────────────────────────────────────────
        org = (
            db.query(models.Organization)
            .filter(models.Organization.id == scan.organization_id)
            .first()
        )

        # ── h. Fetch allowlisted ports for response ──────────────────────────
        allowlisted_raw = (
            db.query(models.OrgPortAllowlist)
            .filter(models.OrgPortAllowlist.organization_id == org.id)
            .all()
        ) if org else []
        allowlisted_ports = [
            {"port": e.port, "description": e.description}
            for e in allowlisted_raw
        ]

        # ── i. Return full response ──────────────────────────────────────────
        return _build_full_scan_response(
            scan=scan,
            org=org,
            allowlisted_ports=allowlisted_ports,
            remediation_priorities=priorities,
        )

    except HTTPException:
        raise  # re-raise 404 / 400 without wrapping them in 500
    except Exception as exc:
        db.rollback()
        logger.exception("submit_governance pipeline failed: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Governance scoring error: {exc}",
        ) from exc


# ===========================================================================
# ENDPOINT 4 — Latest scan for an org
# ===========================================================================

@app.get(
    "/api/scans/latest",
    response_model=FullScanResponse,
    status_code=status.HTTP_200_OK,
    tags=["Dashboard"],
    summary="Get most recent scan for an organisation",
)
def get_latest_scan(
    org_name: str = Query(default="Test MSME", description="Organisation name"),
    db: Session = Depends(get_db),
) -> FullScanResponse:
    """
    Returns the most recent scan (any status) for the queried organisation.

    If the scan is pending_governance, scores are zeroed and risk_band is
    "PENDING" — the dashboard shows an onboarding card prompting the owner
    to complete the governance checklist.

    If the scan is complete, the full MRQM scorecard is returned including
    remediation priorities reconstructed from stored governance answers.
    """
    org = (
        db.query(models.Organization)
        .filter(models.Organization.name == org_name)
        .first()
    )
    if org is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Organisation '{org_name}' not found.",
        )

    scan = (
        db.query(models.ScanHistory)
        .filter(models.ScanHistory.organization_id == org.id)
        .order_by(models.ScanHistory.timestamp.desc())
        .first()
    )
    if scan is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No scans found for organisation '{org_name}'.",
        )

    allowlisted_raw = (
        db.query(models.OrgPortAllowlist)
        .filter(models.OrgPortAllowlist.organization_id == org.id)
        .all()
    )
    allowlisted_ports = [
        {"port": e.port, "description": e.description} for e in allowlisted_raw
    ]

    # Reconstruct remediation priorities if complete
    if scan.status == "complete" and scan.governance_answers:
        _, breakdown = calculate_governance_score(
            answers=scan.governance_answers,
            it_maturity=org.it_maturity,
        )
        priorities = get_remediation_priorities(breakdown)
    else:
        priorities = []

    return _build_full_scan_response(
        scan=scan,
        org=org,
        allowlisted_ports=allowlisted_ports,
        remediation_priorities=priorities,
    )


# ===========================================================================
# ENDPOINT 5 — Scan history (trend chart)
# ===========================================================================

@app.get(
    "/api/scans/history",
    response_model=list[ScanHistoryItem],
    status_code=status.HTTP_200_OK,
    tags=["Dashboard"],
    summary="Get all scans for an organisation (trend chart)",
)
def get_scan_history(
    org_name: str = Query(default="Test MSME", description="Organisation name"),
    db: Session = Depends(get_db),
) -> list[ScanHistoryItem]:
    """
    Returns all scans for the queried organisation, ordered timestamp ASC
    (oldest → newest) for the MRQM trend chart in the dashboard.

    Only scalar fields are returned (no heavy JSONB payloads) to keep the
    history response lightweight and chart-friendly.
    """
    org = (
        db.query(models.Organization)
        .filter(models.Organization.name == org_name)
        .first()
    )
    if org is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Organisation '{org_name}' not found.",
        )

    scans = (
        db.query(models.ScanHistory)
        .filter(models.ScanHistory.organization_id == org.id)
        .order_by(models.ScanHistory.timestamp.asc())
        .all()
    )

    return [
        ScanHistoryItem(
            scan_id=s.id,
            timestamp=s.timestamp.isoformat() if s.timestamp else "",
            mrqm_score=s.mrqm_score,
            tech_score=s.tech_score,
            governance_score=s.gov_score,
            exposure_score=s.exp_score,
            risk_band=s.risk_band,
            status=s.status,
        )
        for s in scans
    ]


# ===========================================================================
# ENDPOINT 6 — Specific scan by ID
# ===========================================================================

@app.get(
    "/api/scans/{scan_id}",
    response_model=FullScanResponse,
    status_code=status.HTTP_200_OK,
    tags=["Dashboard"],
    summary="Get a specific scan by ID",
)
def get_scan_by_id(
    scan_id: int,
    db: Session = Depends(get_db),
) -> FullScanResponse:
    """
    Returns the full scan result for a specific scan ID.

    Useful for the dashboard when the owner navigates to a historical report
    or when the PDF generator fetches the data for a specific scan.

    Returns 404 if the scan does not exist.
    """
    scan = (
        db.query(models.ScanHistory)
        .filter(models.ScanHistory.id == scan_id)
        .first()
    )
    if scan is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan {scan_id} not found.",
        )

    org = (
        db.query(models.Organization)
        .filter(models.Organization.id == scan.organization_id)
        .first()
    )

    allowlisted_raw = (
        db.query(models.OrgPortAllowlist)
        .filter(models.OrgPortAllowlist.organization_id == scan.organization_id)
        .all()
    )
    allowlisted_ports = [
        {"port": e.port, "description": e.description} for e in allowlisted_raw
    ]

    if scan.status == "complete" and scan.governance_answers:
        _, breakdown = calculate_governance_score(
            answers=scan.governance_answers,
            it_maturity=org.it_maturity if org else "basic",
        )
        priorities = get_remediation_priorities(breakdown)
    else:
        priorities = []

    return _build_full_scan_response(
        scan=scan,
        org=org,
        allowlisted_ports=allowlisted_ports,
        remediation_priorities=priorities,
    )


# ===========================================================================
# ENDPOINT 7 — Add port to allowlist (POST)
# ===========================================================================

@app.post(
    "/api/organizations/{org_id}/allowlist",
    response_model=PortAllowlistResponse,
    status_code=status.HTTP_200_OK,
    tags=["Port Allowlist"],
    summary="Add a port to organisation's allowlist",
)
def add_port_to_allowlist(
    org_id: int,
    payload: PortAllowlistEntry,
    db: Session = Depends(get_db),
) -> PortAllowlistResponse:
    """
    Allowlists a port for an organisation, removing it from future exposure
    score calculations.

    Idempotent: if the port is already allowlisted, the existing entry is
    returned without creating a duplicate.

    Example use-case: a company legitimately runs SSH on port 22 for a
    hardened bastion host. They add it here to prevent the exposure score
    from penalising a deliberately managed and monitored service.
    """
    org = db.query(models.Organization).filter(models.Organization.id == org_id).first()
    if org is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Organisation {org_id} not found.",
        )

    # Idempotent: return existing entry if port already allowlisted
    existing = (
        db.query(models.OrgPortAllowlist)
        .filter(
            models.OrgPortAllowlist.organization_id == org_id,
            models.OrgPortAllowlist.port == payload.port,
        )
        .first()
    )
    if existing:
        logger.info(
            "Port %d already on allowlist for org %d — returning existing entry.",
            payload.port, org_id,
        )
        return PortAllowlistResponse(
            id=existing.id,
            port=existing.port,
            description=existing.description,
            added_at=existing.added_at.isoformat() if existing.added_at else "",
        )

    entry = models.OrgPortAllowlist(
        organization_id=org_id,
        port=payload.port,
        description=payload.description,
    )
    db.add(entry)
    db.commit()
    db.refresh(entry)
    logger.info("Port %d added to allowlist for org %d", payload.port, org_id)

    return PortAllowlistResponse(
        id=entry.id,
        port=entry.port,
        description=entry.description,
        added_at=entry.added_at.isoformat() if entry.added_at else "",
    )


# ===========================================================================
# ENDPOINT 8 — Get allowlisted ports (GET)
# ===========================================================================

@app.get(
    "/api/organizations/{org_id}/allowlist",
    response_model=list[PortAllowlistResponse],
    status_code=status.HTTP_200_OK,
    tags=["Port Allowlist"],
    summary="Get all allowlisted ports for an organisation",
)
def get_port_allowlist(
    org_id: int,
    db: Session = Depends(get_db),
) -> list[PortAllowlistResponse]:
    """
    Returns all allowlisted ports for an organisation.

    Used by the dashboard to display managed exceptions and by api.py
    internally to filter ports before computing the exposure score.
    """
    org = db.query(models.Organization).filter(models.Organization.id == org_id).first()
    if org is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Organisation {org_id} not found.",
        )

    entries = (
        db.query(models.OrgPortAllowlist)
        .filter(models.OrgPortAllowlist.organization_id == org_id)
        .all()
    )
    return [
        PortAllowlistResponse(
            id=e.id,
            port=e.port,
            description=e.description,
            added_at=e.added_at.isoformat() if e.added_at else "",
        )
        for e in entries
    ]


# ===========================================================================
# ENDPOINT 9 — Register
# ===========================================================================

@app.post(
    "/api/auth/register",
    response_model=AuthResponse,
    status_code=status.HTTP_201_CREATED,
    tags=["Auth"],
    summary="Register a new MSME organisation",
)
def register(payload: RegisterRequest, db: Session = Depends(get_db)) -> AuthResponse:
    """
    Create a new Organisation row, hash the password, and return a JWT.

    - 400 if the email is already registered.
    - The plain-text password is discarded immediately after hashing.
    """
    # Check email uniqueness
    if db.query(models.Organization).filter(
        models.Organization.email == str(payload.email)
    ).first():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="An account with this email already exists.",
        )

    # Check business name uniqueness
    if db.query(models.Organization).filter(
        models.Organization.name == payload.business_name
    ).first():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="A business with this name is already registered. Choose a different name.",
        )

    try:
        org = models.Organization(
            name=payload.business_name,
            email=str(payload.email),
            password_hash=get_password_hash(payload.password),
            sector=payload.sector,
            employee_count=payload.employee_count,
            udyam_number=payload.gst_number or None,
        )
        db.add(org)
        db.commit()
        db.refresh(org)
    except IntegrityError as exc:
        db.rollback()
        logger.error("Registration IntegrityError: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Registration failed: email or business name already in use.",
        )

    token = create_access_token({"sub": str(org.id)})
    return AuthResponse(
        access_token=token,
        org_id=str(org.id),
        business_name=org.name,
    )


# ===========================================================================
# ENDPOINT 10 — Login
# ===========================================================================

@app.post(
    "/api/auth/login",
    response_model=AuthResponse,
    tags=["Auth"],
    summary="Sign in to an existing MSME organisation account",
)
def login(payload: LoginRequest, db: Session = Depends(get_db)) -> AuthResponse:
    """
    Verify credentials and return a fresh JWT.

    - 401 if email not found or password is wrong.
    """
    org = (
        db.query(models.Organization)
        .filter(models.Organization.email == str(payload.email))
        .first()
    )
    if not org or not verify_password(payload.password, org.password_hash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password.",
        )

    token = create_access_token({"sub": str(org.id)})
    return AuthResponse(
        access_token=token,
        org_id=str(org.id),
        business_name=org.name,
    )
