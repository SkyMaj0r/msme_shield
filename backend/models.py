"""
models.py
---------
SQLAlchemy ORM models for the MSME Shield platform.

Tables:
    organizations  — One row per registered MSME.
    scan_history   — One row per agent-initiated scan (two-step flow).

Two-step scan lifecycle (status field on ScanHistory):
    pending_governance → Agent has submitted; tech_score computed; awaiting
                         governance answers from the dashboard.
    complete           → Governance answers submitted; full MRQM computed.
    failed             → Pipeline error at any stage.

Import rule: ALL imports are absolute (uvicorn runs from backend/).
"""

from sqlalchemy import Boolean, Column, DateTime, ForeignKey, Integer, String, Float
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.sql import func

from database import Base


# ---------------------------------------------------------------------------
# Organization
# ---------------------------------------------------------------------------

class Organization(Base):
    """
    Represents a registered MSME entity.

    Fields added in v2 (two-step flow):
        udyam_number            — Legal Udyam registration number (nullable).
        domain                  — Apex domain for SSL checks (nullable).
        employee_count          — Headcount (nullable).
        sector                  — Industry sector e.g. "Manufacturing" (nullable).
        udyam_size              — Legal size classification: micro | small | medium.
                                  Determines applicable regulatory burden.
        it_maturity             — Self-selected IT maturity: basic | intermediate | advanced.
                                  Drives which governance tier is applied in the checklist.
        active_scanning_enabled — Opt-in toggle for Phase 3 active scanning.
                                  Off by default; visible only on intermediate/advanced dashboards.
    """

    __tablename__ = "organizations"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, unique=True, index=True, nullable=False)

    # --- auth fields ---
    # unique=True is intentionally omitted here; a partial unique index
    # (WHERE email <> '') is created at startup so agent-created orgs
    # with email='' don't conflict with each other.
    email         = Column(String(255), nullable=False, server_default="")
    password_hash = Column(String(255), nullable=False, server_default="")

    # --- v2 fields ---
    udyam_number            = Column(String,  nullable=True)
    domain                  = Column(String,  nullable=True)
    employee_count          = Column(Integer, nullable=True)
    sector                  = Column(String,  nullable=True)
    udyam_size              = Column(String,  nullable=False, default="micro")
    it_maturity             = Column(String,  nullable=False, default="basic")
    active_scanning_enabled = Column(Boolean, nullable=False, server_default="false")

    created_at = Column(DateTime(timezone=True), server_default=func.now())


# ---------------------------------------------------------------------------
# ScanHistory
# ---------------------------------------------------------------------------

class ScanHistory(Base):
    """
    One row per agent-initiated scan.

    Lifecycle:
        Agent POSTs → status="pending_governance", tech_score populated.
        Owner submits governance → status="complete", gov_score + mrqm populated.
        Any pipeline error      → status="failed".

    JSONB columns:
        software_inventory  — Raw list of {name, version} dicts from agent.
        cve_findings        — Enriched list from threat_intel: CVEs, CVSS,
                              EPSS probability, EOL flag per software.
        governance_answers  — Submitted checklist answers (key→bool dict).
        raw_payload         — Full agent POST body for audit traceability.
    """

    __tablename__ = "scan_history"

    id              = Column(Integer, primary_key=True, index=True)
    organization_id = Column(Integer, ForeignKey("organizations.id"), nullable=False)
    timestamp       = Column(DateTime(timezone=True), server_default=func.now())

    # --- Scan lifecycle ---
    status = Column(String, nullable=False, default="pending_governance")
    # Allowed values: pending_governance | complete | failed

    # --- Pillar scores (nullable until each step completes) ---
    mrqm_score = Column(Float,   nullable=True)
    tech_score = Column(Float,   nullable=True)
    gov_score  = Column(Float,   nullable=True)
    exp_score  = Column(Float,   nullable=True)
    risk_band  = Column(String,  nullable=True)

    # --- Active-tool outputs ---
    ssl_days       = Column(Integer, nullable=True)
    password_score = Column(Integer, nullable=True)

    # --- JSONB payloads ---
    software_inventory = Column(JSONB, nullable=True)
    # Raw [{name, version}, ...] list from agent inventory

    cve_findings = Column(JSONB, nullable=True)
    # Enriched [{software, cves:[{cve_id, cvss, epss}], is_eol, software_risk}, ...]

    governance_answers = Column(JSONB, nullable=True)
    # {log_retention: bool, incident_reporting: bool, ...}

    raw_payload = Column(JSONB, nullable=True)
    # Full agent POST body — kept for audit traceability


# ---------------------------------------------------------------------------
# OrgPortAllowlist
# ---------------------------------------------------------------------------

class OrgPortAllowlist(Base):
    """
    Ports intentionally open at an organisation that should be excluded from
    the perimeter exposure score.

    Example: A managed SSH bastion on port 22 that is expected and monitored
    should not penalise the organisation's exposure score. The owner adds it
    here with a justification, and api.py filters it out before calling
    risk_engine.calculate_exposure_score().
    """

    __tablename__ = "org_port_allowlist"

    id              = Column(Integer, primary_key=True, index=True)
    organization_id = Column(Integer, ForeignKey("organizations.id"), nullable=False)
    port            = Column(Integer, nullable=False)
    description     = Column(String, nullable=False, default="")
    added_at        = Column(DateTime(timezone=True), server_default=func.now())
