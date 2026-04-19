# MSME Shield — Claude Code Context

You are working on **MSME Shield**, a Passive-Hybrid Cyber Risk
Quantification Platform for Indian MSMEs.

Read all files in the project before doing anything.
Confirm what you have read before taking any action.

---

## Project Identity

- **Product:** MSME Shield
- **Tagline:** Passive-Hybrid Cyber Risk Quantification Platform for Indian MSMEs
- **SDG:** SDG 9 — Industry, Innovation & Infrastructure
- **TRL:** 8 — System complete and qualified
- **Demo:** April 28–30, 2026 at SRM IST Kattankulathur
- **Team:** Sarthak Suwan (Product Owner), Avinash Shankar (Scrum Master)
- **Supervisors:** Dr. Balachander T, Dr. Lakshmi Narayanan R

---

## How To Run

```bash
# Backend (from backend/ directory)
source venv/bin/activate
uvicorn api:app --reload --port 8000

# Edge Agent (from edge_agent/ directory, use sudo on Mac)
source venv/bin/activate
sudo python sensor.py

# Dashboard (from frontend/ directory)
source venv/bin/activate
streamlit run dashboard.py
```

Environment variables live in backend/.env:
- DATABASE_URL — PostgreSQL connection string
- NVD_API_KEY — NVD API v2.0 key

---

## Core Formula — MRQM

MRQM = (0.45 × Technical_Score) + (0.35 × Governance_Score) + (0.20 × Exposure_Score)

- Risk Bands: LOW < 40 | MEDIUM < 70 | CRITICAL >= 70
- Pillar weights: NIST SP 800-30 Rev 1, Tables G-2/G-3
- Governance hybrid: CERT-In Directions April 2022 + NIST CSF 2.0
- EPSS: FIRST.org / Jacobs et al., IEEE S&P 2021
- EOL penalty: CISA KEV catalog

---

## Architecture Overview

sensor.py (edge agent, Mac/Windows)
    -> POST /api/agent/submit
    -> backend: NVD + EPSS + EOL APIs -> computes tech_score
    -> stores scan as status="pending_governance"
    -> returns scan_id

MSME owner opens Streamlit dashboard
    -> sees tech pillar already scored
    -> fills governance checklist
    -> POST /api/scans/{scan_id}/governance
    -> backend computes final MRQM
    -> updates scan to status="complete"
    -> dashboard shows full results + PDF download

Scan initiation is agent-driven, not web-driven.
The agent runs the scan. The dashboard shows results.
There is no "Scan Now" button.

---

## IMMUTABLE RULES — NEVER VIOLATE

1. NEVER modify backend/database.py — it is perfect and working.
2. NEVER use relative imports anywhere in backend/.
   Uvicorn runs from backend/ as top-level. Always use absolute imports.
   "from database import get_db" is correct.
   "from .database import get_db" will always crash.
3. NEVER hardcode DATABASE_URL or NVD_API_KEY. Always from .env.
4. NEVER add simulation flags (sim_rdp_exposed, sliders etc.) — deleted permanently.
5. NEVER put HTTP calls inside risk_engine.py — pure math only.
6. NEVER put DB calls inside risk_engine.py — pure math only.
7. NEVER put math logic inside api.py — call risk_engine functions only.
8. NEVER define Pydantic models outside schemas.py.
9. admin_password is NEVER stored, logged, or persisted anywhere.
   Evaluate with zxcvbn in-process, return integer score, discard immediately.

---

## File Responsibilities

database.py    — SQLAlchemy engine + session. DO NOT MODIFY.
models.py      — ORM table definitions. Add columns only via create_all.
schemas.py     — ALL Pydantic models. No models anywhere else.
risk_engine.py — Pure MRQM math. Zero HTTP, zero DB calls inside.
threat_intel.py — NVD + EPSS + EOL API calls. Zero math, zero DB.
active_tools.py — check_ssl + check_password. THE live probing file.
api.py         — HTTP routing + DB + orchestration. Only file knowing HTTP+DB.
sensor.py      — System telemetry collection. Zero FastAPI/SQLAlchemy.
dashboard.py   — Streamlit UI. Zero Pydantic, zero SQLAlchemy.
pdf_generator.py — ReportLab PDF. Zero HTTP, zero DB.
scripts/active_scanners.py — Phase 3 placeholder. DO NOT CALL.

---

## CORRECTIONS — Ground Truth (Follow These Over Everything Else)

1. active_tools.py is the live probing file.
   check_ssl() and check_password() live in backend/active_tools.py.
   scripts/active_scanners.py is Phase 3 placeholder — zero callable functions.
   Always import: from active_tools import check_ssl, check_password

2. Request timeout is 120s in sensor.py.
   NVD pipeline for 34 apps takes ~46s at 0.2s/call rate.
   Always use timeout=120 in sensor.py requests.post().

3. OrgPortAllowlist table exists in models.py.
   Three ORM classes: Organization, ScanHistory, OrgPortAllowlist.
   Three live DB tables: organizations, scan_history, org_port_allowlist.

4. psutil AccessDenied on Mac without sudo — expected behaviour.
   Run: sudo python sensor.py on Mac.
   Windows .exe works without elevation automatically.
   nmap fills port gap when psutil is denied.

5. nmap is skipped on Windows intentionally.
   nmap binary triggers Windows Defender on client machines.
   Only run nmap on Mac/Linux. psutil covers Windows port detection.

6. AGENT_DOMAIN must be set in edge_agent/.env for real SSL check.
   socket.getfqdn() returns reverse DNS of 127.0.0.1 — useless for SSL.

---

## Database Schema (Live State)

Table: organizations
  id                      Integer PK
  name                    String unique
  udyam_number            String nullable
  domain                  String nullable
  employee_count          Integer nullable
  sector                  String nullable
  udyam_size              String default=micro
  it_maturity             String default=basic
  active_scanning_enabled Boolean default=False
  created_at              DateTime server_default now()

Table: scan_history
  id                      Integer PK
  organization_id         Integer FK -> organizations.id
  timestamp               DateTime server_default now()
  status                  String default=pending_governance
  mrqm_score              Float nullable
  tech_score              Float nullable
  gov_score               Float nullable
  exp_score               Float nullable
  risk_band               String nullable
  ssl_days                Integer nullable
  password_score          Integer nullable
  software_inventory      JSONB nullable
  cve_findings            JSONB nullable
  governance_answers      JSONB nullable
  raw_payload             JSONB nullable

Table: org_port_allowlist
  id                      Integer PK
  organization_id         Integer FK -> organizations.id
  port                    Integer
  description             String default=""
  added_at                DateTime server_default now()

---

## API Endpoints

GET  /health                                — liveness probe
POST /api/agent/submit                      — agent telemetry -> threat intel -> pending scan
POST /api/scans/{id}/governance             — governance answers -> final MRQM
GET  /api/scans/latest                      — latest scan for org
GET  /api/scans/history                     — all scans for trend chart
GET  /api/scans/{id}                        — specific scan by ID
POST /api/organizations/{id}/allowlist      — add port to allowlist
GET  /api/organizations/{id}/allowlist      — get allowlisted ports
POST /api/auth/register                     — STUB, returns 501

---

## Governance Registry (20 Controls, 3 Tiers)

Weights auto-normalize at runtime. Sum always = 100.
CERT-In statutory controls always included regardless of maturity.

TIER 1 (all maturities):
  log_retention        raw_weight=5  CERT-In Section 6(ii)              statutory
  incident_reporting   raw_weight=5  CERT-In Section 4                  statutory
  incident_plan        raw_weight=4  CERT-In/GEN-2/2022 + NIST RS.RP-1  statutory
  mfa_enabled          raw_weight=4  CERT-In Section 6(v) + NIST PR.AC-7 statutory
  ntp_sync             raw_weight=3  CERT-In Section 6(i)               statutory
  offline_backup       raw_weight=3  NIST PR.IP-4
  least_privilege      raw_weight=3  NIST PR.AC-4
  patch_management     raw_weight=3  NIST PR.IP-12
  phishing_training    raw_weight=2  NIST PR.AT-1
  firewall_segmentation raw_weight=2 NIST PR.PT-3

TIER 2 (intermediate + advanced):
  asset_inventory, vulnerability_disclosure, privileged_access_ws,
  security_logging, vendor_risk

TIER 3 (advanced only):
  penetration_testing, data_classification, bcp_drp_tested,
  vapt_remediation, dedicated_ir_team

IT Maturity mapping:
  basic        -> Tier 1 only (10 controls)
  intermediate -> Tier 1 + Tier 2 (15 controls)
  advanced     -> Tier 1 + Tier 2 + Tier 3 (20 controls)

---

## Tech Score Formula

For each software in inventory:
  NVD API -> CVEs + CVSS scores
  EPSS API -> exploit probability per CVE
  per_cve_risk = cvss_score x epss_probability
  software_risk = max(per_cve_risk values, default=0.0)

raw_tech = (sum of software_risk / software_count) x 10
+ 20.0 if any_eol     (EOL_PENALTY — flat, categorical risk)
+ 15.0 if ssl_days <= 30  (SSL_EXPIRY_PENALTY)
tech_score = min(raw_tech, 100.0)

---

## Port Allowlist System

MSMEs run legitimate services on non-standard ports.
Per-org allowlist prevents false positive flagging.
- Ports in allowlist -> zero exposure contribution -> shown as Safe
- Only show ports <= 49151 (EPHEMERAL_THRESHOLD) in UI
- Ephemeral ports (>49151) like 59xxx, 60xxx are filtered out entirely
- Unknown ports (not in PORT_RISK_WEIGHTS, not allowlisted) -> prompt user

---

## Current Build Status

COMPLETE AND WORKING:
  PostgreSQL database with 3 tables
  threat_intel.py — live NVD + EPSS + EOL API calls
  risk_engine.py — tiered registry, real formula, auto-normalized weights
  schemas.py — two-step flow (AgentPayload + GovernanceSubmission)
  api.py — all 8 endpoints working, end-to-end verified
  sensor.py — software collection (Mac: plistlib, Windows: winreg) + ports
  dashboard.py — 3 pages (Overview, History, Governance) with top navbar
  pdf_generator.py — full A4 ReportLab report

KNOWN BUGS TO FIX (priority order):
  1. Raw HTML in governance control cards
     Citation divs rendering as text — missing unsafe_allow_html=True
     in st.markdown() calls inside page_governance() controls loop.

  2. Governance score preview showing raw HTML code
     Same issue — the preview card st.markdown() missing unsafe_allow_html=True.

  3. Yes/No buttons — replace with st.radio() per control
     Current st.button() pairs remain clickable after selection.
     Replace with horizontal st.radio() storing value in session_state.

  4. Top bar CSS overlap hiding navbar buttons
     A fixed/sticky CSS rule is covering the navbar area.
     Find position:fixed or position:sticky in CSS injection block and fix.

NOT BUILT YET (post-demo scope, do not build now):
  Registration flow (Udyam number, IT maturity onboarding)
  Active scanning (scripts/active_scanners.py implementation)
  Windows .exe compilation via PyInstaller
  Cloud deployment / containerization

---

## Dashboard Design System — Apple Light

PAGE_BG  = "#f5f5f7"              warm light grey, never pure white
CARD_BG  = "#ffffff"              white cards
TEXT_1   = "#1d1d1f"              primary text
TEXT_2   = "rgba(0,0,0,0.80)"     secondary
TEXT_3   = "rgba(0,0,0,0.48)"     tertiary/disabled
BLUE     = "#0071e3"              Apple Blue — ONLY chromatic accent
SHADOW   = "rgba(0,0,0,0.22) 3px 5px 30px 0px"
SUCCESS  = "#34c759"              data color only, not UI chrome
WARNING  = "#ff9f0a"              data color only
DANGER   = "#ff3b30"              data color only

Rules:
- NO visible card borders — shadow only for elevation
- NO gradients, NO textures, NO extra accent colors
- BLUE is the ONLY chromatic accent for interactive elements
- Letter spacing: -0.28px headings, -0.374px body 17px, -0.224px caption 14px
- Cards: 12px border-radius, shadow, no border

---

## Active Scanning — Phase 3 Placeholder

scripts/active_scanners.py is all comments — zero callable functions.
The hook comment in api.py marks where it connects in Phase 3.
active_scanning_enabled toggle on Organization model — not functional yet.
DO NOT implement until demo bugs are fixed and demo is done.

---

## Registration Flow — Post-Demo

Not built. Placeholder hooks exist in api.py (POST /api/auth/register -> 501).
Organization model has udyam_number, udyam_size, it_maturity columns ready.
"Test MSME" org is auto-created for demo.
DO NOT build this before April 28 demo.