<div align="center">

# 🛡️ MSME Shield

### Passive-Hybrid Cyber Risk Quantification Platform for Indian MSMEs

*Zero passwords. Zero network disruption. Full CERT-In compliance.*

[![Python](https://img.shields.io/badge/Python-3.11+-3776AB?style=flat&logo=python&logoColor=white)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.110+-009688?style=flat&logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com/)
[![PostgreSQL](https://img.shields.io/badge/PostgreSQL-15+-336791?style=flat&logo=postgresql&logoColor=white)](https://www.postgresql.org/)
[![Streamlit](https://img.shields.io/badge/Streamlit-1.30+-FF4B4B?style=flat&logo=streamlit&logoColor=white)](https://streamlit.io/)
[![TRL](https://img.shields.io/badge/TRL-7-success?style=flat)](https://en.wikipedia.org/wiki/Technology_readiness_level)
[![SDG](https://img.shields.io/badge/SDG-9-fd6925?style=flat)](https://sdgs.un.org/goals/goal9)
[![License](https://img.shields.io/badge/License-Academic-blue?style=flat)](#license)

</div>

---

## 📖 Table of Contents

- [The One-Line Pitch](#-the-one-line-pitch)
- [The Problem We Are Solving](#-the-problem-we-are-solving)
- [Research Gaps Addressed](#-research-gaps-addressed)
- [Key Features](#-key-features)
- [System Architecture](#-system-architecture)
- [The MRQM Formula](#-the-mrqm-formula)
- [Tech Stack](#-tech-stack)
- [CVE Intelligence Pipeline](#-cve-intelligence-pipeline)
- [Repository Structure](#-repository-structure)
- [Installation & Setup](#-installation--setup)
- [Running the Application](#-running-the-application)
- [API Reference](#-api-reference)
- [Database Schema](#-database-schema)
- [Academic Grounding](#-academic-grounding)
- [Sprint Roadmap](#-sprint-roadmap)
- [The Team](#-the-team)
- [License](#-license)

---

## 🚀 The One-Line Pitch

**MSME Shield** is a passive-hybrid cyber risk quantification platform that gives Indian small business owners a **simple, jargon-free vulnerability report in under 10 minutes** — with zero network disruption, zero admin passwords, and full CERT-In compliance mapping.

Built specifically for the Indian *Dukaandaar* (business owner), it transforms the National Vulnerability Database (NVD), CISA Known Exploited Vulnerabilities (KEV) catalog, and Exploit Prediction Scoring System (EPSS) data into a single, actionable risk score on a 0–100 scale.

---

## 🎯 The Problem We Are Solving

Indian MSMEs constitute **~30% of the national GDP**, yet operate without dedicated security teams, SOCs, or CISOs. Existing solutions fail them on three concrete fronts:

| Problem | How Nessus / OpenVAS Fails | How MSME Shield Solves It |
|---|---|---|
| **Authentication Overhead** | Requires centralized admin passwords for every device. MSME networks have no Active Directory — causes 100% auth failure. | Edge Agent uses read-only OS commands. **Zero passwords needed.** No network disruption. |
| **Prohibitive Cost** | Nessus Professional: **₹3.3 lakh / year**. Qualys costs more. Unaffordable for any MSME. | Free, open-source. Runs on any Windows PC. No license fees. |
| **No Indian Compliance** | Reports cite HIPAA, SOC2, PCI-DSS. **CERT-In is never mentioned.** | Questionnaire built around **CERT-In April 2022 mandates** with specific section references. |
| **False Positive Flood** | Maps every software against the entire NVD — produces 500-page reports of theoretical, unexploitable bugs. | Filters through **CISA KEV catalog** — flags only bugs actively exploited by real attackers today. |

---

## 🔬 Research Gaps Addressed

Every architectural decision traces back to at least one of these three academic research gaps:

1. **Authentication Overhead & Network Disruption** — Traditional active scanners require credential management and aggressive probing, causing failures in decentralised MSME networks.
2. **Lack of Localized Compliance Mapping** — No existing tool integrates CERT-In's 6-hour incident reporting and 180-day log retention mandates into its risk algorithm.
3. **High False Positive Rates & Contextual Ignorance** — Current tools map indiscriminately against the entire NVD, causing alert fatigue instead of using CISA KEV to surface actively exploited threats.

---

## ✨ Key Features

### Core Engine

- **🧮 MRQM Risk Quantification** — Composite 0–100 score across three weighted pillars (Technical 45%, Governance 35%, Exposure 20%).
- **🔍 NVD + CISA KEV + EPSS Pipeline** — Live threat intelligence from official US government and FIRST.org sources.
- **💀 End-of-Life Detection** — Flags unpatched, unsupported software via the `endoflife.date` API.
- **🇮🇳 CERT-In Compliance Mapping** — Every governance question linked to a specific NIST CSF control and CERT-In directive section.

### Edge Agent (Zero-Setup, Read-Only)

- **🪶 Single `.exe` Distribution** — PyInstaller-packed Python script. No installation, no admin rights.
- **🔐 HMAC-SHA256 Payload Signing** — Tamper-proof telemetry submission.
- **📦 Comprehensive Inventory** — Software list (`winreg`), open ports (`psutil`), running services, antivirus status, browser extensions.

### Active Probing

- **🔒 SSL/TLS Certificate Validator** — Detects expired or weak certificates, factored into the technical score.
- **🔑 Password Strength Checker** — `zxcvbn`-based scoring (Dropbox standard), feeds governance penalty.
- **🌐 Perimeter Scanning** — Dual-mode (Nmap + Shodan) to bypass the Indian CGNAT problem.

### User-Facing Output

- **📊 Interactive Streamlit Dashboard** — Apple-inspired light/dark theme, three pages (Overview / History / Governance), persistent session state.
- **📄 ReportLab PDF Generator** — Boardroom-ready A4 report with NIST/CERT-In citations, color-coded gap tables, plain-English remediation.
- **📈 Re-Scan Delta Tracking** — Shows progression across multiple scans, building user retention.

---

## 🏗️ System Architecture

### Architecture Style: Modular Client-Server

We evaluated three patterns before choosing:

| Pattern | Verdict | Reason |
|---|---|---|
| Microservices | ❌ Rejected | Overkill for a 2-person team. Docker/Kubernetes overhead kills timeline. |
| Serverless (AWS Lambda) | ❌ Rejected | Cold-start latency breaks real-time scan UX. No persistent DB. AWS cost. |
| **Modular Client-Server** | ✅ **Chosen** | Clean separation of concerns. Production-ready upgrade path. Buildable by 2 people. |

### The Four Layers

```
┌─────────────────────────────────────────────────────────────────┐
│  Layer 1 — Edge Agent (MSME's Windows Machine)                  │
│  • Python + PyInstaller (.exe)                                  │
│  • Reads winreg, psutil, WMI — zero admin rights                │
│  • HMAC-SHA256 signs payload                                    │
└─────────────────────────┬───────────────────────────────────────┘
                          │ HTTPS POST (signed JSON)
                          ▼
┌─────────────────────────────────────────────────────────────────┐
│  Layer 2 — Backend Server                                       │
│  • FastAPI + Pydantic + Celery + Redis                          │
│  • schemas.py (data contract)                                   │
│  • risk_engine.py (pure MRQM math)                              │
│  • api.py (routing & orchestration)                             │
│  • threat_intel.py (NVD + KEV + EPSS pipeline)                  │
└──────────┬──────────────────────────────────┬───────────────────┘
           │ JSON                              │ SQL (ORM)
           ▼                                   ▼
┌──────────────────────────────┐  ┌──────────────────────────────┐
│  Layer 3 — Frontend          │  │  Layer 4 — Database          │
│  • Streamlit dashboard       │  │  • PostgreSQL + SQLAlchemy   │
│  • pdf_generator.py          │  │  • JSONB scan payloads       │
│  • Session-state caching     │  │  • UUID primary keys         │
└──────────────────────────────┘  └──────────────────────────────┘
```

### Core Architectural Principles

- **Separation of Concerns** — `schemas.py` owns data contracts; `api.py` owns routing; `risk_engine.py` owns mathematics. No module mixes responsibilities.
- **Fail-Secure Design** — Every ambiguity defaults to the most conservative (highest-risk) result. A missing governance key is treated as non-compliant.
- **Stateless Engine** — The MRQM calculator holds no session state. Identical inputs always produce identical outputs — critical for auditability.
- **Passive-Hybrid Telemetry** — The Edge Agent uses only read-only OS APIs. Never writes, modifies, or probes the network.

---

## 🧮 The MRQM Formula

The **MSME Risk Quantification Model (MRQM)** is the mathematical heart of the platform — an original named contribution suitable for academic citation.

> ### `MRQM = (0.45 × Technical) + (0.35 × Governance) + (0.20 × Exposure)`
>
> **Risk Bands:** `< 40 = LOW` · `40–69 = MEDIUM` · `≥ 70 = CRITICAL`

### Pillar 1 — Technical Score (Weight: 45%)

Combines static CVE base scores with dynamic threat intelligence amplifiers:

```
Technical_Score = SUM(CVSS_Base × EPSS_Score × KEV_Multiplier) ÷ Software_Count
                  + EOL_Penalty (+20 flat)
                  + EPSS_Penalty (probability × 30)
                  + SSL_Expiry_Penalty (+15 if cert < 30 days)
```

**Why these components?**
- **CVSS Base** — Industry-standard severity (0–10) from NVD.
- **EPSS Score** — Exploit probability (0.0–1.0) from FIRST.org. Multiplying CVSS × EPSS prioritizes vulnerabilities that are both severe *and* likely to be exploited.
- **KEV Multiplier (×2.5)** — Amplifies CVEs already in CISA's Known Exploited Vulnerabilities catalog. Ensures KEV bugs always rank above theoretical ones.
- **÷ Software_Count** — Normalizes so an MSME with 50 products isn't auto-scored worse than one with 5.

### Pillar 2 — Governance Score (Weight: 35%)

Tiered governance registry with auto-normalized weights summing to 100:

| Tier | Controls | Mapping |
|---|---|---|
| **Basic** | 10 controls | CERT-In statutory + NIST essentials |
| **Intermediate** | 15 controls | + 5 operational NIST CSF |
| **Advanced** | 20 controls | + 5 advanced NIST CSF |

Statutory CERT-In controls always carry the highest weight (e.g., 180-day log retention = 25–34 pts), reflecting their legal severity under **Section 70B of the IT Act 2000**.

### Pillar 3 — Exposure Score (Weight: 20%)

Sums `risk_weight` of all open ports, capped at 100:

| Port | Service | Risk Weight | Why Dangerous |
|---|---|---|---|
| **3389** | RDP | 85 | Most common ransomware entry point |
| **23** | Telnet | 90 | Credentials in plaintext — never use |
| **21** | FTP | 70 | Plaintext file transfer |
| **22** | SSH | 30 | Encrypted, but brute-force target |
| **443** | HTTPS | 5 | Baseline acceptable |

The cap preserves the convex-combination invariant: MRQM is bounded to `[0, 100]` regardless of how many high-risk ports are open.

---

## 🛠️ Tech Stack

| Component | Technology | Why This Choice |
|---|---|---|
| **Backend Framework** | FastAPI (Python 3.11+) | Async support, auto-generated OpenAPI docs, native Pydantic validation |
| **Data Validation** | Pydantic v2 | Strict type enforcement; rejects invalid data before engine is called |
| **Database** | PostgreSQL 15+ | JSONB for raw payloads, UUID keys, concurrent access, production-ready |
| **ORM** | SQLAlchemy 2.0 | Pythonic, type-hinted, production-grade |
| **Task Queue** | Celery + Redis | Async CVE lookups (30–60s) without blocking the UI |
| **Frontend UI** | Streamlit 1.30+ | Pure Python dashboard, professional output in ~300 lines |
| **PDF Generation** | ReportLab | Full programmatic control over A4 layout, tables, colors |
| **Edge Agent** | Python + PyInstaller | Single `.exe`, zero install, no admin rights |
| **Authentication** | JWT (python-jose) | Stateless, 15-min access + 7-day refresh tokens |
| **Perimeter Scan** | python-nmap + Shodan API | Dual-mode active/passive (CGNAT bypass) |
| **CVE Data** | NVD API v2.0 | Official US government CVE database |
| **Exploit Filter** | CISA KEV Catalog | ~1,100 actively exploited CVEs out of 200,000+ |
| **Exploit Probability** | EPSS (FIRST.org) | ML-based 30-day exploitation probability |
| **EOL Detection** | endoflife.date API | Tracks 300+ software end-of-life dates |
| **Caching** | Redis | 24h cache for NVD/EPSS results to avoid rate limits |
| **Password Strength** | zxcvbn | Same library used by Dropbox |

---

## 🔗 CVE Intelligence Pipeline

The core technical innovation. Every step is deliberate:

### Step 1 — CPE Normalization

Converts software names into NVD-compatible CPE strings:

```
"Apache HTTP Server 2.4.49"
        ↓
"cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*"
```

### Step 2 — NVD API v2.0 Query

- Rate limit: 50 requests / 10 seconds → **6-second delay between queries**.
- Redis cache (TTL = 86,400s) → if two MSMEs run Apache 2.4.49, NVD is queried once per day.
- All queries dispatched via Celery → user's browser never blocks.

### Step 3 — CISA KEV Filter

Out of **200,000+ NVD CVEs**, only **~1,100** are confirmed actively exploited. We filter against the daily KEV JSON dump and apply a **×2.5 multiplier** to any KEV match.

### Step 4 — EPSS Enrichment

Every CVE is enriched with its EPSS score:

> Example: **CVE-2021-44228 (Log4Shell)** has EPSS = **0.9754** → 97.54% probability of exploitation in 30 days. A theoretical SQLi in an obscure library might score 0.003.

### Step 5 — EOL Detection

Calls `endoflife.date` API. If the installed version is past EOL date → `is_eol = TRUE` → flat **+20 point penalty** applied (no patch will ever fix it).

---

## 📁 Repository Structure

```
msme_shield/
├── backend/
│   ├── __init__.py
│   ├── api.py                # FastAPI router; orchestrates 4-step pipeline
│   ├── risk_engine.py        # Pure MRQM mathematics; zero I/O
│   ├── schemas.py            # Pydantic data contracts
│   ├── models.py             # SQLAlchemy ORM (Organization, ScanHistory, OrgPortAllowlist)
│   ├── database.py           # ⚠️  DO NOT MODIFY — DB connection setup
│   ├── threat_intel.py       # NVD + EPSS + endoflife.date pipeline
│   └── active_tools.py       # check_ssl() and check_password() live functions
│
├── frontend/
│   ├── __init__.py
│   ├── dashboard.py          # Streamlit UI (Overview / History / Governance)
│   └── pdf_generator.py      # ReportLab A4 report
│
├── edge_agent/
│   ├── sensor.py             # Reads winreg/plistlib + psutil; POSTs to backend
│   └── .env.example          # AGENT_DOMAIN, API endpoint
│
├── scripts/
│   ├── __init__.py
│   └── active_scanners.py    # ⚠️  Legacy — do NOT import; use active_tools.py
│
├── docs/
│   ├── Architecture.pdf
│   ├── FunctionalDoc.pdf
│   ├── TestCases.pdf
│   └── MSME_Shield_Technical_Bible.docx
│
├── .env.example              # DATABASE_URL, NVD_API_KEY
├── requirements.txt
├── CLAUDE.md                 # Full architecture context for Claude Code
└── README.md                 # You are here
```

### Critical Architecture Rules

> ⚠️ **Read before contributing:**
>
> - **NEVER** modify `backend/database.py`
> - **NEVER** use relative imports (`from .module import x`) — Uvicorn runs from `backend/` as top-level. Absolute imports only.
> - **NEVER** hardcode `DATABASE_URL` or `NVD_API_KEY` — use `.env`.
> - **NEVER** add simulation flags or sliders.
> - **NEVER** put HTTP/DB calls in `risk_engine.py` — pure math only.
> - **NEVER** put Pydantic models outside `schemas.py`.
> - **NEVER** store `admin_password` in `session_state`.
> - **NEVER** import from `scripts/active_scanners.py` — use `backend/active_tools.py`.

---

## ⚙️ Installation & Setup

### Prerequisites

- **Python 3.11+**
- **PostgreSQL 15+** (running locally or accessible via URL)
- **Redis** (for Celery task queue)
- **Nmap** (Mac/Linux only — skipped on Windows)
- **macOS / Linux / Windows** (Edge Agent is Windows-primary; sensor.py supports Mac via `plistlib`)

### Step 1 — Clone & Create Environment

```bash
git clone https://github.com/<your-org>/msme-shield.git
cd msme-shield
python -m venv venv
source venv/bin/activate          # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

### Step 2 — Configure Environment Variables

Create `backend/.env`:

```env
DATABASE_URL=postgresql://user:password@localhost:5432/msme_shield
NVD_API_KEY=your_nvd_api_key_here
JWT_SECRET=your_jwt_secret_min_32_chars
REDIS_URL=redis://localhost:6379/0
```

Create `edge_agent/.env`:

```env
AGENT_DOMAIN=yourbusiness.in
API_BASE_URL=http://localhost:8000
HMAC_SECRET=shared_hmac_secret_with_backend
```

> 🔑 Get a free NVD API key at [nvd.nist.gov/developers/request-an-api-key](https://nvd.nist.gov/developers/request-an-api-key) — required for rate-limit lift.

### Step 3 — Initialize the Database

```bash
# Start PostgreSQL, then:
createdb msme_shield
cd backend
python -c "from database import Base, engine; from models import *; Base.metadata.create_all(engine)"
```

---

## ▶️ Running the Application

Open **three terminals** and run each component:

### Terminal 1 — Backend API

```bash
cd backend
uvicorn api:app --reload --port 8000
```

> API docs available at: `http://localhost:8000/docs`

### Terminal 2 — Frontend Dashboard

```bash
cd frontend
streamlit run dashboard.py
```

> Dashboard at: `http://localhost:8501`

### Terminal 3 — Edge Agent (on the MSME machine)

```bash
cd edge_agent
sudo python sensor.py        # macOS — psutil needs sudo
# OR on Windows (skip nmap automatically):
python sensor.py
```

> The agent collects telemetry, signs with HMAC-SHA256, and POSTs to `/api/agent/submit`. Timeout is **120s** (NVD pipeline takes ~46s).

---

## 📡 API Reference

All endpoints are REST/JSON. Authentication uses JWT Bearer tokens.

| Method | Endpoint | Auth | Purpose |
|---|---|---|---|
| `POST` | `/api/auth/register` | ❌ | Register new organization; returns JWT pair |
| `POST` | `/api/auth/login` | ❌ | Login; returns access + refresh tokens |
| `POST` | `/api/auth/refresh` | Refresh token | Get new access token |
| `POST` | `/api/agent/submit` | ✅ | Receive agent payload; verify HMAC; queue CVE job |
| `GET` | `/api/scans/{scan_id}/status` | ✅ | Poll scan status (pending / processing / complete) |
| `GET` | `/api/scans/{scan_id}/results` | ✅ | Full scan results: CVEs, scores, gaps |
| `POST` | `/api/scans/{scan_id}/governance` | ✅ | Submit questionnaire; compute governance score |
| `POST` | `/api/v1/calculate-risk` | ✅ | One-shot MRQM calculation (no DB persistence) |
| `GET` | `/api/scans/{scan_id}/report` | ✅ | Generate & stream PDF report |
| `GET` | `/api/organizations/{org_id}/history` | ✅ | All scans for an org — delta tracking |
| `GET` | `/api/benchmarks/{sector}` | ✅ | Sector average risk score |
| `GET` | `/api/perimeter/scan` | ✅ | Trigger Nmap/Shodan scan |
| `GET` | `/health` | ❌ | Liveness probe |

---

## 🗄️ Database Schema

| Table | Purpose |
|---|---|
| `organizations` | MSME profile — `org_id (UUID)`, name, GST, sector, employee_count |
| `scans` | One row per scan — `scan_id (UUID)`, `agent_payload (JSONB)`, status, HMAC, timestamps |
| `software_inventory` | Per-software-per-scan rows — name, vendor, version, CPE string, `is_eol` |
| `cve_findings` | Per-CVE-per-software-per-scan — CVE ID, CVSS, EPSS, `is_in_kev`, remediation |
| `governance_assessments` | Per-question-per-scan — NIST/CERT-In refs, answer, weight contribution |
| `risk_scores` | Final scores per scan — technical, governance, exposure, MRQM, risk band |

All primary keys are **UUIDs** (non-guessable, multi-tenant-ready). Raw agent payloads stored as **JSONB** for in-database querying without re-parsing.

---

## 🎓 Academic Grounding

Every design choice in MSME Shield maps to published standards or peer-reviewed research:

| Element | Citation |
|---|---|
| **Pillar Weights (45/35/20)** | NIST SP 800-30 Rev 1, Tables G-2 / G-3 |
| **Governance Controls** | CERT-In Directions, April 2022 + NIST CSF 2.0 |
| **Statutory Weighting** | IT Act 2000, Section 70B |
| **EPSS Scoring** | Jacobs et al., IEEE S&P 2021 |
| **EOL Penalty Rationale** | CISA KEV catalog methodology |
| **Port Risk Weights** | CISA / FBI StopRansomware Advisory 2022 |
| **CGNAT Solution** | Original — addresses unique Indian ISP infrastructure |
| **HMAC-SHA256 Signing** | RFC 2104 |

### SDG Alignment

> **SDG 9 — Industry, Innovation, and Infrastructure** · *Enhancing technological capability of Indian MSMEs*

By providing a low-cost, zero-friction tool that translates complex threat intelligence (NVD/CVE data) into simple, actionable remediation, MSME Shield **democratizes enterprise-grade cybersecurity**. MSMEs can build resilient digital infrastructure, securely participate in the digital economy, and sustain industrial growth without being crippled by ransomware or data breaches.

### TRL Target

> **TRL 7 — System Prototype in Operational Environment**
>
> The platform is tested on real Windows PCs with real software inventories, hitting live NVD/EPSS/KEV APIs, generating production-grade PDF reports retained as compliance evidence.

---

## 🗓️ Sprint Roadmap

| Sprint | Timeline | Status | Deliverables |
|---|---|---|---|
| **Sprint 1** | Feb 21, 2026 | ✅ Done | Abstract, DB schema, login/dashboard skeleton, NIST/CERT-In questionnaire forms |
| **Sprint 2** | March 22, 2026 | ✅ Done | Edge Agent (winreg + HMAC), Nmap/Shodan scan, agent-backend REST connection |
| **Sprint 3** | April 7, 2026 | ✅ Done | CVE Intelligence Pipeline (NVD + KEV + EPSS), EOL detection, CPE normalizer, Redis caching |
| **Sprint 4** | April 20, 2026 | 🟡 In Progress | MRQM scoring engine, governance scoring, sector benchmarking, delta tracking |
| **Sprint 5 (Final)** | **April 28–30, 2026** | 🔜 Upcoming | ReportLab PDF, full integration testing, demo prep |

### Currently in Sprint 4 — Pending Tasks

- [ ] Fix raw HTML rendering in governance control cards (`unsafe_allow_html=True`)
- [ ] Replace Yes/No buttons with `st.radio()` for non-sticky toggle behavior
- [ ] Wire PDF download button to `generate_report()` end-to-end
- [ ] Full end-to-end demo run verification
- [ ] Registration flow design + build
- [ ] Windows demo machine preparation checklist
- [ ] Viva Q&A preparation document

---

## 👥 The Team

> *SRM Institute of Science and Technology, Kattankulathur — School of Computing*

| Member | Role | Roll No |
|---|---|---|
| **Sarthak Suwan** | Product Owner / Developer | RA2311030010094 |
| **Avinash Shankar** | Scrum Master / Developer | RA2311030010110 |

### Faculty

- **Supervisor:** Dr. Balachander T
- **Faculty Advisor:** Dr. Lakshmi Narayanan R
- **Panel Head:** Dr. R. Radhika

---

## 🎤 Quick Reference — Viva Cheat Sheet

| Question | Answer |
|---|---|
| **Why not Nessus?** | ₹3.3L/year, requires admin passwords, no CERT-In mapping, 500-page jargon reports |
| **What is CGNAT?** | 78% of Indian MSMEs share a public IP with hundreds of others. Cloud-side Nmap hits the ISP, not the MSME. Solved with dual-mode (Shodan + inside-out). |
| **What is CISA KEV?** | Known Exploited Vulnerabilities catalog — ~1,100 CVEs confirmed actively exploited. We filter 200,000+ NVD CVEs down to what actually matters. |
| **What is EPSS?** | Exploit Prediction Scoring System by FIRST.org. 0–1 probability a CVE will be exploited in 30 days. Industry standard (Tenable.io). |
| **What is HMAC-SHA256?** | Hash-based Message Authentication Code. Agent signs payload so backend verifies it was not tampered with. |
| **What does MRQM stand for?** | MSME Risk Quantification Model — our original named formula. `(0.45 × T) + (0.35 × G) + (0.20 × E)` |
| **Why FastAPI over Flask?** | Async (non-blocking NVD calls), auto OpenAPI docs, native Pydantic validation |
| **Why PostgreSQL over SQLite?** | JSONB column type, UUID keys, concurrent writes, production-ready |
| **Why TRL 7?** | System prototype demonstrated in operational environment — real Windows PCs, real software inventories, live APIs |

---

## 📜 License

This project is developed as an academic capstone (Minor Project) at **SRM IST, Kattankulathur** for the 2025–26 academic year.

For commercial inquiries, partnership, or production deployment, please contact the team via the institution.

---

<div align="center">

**Built with 💛 for Indian MSMEs**

*Democratizing cybersecurity, one Dukaandaar at a time.*

—

[Report a Bug](https://github.com/<your-org>/msme-shield/issues) · [Request a Feature](https://github.com/<your-org>/msme-shield/issues) · [Documentation](./docs/)

</div>
