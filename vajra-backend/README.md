# VAJRA Forensics (SIH26106)
### AI-Powered Email Threat Detection, GeoLocation & Forensic Intelligence Platform

[![Python Version](https://img.shields.io/badge/python-3.11%20%7C%203.12%20%7C%203.13-blue.svg)](https://www.python.org/)
[![Framework](https://img.shields.io/badge/FastAPI-0.115+-009688.svg?logo=fastapi)](https://fastapi.tiangolo.com/)
[![ORM](https://img.shields.io/badge/SQLAlchemy-2.0%20Async-red.svg)](https://www.sqlalchemy.org/)
[![Validation](https://img.shields.io/badge/Pydantic-v2.9+-E92063.svg)](https://docs.pydantic.dev/)
[![Tests](https://img.shields.io/badge/pytest-22%2F22%20Passing%20(100%25)-brightgreen.svg)](https://docs.pytest.org/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

**VAJRA** is an enterprise-grade, headless cybersecurity backend platform engineered for law enforcement, digital forensics units (DFUs), Security Operations Centers (SOCs), and email security analysts. Built for **Smart India Hackathon 2026 (Problem Statement SIH26106)**, VAJRA ingests suspicious email evidence, mathematically validates cryptographic authentication headers, parses complex hop chains, pinpoints geographic origin, checks threat intelligence databases, and delivers a deterministic 0–100 risk score with a courtroom-ready forensic dossier.

---

## Forensic Processing Pipeline

```text
  [ Raw Email Evidence ] (.eml / .msg / RFC 822 Headers)
            │
            ▼
┌─────────────────────────────────────────────────────────────┐
│ 1. Ingestion & Cryptographic Chain of Custody               │
│    • Strict 25 MB ceiling verification                     │
│    • Deterministic SHA-256 hash generation                  │
│    • Unique Forensic Case ID (VAJRA-YYYYMMDD-HEX)           │
└──────────────────────────┬──────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────┐
│ 2. RFC 5322 Parsing & Spoofing Heuristics                   │
│    • MIME multipart boundary unpacking                      │
│    • Display Name Spoofing & Embedded Email Trap detection  │
│    • Brand Impersonation analysis via Levenshtein Distance  │
└──────────────────────────┬──────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────┐
│ 3. Bottom-Up Hop Traversal & GeoIP Telemetry                │
│    • RFC 1918 Private Subnet & Loopback filtering           │
│    • Chronological reverse Received: hop inspection         │
│    • Originating ISP & MaxMind GeoLite2 City/ASN Resolution │
└──────────────────────────┬──────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────┐
│ 4. Threat Intel & Cryptographic Auth Matrix                 │
│    • SPF (RFC 7208), DKIM (RFC 6376), DMARC (RFC 7489)      │
│    • Live Tor Exit Node matching                            │
│    • Bulletproof / Hosting Datacenter ASN Flagging          │
└──────────────────────────┬──────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────┐
│ 5. Deterministic Risk Engine (0-100) & Offline AI           │
│    • Mathematically bound, capped penalty aggregation       │
│    • Severity Classification (SAFE / MODERATE / SUSPICIOUS /│
│      HIGH RISK / CRITICAL THREAT)                           │
│    • Air-gapped local LLM forensic justification (Ollama)   │
└──────────────────────────┬──────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────┐
│ 6. Actionable Output & Courtroom Evidence Export            │
│    • Machine-readable REST JSON Contracts                   │
│    • 1-Click Direct Download A4 PDF Forensic Dossier        │
└─────────────────────────────────────────────────────────────┘
```

---

## Key Forensic Capabilities

- **Air-Gapped & Privacy-Preserving**: Complete local execution with zero third-party cloud data leakage. Operates securely in isolated digital forensic lab environments.
- **Dual Ingestion Pathways**:
  - Binary multipart upload supporting standard RFC 5322 `.eml` and Microsoft Outlook `.msg` files.
  - REST JSON payload ingestion for raw header and body text strings.
- **Cryptographic Chain of Custody**: Immediate SHA-256 evidence hashing prevents evidence repudiation and establishes legal defensibility.
- **Defensive Bottom-Up Hop Analysis**: RFC-compliant hop extraction filters out non-routable private subnets (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `127.0.0.0/8`) to reliably expose true foreign relays.
- **Live MaxMind GeoIP & ASN Resolution**: Local binary database resolution (`GeoLite2-City.mmdb`, `GeoLite2-ASN.mmdb`) with graceful fallback to mock telemetry when databases are offline.
- **Threat Intelligence Feeds**: Real-time cross-referencing against verified Tor exit nodes and suspicious hosting providers.
- **Cryptographic Authentication Matrix**: Comprehensive validation of SPF, DKIM public-key signatures, and domain DMARC alignment policies.
- **Display Name & Brand Impersonation Defense**: Identifies deceptive display names (e.g., `"CEO <attacker@evil.com>"` or typosquatted brand domains).
- **Courtroom-Ready PDF Dossier**: Built-in 1-click A4 forensic report generator featuring executive summary, visual hop breakdown, threat vectors, and investigative recommendations.

---

## Database Decoupling: SQLite vs. PostgreSQL

VAJRA utilizes an asynchronous SQLAlchemy 2.0 storage layer decoupled from specific database engines:

1. **Embedded SQLite (`sqlite+aiosqlite`) — Default**:
   - Zero-RAM, zero-daemon configuration.
   - Ideal for rapid local development, laptop triage, and offline hackathon testing.
   - Out-of-the-box storage in `vajra.db`.
2. **Enterprise PostgreSQL (`postgresql+asyncpg`)**:
   - High-concurrency production storage with connection pooling.
   - Configured seamlessly via `DATABASE_URL` in `.env` or via Docker Compose.

---

## REST API Reference

The interactive Swagger UI documentation is available at `http://localhost:8000/docs`, and OpenAPI 3.1 JSON is accessible at `http://localhost:8000/api/v1/openapi.json`.

| Method | Endpoint | Description | Auth Required |
| :--- | :--- | :--- | :--- |
| `GET` | `/health` | System health check and telemetry status | No |
| `POST` | `/api/v1/auth/register` | Register a forensic investigator account | No |
| `POST` | `/api/v1/auth/login` | Authenticate and obtain JWT bearer token (supports JSON & Swagger OAuth form) | No |
| `POST` | `/api/v1/analyze/upload` | Upload `.eml` or `.msg` binary files for automated forensic analysis | Optional / Bearer |
| `POST` | `/api/v1/analyze/raw` | Submit raw RFC headers and body strings via JSON payload | Optional / Bearer |
| `GET` | `/api/v1/analyze/cases` | Paginated listing of forensic investigation cases | Optional / Bearer |
| `GET` | `/api/v1/analyze/cases/{id}` | Retrieve complete forensic dossier for a specific case ID | Optional / Bearer |
| `GET` | `/api/v1/analyze/cases/{id}/report` | Render 1-click downloadable A4 PDF forensic evidence dossier | Optional / Bearer |

---

## Repository Structure

```text
vajra-backend/
├── app/
│   ├── api/
│   │   └── v1/
│   │       ├── endpoints/
│   │       │   ├── analyze.py         # Forensic analysis & ingestion endpoints
│   │       │   └── auth.py            # User registration & JWT authentication
│   │       └── api.py                 # API v1 central router
│   ├── core/
│   │   ├── config.py                  # Pydantic Settings & environment validation
│   │   ├── database.py                # Async SQLAlchemy engine & session factory
│   │   └── security.py                # Password hashing & JWT token management
│   ├── models/
│   │   ├── case.py                    # EmailCase SQLAlchemy ORM model
│   │   └── user.py                    # User SQLAlchemy ORM model
│   ├── schemas/
│   │   ├── analyze.py                 # Pydantic forensic request/response schemas
│   │   ├── token.py                   # JWT token schemas
│   │   └── user.py                    # User account schemas
│   ├── services/
│   │   ├── auth_verifier.py           # SPF / DKIM / DMARC verification
│   │   ├── explainer.py               # Deterministic rule & Ollama LLM explanations
│   │   ├── geoip.py                   # MaxMind GeoLite2 binary IP/ASN resolver
│   │   ├── hops.py                    # RFC 5322 Received: hop traversal & parser
│   │   ├── parser.py                  # EML / MSG extraction & spoofing detection
│   │   ├── report_generator.py        # 1-Click A4 PDF forensic report template
│   │   ├── risk_scorer.py             # 0-100 Risk engine with penalty ceilings
│   │   └── threat_intel.py            # Tor exit node & Datacenter ASN lookup
│   └── main.py                        # FastAPI application entrypoint & lifespan
├── data/
│   ├── .gitkeep                       # Preserves directory in git
│   ├── tor_exit_nodes.txt             # Verified Tor exit node cache
│   ├── GeoLite2-City.mmdb             # (Auto-downloaded, ignored by git)
│   └── GeoLite2-ASN.mmdb              # (Auto-downloaded, ignored by git)
├── scripts/
│   └── download_geoip.py              # Automated MaxMind GeoIP binary downloader
├── tests/
│   ├── test_api.py                    # API endpoints & authentication test suite
│   ├── test_hops.py                   # Hop parser & private IP filtering tests
│   ├── test_parser.py                 # SHA-256 hash & spoofing heuristics tests
│   ├── test_risk_scorer.py            # Scoring penalties & boundary capping tests
│   └── test_threat_intel.py           # Tor exit & Datacenter ASN tests
├── .dockerignore                      # Docker build exclusions
├── .env.example                       # Environment configuration template
├── .gitignore                         # Git hygiene rules
├── Dockerfile                         # Production container definition
├── docker-compose.yml                 # Multi-service stack (Backend + PostgreSQL)
├── requirements.txt                   # Production Python dependencies
└── run.sh                             # Portable bash runner for Linux / macOS / WSL
```

---

## Quickstart Guide

### 1. Prerequisites
- **Python**: 3.11, 3.12, or 3.13
- **Git**

### 2. Environment Setup

Clone the repository and create a clean virtual environment:

```bash
# Clone the repository
git clone https://github.com/your-username/vajra-backend.git
cd vajra-backend

# Create and activate Python virtual environment
python -m venv .venv

# On Linux / macOS:
source .venv/bin/activate

# On Windows (PowerShell):
.venv\Scripts\Activate.ps1
# On Windows (CMD):
.venv\Scripts\activate.bat
```

### 3. Install Dependencies

```bash
pip install --upgrade pip
pip install -r requirements.txt
```

### 4. Configure Environment Variables

Copy the provided template:

```bash
cp .env.example .env
```

By default, `.env` is configured for **SQLite** with zero setup required:
```env
DATABASE_URL=sqlite:///./vajra.db
SECRET_KEY=change-this-to-a-secure-random-secret-in-production-2026
ENVIRONMENT=development
```

### 5. Download MaxMind GeoIP Databases

Run the automated installer to download the compiled MaxMind GeoLite2 binary databases:

```bash
python scripts/download_geoip.py
```

*(Note: If skipped, VAJRA gracefully falls back to mock GeoIP telemetry for local testing without crashing).*

### 6. Launch the Application

#### Option A: Direct Uvicorn Command
```bash
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

#### Option B: Portable Shell Runner (Linux / macOS / WSL)
```bash
chmod +x run.sh
./run.sh
```

Navigate to:
- **Interactive Documentation**: [http://localhost:8000/docs](http://localhost:8000/docs)
- **Alternative ReDoc**: [http://localhost:8000/redoc](http://localhost:8000/redoc)
- **Diagnostics Health Check**: [http://localhost:8000/health](http://localhost:8000/health)

---

## Running Automated Tests

VAJRA includes a comprehensive 22-test automated suite covering API endpoints, authentication, hop ordering, spoofing heuristics, and risk engine ceilings:

```bash
pytest -v
```

Expected output:
```text
============================= test session starts =============================
collected 22 items

tests/test_api.py::test_health_endpoint PASSED                           [  4%]
tests/test_api.py::test_auth_registration_and_login PASSED               [  9%]
tests/test_api.py::test_validation_error_jsonable_encoder PASSED         [ 13%]
tests/test_api.py::test_analyze_raw_endpoint_and_db_persistence PASSED   [ 18%]
tests/test_api.py::test_analyze_file_upload_eml PASSED                   [ 22%]
tests/test_api.py::test_case_report_html_endpoint PASSED                 [ 27%]
tests/test_api.py::test_payload_too_large_ceiling PASSED                 [ 31%]
tests/test_hops.py::test_rfc1918_and_loopback_filtering PASSED           [ 36%]
tests/test_hops.py::test_bottom_up_traversal_order PASSED                [ 40%]
tests/test_parser.py::test_sha256_cryptographic_evidence_chain PASSED    [ 45%]
tests/test_parser.py::test_display_name_spoofing_embedded_email PASSED   [ 50%]
tests/test_parser.py::test_display_name_spoofing_brand_mismatch PASSED   [ 54%]
tests/test_parser.py::test_legitimate_display_name_clean PASSED          [ 59%]
tests/test_risk_scorer.py::test_clean_safe_email PASSED                  [ 63%]
tests/test_risk_scorer.py::test_spf_fail_penalty PASSED                  [ 68%]
tests/test_risk_scorer.py::test_dkim_fail_penalty PASSED                 [ 72%]
tests/test_risk_scorer.py::test_dmarc_fail_penalty PASSED                [ 77%]
tests/test_risk_scorer.py::test_tor_exit_penalty PASSED                  [ 81%]
tests/test_risk_scorer.py::test_datacenter_and_spoofing_suspicious PASSED [ 86%]
tests/test_risk_scorer.py::test_maximum_ceiling_capped_at_100 PASSED     [ 90%]
tests/test_threat_intel.py::test_tor_exit_node_detection PASSED          [ 95%]
tests/test_threat_intel.py::test_datacenter_asn_detection PASSED         [100%]

============================= 22 passed in 15.95s =============================
```

---

## Docker Deployment

To spin up the entire production stack (FastAPI backend + PostgreSQL 15) with a single command:

```bash
docker compose up --build
```

The API service will be immediately accessible on port `8000`.

---

## Forensic Integrity & Compliance Notice

VAJRA is designed in alignment with digital forensics best practices:
1. **Non-Destructive Ingestion**: Input email payloads are never altered during parsing.
2. **Cryptographic Validation**: Evidence records include SHA-256 digests and timestamped audit trails.
3. **Deterministic Scoring**: Risk calculations are explainable, formula-driven, and repeatable for courtroom testimony.
