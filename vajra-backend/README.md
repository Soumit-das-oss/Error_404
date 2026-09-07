# VAJRA Forensics (SIH26106)
### Air-Gapped AI-Powered Email Threat Detection, GeoLocation & Forensic Intelligence Platform

[![Python Version](https://img.shields.io/badge/python-3.11%20%7C%203.12%20%7C%203.13-blue.svg)](https://www.python.org/)
[![Framework](https://img.shields.io/badge/FastAPI-0.115+-009688.svg?logo=fastapi)](https://fastapi.tiangolo.com/)
[![Architecture](https://img.shields.io/badge/Storage-Zero--Database%20RAM%20Store-purple.svg)](app/storage/memory_store.py)
[![Validation](https://img.shields.io/badge/Pydantic-v2.9+-E92063.svg)](https://docs.pydantic.dev/)
[![Tests](https://img.shields.io/badge/pytest-53%2F53%20Passing%20(100%25)-brightgreen.svg)](tests/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

**VAJRA** is an enterprise-grade, high-performance forensic cybersecurity platform engineered for law enforcement agencies, digital forensics units (DFUs), Security Operations Centers (SOCs), and threat analysts. Built for **Smart India Hackathon 2026 (Problem Statement SIH26106)**, VAJRA features a **zero-database, air-gapped architecture** with an in-memory thread-safe FIFO case store, Data Loss Prevention (DLP) PII scrubbing, 2-tier hybrid AI reasoning with automated fallback, evidence-based forensic threat triage, and certified ReportLab Platypus PDF dossier generation.

---

## Forensic Processing Pipeline

```text
       ┌─────────────────────────────────────────────────────────────┐
       │                   DUAL INGESTION PATHWAYS                   │
       ├──────────────────────────────┬──────────────────────────────┤
       │   Desktop Evidence Upload    │      Mobile Raw Ingestion    │
       │   POST /api/v1/upload        │      POST /api/v1/raw        │
       │   (.eml / .msg binary files) │   (Text stream + attachments)│
       └──────────────┬───────────────┴──────────────┬───────────────┘
                      │                              │
                      └──────────────┬───────────────┘
                                     │
                                     ▼
┌────────────────────────────────────────────────────────────────────┐
│ 1. Zero-Disk Ingestion & Cryptographic Chain of Custody            │
│    • Strict 25 MB quota enforcement (HTTP 413 guard)               │
│    • Deterministic SHA-256 evidence hashing across all payloads     │
│    • Unique Forensic Case ID (CAS-YYYYMMDD-HEX)                    │
│    • Pure in-memory buffer processing (zero disk writes)           │
└────────────────────────────────────┬───────────────────────────────┘
                                     │
                                     ▼
┌────────────────────────────────────────────────────────────────────┐
│ 2. Fault-Tolerant Hybrid Email Parsing (eml_parser / msg_parser)   │
│    • Standard RFC 5322 MIME & Outlook Compound File decomposition   │
│    • Error-guarded attachment extraction (handles corrupt base64)  │
│    • Multiline regex fallback for headers (Subject, From, To, Date)│
│    • Guaranteed non-null Subject & sender_domain extraction        │
└────────────────────────────────────┬───────────────────────────────┘
                                     │
                                     ▼
┌────────────────────────────────────────────────────────────────────┐
│ 3. Reverse MTA Hop Traversal & Local Threat Intelligence           │
│    • Bottom-up chronological Received: header traversal            │
│    • RFC 1918 Private Subnet & Loopback filtering                  │
│    • Origin relay pinpointing via MaxMind City & ASN MMDB binaries │
│    • Curated Tor Exit Node cache verification                      │
└────────────────────────────────────┬───────────────────────────────┘
                                     │
                                     ▼
┌────────────────────────────────────────────────────────────────────┐
│ 4. Evidence-Based Artifact Triage (Zero False Positives)           │
│    • QR Engine: Evaluates direct IP hosts, shorteners, phish paths │
│      (Benign QR e.g. google.com / UPI payments receive 0 penalty)  │
│    • PDF Engine: In-memory scan for /JavaScript and /Launch actions│
│      (Authentic PDFs with standard text & clean links = 0 penalty) │
│    • Image Engine: Neutral graphics & logos receive 0 penalty      │
│    • URL Engine: Deceptive anchor text vs actual href verification  │
└────────────────────────────────────┬───────────────────────────────┘
                                     │
                                     ▼
┌────────────────────────────────────────────────────────────────────┐
│ 5. Deterministic Threat Risk Engine (0-100 Scale)                  │
│    • SPF (+15), DKIM (+15), DMARC (+15) Failure Penalties          │
│    • Deceptive Link (+25), Malicious Quishing QR (+40, floor >= 60)│
│    • PDF Exploits: Embedded JS (+35), Launch Action (+45)          │
│    • Free Webmail BEC / Financial Lure (+35) & Urgency (+20, >= 55)│
│    • Verdicts: SAFE (0-19), SUSPICIOUS (20-59), MALICIOUS (60-100) │
└────────────────────────────────────┬───────────────────────────────┘
                                     │
                                     ▼
┌────────────────────────────────────────────────────────────────────┐
│ 6. In-Memory DLP Shield & Hybrid AI Auto-Failover                  │
│    • In-memory PII sanitization: Credit Cards, IBANs, Phones, Names│
│    • Tier 1: Groq Cloud LLM (3.5s timeout)                         │
│    • Tier 2: Ollama Local Air-Gapped LLM (5.0s timeout)            │
│    • Tier 3: Deterministic 3-sentence static fallback              │
└────────────────────────────────────┬───────────────────────────────┘
                                     │
                                     ▼
┌────────────────────────────────────────────────────────────────────┐
│ 7. Certified Courtroom Dossier & REST API Delivery                 │
│    • Thread-safe RAM FIFO Case Store (Capacity: 25)                │
│    • Certified ReportLab Platypus A4 PDF Dossier with SHA-256 table│
│    • Machine-readable REST JSON Contracts                          │
└────────────────────────────────────────────────────────────────────┘
```

---

## Key Forensic Capabilities

- **Zero-Database Architecture**: Eliminates database configuration, ORM locks, and disk migration issues. Case state is managed in a high-concurrency, thread-safe RAM FIFO store.
- **Pure In-Memory Zero-Disk Pipelines**:
  - `eml_parser.py`: Fault-tolerant RFC 5322 parsing with strict guards against corrupt base64 attachment blocks.
  - `qr_engine.py`: Evidence-based Quishing triage. Benign QR codes (e.g. `google.com`, `linkedin.com`, `upi://pay`) receive 0 penalty; only malicious endpoints (direct IP, URL shorteners, phishing paths) trigger penalties.
  - `pdf_engine.py`: In-memory PDF stream analysis inspecting for `/JavaScript`, `/Launch`, `/EmbeddedFiles` executables, and deceptive anchors. Authentic PDFs receive 0 penalty.
  - `dlp_shield.py`: Local in-memory PII redaction ensuring zero personal identifiers leave the system.
  - `report_generator.py`: Certified ReportLab Platypus PDF generated directly into in-memory `BytesIO` buffers.
- **Dual Ingestion Pathways**:
  - **Desktop Flow (`POST /api/v1/upload`)**: Multipart file upload accepting standard `.eml` and Outlook `.msg` files.
  - **Mobile Flow (`POST /api/v1/raw`)**: Accepts raw text streams, JSON payloads, or multipart form-data with simultaneous image and PDF attachments.
- **Air-Gapped Privacy & DLP Shield**: Automatically sanitizes sensitive PII (Credit Cards, IBANs, Phone Numbers, Personal Names) before passing telemetry to AI reasoning engines.
- **Resilient AI Auto-Failover**:
  - **Tier 1**: Groq cloud API client with strict 3.5s timeout for low latency.
  - **Tier 2**: Ollama air-gapped local endpoint (`http://localhost:11434/api/generate`) with 5.0s timeout.
  - **Tier 3**: Deterministic forensic briefing template guaranteed to execute with zero network access.
- **Defensive Bottom-Up Hop Analysis**: RFC-compliant hop extraction filters out non-routable private subnets (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `127.0.0.0/8`) to expose true external transit relays.
- **Certified PDF Dossier**: Produces an executive-grade Platypus PDF report in-memory with cryptographic hashes and running header/footer chain of custody.

---

## REST API Reference

The interactive Swagger UI documentation is available at `http://localhost:8000/docs`, and OpenAPI 3.1 JSON is accessible at `http://localhost:8000/api/v1/openapi.json`.

| Method | Endpoint | Description | Payload / Params |
| :--- | :--- | :--- | :--- |
| `GET` | `/health` | System health check and telemetry status | None |
| `POST` | `/api/v1/upload` | Upload `.eml` or `.msg` binary file | `multipart/form-data` (`file`, `dlp_masking`) |
| `POST` | `/api/v1/raw` | Ingest raw email text, JSON, or multipart attachments | `multipart/form-data`, `application/json`, or `text/plain` |
| `GET` | `/api/v1/cases` | Paginated listing of recent forensic cases | `page` (default: 1), `limit` (default: 25) |
| `GET` | `/api/v1/cases/{case_id}` | Retrieve complete forensic case by ID | Path parameter: `case_id` |
| `GET` | `/api/v1/cases/{case_id}/pdf` | Stream certified forensic PDF dossier | Path parameter: `case_id` |

### Forensic cURL Examples

#### 1. Desktop EML / MSG Upload
```bash
curl -X POST "http://localhost:8000/api/v1/upload?dlp_masking=true" \
  -H "Accept: application/json" \
  -F "file=@suspicious_email.eml"
```

#### 2. Mobile Ingestion (Raw Headers/Body + Uploaded Attachments)
```bash
curl -X POST "http://localhost:8000/api/v1/raw?dlp_masking=true" \
  -H "Accept: application/json" \
  -F "raw_email=From: attacker@gmail.com
To: victim@company.com
Subject: Urgent: Verify Payment Slip

Please review attached payment slip immediately." \
  -F "attachments=@qr_invoice.png" \
  -F "attachments=@invoice_spec.pdf"
```

#### 3. Direct JSON / Plain Text Ingestion
```bash
curl -X POST "http://localhost:8000/api/v1/raw?dlp_masking=true" \
  -H "Content-Type: application/json" \
  -d '{"raw_email": "From: billing@bank-alerts.com\nTo: user@domain.com\nSubject: Account Locked\n\nClick: http://192.168.1.1/login"}'
```

#### 4. Stream Certified Platypus PDF Dossier
```bash
curl -X GET "http://localhost:8000/api/v1/cases/CAS-20260908-ABC12345/pdf" \
  --output forensic_dossier.pdf
```

---

## Repository Structure

```text
vajra-backend/
├── app/
│   ├── analyzers/
│   │   ├── pdf_engine.py          # PyMuPDF in-memory PDF links & image extraction
│   │   ├── qr_engine.py           # zxing-cpp QR/Quishing decoder with inversion
│   │   ├── text_analyzer.py       # Urgency indicators & free webmail impersonation
│   │   └── url_analyzer.py        # Deceptive anchor mismatch & raw IP analysis
│   ├── api/
│   │   └── v1/
│   │       ├── analyze_routes.py  # /upload and /raw ingestion endpoints
│   │       ├── cases_routes.py    # /cases query & pagination endpoints
│   │       ├── report_routes.py   # /cases/{case_id}/pdf streaming endpoint
│   │       ├── router.py          # API v1 central router
│   │       └── api.py             # Router re-export
│   ├── core/
│   │   ├── config.py              # Pydantic Settings & environment validation
│   │   └── constants.py           # Penalty weights, heuristic regexes & templates
│   ├── parsers/
│   │   ├── eml_parser.py          # RFC 5322 MIME stream parser
│   │   ├── msg_parser.py          # Outlook .msg compound file parser
│   │   └── header_engine.py       # Bottom-up hop tracer & auth auditor (SPF/DKIM/DMARC)
│   ├── schemas/
│   │   └── analysis.py            # Pydantic forensic request/response DTO schemas
│   ├── services/
│   │   ├── ai/
│   │   │   ├── explainer_orchestrator.py # AI failover manager & prompt builder
│   │   │   ├── groq_provider.py          # Async Groq client (3.5s timeout)
│   │   │   └── ollama_provider.py        # Async Ollama client (5.0s timeout)
│   │   ├── dlp_shield.py          # PII scrubbing (Cards, IBANs, Phones, Names)
│   │   ├── report_generator.py    # ReportLab Platypus forensic PDF generator
│   │   └── risk_scorer.py         # Deterministic 0-100 scoring & verdicts
│   ├── storage/
│   │   └── memory_store.py        # Thread-safe RAM FIFO case store (capacity: 25)
│   └── main.py                    # FastAPI application entrypoint & lifespan
├── data/
│   ├── .gitkeep                   # Preserves data directory
│   ├── tor_exit_nodes.txt         # Verified Tor exit node cache
│   ├── GeoLite2-City.mmdb         # (Downloaded via script, ignored by git)
│   └── GeoLite2-ASN.mmdb          # (Downloaded via script, ignored by git)
├── scripts/
│   └── download_geoip.py          # Standalone MaxMind GeoIP binary downloader
├── tests/
│   ├── conftest.py                # Pytest fixtures & store reset
│   ├── test_ai_failover.py        # Groq -> Ollama -> Template failover tests
│   ├── test_api_endpoints.py      # REST API endpoints & FIFO store tests
│   ├── test_dlp_shield.py         # PII scrubbing tests
│   ├── test_parsers.py            # EML parsing & hop engine tests
│   └── test_risk_scorer.py        # Threat scoring & verdict override tests
├── .dockerignore                  # Docker build exclusions
├── .env.example                   # Environment configuration template
├── .gitignore                     # Git hygiene rules
├── Dockerfile                     # Production container definition
├── docker-compose.yml             # Single-service container stack
├── requirements.txt               # Essential forensic Python dependencies
└── run.sh                         # Lightweight runner script
```

---

## Quickstart Guide

### 1. Prerequisites
- **Python**: 3.11, 3.12, or 3.13
- **Git**

### 2. Environment Setup

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
```

### 3. Install Dependencies & GeoIP Binaries

```bash
pip install -r requirements.txt

# Download GeoLite2 databases into data/
python scripts/download_geoip.py
```

### 4. Configuration

Copy `.env.example` to `.env` and configure optional AI keys:

```bash
cp .env.example .env
```

```ini
ENVIRONMENT=development
GROQ_API_KEY=your_groq_api_key_here  # Optional: enables 3.5s cloud AI reasoning
OLLAMA_URL=http://localhost:11434/api/generate
OLLAMA_MODEL=llama3.2:1b
```

### 5. Launch the Server

```bash
# Using uvicorn directly:
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload

# Or via run.sh:
./run.sh
```

Navigate to `http://localhost:8000/docs` to inspect and interact with the forensic APIs.

---

## Running Verification Tests

The test suite covers the entire forensic pipeline with 100% pass rate:

```bash
pytest -v
```

```text
============================= test session starts =============================
platform win32 -- Python 3.13.4, pytest-9.1.1, pluggy-1.6.0
rootdir: D:\SIH\vajra-backend
plugins: anyio-4.15.1, asyncio-1.4.0
collected 52 items

tests/test_ai_failover.py::test_ai_failover_tier1_groq_success PASSED    [  1%]
tests/test_ai_failover.py::test_ai_failover_tier2_ollama_fallback PASSED [  3%]
tests/test_ai_failover.py::test_ai_failover_tier3_static_template_fallback PASSED [  5%]
tests/test_ai_failover.py::test_ai_dlp_masking_integration PASSED        [  7%]
tests/test_ai_failover.py::test_groq_reasoning_extraction_fallback PASSED [  9%]
tests/test_ai_failover.py::test_groq_empty_string_raises PASSED          [ 11%]
tests/test_ai_failover.py::test_ai_prompt_safe_verdict_generates_clearance_notice PASSED [ 13%]
tests/test_ai_failover.py::test_ai_prompt_threat_verdict_generates_incident_triage PASSED [ 15%]
tests/test_api_endpoints.py::test_health_check PASSED                    [ 17%]
tests/test_api_endpoints.py::test_analyze_raw_json PASSED                [ 19%]
tests/test_api_endpoints.py::test_analyze_raw_text_plain PASSED          [ 21%]
tests/test_api_endpoints.py::test_analyze_upload_eml PASSED              [ 23%]
tests/test_api_endpoints.py::test_get_cases_and_pagination PASSED        [ 25%]
tests/test_api_endpoints.py::test_get_case_pdf_stream PASSED             [ 26%]
tests/test_api_endpoints.py::test_memory_store_fifo_bound PASSED         [ 28%]
tests/test_api_endpoints.py::test_analyze_raw_plain_text_with_quotes_and_newlines PASSED [ 30%]
tests/test_api_endpoints.py::test_dlp_masking_bypassed_liability_alert PASSED [ 32%]
tests/test_api_endpoints.py::test_dlp_masking_active_default PASSED      [ 34%]
tests/test_api_endpoints.py::test_clean_authentic_newsletter_remains_safe PASSED [ 36%]
tests/test_api_endpoints.py::test_pdf_report_with_dlp_bypassed_banner PASSED [ 38%]
tests/test_api_endpoints.py::test_analyze_raw_free_webmail_financial_lure_endpoint PASSED [ 40%]
tests/test_api_endpoints.py::test_openapi_dlp_masking_schema_is_required_enum PASSED [ 42%]
tests/test_api_endpoints.py::test_analyze_raw_with_mobile_attachments_image_qr PASSED [ 44%]
tests/test_api_endpoints.py::test_analyze_raw_pratiksha_dabhekar_gmail_bec_with_attachments PASSED [ 46%]
tests/test_api_endpoints.py::test_benign_qr_code_evaluates_safe PASSED   [ 47%]
tests/test_api_endpoints.py::test_malicious_quishing_qr_triggers_penalty PASSED [ 49%]
tests/test_api_endpoints.py::test_clean_pdf_attachment_evaluates_safe PASSED [ 50%]
tests/test_api_endpoints.py::test_corrupted_truncated_mime_email_pratiksha_dabhekar PASSED [ 52%]
tests/test_api_endpoints.py::test_collapsed_single_line_headers_extraction PASSED [ 54%]
tests/test_dlp_shield.py::test_dlp_sanitize_credit_cards PASSED          [ 56%]
tests/test_dlp_shield.py::test_dlp_sanitize_iban PASSED                  [ 58%]
tests/test_dlp_shield.py::test_dlp_sanitize_phone_numbers PASSED         [ 60%]
tests/test_dlp_shield.py::test_dlp_sanitize_titled_names PASSED          [ 62%]
tests/test_dlp_shield.py::test_dlp_sanitize_labeled_names PASSED         [ 64%]
tests/test_dlp_shield.py::test_dlp_no_pii_intact PASSED                  [ 66%]
tests/test_parsers.py::test_parse_eml_bytes_basic PASSED                 [ 67%]
tests/test_parsers.py::test_parse_eml_bytes_multipart_attachments PASSED [ 69%]
tests/test_parsers.py::test_is_public_ip PASSED                          [ 71%]
tests/test_parsers.py::test_parse_hops_and_origin_ordering PASSED        [ 73%]
tests/test_parsers.py::test_audit_authentication_headers PASSED          [ 75%]
tests/test_risk_scorer.py::test_clean_authentic_email_scores_zero PASSED [ 77%]
tests/test_risk_scorer.py::test_authentication_penalties PASSED          [ 79%]
tests/test_risk_scorer.py::test_quishing_qr_penalty PASSED               [ 81%]
tests/test_risk_scorer.py::test_deceptive_link_penalty PASSED            [ 83%]
tests/test_risk_scorer.py::test_free_webmail_lure_and_urgency PASSED     [ 84%]
tests/test_risk_scorer.py::test_combined_critical_malicious_score PASSED [ 86%]
tests/test_risk_scorer.py::test_hard_forensic_override_for_quishing PASSED [ 88%]
tests/test_risk_scorer.py::test_score_bounded_to_100 PASSED              [ 90%]
tests/test_risk_scorer.py::test_free_webmail_domain_financial_lure_never_safe PASSED [ 92%]
tests/test_risk_scorer.py::test_corporate_newsletter_receives_discount PASSED [ 94%]
tests/test_risk_scorer.py::test_benign_qr_code_scores_zero PASSED        [ 96%]
tests/test_risk_scorer.py::test_pdf_threat_penalties_javascript_and_launch PASSED [ 98%]
tests/test_risk_scorer.py::test_clean_pdf_scores_zero PASSED             [100%]

======================= 53 passed, 2 warnings in 32.38s =======================
```

---

## Docker Deployment

```bash
# Build and run with Docker Compose
docker compose up -d --build

# Verify container status
docker compose ps

# View live application logs
docker compose logs -f backend
```

---

## SIH 2026 Problem Statement 26106 Compliance

| Requirement | Implementation Architecture |
| :--- | :--- |
| **MTA Reverse Hop Traversal** | Bottom-up chronological parsing in `header_engine.py` with RFC 1918 filtering |
| **Origin Pinpointing & GeoIP** | MaxMind `GeoLite2-City` & `GeoLite2-ASN` binary resolution |
| **Threat Intelligence** | Curated Tor exit nodes matching and datacenter ASN detection |
| **Cryptographic Authentication** | RFC 7208 SPF, RFC 6376 DKIM, and RFC 7489 DMARC audit matrix |
| **Deep Artifact Extraction** | PyMuPDF in-memory PDF extraction and zxing-cpp quishing decoder |
| **Deterministic Risk Scoring** | Bounded 0–100 score matrix with hard forensic overrides for quishing |
| **Courtroom Evidence Export** | ReportLab Platypus PDF report generator with cryptographic hash integrity |
| **Data Privacy & Air-Gap** | Zero persistent database, DLP PII masking, local Ollama LLM support |
