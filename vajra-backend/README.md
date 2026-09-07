# VAJRA Forensics (SIH26106)
### Air-Gapped AI-Powered Email Threat Detection, GeoLocation & Forensic Intelligence Platform

[![Python Version](https://img.shields.io/badge/python-3.11%20%7C%203.12%20%7C%203.13-blue.svg)](https://www.python.org/)
[![Framework](https://img.shields.io/badge/FastAPI-0.115+-009688.svg?logo=fastapi)](https://fastapi.tiangolo.com/)
[![Architecture](https://img.shields.io/badge/Storage-Zero--Database%20RAM%20Store-purple.svg)](app/storage/memory_store.py)
[![Validation](https://img.shields.io/badge/Pydantic-v2.9+-E92063.svg)](https://docs.pydantic.dev/)
[![Tests](https://img.shields.io/badge/pytest-30%2F30%20Passing%20(100%25)-brightgreen.svg)](tests/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

**VAJRA** is an enterprise-grade, high-performance forensic cybersecurity platform engineered for law enforcement agencies, digital forensics units (DFUs), Security Operations Centers (SOCs), and threat analysts. Built for **Smart India Hackathon 2026 (Problem Statement SIH26106)**, VAJRA features a **zero-database, air-gapped architecture** with an in-memory thread-safe FIFO case store, Data Loss Prevention (DLP) PII scrubbing, 2-tier hybrid AI reasoning with automated fallback, and certified ReportLab Platypus PDF dossier generation.

---

## Forensic Processing Pipeline

```text
  [ Raw Email Evidence ] (.eml / .msg / RFC 5322 MIME Stream)
            │
            ▼
┌─────────────────────────────────────────────────────────────┐
│ 1. Ingestion & Cryptographic Chain of Custody               │
│    • Strict 25 MB ceiling verification                     │
│    • Deterministic SHA-256 evidence hashing                 │
│    • Unique Forensic Case ID (CAS-YYYYMMDD-HEX)             │
│    • Zero disk writes: 100% RAM buffer processing           │
└──────────────────────────┬──────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────┐
│ 2. RFC 5322 Parsing & Multipart Unpacking                   │
│    • In-memory MIME tree decomposition (eml_parser)         │
│    • Outlook compound binary parsing (msg_parser)           │
│    • Body extraction (Plain text & HTML DOM parsing)        │
│    • Cryptographic attachment hashing                       │
└──────────────────────────┬──────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────┐
│ 3. Reverse MTA Hop Traversal & GeoIP Telemetry              │
│    • Bottom-up chronological Received: header traversal     │
│    • RFC 1918 Private Subnet & Loopback filtering           │
│    • Candidate origin IP pinpointing                        │
│    • MaxMind GeoLite2 City & ASN local binary resolution    │
│    • Tor Exit Node verification                             │
└──────────────────────────┬──────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────┐
│ 4. Deep Artifact Extraction & Quishing Engine               │
│    • PyMuPDF in-memory PDF hyperlink & anchor extraction    │
│    • Isolated zxing-cpp QR decoder with inverted polarity   │
│    • Deceptive URL mismatch detector (display vs href)      │
│    • Raw IP URL & dangerous payload extension detection     │
└──────────────────────────┬──────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────┐
│ 5. Deterministic Risk Engine (0-100 Scale)                  │
│    • SPF Fail (+15), DKIM Fail (+15), DMARC Fail (+15)      │
│    • Deceptive Link (+25), Quishing QR (+40)                │
│    • Urgency Indicators (+20), Free Webmail Lure (+35)      │
│    • Verdict: SAFE (0-19), SUSPICIOUS (20-59), MALICIOUS    │
│    • Hard Forensic Override for Quishing & Deceptive links  │
└──────────────────────────┬──────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────┐
│ 6. DLP Shield & Hybrid AI Auto-Failover                     │
│    • DLP scrubbing: Credit Cards, IBANs, Phones, Names      │
│    • Tier 1: Groq Cloud LLM (3.5s timeout)                  │
│    • Tier 2: Ollama Local Air-Gapped LLM (5.0s timeout)     │
│    • Tier 3: Deterministic 3-sentence static fallback       │
└──────────────────────────┬──────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────┐
│ 7. Certified Courtroom Dossier & REST API Delivery          │
│    • Thread-safe RAM FIFO Case Store (Capacity: 25)         │
│    • Machine-readable REST JSON Contracts                   │
│    • Certified ReportLab Platypus A4 PDF Dossier Stream     │
└─────────────────────────────────────────────────────────────┘
```

---

## Key Forensic Capabilities

- **Zero-Database Architecture**: Eliminates database configuration, ORM locks, and disk migration issues. Case state is managed in a high-concurrency, thread-safe RAM FIFO store.
- **Air-Gapped Privacy & DLP Shield**: Automatically sanitizes sensitive PII (Credit Cards, IBANs, Phone Numbers, and Personal Names) before passing telemetry to AI reasoning engines.
- **Resilient AI Auto-Failover**:
  - **Tier 1**: Groq cloud API client with strict 3.5s timeout for low latency.
  - **Tier 2**: Ollama air-gapped local endpoint (`http://localhost:11434/api/generate`) with 5.0s timeout.
  - **Tier 3**: Deterministic forensic briefing template guaranteed to execute with zero network access.
- **Dual Ingestion Pathways**:
  - Binary multipart upload supporting standard RFC 5322 `.eml` and Microsoft Outlook `.msg` files.
  - Raw RFC 5322 plain text and JSON payload ingestion with control character crash protection.
- **Defensive Bottom-Up Hop Analysis**: RFC-compliant hop extraction filters out non-routable private subnets (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `127.0.0.0/8`) to expose true external transit relays.
- **Local Threat Intelligence**: MaxMind GeoIP/ASN MMDB binary resolution and curated Tor exit node matching.
- **Quishing Defense**: Uses `zxing-cpp` with dual contrast passes (including inverted polarity) to decode dark-mode QR codes in image attachments and PDF pages.
- **Certified PDF Dossier**: Produces an executive-grade Platypus PDF report in-memory with cryptographic hashes and running header/footer chain of custody.

---

## REST API Reference

The interactive Swagger UI documentation is available at `http://localhost:8000/docs`, and OpenAPI 3.1 JSON is accessible at `http://localhost:8000/api/v1/openapi.json`.

| Method | Endpoint | Description | Payload / Params |
| :--- | :--- | :--- | :--- |
| `GET` | `/health` | System health check and telemetry status | None |
| `POST` | `/api/v1/upload` | Upload `.eml` or `.msg` binary file | `multipart/form-data` (`file`, `dlp_masking`) |
| `POST` | `/api/v1/raw` | Ingest raw RFC 5322 email string or stream | `application/json` or `text/plain` |
| `GET` | `/api/v1/cases` | Paginated listing of recent forensic cases | `page` (default: 1), `limit` (default: 25) |
| `GET` | `/api/v1/cases/{case_id}` | Retrieve complete forensic case by ID | Path parameter: `case_id` |
| `GET` | `/api/v1/cases/{case_id}/pdf` | Stream certified forensic PDF dossier | Path parameter: `case_id` |

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
collected 30 items

tests/test_ai_failover.py::test_ai_failover_tier1_groq_success PASSED    [  3%]
tests/test_ai_failover.py::test_ai_failover_tier2_ollama_fallback PASSED [  6%]
tests/test_ai_failover.py::test_ai_failover_tier3_static_template_fallback PASSED [ 10%]
tests/test_ai_failover.py::test_ai_dlp_masking_integration PASSED        [ 13%]
tests/test_api_endpoints.py::test_health_check PASSED                    [ 16%]
tests/test_api_endpoints.py::test_analyze_raw_json PASSED                [ 20%]
tests/test_api_endpoints.py::test_analyze_raw_text_plain PASSED          [ 23%]
tests/test_api_endpoints.py::test_analyze_upload_eml PASSED              [ 26%]
tests/test_api_endpoints.py::test_get_cases_and_pagination PASSED        [ 30%]
tests/test_api_endpoints.py::test_get_case_pdf_stream PASSED             [ 33%]
tests/test_api_endpoints.py::test_memory_store_fifo_bound PASSED         [ 36%]
tests/test_dlp_shield.py::test_dlp_sanitize_credit_cards PASSED          [ 40%]
tests/test_dlp_shield.py::test_dlp_sanitize_iban PASSED                  [ 43%]
tests/test_dlp_shield.py::test_dlp_sanitize_phone_numbers PASSED         [ 46%]
tests/test_dlp_shield.py::test_dlp_sanitize_titled_names PASSED          [ 50%]
tests/test_dlp_shield.py::test_dlp_sanitize_labeled_names PASSED         [ 53%]
tests/test_dlp_shield.py::test_dlp_no_pii_intact PASSED                  [ 56%]
tests/test_parsers.py::test_parse_eml_bytes_basic PASSED                 [ 60%]
tests/test_parsers.py::test_parse_eml_bytes_multipart_attachments PASSED [ 63%]
tests/test_parsers.py::test_is_public_ip PASSED                          [ 66%]
tests/test_parsers.py::test_parse_hops_and_origin_ordering PASSED        [ 70%]
tests/test_parsers.py::test_audit_authentication_headers PASSED          [ 73%]
tests/test_risk_scorer.py::test_clean_authentic_email_scores_zero PASSED [ 76%]
tests/test_risk_scorer.py::test_authentication_penalties PASSED          [ 80%]
tests/test_risk_scorer.py::test_quishing_qr_penalty PASSED               [ 83%]
tests/test_risk_scorer.py::test_deceptive_link_penalty PASSED            [ 86%]
tests/test_risk_scorer.py::test_free_webmail_lure_and_urgency PASSED     [ 90%]
tests/test_risk_scorer.py::test_combined_critical_malicious_score PASSED [ 93%]
tests/test_risk_scorer.py::test_hard_forensic_override_for_quishing PASSED [ 96%]
tests/test_risk_scorer.py::test_score_bounded_to_100 PASSED              [100%]

======================= 30 passed, 2 warnings in 26.42s =======================
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
