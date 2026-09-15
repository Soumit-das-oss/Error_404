# VAJRA Forensics (SIH26106)
### Offline-First / Air-Gapped-Capable AI Email Threat Detection, Geolocation & Forensic Intelligence Platform

[![Python Version](https://img.shields.io/badge/python-3.11%20%7C%203.12%20%7C%203.13-blue.svg)](https://www.python.org/)
[![Framework](https://img.shields.io/badge/FastAPI-0.115+-009688.svg?logo=fastapi)](https://fastapi.tiangolo.com/)
[![Architecture](https://img.shields.io/badge/Storage-Zero--Database%20RAM%20Store-purple.svg)](app/storage/memory_store.py)
[![Validation](https://img.shields.io/badge/Pydantic-v2.9+-E92063.svg)](https://docs.pydantic.dev/)
[![Tests](https://img.shields.io/badge/pytest-67%2F67%20Passing%20(100%25)-brightgreen.svg)](tests/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

**VAJRA** is an enterprise-grade, high-performance forensic cybersecurity platform engineered for law enforcement agencies, digital forensics units (DFUs), Security Operations Centers (SOCs), and threat analysts. Built for **Smart India Hackathon 2026 (Problem Statement SIH26106)**, VAJRA features an **offline-first / air-gapped-capable architecture** with a **security-focused operational design**, an in-memory thread-safe FIFO case store, Data Loss Prevention (DLP) sanitizing payment cards, banking details, contact numbers, and personal names, 3-tier offline-first AI reasoning with automated fallback, an **evidence-based heuristic and explainable rule-based detection engine**, and certified ReportLab Platypus PDF dossier generation.

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
│    • Quote-sanitized ID resolution (supports `"CAS-..."` inputs)   │
│    • Pure in-memory buffer processing (zero persistent disk writes)│
│    • Intentionally ephemeral RAM store preserving forensic hygiene │
└────────────────────────────────────┬───────────────────────────────┘
                                     │
                                     ▼
┌────────────────────────────────────────────────────────────────────┐
│ 2. Fault-Tolerant Hybrid Email Parsing (eml_parser / msg_parser)   │
│    • Standard RFC 5322 MIME & Outlook Compound File decomposition   │
│    • Error-guarded attachment extraction (handles corrupt base64)  │
│    • Multiline regex fallback for headers (Subject, From, To, Date)│
│    • Collapsed single-line header reconstruction for webmail posts │
│    • Guaranteed non-null Subject & sender_domain extraction        │
└────────────────────────────────────┬───────────────────────────────┘
                                     │
                                     ▼
┌────────────────────────────────────────────────────────────────────┐
│ 3. Dual-Layer Cryptographic & DNS Authentication Engine            │
│    • Layer 1 (Recorded MTA Claims): RFC 7208 / 7489 header audit   │
│    • Layer 2 (Independent Verification):                           │
│      - Cryptographic DKIM: Local mathematical validation (dkimpy)  │
│      - Independent Live SPF: Active DNS TXT lookup & CIDR check    │
│      - Independent Live DMARC: _dmarc.<domain> policy & alignment  │
│      - Air-Gap Fallback: 2.0s timeout -> OFFLINE_RECORDED_AUDIT    │
│      - Full transparency: tag 'live_dns', 'cryptographic', 'mta'   │
└────────────────────────────────────┬───────────────────────────────┘
                                     │
                                     ▼
┌────────────────────────────────────────────────────────────────────┐
│ 4. Reverse MTA Hop Traversal & Infrastructure Geolocation          │
│    • Bottom-up chronological Received: header traversal            │
│    • RFC 1918 Private Subnet & Loopback filtering                  │
│    • Sending infrastructure geolocation via MaxMind City & ASN     │
│    • Curated Tor Exit Node cache verification                      │
└────────────────────────────────────┬───────────────────────────────┘
                                     │
                                     ▼
┌────────────────────────────────────────────────────────────────────┐
│ 5. Brand Impersonation & Typosquatting Engine (Levenshtein)        │
│    • Protected Registry: flipkart, amazon, paypal, sbi, hdfc, etc. │
│    • Levenshtein Distance (<= 2) analysis on SLDs (e.g. filipkart) │
│    • Homoglyph & visual character substitution detection (0->o, 1->l)│
│    • Deceptive brand token embeds (e.g. flipkart-offers.com)       │
│    • High-confidence deceptive penalties: TYPOSQUAT (+45, CRITICAL)│
└────────────────────────────────────┬───────────────────────────────┘
                                     │
                                     ▼
┌────────────────────────────────────────────────────────────────────┐
│ 6. Cross-Channel Artifact & Quishing Linkage Engine                │
│    • QR Engine: Evaluates direct IP hosts, shorteners, phish paths │
│    • Cross-Channel Linkage: QR pointing to typosquatted domain     │
│      triggers QUISHING_MALICIOUS_PAYLOAD (+45, CRITICAL)           │
│    • Benign QR codes (e.g. google.com / UPI) receive 0 penalty     │
│    • PDF Engine: In-memory scan for /JavaScript and /Launch actions│
│    • In-Body Header Forgery (*From:* Brand <...>) detection (+35)  │
│    • Free Webmail Commercial Brand Lure detection (+40, HIGH)      │
└────────────────────────────────────┬───────────────────────────────┘
                                     │
                                     ▼
┌────────────────────────────────────────────────────────────────────┐
│ 7. Evidence-Based Heuristic Threat Scorer & SOC Calibration        │
│    • Real-World SOC Principle: SPF/DKIM pass on free webmail       │
│      proves infrastructure validity, NOT benevolence.              │
│    • High-confidence deception forces score >= 75 (MALICIOUS)      │
│    • Itemized explainable forensic penalty breakdown               │
│    • Verdicts: SAFE (0-19), SUSPICIOUS (20-59), MALICIOUS (60-100) │
└────────────────────────────────────┬───────────────────────────────┘
                                     │
                                     ▼
┌────────────────────────────────────────────────────────────────────┐
│ 8. In-Memory DLP Shield & 3-Tier Offline-First AI Failover         │
│    • In-memory PII sanitization: Cards, IBANs, Phones, Names       │
│    • Tier 1: Groq Cloud LLM (llama-3.3-70b-versatile, 4.0s timeout)│
│    • Tier 2: Ollama Local Air-Gapped LLM (llama3.2:1b, 15s timeout)│
│    • Tier 3: Deterministic heuristic forensic auditor briefing     │
└────────────────────────────────────┬───────────────────────────────┘
                                     │
                                     ▼
┌────────────────────────────────────────────────────────────────────┐
│ 9. Certified Courtroom Dossier & REST API Delivery                 │
│    • Ephemeral RAM FIFO Case Store (Capacity: 25)                  │
│    • Certified ReportLab Platypus A4 PDF Dossier with SHA-256 table│
│    • Authentication matrix with live vs recorded source tags       │
│    • Permanent evidentiary PDF artifact with cryptographic integrity│
│    • Machine-readable REST JSON Contracts                          │
└────────────────────────────────────────────────────────────────────┘
```

---

## Key Forensic Capabilities

- **Offline-First / Air-Gapped-Capable Architecture**: Operates with zero persistent database dependencies, ORM locks, or disk migrations. Case storage in memory is intentionally ephemeral to preserve zero-disk hygiene, while the downloaded cryptographic PDF dossier serves as the permanent evidentiary artifact.
- **Dual-Layer Authentication Verification**:
  - **Recorded Claims Audit**: Inspects upstream MTA headers (`Authentication-Results`, `Received-SPF`, `DKIM-Signature`).
  - **Independent Active Verification**: Performs live DNS TXT lookups for SPF (`v=spf1`) against extracted origin IPs, live DMARC lookups for policy enforcement (`_dmarc.<domain>`), and local cryptographic DKIM signature verification via `dkimpy`.
  - **Air-Gapped Resiliency**: All live DNS operations are guarded by a 2.0-second timeout with automated failover to `OFFLINE_RECORDED_AUDIT`.
- **Brand Impersonation & Typosquatting Engine (`brand_registry.py`)**:
  - Maintains a protected registry of major commercial and financial brands (`flipkart.com`, `amazon.in`, `amazon.com`, `paypal.com`, `google.com`, `microsoft.com`, `apple.com`, `netflix.com`, `sbi.co.in`, `hdfcbank.com`, `icicibank.com`).
  - Performs pure-Python Levenshtein distance analysis (threshold <= 2) and visual homoglyph substitution matching (e.g. `filipkart.com`, `paypa1.com`).
  - Flags deceptive brand token embeddings with suspicious affixes (`flipkart-rewards.com`, `amazon-security-alert.in`).
- **Free Webmail BEC & In-Body Spoofing Defenses**:
  - **Commercial Enterprise Lures on Free Webmail**: Detects commercial lures ("Flipkart", "Big Billion Days", "Exclusive Voucher", "KYC Alert") originating from free webmail providers (`@gmail.com`, `@yahoo.com`, etc.), penalizing `FREE_WEBMAIL_BRAND_IMPERSONATION` (+40, HIGH).
  - **In-Body Header Forgery**: Uncovers hidden fake header blocks embedded in the plain-text body (`*From:* Flipkart Support <support@flipkart.com>`) that contradict envelope transmission headers (`IN_BODY_HEADER_SPOOFING`, +35, HIGH).
- **Cross-Channel Quishing Linkage & Threat Calibration**:
  - Scans visual attachments (PNG, JPG, WEBP) in-memory for embedded QR codes.
  - Automatically links decoded QR destinations to the typosquatting engine; if a QR payload points to a deceptive or typosquatted domain, triggers `QUISHING_MALICIOUS_PAYLOAD` (+45, CRITICAL) and suppresses benign QR discounts.
  - Enforces the real-world SOC investigative standard: high-confidence deception vectors automatically force `score >= 75` (`MALICIOUS`).
- **Quote-Sanitized Case Resolution**:
  - All case lookup endpoints (`/api/v1/cases/{case_id}` and `/api/v1/cases/{case_id}/pdf`) automatically strip quotes and whitespace, preventing 404 errors when users copy-paste quoted case IDs from Swagger UI.
- **Pure In-Memory Zero-Disk Pipelines**:
  - `eml_parser.py`: Fault-tolerant RFC 5322 parsing with multiline regex header fallback and single-line collapsed header reconstruction.
  - `qr_engine.py`: In-memory visual QR decoding with inverted color support.
  - `pdf_engine.py`: In-memory PDF stream analysis inspecting for `/JavaScript`, `/Launch`, `/EmbeddedFiles` executables, and deceptive anchors.
  - `dlp_shield.py`: Local in-memory PII redaction targeting payment cards, banking details, contact numbers, and personal names before passing telemetry to AI reasoning engines.
  - `report_generator.py`: Certified ReportLab Platypus PDF generated directly into in-memory `BytesIO` buffers.
- **Resilient 3-Tier AI Auto-Failover**:
  - **Tier 1 (Cloud)**: Groq cloud API client (`llama-3.3-70b-versatile`, 4.0s timeout).
  - **Tier 2 (Local Air-Gapped)**: Ollama local endpoint (`http://localhost:11434/api/generate`, `llama3.2:1b`, 15.0s timeout).
  - **Tier 3 (Deterministic Heuristic)**: Objective forensic SOC auditor template guaranteed to execute with zero network access.

---

## REST API Reference

The interactive Swagger UI documentation is available at `http://localhost:8000/docs`, and OpenAPI 3.1 JSON is accessible at `http://localhost:8000/api/v1/openapi.json`.

| Method | Endpoint | Description | Primary Schema / Params |
| :--- | :--- | :--- | :--- |
| `GET` | `/health` | System health check and telemetry status | None |
| `POST` | `/api/v1/upload` | Upload `.eml` or `.msg` binary file | `multipart/form-data` (`file`, `dlp_masking`) |
| `POST` | `/api/v1/raw` | Canonical ingestion for raw text + attachments | `multipart/form-data` (`raw_email`, `attachments`, `dlp_masking`) (with JSON fallback) |
| `GET` | `/api/v1/cases` | Paginated listing of recent forensic cases | `page` (default: 1), `limit` (default: 25) |
| `GET` | `/api/v1/cases/{case_id}` | Retrieve complete forensic case by ID | Path parameter: `case_id` (auto-unquotes) |
| `GET` | `/api/v1/cases/{case_id}/pdf` | Stream certified forensic PDF dossier | Path parameter: `case_id` (auto-unquotes) |

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
  -F "raw_email=From: dealsflipkart99@gmail.com
To: victim@company.com
Subject: Flipkart Big Billion Days - Exclusive Voucher

Scan the attached QR code to claim your 5000 Rs voucher." \
  -F "attachments=@qr_invoice.png" \
  -F "attachments=@invoice_spec.pdf"
```

#### 3. Direct JSON / Plain Text Ingestion
```bash
curl -X POST "http://localhost:8000/api/v1/raw?dlp_masking=true" \
  -H "Content-Type: application/json" \
  -d '{"raw_email": "From: billing@bank-alerts.com\nTo: user@domain.com\nSubject: Account Locked\n\nClick: https://www.filipkart.com/login"}'
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
│   │   ├── text_analyzer.py       # Urgency, commercial lures & in-body spoofing
│   │   └── url_analyzer.py        # Deceptive anchor mismatch & typosquat inspection
│   ├── api/
│   │   └── v1/
│   │       ├── analyze_routes.py  # /upload and /raw ingestion endpoints
│   │       ├── cases_routes.py    # /cases query & quote-sanitized lookup
│   │       ├── report_routes.py   # /cases/{case_id}/pdf streaming endpoint
│   │       ├── router.py          # API v1 central router
│   │       └── api.py             # Router re-export
│   ├── core/
│   │   ├── config.py              # Pydantic Settings & environment validation
│   │   └── constants.py           # Penalty weights, brand lures & heuristic regexes
│   ├── parsers/
│   │   ├── eml_parser.py          # RFC 5322 MIME stream parser with regex fallback
│   │   ├── msg_parser.py          # Outlook .msg compound file parser
│   │   └── header_engine.py       # Bottom-up hop tracer & recorded auth auditor
│   ├── schemas/
│   │   └── analysis.py            # Pydantic forensic request/response DTO schemas
│   ├── services/
│   │   ├── ai/
│   │   │   ├── explainer_orchestrator.py # AI failover manager & prompt builder
│   │   │   ├── groq_provider.py          # Async Groq client (4.0s timeout)
│   │   │   └── ollama_provider.py        # Async Ollama client (15.0s timeout)
│   │   ├── detectors/
│   │   │   └── brand_registry.py      # Brand registry, Levenshtein & typosquat engine
│   │   ├── auth_engine.py             # Dual-layer live DNS verification & air-gap fallback
│   │   ├── dlp_shield.py              # PII scrubbing (Cards, IBANs, Phones, Names)
│   │   ├── report_generator.py        # ReportLab Platypus forensic PDF generator
│   │   └── risk_scorer.py             # Deterministic 0-100 scoring & SOC calibration
│   ├── storage/
│   │   └── memory_store.py            # Thread-safe RAM FIFO case store (capacity: 25)
│   └── main.py                        # FastAPI application entrypoint & lifespan
├── data/
│   ├── .gitkeep                       # Preserves data directory
│   ├── tor_exit_nodes.txt             # Verified Tor exit node cache
│   ├── GeoLite2-City.mmdb             # (Downloaded via script, ignored by git)
│   └── GeoLite2-ASN.mmdb              # (Downloaded via script, ignored by git)
├── scripts/
│   └── download_geoip.py              # Standalone MaxMind GeoIP binary downloader
├── tests/
│   ├── conftest.py                    # Pytest fixtures & store reset
│   ├── test_ai_failover.py            # Groq -> Ollama -> Template failover tests
│   ├── test_api_endpoints.py          # REST API endpoints & FIFO store tests
│   ├── test_dlp_shield.py             # PII scrubbing tests
│   ├── test_parsers.py                # EML parsing & hop engine tests
│   └── test_risk_scorer.py            # Threat scoring, typosquat & quishing tests
├── .dockerignore                      # Docker build exclusions
├── .env.example                       # Environment configuration template
├── .gitignore                         # Git hygiene rules
├── Dockerfile                         # Production container definition
├── docker-compose.yml                 # Single-service container stack
├── requirements.txt                   # Essential forensic Python dependencies
└── run.sh                             # Lightweight runner script
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
CORS_ORIGINS=["http://localhost:5173","http://127.0.0.1:5173","http://localhost:3000","http://127.0.0.1:3000"]
GROQ_API_KEY=your_groq_api_key_here
GROQ_MODEL=llama-3.3-70b-versatile
OLLAMA_BASE_URL=http://localhost:11434
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
collected 67 items

tests/test_ai_failover.py::test_ai_failover_tier1_groq_success PASSED    [  1%]
tests/test_ai_failover.py::test_ai_failover_tier2_ollama_fallback PASSED [  2%]
tests/test_ai_failover.py::test_ai_failover_tier3_static_template_fallback PASSED [  4%]
tests/test_ai_failover.py::test_ai_dlp_masking_integration PASSED        [  5%]
tests/test_ai_failover.py::test_groq_reasoning_extraction_fallback PASSED [  7%]
tests/test_ai_failover.py::test_groq_empty_string_raises PASSED          [  8%]
tests/test_ai_failover.py::test_ai_prompt_safe_verdict_generates_clearance_notice PASSED [ 10%]
tests/test_ai_failover.py::test_ai_prompt_threat_verdict_generates_incident_triage PASSED [ 11%]
tests/test_ai_failover.py::test_ai_orchestrator_service_export_and_3tier_failover PASSED [ 13%]
tests/test_ai_failover.py::test_ai_engine_prefix_and_provider_attribution PASSED [ 14%]
tests/test_ai_failover.py::test_pdf_report_renders_engine_attribution PASSED [ 16%]
tests/test_ai_failover.py::test_ollama_safety_refusal_triggers_fallback_to_heuristic PASSED [ 17%]
tests/test_ai_failover.py::test_ollama_provider_direct_refusal_and_short_response PASSED [ 19%]
tests/test_api_endpoints.py::test_health_check PASSED                    [ 20%]
tests/test_api_endpoints.py::test_analyze_raw_json PASSED                [ 22%]
tests/test_api_endpoints.py::test_analyze_raw_text_plain PASSED          [ 23%]
tests/test_api_endpoints.py::test_analyze_upload_eml PASSED              [ 25%]
tests/test_api_endpoints.py::test_get_cases_and_pagination PASSED        [ 26%]
tests/test_api_endpoints.py::test_get_case_pdf_stream PASSED             [ 28%]
tests/test_api_endpoints.py::test_memory_store_fifo_bound PASSED         [ 29%]
tests/test_api_endpoints.py::test_analyze_raw_plain_text_with_quotes_and_newlines PASSED [ 31%]
tests/test_api_endpoints.py::test_dlp_masking_bypassed_liability_alert PASSED [ 32%]
tests/test_api_endpoints.py::test_dlp_masking_active_default PASSED      [ 34%]
tests/test_api_endpoints.py::test_clean_authentic_newsletter_remains_safe PASSED [ 35%]
tests/test_api_endpoints.py::test_pdf_report_with_dlp_bypassed_banner PASSED [ 37%]
tests/test_api_endpoints.py::test_analyze_raw_free_webmail_financial_lure_endpoint PASSED [ 38%]
tests/test_api_endpoints.py::test_openapi_dlp_masking_schema_is_required_enum PASSED [ 40%]
tests/test_api_endpoints.py::test_analyze_raw_with_mobile_attachments_image_qr PASSED [ 41%]
tests/test_api_endpoints.py::test_analyze_raw_pratiksha_dabhekar_gmail_bec_with_attachments PASSED [ 43%]
tests/test_api_endpoints.py::test_benign_qr_code_evaluates_safe PASSED   [ 44%]
tests/test_api_endpoints.py::test_malicious_quishing_qr_triggers_penalty PASSED [ 46%]
tests/test_api_endpoints.py::test_clean_pdf_attachment_evaluates_safe PASSED [ 47%]
tests/test_api_endpoints.py::test_corrupted_truncated_mime_email_pratiksha_dabhekar PASSED [ 49%]
tests/test_api_endpoints.py::test_collapsed_single_line_headers_extraction PASSED [ 50%]
tests/test_api_endpoints.py::test_cors_origins_whitelisting PASSED       [ 52%]
tests/test_api_endpoints.py::test_case_id_quote_sanitization PASSED      [ 53%]
tests/test_api_endpoints.py::test_brand_typosquatting_filipkart_detection PASSED [ 55%]
tests/test_api_endpoints.py::test_free_webmail_commercial_lure_flipkart PASSED [ 56%]
tests/test_api_endpoints.py::test_independent_verification_source_and_fallback PASSED [ 58%]
tests/test_dlp_shield.py::test_dlp_sanitize_credit_cards PASSED          [ 59%]
tests/test_dlp_shield.py::test_dlp_sanitize_iban PASSED                  [ 61%]
tests/test_dlp_shield.py::test_dlp_sanitize_phone_numbers PASSED         [ 62%]
tests/test_dlp_shield.py::test_dlp_sanitize_titled_names PASSED          [ 64%]
tests/test_dlp_shield.py::test_dlp_sanitize_labeled_names PASSED         [ 65%]
tests/test_dlp_shield.py::test_dlp_no_pii_intact PASSED                  [ 67%]
tests/test_parsers.py::test_parse_eml_bytes_basic PASSED                 [ 68%]
tests/test_parsers.py::test_parse_eml_bytes_multipart_attachments PASSED [ 70%]
tests/test_parsers.py::test_is_public_ip PASSED                          [ 71%]
tests/test_parsers.py::test_parse_hops_and_origin_ordering PASSED        [ 73%]
tests/test_parsers.py::test_audit_authentication_headers PASSED          [ 74%]
tests/test_risk_scorer.py::test_clean_authentic_email_scores_zero PASSED [ 76%]
tests/test_risk_scorer.py::test_authentication_penalties PASSED          [ 77%]
tests/test_risk_scorer.py::test_quishing_qr_penalty PASSED               [ 79%]
tests/test_risk_scorer.py::test_deceptive_link_penalty PASSED            [ 80%]
tests/test_risk_scorer.py::test_free_webmail_lure_and_urgency PASSED     [ 82%]
tests/test_risk_scorer.py::test_combined_critical_malicious_score PASSED [ 83%]
tests/test_risk_scorer.py::test_hard_forensic_override_for_quishing PASSED [ 85%]
tests/test_risk_scorer.py::test_score_bounded_to_100 PASSED              [ 86%]
tests/test_risk_scorer.py::test_free_webmail_domain_financial_lure_never_safe PASSED [ 88%]
tests/test_risk_scorer.py::test_corporate_newsletter_receives_discount PASSED [ 89%]
tests/test_risk_scorer.py::test_benign_qr_code_scores_zero PASSED        [ 91%]
tests/test_risk_scorer.py::test_pdf_threat_penalties_javascript_and_launch PASSED [ 92%]
tests/test_risk_scorer.py::test_clean_pdf_scores_zero PASSED             [ 94%]
tests/test_risk_scorer.py::test_typosquat_brand_impersonation_penalty PASSED [ 95%]
tests/test_risk_scorer.py::test_free_webmail_commercial_lure_forces_malicious PASSED [ 97%]
tests/test_risk_scorer.py::test_in_body_header_spoofing_penalty PASSED   [ 98%]
tests/test_risk_scorer.py::test_cross_channel_quishing_linkage_to_typosquat PASSED [100%]

======================= 67 passed, 2 warnings in 54.19s =======================
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

## SIH 2026 Problem Statement SIH26106 Compliance

| Requirement | Implementation Architecture |
| :--- | :--- |
| **MTA Reverse Hop Traversal** | Bottom-up chronological parsing in `header_engine.py` with RFC 1918 private subnet filtering |
| **Sending Infrastructure Geolocation** | MaxMind `GeoLite2-City` & `GeoLite2-ASN` binary resolution identifying probable sending infrastructure |
| **Threat Intelligence** | Curated Tor exit nodes matching and datacenter ASN detection |
| **Dual-Layer Authentication** | Cryptographic DKIM + live DNS SPF/DMARC lookup with 2.0s air-gapped fallback to upstream recorded claims |
| **Brand Impersonation & Typosquatting** | Pure-Python Levenshtein distance analysis (<= 2) and brand token embedding detection in `brand_registry.py` |
| **Cross-Channel Quishing Linkage** | In-memory QR decoding cross-linked to typosquatting & deceptive endpoints; suppress false benign discounts |
| **Evidence-Based Risk Scoring** | Explainable heuristic scoring matrix (0–100 scale) with SOC calibration for high-confidence deception vectors |
| **Courtroom Evidence Export** | ReportLab Platypus PDF report generator with cryptographic SHA-256 evidence chain of custody & source tags |
| **Data Privacy & Ephemerality** | Ephemeral RAM case store (zero-disk hygiene), DLP PII masking (cards, IBANs, phones, names), 3-tier offline-first AI fallback |
