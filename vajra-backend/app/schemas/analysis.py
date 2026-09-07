from datetime import datetime
from enum import Enum
from typing import List, Optional, Union, Dict, Any
from pydantic import BaseModel, Field, ConfigDict, model_validator


class DlpOption(str, Enum):
    TRUE = "true"
    FALSE = "false"


class HopDTO(BaseModel):
    """Forensic Mail Transfer Agent (MTA) Hop Information."""
    hop_number: int = Field(..., description="1-indexed chronological hop index (1 = earliest entry MTA)")
    ip: str = Field(..., description="Extracted IPv4 or IPv6 address")
    hostname: Optional[str] = Field(None, description="Reported or reverse-DNS hostname")
    country: Optional[str] = Field(None, description="Country name resolved via GeoIP")
    country_code: Optional[str] = Field(None, description="ISO two-letter country code")
    city: Optional[str] = Field(None, description="City name resolved via GeoIP")
    latitude: Optional[float] = Field(None, description="Geographical latitude")
    longitude: Optional[float] = Field(None, description="Geographical longitude")
    asn: Optional[int] = Field(None, description="Autonomous System Number")
    asn_org: Optional[str] = Field(None, description="Autonomous System Organization name")
    is_datacenter: bool = Field(False, description="True if IP belongs to known hosting/datacenter ASN")
    is_tor_exit: bool = Field(False, description="True if IP is an identified Tor Exit Node")
    delay_seconds: Optional[float] = Field(None, description="Transit delay from preceding hop in seconds")


class AuthStatusDetailDTO(BaseModel):
    """Cryptographic and DNS Email Authentication Sub-Check."""
    status: str = Field(..., description="Status: PASS, FAIL, SOFTFAIL, NEUTRAL, NONE, or UNKNOWN")
    details: str = Field(..., description="Forensic context, cryptographic validation status or error logs")


class DmarcDetailDTO(BaseModel):
    """DMARC Policy Evaluation Details."""
    status: str = Field(..., description="Status: PASS, FAIL, NONE, or UNKNOWN")
    policy: str = Field(..., description="Configured DMARC policy: reject, quarantine, none, or missing")
    details: str = Field(..., description="Forensic record context or alignment status")


class AuthMatrixDTO(BaseModel):
    """Tripartite Authentication Matrix: SPF, DKIM, and DMARC."""
    spf: AuthStatusDetailDTO
    dkim: AuthStatusDetailDTO
    dmarc: DmarcDetailDTO


class RecordedAuthClaimDTO(BaseModel):
    """Authentication claims recorded directly in the raw email headers by intermediate MTAs."""
    authentication_results: List[str] = Field(
        default_factory=list,
        description="Raw Authentication-Results header lines as claimed in message"
    )
    received_spf: List[str] = Field(
        default_factory=list,
        description="Raw Received-SPF header lines as claimed in message"
    )
    dkim_signatures: List[str] = Field(
        default_factory=list,
        description="Raw DKIM-Signature header lines as claimed in message"
    )


class IndependentVerificationDTO(BaseModel):
    """Independent verification performed directly by the VAJRA forensic engine."""
    spf: AuthStatusDetailDTO
    dkim: AuthStatusDetailDTO
    dmarc: DmarcDetailDTO


class DeceptiveUrlDTO(BaseModel):
    """Detected deceptive or disguised hyperlink where display text contradicts actual destination."""
    anchor_text: str = Field(..., description="Visible anchor text presented to recipient")
    actual_href: str = Field(..., description="True destination URL specified in href attribute")
    display_domain: Optional[str] = Field(None, description="Domain implied by the anchor text")
    target_domain: Optional[str] = Field(None, description="Actual destination domain")
    indicator: str = Field("DECEPTIVE_HYPERLINK", description="Threat classification indicator")


class ArtifactContentDTO(BaseModel):
    """Advanced extracted content and forensic artifacts."""
    plain_text_snippet: Optional[str] = Field(None, description="Truncated plain text snippet")
    html_links_count: int = Field(0, description="Total number of hyperlinks discovered in HTML body")
    extracted_urls: List[str] = Field(default_factory=list, description="Normalized, deduplicated discovered URLs")
    deceptive_urls: List[DeceptiveUrlDTO] = Field(
        default_factory=list,
        description="Mismatched anchor text / target href deceptive hyperlinks"
    )
    pdf_extracted_links: List[str] = Field(
        default_factory=list,
        description="Hyperlinks extracted in-memory from attached PDF documents"
    )
    pdf_extracted_text_snippets: List[str] = Field(
        default_factory=list,
        description="Text content extracted in-memory from attached PDF documents"
    )
    qr_code_urls: List[str] = Field(
        default_factory=list,
        description="Decoded URLs from embedded QR codes (Quishing threat vectors)"
    )
    quishing_detected: bool = Field(False, description="True if a QR code quishing vector was identified")
    ocr_extracted_text: List[str] = Field(
        default_factory=list,
        description="Text recognized from image attachments or PDF images via local OCR"
    )


class PenaltyItemDTO(BaseModel):
    """Itemized penalty contributing to deterministic threat score."""
    rule: str = Field(..., description="Rule trigger identifier (e.g., SPF Fail, Tor Exit Node, Deceptive Hyperlink)")
    penalty: int = Field(..., description="Points added to risk score")
    reason: str = Field(..., description="Forensic justification for the penalty")


class RiskBreakdownDTO(BaseModel):
    """Deterministic Security Scoring Matrix (0–100 Scale)."""
    score: int = Field(..., ge=0, le=100, description="Risk score from 0 (harmless) to 100 (critical threat)")
    verdict: str = Field(..., description="SAFE (0-19), SUSPICIOUS (20-59), MALICIOUS (60-100), or INCOMPLETE_ANALYSIS")
    itemized_penalties: List[PenaltyItemDTO] = Field(
        default_factory=list,
        description="Detailed list of specific triggered threat rules and scores"
    )
    engine_warnings: List[str] = Field(
        default_factory=list,
        description="Warnings or non-fatal extraction issues encountered during analysis"
    )


class AttachmentMetaDTO(BaseModel):
    """Extracted attachment forensic metadata."""
    filename: str
    content_type: str
    size_bytes: int
    sha256: str


class DlpSecurityDTO(BaseModel):
    """Data Loss Prevention compliance audit and liability disclaimer status."""
    status: str = Field("ACTIVE", description="ACTIVE or BYPASSED")
    masking_active: bool = Field(True, description="True if local PII masking was enforced")
    compliance_alert: Optional[str] = Field(None, description="Regulatory and liability warning if bypassed")
    liability_disclaimed: bool = Field(False, description="True if platform disclaims liability due to manual bypass")


class RawEmailRequest(BaseModel):
    """Payload for single-stream RFC 5322 email string ingestion."""
    raw_email: str = Field(
        ...,
        min_length=10,
        description="Full RFC 5322 email text stream (headers + body)",
        examples=[
            "From: security@paypal-alerts.com\nTo: victim@example.com\nSubject: Account Suspended\n\nDear user, verify your account within 24 hours."
        ],
        json_schema_extra={
            "example": "From: security@paypal-alerts.com\nTo: victim@example.com\nSubject: Account Suspended\n\nDear user, verify your account within 24 hours."
        },
    )

    @model_validator(mode="before")
    @classmethod
    def assemble_raw_email(cls, values: Any) -> Any:
        """Gracefully accept strings, bytes, and legacy headers/body dictionary inputs."""
        if isinstance(values, str):
            return {"raw_email": values}
        if isinstance(values, bytes):
            return {"raw_email": values.decode("utf-8", errors="replace")}
        if isinstance(values, dict):
            if "raw_email" not in values and "headers" in values:
                headers = str(values.get("headers") or "").strip()
                body = str(values.get("body") or "").strip()
                values["raw_email"] = f"{headers}\n\n{body}".strip()
        return values


class CaseResponseDTO(BaseModel):
    """Comprehensive Forensic Intelligence Response for UI and API integration."""
    case_id: str = Field(..., description="Unique immutable forensic case identifier (e.g. CAS-...)")
    sha256: str = Field(..., description="Cryptographic SHA-256 hash of raw input payload")
    subject: Optional[str] = Field(None, description="Extracted email subject line")
    sender: Optional[str] = Field(None, description="Sender email address / envelope from")
    sender_display_name: Optional[str] = Field(None, description="Sender display name")
    sender_address: Optional[str] = Field(None, description="Normalized sender email address")
    sender_domain: Optional[str] = Field(None, description="Extracted sender domain")
    recipient: Optional[str] = Field(None, description="Recipient email address")
    date: Optional[str] = Field(None, description="Origination timestamp from email header")
    message_id: Optional[str] = Field(None, description="RFC 5322 Message-ID header")
    return_path: Optional[str] = Field(None, description="Return-Path envelope address")
    earliest_public_ip: Optional[str] = Field(None, description="First public origin entry MTA IP")
    auth: AuthMatrixDTO = Field(..., description="SPF, DKIM, and DMARC forensic audit")
    recorded_authentication: RecordedAuthClaimDTO = Field(
        default_factory=RecordedAuthClaimDTO,
        description="Raw header authentication claims recorded by intermediate relays"
    )
    independent_verification: IndependentVerificationDTO = Field(
        ...,
        description="Independent DNS and cryptographic verification performed by VAJRA engine"
    )
    artifacts: ArtifactContentDTO = Field(
        default_factory=ArtifactContentDTO,
        description="Advanced extracted content, deceptive links, and PDF/vision telemetry"
    )
    engine_warnings: List[str] = Field(
        default_factory=list,
        description="Forensic warnings or partial extraction notes"
    )
    hops: List[HopDTO] = Field(default_factory=list, description="Ordered reverse MTA hop traversal")
    attachments: List[AttachmentMetaDTO] = Field(default_factory=list, description="Attachment metadata")
    risk: RiskBreakdownDTO = Field(..., description="Deterministic scoring matrix and verdict")
    verdict: Optional[str] = Field(None, description="Overall forensic verdict reflecting overrides (SAFE, SUSPICIOUS, MALICIOUS, INCOMPLETE_ANALYSIS)")
    quishing_detected: Optional[bool] = Field(False, description="True if a QR code quishing vector was identified")
    llm_summary: str = Field(..., description="2-3 sentence cyber threat analyst executive brief")
    dlp_security: DlpSecurityDTO = Field(
        default_factory=lambda: DlpSecurityDTO(
            status="ACTIVE",
            masking_active=True,
            compliance_alert=None,
            liability_disclaimed=False,
        ),
        description="Data Loss Prevention compliance audit and liability status",
    )
    created_at: Optional[datetime] = Field(None, description="Case timestamp in UTC")

    model_config = ConfigDict(from_attributes=True)

    @model_validator(mode="after")
    def sync_verdict(self) -> "CaseResponseDTO":
        if self.verdict is None and self.risk:
            self.verdict = self.risk.verdict
        return self


class PaginatedCasesResponse(BaseModel):
    """Paginated list of historical forensic email cases."""
    total: int = Field(..., description="Total number of cases found")
    page: int = Field(..., ge=1, description="Current page number")
    limit: int = Field(..., ge=1, description="Items per page")
    items: List[CaseResponseDTO] = Field(default_factory=list, description="Page of forensic cases")
