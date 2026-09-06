from datetime import datetime
from typing import List, Optional, Union
from pydantic import BaseModel, Field, ConfigDict


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


class PenaltyItemDTO(BaseModel):
    """Itemized penalty contributing to deterministic threat score."""
    rule: str = Field(..., description="Rule trigger identifier (e.g., SPF Fail, Tor Exit Node)")
    penalty: int = Field(..., description="Points added to risk score")
    reason: str = Field(..., description="Forensic justification for the penalty")


class RiskBreakdownDTO(BaseModel):
    """Deterministic Security Scoring Matrix (0–100 Scale)."""
    score: int = Field(..., ge=0, le=100, description="Risk score from 0 (harmless) to 100 (critical threat)")
    verdict: str = Field(..., description="SAFE (<30), SUSPICIOUS (30-69), or CRITICAL (70+)")
    itemized_penalties: List[PenaltyItemDTO] = Field(
        default_factory=list,
        description="Detailed list of specific triggered threat rules and scores"
    )


class AttachmentMetaDTO(BaseModel):
    """Extracted attachment forensic metadata."""
    filename: str
    content_type: str
    size_bytes: int
    sha256: str


class RawEmailRequest(BaseModel):
    """Payload for direct raw email string ingestion."""
    headers: str = Field(..., description="Raw RFC 5322 header block")
    body: Optional[str] = Field("", description="Raw email body text or MIME content")


class CaseResponseDTO(BaseModel):
    """Comprehensive Forensic Intelligence Response for UI integration."""
    case_id: str = Field(..., description="Unique immutable forensic case identifier (e.g. CAS-...)")
    sha256: str = Field(..., description="Cryptographic SHA-256 hash of raw input payload")
    subject: Optional[str] = Field(None, description="Extracted email subject line")
    sender: Optional[str] = Field(None, description="Sender email address / envelope from")
    sender_display_name: Optional[str] = Field(None, description="Sender display name")
    recipient: Optional[str] = Field(None, description="Recipient email address")
    date: Optional[str] = Field(None, description="Origination timestamp from email header")
    message_id: Optional[str] = Field(None, description="RFC 5322 Message-ID header")
    return_path: Optional[str] = Field(None, description="Return-Path envelope address")
    earliest_public_ip: Optional[str] = Field(None, description="First public origin entry MTA IP")
    auth: AuthMatrixDTO = Field(..., description="SPF, DKIM, and DMARC forensic audit")
    hops: List[HopDTO] = Field(default_factory=list, description="Ordered reverse MTA hop traversal")
    attachments: List[AttachmentMetaDTO] = Field(default_factory=list, description="Attachment metadata")
    risk: RiskBreakdownDTO = Field(..., description="Deterministic scoring matrix and verdict")
    llm_summary: str = Field(..., description="2-3 sentence cyber threat analyst executive brief")
    created_at: Optional[datetime] = Field(None, description="Case timestamp in UTC")

    model_config = ConfigDict(from_attributes=True)


class PaginatedCasesResponse(BaseModel):
    """Paginated list of historical forensic email cases."""
    total: int = Field(..., description="Total number of cases found")
    page: int = Field(..., ge=1, description="Current page number")
    limit: int = Field(..., ge=1, description="Items per page")
    items: List[CaseResponseDTO] = Field(default_factory=list, description="Page of forensic cases")
