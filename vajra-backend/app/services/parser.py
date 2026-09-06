import email
import email.header
import email.policy
import email.utils
import hashlib
import io
import re
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any, Tuple


@dataclass
class AttachmentInfo:
    filename: str
    content_type: str
    size_bytes: int
    sha256: str


@dataclass
class ParsedEmailResult:
    sha256: str
    subject: Optional[str] = None
    sender: Optional[str] = None
    sender_display_name: Optional[str] = None
    sender_address: Optional[str] = None
    sender_domain: Optional[str] = None
    recipient: Optional[str] = None
    date: Optional[str] = None
    message_id: Optional[str] = None
    return_path: Optional[str] = None
    return_path_domain: Optional[str] = None
    received_headers: List[str] = field(default_factory=list)
    body_plain: Optional[str] = None
    body_html: Optional[str] = None
    attachments: List[AttachmentInfo] = field(default_factory=list)
    display_name_spoofed: bool = False
    spoof_reason: Optional[str] = None
    raw_headers_text: str = ""


# High-profile brands and executive titles frequently targeted for display name spoofing
SUSPICIOUS_DISPLAY_NAME_PATTERNS = [
    r"paypal",
    r"microsoft",
    r"apple\s*support",
    r"google\s*security",
    r"amazon\s*support",
    r"netflix",
    r"chase\s*bank",
    r"bank\s*of\s*america",
    r"wells\s*fargo",
    r"irs\s*tax",
    r"it\s*helpdesk",
    r"security\s*alert",
    r"account\s*suspension",
    r"urgent\s*notice",
    r"\bceo\b",
    r"\bcfo\b",
    r"executive\s*office",
]


def decode_mime_header_value(header_val: Optional[str]) -> Optional[str]:
    """Safely decode RFC 2047 encoded header words."""
    if not header_val:
        return None
    try:
        decoded_parts = email.header.decode_header(header_val)
        result = []
        for part, encoding in decoded_parts:
            if isinstance(part, bytes):
                result.append(part.decode(encoding or "utf-8", errors="replace"))
            else:
                result.append(str(part))
        return "".join(result).strip()
    except Exception:
        return str(header_val).strip()


def extract_domain(email_addr: Optional[str]) -> Optional[str]:
    """Extract lowercase domain name from email address string."""
    if not email_addr:
        return None
    if "@" in email_addr:
        return email_addr.split("@")[-1].strip().lower().rstrip(">")
    return None


def detect_display_name_spoofing(
    display_name: Optional[str],
    sender_address: Optional[str],
    return_path: Optional[str] = None,
) -> Tuple[bool, Optional[str]]:
    """Evaluate whether the sender display name exhibits social engineering or spoofing indicators."""
    if not display_name or not sender_address:
        return False, None

    sender_domain = extract_domain(sender_address) or ""
    disp = display_name.strip()

    # 1. Check if display name contains an embedded email address differing from the sender address
    email_in_name_match = re.search(r"[\w\.-]+@[\w\.-]+\.\w+", disp)
    if email_in_name_match:
        embedded_email = email_in_name_match.group(0).lower()
        if embedded_email != sender_address.lower():
            return True, f"Display name embeds fraudulent identity address '{embedded_email}' differing from actual sender '{sender_address}'"

    # 2. Check for high-value brand / executive title spoofing against non-matching sender domain
    disp_lower = disp.lower()
    for pattern in SUSPICIOUS_DISPLAY_NAME_PATTERNS:
        if re.search(pattern, disp_lower):
            # Check if brand name matches domain
            cleaned_brand = re.sub(r"[^a-zA-Z0-9]", "", pattern)
            if cleaned_brand not in sender_domain:
                return True, f"Display name claims official authority '{disp}' but originates from unrelated domain '{sender_domain}'"

    # 3. Return-path domain severe mismatch with organizational sender domain
    if return_path:
        rp_domain = extract_domain(return_path)
        if rp_domain and sender_domain and (rp_domain != sender_domain):
            # e.g., Return-Path differs significantly from From domain
            if not (sender_domain.endswith(f".{rp_domain}") or rp_domain.endswith(f".{sender_domain}")):
                # Flag if sender claims a common org but return path is strange
                if any(brand in sender_domain for brand in ["paypal", "microsoft", "google", "apple", "amazon"]):
                    return True, f"Sender domain '{sender_domain}' contradicted by envelope return-path '{rp_domain}'"

    return False, None


def parse_rfc5322_bytes(raw_bytes: bytes) -> ParsedEmailResult:
    """Parse standard RFC 5322 MIME email bytes."""
    sha256_hash = hashlib.sha256(raw_bytes).hexdigest()

    msg = email.message_from_bytes(raw_bytes, policy=email.policy.default)

    raw_subject = msg.get("Subject")
    subject = decode_mime_header_value(raw_subject)

    raw_from = msg.get("From")
    from_decoded = decode_mime_header_value(raw_from)
    display_name, sender_addr = email.utils.parseaddr(from_decoded or "")

    raw_to = msg.get("To")
    recipient = decode_mime_header_value(raw_to)

    raw_date = msg.get("Date")
    date_str = decode_mime_header_value(raw_date)

    message_id = msg.get("Message-ID")
    if message_id:
        message_id = str(message_id).strip()

    raw_return_path = msg.get("Return-Path")
    return_path = None
    if raw_return_path:
        _, return_path = email.utils.parseaddr(decode_mime_header_value(raw_return_path) or "")

    # Extract all Received headers
    received_headers: List[str] = []
    for h_name, h_val in msg.items():
        if h_name.lower() == "received":
            received_headers.append(str(h_val))

    # Extract body and attachments
    body_plain = None
    body_html = None
    attachments: List[AttachmentInfo] = []

    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            content_disposition = str(part.get("Content-Disposition", ""))

            # Attachment detection
            if "attachment" in content_disposition.lower() or part.get_filename():
                filename = part.get_filename() or "unnamed_attachment"
                payload = part.get_payload(decode=True) or b""
                att_hash = hashlib.sha256(payload).hexdigest()
                attachments.append(
                    AttachmentInfo(
                        filename=filename,
                        content_type=content_type,
                        size_bytes=len(payload),
                        sha256=att_hash,
                    )
                )
            elif content_type == "text/plain" and body_plain is None:
                try:
                    payload = part.get_payload(decode=True)
                    if payload:
                        body_plain = payload.decode(part.get_content_charset() or "utf-8", errors="replace")
                except Exception:
                    pass
            elif content_type == "text/html" and body_html is None:
                try:
                    payload = part.get_payload(decode=True)
                    if payload:
                        body_html = payload.decode(part.get_content_charset() or "utf-8", errors="replace")
                except Exception:
                    pass
    else:
        payload = msg.get_payload(decode=True)
        if payload:
            charset = msg.get_content_charset() or "utf-8"
            decoded_text = payload.decode(charset, errors="replace")
            if msg.get_content_type() == "text/html":
                body_html = decoded_text
            else:
                body_plain = decoded_text

    sender_domain = extract_domain(sender_addr)
    return_path_domain = extract_domain(return_path)

    spoofed, spoof_reason = detect_display_name_spoofing(display_name, sender_addr, return_path)

    # Reconstruct raw header text representation
    raw_headers = "\n".join(f"{k}: {v}" for k, v in msg.items())

    return ParsedEmailResult(
        sha256=sha256_hash,
        subject=subject,
        sender=from_decoded or sender_addr,
        sender_display_name=display_name if display_name else None,
        sender_address=sender_addr if sender_addr else None,
        sender_domain=sender_domain,
        recipient=recipient,
        date=date_str,
        message_id=message_id,
        return_path=return_path,
        return_path_domain=return_path_domain,
        received_headers=received_headers,
        body_plain=body_plain,
        body_html=body_html,
        attachments=attachments,
        display_name_spoofed=spoofed,
        spoof_reason=spoof_reason,
        raw_headers_text=raw_headers,
    )


def parse_msg_bytes(raw_bytes: bytes) -> ParsedEmailResult:
    """Parse Outlook .msg binary files using extract-msg, falling back gracefully to RFC parser if needed."""
    sha256_hash = hashlib.sha256(raw_bytes).hexdigest()

    try:
        import extract_msg

        msg_obj = extract_msg.Message(io.BytesIO(raw_bytes))
        msg_obj.process()

        subject = msg_obj.subject
        sender = msg_obj.sender
        display_name, sender_addr = email.utils.parseaddr(sender or "")
        recipient = msg_obj.to
        date_str = str(msg_obj.date) if msg_obj.date else None
        body_plain = msg_obj.body
        body_html = getattr(msg_obj, "htmlBody", None)
        if isinstance(body_html, bytes):
            body_html = body_html.decode("utf-8", errors="replace")

        # Extract headers from msg.header
        raw_headers_text = str(msg_obj.header or "")
        received_headers: List[str] = []
        message_id = None
        return_path = None

        if raw_headers_text:
            # Parse header lines
            header_email = email.message_from_string(raw_headers_text)
            for h_name, h_val in header_email.items():
                if h_name.lower() == "received":
                    received_headers.append(str(h_val))
            message_id = header_email.get("Message-ID")
            raw_rp = header_email.get("Return-Path")
            if raw_rp:
                _, return_path = email.utils.parseaddr(raw_rp)

        # Attachments
        attachments: List[AttachmentInfo] = []
        for att in getattr(msg_obj, "attachments", []):
            try:
                data = att.data or b""
                att_hash = hashlib.sha256(data).hexdigest()
                attachments.append(
                    AttachmentInfo(
                        filename=att.longFilename or att.shortFilename or "attachment",
                        content_type=getattr(att, "mimetype", "application/octet-stream") or "application/octet-stream",
                        size_bytes=len(data),
                        sha256=att_hash,
                    )
                )
            except Exception:
                pass

        sender_domain = extract_domain(sender_addr)
        return_path_domain = extract_domain(return_path)
        spoofed, spoof_reason = detect_display_name_spoofing(display_name, sender_addr, return_path)

        return ParsedEmailResult(
            sha256=sha256_hash,
            subject=subject,
            sender=sender,
            sender_display_name=display_name if display_name else None,
            sender_address=sender_addr if sender_addr else None,
            sender_domain=sender_domain,
            recipient=recipient,
            date=date_str,
            message_id=message_id,
            return_path=return_path,
            return_path_domain=return_path_domain,
            received_headers=received_headers,
            body_plain=body_plain,
            body_html=body_html,
            attachments=attachments,
            display_name_spoofed=spoofed,
            spoof_reason=spoof_reason,
            raw_headers_text=raw_headers_text,
        )
    except Exception:
        # Fallback to standard RFC parser
        return parse_rfc5322_bytes(raw_bytes)


def parse_raw_text(headers: str, body: str = "") -> ParsedEmailResult:
    """Parse raw header and body text strings."""
    combined = f"{headers.strip()}\n\n{body.strip()}".encode("utf-8")
    return parse_rfc5322_bytes(combined)
