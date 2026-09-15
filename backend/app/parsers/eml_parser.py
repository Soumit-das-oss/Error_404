"""
VAJRA Forensic Platform - Native RFC 5322 .eml Email Parser
Extracts headers, multipart MIME text/HTML streams, attachments, and cryptographic evidence hashes.
"""

import binascii
import email
import email.errors
import email.header
import email.policy
import email.utils
import hashlib
import logging
import re
from typing import Dict, Any, List, Optional
from app.core.constants import REGEX_URL

logger = logging.getLogger("vajra.parsers.eml")


def parse_eml_bytes(raw_bytes: bytes) -> Dict[str, Any]:
    """Parse raw RFC 5322 email bytes into structured forensic dictionary."""
    if not raw_bytes:
        raw_bytes = b""

    raw_text = raw_bytes.decode("utf-8", errors="ignore")

    # 1. Handle Single-Line / Collapsed Newlines (Browser Form-Data bug)
    if raw_text.count("\n") < 5 and len(raw_text) > 100:
        header_keys = [
            "delivered-to", "received", "x-received", "arc-seal",
            "arc-message-signature", "arc-authentication-results",
            "return-path", "received-spf", "authentication-results",
            "dkim-signature", "x-google-dkim-signature", "x-gm-message-state",
            "x-gm-gg", "mime-version", "from", "date", "message-id",
            "subject", "to", "content-type", "content-disposition",
            "content-transfer-encoding", "x-attachment-id"
        ]
        pattern = r'(?i)(?<=\s)(' + '|'.join(re.escape(k) for k in header_keys) + r'):\s*'
        raw_text = re.sub(pattern, r'\n\1: ', raw_text)
        raw_bytes = raw_text.encode("utf-8", errors="ignore")

    sha256_hash = hashlib.sha256(raw_bytes).hexdigest()
    text_decoded = raw_text

    msg = email.message_from_bytes(raw_bytes, policy=email.policy.default)

    # 2. Extract Core Headers via Standard Parser
    subject = str(msg.get("Subject", "") or "").rstrip("\r\n").strip()
    sender = str(msg.get("From", "") or "").rstrip("\r\n").strip()
    recipient = str(msg.get("To", "") or "").rstrip("\r\n").strip()
    date_hdr = str(msg.get("Date", "") or "").rstrip("\r\n").strip()
    message_id = str(msg.get("Message-ID", "") or "").rstrip("\r\n").strip()
    return_path = str(msg.get("Return-Path", "") or "").rstrip("\r\n").strip()

    # 3. Boundary-Aware Regex Fallback for Missing / Malformed Headers in Mobile / Raw Pastes
    if not subject or subject.lower() in ("none", "no subject line", "unknown"):
        m_subj = re.search(r"(?im)^subject\s*:\s*(.+)$", raw_text)
        if m_subj:
            subject = m_subj.group(1).rstrip("\r\n").strip()
        if not subject or subject.lower() in ("none", "no subject line", "unknown"):
            m_subj_b = re.search(r'(?i)\bsubject\s*:\s*([^:\r\n]+?)(?=\s*(?:from|to|date|message-id|return-path|content-type|mime-version|delivered-to|\r|\n|$))', raw_text)
            if m_subj_b:
                subject = m_subj_b.group(1).rstrip("\r\n").strip()

    if not sender or sender.lower() in ("none", "unknown"):
        m_from = re.search(r"(?im)^from\s*:\s*(.+)$", raw_text)
        if m_from:
            sender = m_from.group(1).rstrip("\r\n").strip()
        if not sender or sender.lower() in ("none", "unknown"):
            m_from_b = re.search(r'(?i)\bfrom\s*:\s*([^:\r\n]+?)(?=\s*(?:subject|to|date|message-id|return-path|content-type|mime-version|\r|\n|$))', raw_text)
            if m_from_b:
                sender = m_from_b.group(1).rstrip("\r\n").strip()

    if not recipient or recipient.lower() in ("none", "unknown"):
        m_to = re.search(r"(?im)^to\s*:\s*(.+)$", raw_text)
        if m_to:
            recipient = m_to.group(1).rstrip("\r\n").strip()
        if not recipient or recipient.lower() in ("none", "unknown"):
            m_to_b = re.search(r'(?i)\bto\s*:\s*([^:\r\n]+?)(?=\s*(?:subject|from|date|message-id|return-path|content-type|mime-version|\r|\n|$))', raw_text)
            if m_to_b:
                recipient = m_to_b.group(1).rstrip("\r\n").strip()

    if not date_hdr:
        m_date = re.search(r"(?im)^date\s*:\s*(.+)$", raw_text)
        if m_date:
            date_hdr = m_date.group(1).rstrip("\r\n").strip()
        if not date_hdr:
            m_date_b = re.search(r'(?i)\bdate\s*:\s*([^:\r\n]+?)(?=\s*(?:subject|from|to|message-id|return-path|content-type|mime-version|\r|\n|$))', raw_text)
            if m_date_b:
                date_hdr = m_date_b.group(1).rstrip("\r\n").strip()

    # Strip leading/trailing whitespace and <...> brackets
    if subject:
        subject = subject.strip().strip("<>").strip()
    if sender:
        sender = sender.strip()
        if sender.startswith("<") and sender.endswith(">"):
            sender = sender[1:-1].strip()
    if recipient:
        recipient = recipient.strip()
        if recipient.startswith("<") and recipient.endswith(">"):
            recipient = recipient[1:-1].strip()
    if date_hdr:
        date_hdr = date_hdr.strip().strip("<>").strip()

    # Parse From header into display name, email address, and sender domain
    display_name = ""
    sender_address = ""
    sender_domain = ""
    if sender:
        parsed_name, parsed_addr = email.utils.parseaddr(sender)
        display_name = parsed_name.strip().strip("<>").strip()
        sender_address = parsed_addr.strip().strip("<>").strip().lower()

        # Isolate sender_domain via @([\w\.\-]+)
        m_dom = re.search(r"@([\w\.\-]+)", sender)
        if m_dom:
            sender_domain = m_dom.group(1).strip().lower()
        elif "@" in sender_address:
            m_dom_addr = re.search(r"@([\w\.\-]+)", sender_address)
            sender_domain = m_dom_addr.group(1).strip().lower() if m_dom_addr else sender_address.split("@")[-1].strip().lower()

        # Strict regex extraction ensuring sender_address is populated
        m_email = re.search(r"[\w\.\-+]+@[\w\.\-]+", sender)
        if m_email and not sender_address:
            sender_address = m_email.group(0).lower()

    # 2. Extract Chronological Received: Headers
    received_headers: List[str] = []
    for r in msg.get_all("Received", []):
        r_str = str(r).strip()
        if r_str:
            received_headers.append(r_str)

    # 3. Extract Recorded Authentication Claims
    auth_results: List[str] = [str(ar).strip() for ar in msg.get_all("Authentication-Results", [])]
    received_spf: List[str] = [str(rs).strip() for rs in msg.get_all("Received-SPF", [])]
    dkim_signatures: List[str] = [str(ds).strip() for ds in msg.get_all("DKIM-Signature", [])]

    # 4. Walk MIME tree for bodies and attachments
    body_plain_parts: List[str] = []
    body_html_parts: List[str] = []
    attachments: List[Dict[str, Any]] = []

    for part in msg.walk():
        # Check if part is an attachment
        content_disposition = str(part.get("Content-Disposition", "")).lower()
        content_type = str(part.get_content_type() or "").lower()
        filename = part.get_filename()

        is_attachment = ("attachment" in content_disposition) or (filename is not None)

        if is_attachment:
            payload = b""
            try:
                payload = part.get_payload(decode=True) or b""
            except (binascii.Error, email.errors.MessageError, ValueError, Exception) as e:
                logger.debug(f"Skipping malformed or empty attachment {filename}: {e}")
                payload = b""
            if not payload or len(payload) == 0:
                continue
            fname = filename or "unnamed_attachment"
            att_sha = hashlib.sha256(payload).hexdigest()
            attachments.append({
                "filename": fname,
                "content_type": content_type or "application/octet-stream",
                "size_bytes": len(payload),
                "payload_bytes": payload,
                "sha256": att_sha,
            })
        else:
            # Inline / body content
            if content_type == "text/plain":
                try:
                    text_content = part.get_content()
                    if isinstance(text_content, str):
                        body_plain_parts.append(text_content)
                except Exception:
                    payload = part.get_payload(decode=True) or b""
                    body_plain_parts.append(payload.decode("utf-8", errors="replace"))
            elif content_type == "text/html":
                try:
                    html_content = part.get_content()
                    if isinstance(html_content, str):
                        body_html_parts.append(html_content)
                except Exception:
                    payload = part.get_payload(decode=True) or b""
                    body_html_parts.append(payload.decode("utf-8", errors="replace"))

    body_plain = "\n\n".join(body_plain_parts).strip()
    body_html = "\n\n".join(body_html_parts).strip()

    # If body_plain and body_html are empty but text_decoded is present (raw copy-pasted body)
    if not body_plain and not body_html:
        if "\r\n\r\n" in text_decoded:
            body_plain = text_decoded.split("\r\n\r\n", 1)[1].strip()
        elif "\n\n" in text_decoded:
            body_plain = text_decoded.split("\n\n", 1)[1].strip()
        else:
            body_plain = text_decoded.strip()

    # Subject Fallback: If STILL empty, use first non-empty non-header line (up to 80 chars)
    if not subject or subject.lower() in ("none", "no subject line", "unknown"):
        candidate_source = body_plain or text_decoded
        for line in candidate_source.splitlines():
            line_str = line.strip()
            if not line_str:
                continue
            if re.match(r"(?i)^(from|to|subject|date|received|return-path|content-type|mime-version|authentication-results|dkim-signature):\s*", line_str):
                continue
            subject = line_str[:80].strip()
            break
        if not subject:
            subject = "Email Message"

    # Extract all URLs from body streams and decoded payload
    body_combined = f"{body_plain}\n{body_html}\n{text_decoded}"
    extracted_urls = list(dict.fromkeys(REGEX_URL.findall(body_combined)))

    return {
        "sha256": sha256_hash,
        "subject": subject,
        "sender": sender,
        "sender_display_name": display_name or None,
        "sender_address": sender_address or None,
        "sender_domain": sender_domain or None,
        "recipient": recipient,
        "date": date_hdr,
        "message_id": message_id,
        "return_path": return_path or None,
        "received_headers": received_headers,
        "recorded_auth_results": auth_results,
        "recorded_received_spf": received_spf,
        "recorded_dkim_signatures": dkim_signatures,
        "body_plain": body_plain,
        "body_html": body_html,
        "attachments": attachments,
        "urls": extracted_urls,
        "raw_bytes": raw_bytes,
    }
