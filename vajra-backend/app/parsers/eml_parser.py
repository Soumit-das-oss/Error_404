"""
VAJRA Forensic Platform - Native RFC 5322 .eml Email Parser
Extracts headers, multipart MIME text/HTML streams, attachments, and cryptographic evidence hashes.
"""

import email
import email.header
import email.policy
import email.utils
import hashlib
from typing import Dict, Any, List, Optional


def parse_eml_bytes(raw_bytes: bytes) -> Dict[str, Any]:
    """Parse raw RFC 5322 email bytes into structured forensic dictionary."""
    if not raw_bytes:
        raw_bytes = b""

    sha256_hash = hashlib.sha256(raw_bytes).hexdigest()

    msg = email.message_from_bytes(raw_bytes, policy=email.policy.default)

    # 1. Extract Core Headers
    subject = str(msg.get("Subject", "") or "").strip()
    sender = str(msg.get("From", "") or "").strip()
    recipient = str(msg.get("To", "") or "").strip()
    date_hdr = str(msg.get("Date", "") or "").strip()
    message_id = str(msg.get("Message-ID", "") or "").strip()
    return_path = str(msg.get("Return-Path", "") or "").strip()

    # Parse From header into display name and email address
    display_name = ""
    sender_address = ""
    sender_domain = ""
    if sender:
        parsed_name, parsed_addr = email.utils.parseaddr(sender)
        display_name = parsed_name.strip()
        sender_address = parsed_addr.strip().lower()
        if "@" in sender_address:
            sender_domain = sender_address.split("@")[-1].strip().lower()

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
            payload = part.get_payload(decode=True) or b""
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
        "raw_bytes": raw_bytes,
    }
