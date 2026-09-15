"""
VAJRA Forensic Platform - Outlook .msg File Parser
Extracts headers, bodies, and embedded attachment streams using extract-msg.
"""

import io
import hashlib
import email.utils
from typing import Dict, Any, List
import extract_msg


def parse_msg_bytes(raw_bytes: bytes) -> Dict[str, Any]:
    """Parse Outlook .msg binary bytes into the unified forensic dictionary format."""
    sha256_hash = hashlib.sha256(raw_bytes).hexdigest()

    msg_obj = extract_msg.Message(io.BytesIO(raw_bytes))

    try:
        subject = str(msg_obj.subject or "").strip()
        sender = str(msg_obj.sender or "").strip()
        recipient = str(msg_obj.to or "").strip()
        date_hdr = str(msg_obj.date or "").strip()
        message_id = str(msg_obj.messageId or "").strip()

        # Sender decomposition
        display_name = ""
        sender_address = ""
        sender_domain = ""
        if sender:
            parsed_name, parsed_addr = email.utils.parseaddr(sender)
            display_name = parsed_name.strip()
            sender_address = parsed_addr.strip().lower()
            if "@" in sender_address:
                sender_domain = sender_address.split("@")[-1].strip().lower()

        # Body extraction
        body_plain = str(msg_obj.body or "").strip()
        body_html = ""
        if hasattr(msg_obj, "htmlBody") and msg_obj.htmlBody:
            if isinstance(msg_obj.htmlBody, bytes):
                body_html = msg_obj.htmlBody.decode("utf-8", errors="replace").strip()
            else:
                body_html = str(msg_obj.htmlBody).strip()

        # Headers and Received lines from raw header string if present
        received_headers: List[str] = []
        raw_headers = str(msg_obj.header or "")
        for line in raw_headers.splitlines():
            if line.lower().startswith("received:"):
                received_headers.append(line.strip())

        # Attachments extraction
        attachments: List[Dict[str, Any]] = []
        for att in msg_obj.attachments:
            try:
                fname = att.longFilename or att.shortFilename or "attachment"
                att_data = att.data or b""
                att_sha = hashlib.sha256(att_data).hexdigest()
                attachments.append({
                    "filename": fname,
                    "content_type": getattr(att, "mimetype", "application/octet-stream") or "application/octet-stream",
                    "size_bytes": len(att_data),
                    "payload_bytes": att_data,
                    "sha256": att_sha,
                })
            except Exception:
                continue

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
            "return_path": None,
            "received_headers": received_headers,
            "recorded_auth_results": [],
            "recorded_received_spf": [],
            "recorded_dkim_signatures": [],
            "body_plain": body_plain,
            "body_html": body_html,
            "attachments": attachments,
            "raw_bytes": raw_bytes,
        }
    finally:
        try:
            msg_obj.close()
        except Exception:
            pass
