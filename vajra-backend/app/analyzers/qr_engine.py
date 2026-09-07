"""
VAJRA Forensic Platform - Isolated QR / Quishing Engine
Safe, zero-crash zxing-cpp wrapper with polarity inversion for dark-mode QR codes.
"""

import io
import ipaddress
import logging
import re
from typing import List, Union, Dict, Any, Tuple
from urllib.parse import urlparse
from PIL import Image, ImageOps

logger = logging.getLogger("vajra.analyzers.qr")

try:
    import zxingcpp
except ImportError:
    zxingcpp = None


URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "buff.ly",
    "ow.ly", "cutt.ly", "rb.gy", "shorturl.at", "bl.ink", "tiny.cc",
    "qr.ae", "shorte.st", "clck.ru",
}

HIGH_RISK_TLDS = {
    "top", "xyz", "tk", "ml", "ga", "cf", "gq", "icu", "fit", "work",
    "click", "buzz", "monster", "rest", "cam", "loan", "stream", "live",
    "bid", "country", "kim", "party", "science", "gdn", "date",
}

SUSPICIOUS_PATH_KEYWORDS = [
    "login", "signin", "sign-in", "log-in", "verify", "verification",
    "account", "banking", "secure", "update", "authenticate", "auth",
    "credential", "password", "wallet", "recover",
]

SUSPICIOUS_DOMAIN_KEYWORDS = [
    "phishing", "fake", "malicious", "hacker", "evil", "steal",
    "paypa1", "micros0ft", "g00gle", "app1e",
]

TRUSTED_DOMAINS = {
    "google.com", "linkedin.com", "internshala.com", "github.com",
    "microsoft.com", "apple.com", "wikipedia.org", "youtube.com",
}


def is_suspicious_qr_payload(payload: str) -> Tuple[bool, str]:
    """Inspect decoded QR payload for active phishing/quishing indicators.
    
    Returns:
        (is_suspicious: bool, reason: str)
    """
    if not payload:
        return False, "Empty QR payload"

    clean_payload = payload.strip()

    # Standard UPI or custom non-web protocols
    if clean_payload.lower().startswith("upi://pay"):
        return False, f"Authentic payment protocol format: {clean_payload[:30]}"

    if not (clean_payload.startswith("http://") or clean_payload.startswith("https://") or "://" in clean_payload):
        return False, "Neutral non-web payload"

    try:
        parsed = urlparse(clean_payload)
        host = (parsed.hostname or "").lower().strip()
        scheme = (parsed.scheme or "").lower().strip()
        path = (parsed.path or "").lower()
        query = (parsed.query or "").lower()

        # 1. Direct IP address host (e.g. http://192.168.x.x/login)
        if host:
            try:
                ip_obj = ipaddress.ip_address(host)
                return True, f"Direct IP address host in QR payload: {host}"
            except ValueError:
                pass

        # 2. Obfuscated URL shorteners
        if host in URL_SHORTENERS or any(host.endswith(f".{s}") for s in URL_SHORTENERS):
            return True, f"Obfuscated URL shortener in QR payload: {host}"

        # 3. High-risk TLDs
        parts = host.split(".")
        if len(parts) >= 2:
            tld = parts[-1]
            if tld in HIGH_RISK_TLDS:
                return True, f"High-risk top-level domain in QR code: .{tld}"

        # 4. Brand lookalike / threat keywords in domain
        for bkw in SUSPICIOUS_DOMAIN_KEYWORDS:
            if bkw in host:
                return True, f"Suspicious lookalike or threat keyword in QR domain: '{bkw}'"

        # 5. Credential phishing parameters or unencrypted login inputs (http://)
        has_cred_param = any(kw in path or kw in query for kw in SUSPICIOUS_PATH_KEYWORDS)
        if scheme == "http":
            if has_cred_param:
                return True, f"Unencrypted HTTP URL with credential/verification endpoint: {path or '/'}"
            if host and host not in ("localhost", "127.0.0.1"):
                return True, f"Unencrypted HTTP destination in QR code: {host}"

        if has_cred_param:
            is_trusted = any(host == td or host.endswith(f".{td}") for td in TRUSTED_DOMAINS)
            if not is_trusted:
                return True, f"Untrusted domain hosting credential/verification endpoint: {host}{path}"

        return False, f"Benign QR payload verified: {host}"

    except Exception as e:
        logger.debug(f"Error evaluating QR payload '{payload}': {e}")
        return False, "Evaluation completed"


def extract_qr_telemetry(images: List[Union[bytes, Image.Image]]) -> Dict[str, Any]:
    """Safely decode QR code URLs and evaluate evidence of suspicion.
    
    Returns:
        {
            "qr_urls": list[str],
            "suspicious_qr_urls": list[str],
            "benign_qr_urls": list[str],
            "is_suspicious_qr": bool,
            "reasons": list[str],
        }
    """
    decoded_urls = extract_qr_codes(images)
    suspicious_urls: List[str] = []
    benign_urls: List[str] = []
    reasons: List[str] = []

    for u in decoded_urls:
        is_susp, reason = is_suspicious_qr_payload(u)
        if is_susp:
            suspicious_urls.append(u)
            reasons.append(reason)
        else:
            benign_urls.append(u)

    return {
        "qr_urls": decoded_urls,
        "suspicious_qr_urls": suspicious_urls,
        "benign_qr_urls": benign_urls,
        "is_suspicious_qr": len(suspicious_urls) > 0,
        "reasons": reasons,
    }


def scan_qr_telemetry(image_bytes: bytes) -> Dict[str, Any]:
    """Scan raw image bytes and return detailed QR threat telemetry."""
    if not image_bytes:
        return {
            "qr_urls": [],
            "suspicious_qr_urls": [],
            "benign_qr_urls": [],
            "is_suspicious_qr": False,
            "reasons": [],
        }
    return extract_qr_telemetry([image_bytes])


def scan_qr_bytes(image_bytes: bytes) -> List[str]:
    """Scan raw image bytes for embedded QR codes and return list of discovered URLs."""
    if not image_bytes:
        return []
    return extract_qr_codes([image_bytes])


def extract_qr_codes(images: List[Union[bytes, Image.Image]]) -> List[str]:
    """Safely decode QR code URLs from image bytes or PIL Images.

    Returns empty list on any decompression or decoding failure; never raises.
    """
    if not images or zxingcpp is None:
        return []

    decoded_urls: List[str] = []

    for img_input in images:
        try:
            # Normalize to PIL Image
            if isinstance(img_input, bytes):
                if not img_input:
                    continue
                pil_img = Image.open(io.BytesIO(img_input))
            elif isinstance(img_input, Image.Image):
                pil_img = img_input
            else:
                continue

            # Pass 1: Standard contrast read
            results = zxingcpp.read_barcodes(pil_img)
            for r in results:
                text = (r.text or "").strip()
                if text and (text.startswith("http://") or text.startswith("https://") or "://" in text):
                    if text not in decoded_urls:
                        decoded_urls.append(text)

            # Pass 2: Inverted polarity for dark-mode / inverted QR codes
            if not results:
                try:
                    inverted_img = ImageOps.invert(pil_img.convert("RGB"))
                    inv_results = zxingcpp.read_barcodes(inverted_img)
                    for r in inv_results:
                        text = (r.text or "").strip()
                        if text and (text.startswith("http://") or text.startswith("https://") or "://" in text):
                            if text not in decoded_urls:
                                decoded_urls.append(text)
                except Exception:
                    pass

        except Exception as e:
            logger.debug(f"QR decoding skipped image due to: {e}")
            continue

    return decoded_urls
