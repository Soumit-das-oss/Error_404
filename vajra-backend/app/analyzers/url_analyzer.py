"""
VAJRA Forensic Platform - URL & Hyperlink Analyzer
Extracts URLs, analyzes deceptive anchor-to-href mismatches, raw public IP URLs,
and dangerous executable payload downloads.
"""

import ipaddress
import re
from typing import Dict, Any, List, Optional
from urllib.parse import urlparse
from bs4 import BeautifulSoup
from app.core.constants import REGEX_URL, DANGEROUS_PAYLOAD_EXTENSIONS
from app.services.detectors.brand_registry import check_brand_typosquatting

DOMAIN_OR_URL_PATTERN = re.compile(
    r"^(?:https?://)?(?:www\.)?([a-zA-Z0-9][-a-zA-Z0-9]*(?:\.[a-zA-Z0-9][-a-zA-Z0-9]*)+)(?:[/:?#].*)?$",
    re.IGNORECASE
)


def extract_base_domain(host: Optional[str]) -> Optional[str]:
    """Extract registered base domain name or normalized hostname."""
    if not host:
        return None
    host = host.lower().strip().rstrip(".")
    if ":" in host:
        host = host.split(":")[0]
    parts = host.split(".")
    if len(parts) >= 2:
        return f"{parts[-2]}.{parts[-1]}"
    return host


def check_deceptive_link(anchor_text: str, href: str) -> Optional[Dict[str, str]]:
    """Check if visible anchor text resembles a domain that differs from actual target href."""
    if not anchor_text or not href:
        return None

    clean_anchor = anchor_text.strip()
    clean_href = href.strip()

    anchor_match = DOMAIN_OR_URL_PATTERN.match(clean_anchor)
    if anchor_match:
        display_host = anchor_match.group(1).lower()
        display_base = extract_base_domain(display_host)

        parsed_target = urlparse(clean_href)
        target_host = (parsed_target.hostname or "").lower()
        target_base = extract_base_domain(target_host)

        if target_host and display_base and target_base:
            if display_base != target_base and not target_host.endswith(f".{display_base}"):
                return {
                    "anchor_text": clean_anchor,
                    "actual_href": clean_href,
                    "display_domain": display_base,
                    "target_domain": target_base,
                    "indicator": "DECEPTIVE_HYPERLINK",
                }
    return None


def analyze_urls(
    body_plain: Optional[str] = None,
    body_html: Optional[str] = None,
    additional_urls: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """Analyze all URLs in plain text, HTML DOM, and auxiliary streams."""
    extracted_urls: List[str] = []
    deceptive_urls: List[Dict[str, str]] = []
    raw_ip_urls: List[str] = []
    suspicious_payload_urls: List[str] = []

    def _add_url(u: str):
        u_clean = u.strip()
        if u_clean and u_clean not in extracted_urls:
            extracted_urls.append(u_clean)

    # 1. Plain Text URLs
    if body_plain:
        for match in REGEX_URL.findall(body_plain):
            _add_url(match)

    # 2. HTML DOM URLs and Deceptive Anchors
    if body_html:
        try:
            soup = BeautifulSoup(body_html, "html.parser")
            for a_tag in soup.find_all("a", href=True):
                href = a_tag["href"].strip()
                _add_url(href)
                anchor_text = a_tag.get_text().strip()
                deceptive = check_deceptive_link(anchor_text, href)
                if deceptive and deceptive not in deceptive_urls:
                    deceptive_urls.append(deceptive)
        except Exception:
            pass

    # 3. Auxiliary / Extra URLs (e.g. from PDF links or QR codes)
    if additional_urls:
        for u in additional_urls:
            _add_url(u)

    # 4. Inspect extracted URLs for Raw IP, Dangerous Payloads, and Brand Typosquatting
    typosquat_urls: List[Dict[str, Any]] = []
    for u in extracted_urls:
        try:
            parsed = urlparse(u)
            host = parsed.hostname
            if host:
                try:
                    ip_obj = ipaddress.ip_address(host)
                    if not ip_obj.is_private and not ip_obj.is_loopback:
                        if u not in raw_ip_urls:
                            raw_ip_urls.append(u)
                except ValueError:
                    pass

            path = (parsed.path or "").lower()
            if any(path.endswith(ext) for ext in DANGEROUS_PAYLOAD_EXTENSIONS):
                if u not in suspicious_payload_urls:
                    suspicious_payload_urls.append(u)

            # Check Brand Typosquatting / Impersonation
            typo = check_brand_typosquatting(u)
            if typo:
                typo_entry = {
                    "anchor_text": typo["matched_brand"],
                    "actual_href": u,
                    "display_domain": typo["matched_brand"],
                    "target_domain": typo["target_domain"],
                    "indicator": "TYPOSQUAT_BRAND_IMPERSONATION",
                }
                if typo_entry not in deceptive_urls:
                    deceptive_urls.append(typo_entry)
                typo_copy = dict(typo)
                typo_copy["url"] = u
                if typo_copy not in typosquat_urls:
                    typosquat_urls.append(typo_copy)
        except Exception:
            continue

    return {
        "extracted_urls": extracted_urls,
        "deceptive_urls": deceptive_urls,
        "raw_ip_urls": raw_ip_urls,
        "suspicious_payload_urls": suspicious_payload_urls,
        "typosquat_urls": typosquat_urls,
    }
