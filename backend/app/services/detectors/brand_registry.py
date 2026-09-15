"""
VAJRA Forensic Platform - Brand Impersonation & Typosquatting Engine
Identifies visual and lexical typosquatting, character substitution,
and brand token hijacking targeting high-profile commercial and financial institutions.
"""

import re
from typing import Dict, Any, List, Optional, Tuple
from urllib.parse import urlparse

PROTECTED_BRANDS: List[str] = [
    "flipkart.com",
    "amazon.in",
    "amazon.com",
    "paypal.com",
    "google.com",
    "microsoft.com",
    "apple.com",
    "netflix.com",
    "sbi.co.in",
    "hdfcbank.com",
    "icicibank.com",
]

BRAND_TOKENS: Dict[str, str] = {
    "flipkart": "flipkart.com",
    "big billion days": "flipkart.com",
    "amazon": "amazon.com",
    "great indian festival": "amazon.in",
    "paypal": "paypal.com",
    "google": "google.com",
    "microsoft": "microsoft.com",
    "apple": "apple.com",
    "netflix": "netflix.com",
    "sbi": "sbi.co.in",
    "state bank of india": "sbi.co.in",
    "hdfc": "hdfcbank.com",
    "hdfcbank": "hdfcbank.com",
    "icici": "icicibank.com",
    "icicibank": "icicibank.com",
}

# Common homoglyph / visual character substitutions
HOMOGLYPH_MAP: Dict[str, str] = {
    "0": "o",
    "1": "l",
    "i": "l",
    "vv": "w",
    "rn": "m",
}


def levenshtein_distance(s1: str, s2: str) -> int:
    """Compute standard Levenshtein edit distance between two strings."""
    s1 = s1.lower()
    s2 = s2.lower()
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)
    if len(s2) == 0:
        return len(s1)

    previous_row = list(range(len(s2) + 1))
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row

    return previous_row[-1]


def extract_domain_sld(domain: str) -> Tuple[str, str]:
    """
    Extract SLD (second-level domain / main brand name) and TLD.
    e.g. 'filipkart.com' -> ('filipkart', 'com')
    'sbi.co.in' -> ('sbi', 'co.in')
    """
    clean = domain.lower().strip().rstrip(".")
    # Remove port
    if ":" in clean:
        clean = clean.split(":")[0]
    # Remove leading www.
    if clean.startswith("www."):
        clean = clean[4:]

    parts = clean.split(".")
    if len(parts) >= 3 and f"{parts[-2]}.{parts[-1]}" in ("co.in", "com.au", "co.uk", "org.in", "net.in"):
        sld = parts[-3]
        tld = f"{parts[-2]}.{parts[-1]}"
    elif len(parts) >= 2:
        sld = parts[-2]
        tld = parts[-1]
    else:
        sld = clean
        tld = ""

    return sld, tld


def check_brand_typosquatting(target: str) -> Optional[Dict[str, Any]]:
    """
    Inspect a domain or full URL against protected brands and brand tokens.
    Detects:
      1. Direct Levenshtein distance <= 2 (e.g. filipkart.com vs flipkart.com)
      2. Homoglyph/substitution similarity
      3. Deceptive brand token embeds (e.g. flipkart-offers.com, secure-paypal.xyz)
    Returns forensic evaluation dict if typosquatted/impersonating, else None.
    """
    if not target:
        return None

    clean_target = target.strip()
    # If target is a URL, parse out hostname
    if "://" in clean_target:
        parsed = urlparse(clean_target)
        host = parsed.hostname or ""
    elif "/" in clean_target:
        host = clean_target.split("/")[0]
    else:
        host = clean_target

    host = host.lower().strip().rstrip(".")
    if ":" in host:
        host = host.split(":")[0]
    if host.startswith("www."):
        host = host[4:]

    if not host or "." not in host:
        return None

    target_sld, target_tld = extract_domain_sld(host)

    for brand_domain in PROTECTED_BRANDS:
        brand_clean = brand_domain.lower()
        # 1. Exact Match or Legitimate Subdomain -> Safe, not typosquatted
        if host == brand_clean or host.endswith("." + brand_clean):
            return None

        brand_sld, brand_tld = extract_domain_sld(brand_clean)

        # 2. Levenshtein Distance Check on SLD or Full Domain
        # Distance on SLD (e.g. 'filipkart' vs 'flipkart' -> dist=1)
        dist_sld = levenshtein_distance(target_sld, brand_sld)
        dist_full = levenshtein_distance(host, brand_clean)

        if (1 <= dist_sld <= 2 and len(target_sld) >= 4) or (1 <= dist_full <= 2 and len(host) >= 6):
            return {
                "is_typosquat": True,
                "matched_brand": brand_clean,
                "target_domain": host,
                "reason": (
                    f"Typosquatting detected: '{host}' is suspiciously similar to "
                    f"protected brand '{brand_clean}' (Levenshtein distance: {min(dist_sld, dist_full)})."
                ),
                "indicator": "TYPOSQUAT_BRAND_IMPERSONATION",
                "penalty": 45,
            }

        # 3. Homoglyph / Character Substitution Check
        # e.g., 'paypa1.com' -> 'paypal.com', 'amaz0n.com' -> 'amazon.com'
        normalized_target_sld = target_sld
        for char, sub in HOMOGLYPH_MAP.items():
            normalized_target_sld = normalized_target_sld.replace(char, sub)

        if normalized_target_sld == brand_sld and target_sld != brand_sld:
            return {
                "is_typosquat": True,
                "matched_brand": brand_clean,
                "target_domain": host,
                "reason": (
                    f"Character substitution typosquatting detected: '{host}' "
                    f"mimics protected brand '{brand_clean}' using visual homoglyphs."
                ),
                "indicator": "TYPOSQUAT_BRAND_IMPERSONATION",
                "penalty": 45,
            }

    # 4. Deceptive Brand Token Embed Check
    # e.g. flipkart-offers.com, flipkartrewards.com, amazon-security.xyz
    for token, canonical_brand in BRAND_TOKENS.items():
        if " " in token:
            token_slug = token.replace(" ", "")
        else:
            token_slug = token

        if token_slug in target_sld:
            # If target SLD contains the brand token but is NOT the brand's domain
            canonical_clean = canonical_brand.lower()
            if host != canonical_clean and not host.endswith("." + canonical_clean):
                return {
                    "is_typosquat": True,
                    "matched_brand": canonical_brand,
                    "target_domain": host,
                    "reason": (
                        f"Deceptive brand impersonation: '{host}' embeds protected brand "
                        f"token '{token}' with deceptive affixes."
                    ),
                    "indicator": "TYPOSQUAT_BRAND_IMPERSONATION",
                    "penalty": 45,
                }

    return None
