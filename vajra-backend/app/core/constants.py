"""
VAJRA Forensic Platform - Constants, Scoring Weights, Heuristic Regexes & Fallback Templates
"""

import re
from typing import Set, List, Dict, Any

# ==============================================================================
# DETERMINISTIC THREAT SCORING PENALTIES (0 - 100 Scale)
# ==============================================================================
PENALTY_SPF_FAIL: int = 15
PENALTY_DKIM_FAIL: int = 15
PENALTY_DMARC_FAIL: int = 15
PENALTY_DECEPTIVE_LINK: int = 25
PENALTY_QUISHING_QR: int = 40
PENALTY_URGENCY_INDICATORS: int = 20
PENALTY_FREE_WEBMAIL_LURE: int = 35
PENALTY_PDF_JAVASCRIPT: int = 35
PENALTY_PDF_LAUNCH: int = 45

# Verdict Thresholds
VERDICT_SAFE: str = "SAFE"
VERDICT_SUSPICIOUS: str = "SUSPICIOUS"
VERDICT_MALICIOUS: str = "MALICIOUS"

THRESHOLD_SAFE_MAX: int = 19
THRESHOLD_SUSPICIOUS_MAX: int = 59

# ==============================================================================
# HEURISTIC & REPUTATION ASSETS
# ==============================================================================
FREE_WEBMAIL_DOMAINS: Set[str] = {
    "gmail.com",
    "yahoo.com",
    "ymail.com",
    "hotmail.com",
    "outlook.com",
    "live.com",
    "msn.com",
    "aol.com",
    "mail.com",
    "protonmail.com",
    "proton.me",
    "zoho.com",
    "yandex.com",
    "icloud.com",
    "gmx.com",
    "gmx.net",
    "tutanota.com",
    "tutamail.com",
}

IMPERSONATION_TARGET_KEYWORDS: List[str] = [
    "ceo",
    "cfo",
    "coo",
    "chief",
    "director",
    "president",
    "executive",
    "board of directors",
    "human resources",
    "hr department",
    "payroll",
    "finance department",
    "accounting",
    "it support",
    "it helpdesk",
    "helpdesk",
    "system administrator",
    "security team",
    "cyber security",
    "compliance",
    "auditor",
    "paypal",
    "microsoft",
    "apple support",
    "google security",
    "chase bank",
    "bank of america",
    "wells fargo",
    "federal reserve",
    "internal revenue service",
    "irs",
    "income tax",
]

URGENCY_PATTERNS: List[str] = [
    "urgent action required",
    "immediate action required",
    "account suspended",
    "account suspension",
    "unauthorized login",
    "unauthorized access",
    "wire transfer",
    "immediate payment",
    "overdue invoice",
    "security alert",
    "critical alert",
    "verify your identity",
    "identity verification",
    "password reset",
    "password expires",
    "within 24 hours",
    "within 12 hours",
    "final notice",
    "termination warning",
    "account will be closed",
    "immediate response needed",
    "quishing",
    "verify payment",
    "verify payment immediately",
    "payment verification",
    "account verification",
]

FINANCIAL_ACCOUNT_LURES: List[str] = [
    "payment",
    "verification required",
    "verify your account",
    "verify your identity",
    "account suspended",
    "account suspension",
    "security update",
    "security alert",
    "unauthorized login",
    "unauthorized access",
    "billing",
    "invoice",
    "wire transfer",
    "password reset",
    "reset password",
    "critical patch",
    "critical alert",
    "verify payment",
    "payment verification",
    "account verification",
    "payment account verification",
]

DANGEROUS_PAYLOAD_EXTENSIONS: List[str] = [
    ".exe",
    ".scr",
    ".vbs",
    ".bat",
    ".cmd",
    ".ps1",
    ".iso",
    ".dll",
    ".hta",
    ".wsf",
    ".js",
    ".pif",
    ".lnk",
]

# ==============================================================================
# DLP SHIELD REGEX PATTERNS
# ==============================================================================
# Credit Cards (Visa, MasterCard, Amex, Discover, etc. with optional delimiters)
REGEX_CREDIT_CARD = re.compile(
    r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|6(?:011|5[0-9]{2})[0-9]{12}|(?:2131|1800|35\d{3})\d{11}|(?:\d{4}[-\s]?){3}\d{4})\b"
)

# IBAN (International Bank Account Number)
REGEX_IBAN = re.compile(
    r"\b[A-Z]{2}[0-9]{2}[A-Z0-9]{4}[0-9]{7}([A-Z0-9]?){0,16}\b"
)

# International & Standard Phone Numbers
REGEX_PHONE = re.compile(
    r"(?:\+?\d{1,3}[-.\s]?)?(?:\(?\d{3}\)?[-.\s]?)\d{3}[-.\s]?\d{4}\b"
)

# Full Names preceded by common prefixes or form labels
REGEX_NAME_LABELS = re.compile(
    r"(?i)\b(?:Name|Account Holder|Customer|Full Name|Attention|Attn|Employee|Recipient|Sender|User|Client|Beneficiary|Cardholder):\s*([A-Z][a-z]+(?:[ \t]+[A-Z][a-z]+)+)"
)
REGEX_NAME_TITLES = re.compile(
    r"\b(?:Mr\.|Mrs\.|Ms\.|Dr\.|Prof\.)[ \t]+[A-Z][a-z]+(?:[ \t]+[A-Z][a-z]+)?"
)

# General URL regex
REGEX_URL = re.compile(
    r"https?://(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}(?::\d+)?(?:/[^\s<>\"'{}|\\^`]*)*",
    re.IGNORECASE
)


# ==============================================================================
# FALLBACK TEMPLATES FOR OFFLINE / TIMEOUT AI
# ==============================================================================
def get_static_briefing_template(score: int, verdict: str, penalties: List[Dict[str, Any]], sender: str = "", subject: str = "") -> str:
    """Deterministic fallback analyst brief formatted strictly as 3 sentences."""
    penalty_names = [p.get("rule", str(p)) for p in penalties] if penalties else []
    triggers_str = ", ".join(penalty_names) if penalty_names else "clean cryptographic baseline"

    if verdict == VERDICT_MALICIOUS or score >= 60:
        sentence1 = f"Forensic analysis identifies a high-confidence {verdict} threat scoring {score}/100 targeting recipient infrastructure via deceptive transmission."
        sentence2 = f"Telemetry confirms active evasion indicators including {triggers_str} originating from sender identity '{sender or 'unverified'}."
        sentence3 = "Immediate automated perimeter quarantine, credential revocation, and sender IP domain blacklisting are required."
    elif verdict == VERDICT_SUSPICIOUS or score >= 20:
        sentence1 = f"Automated inspection flagged this communication as {verdict} with an aggregated risk score of {score}/100."
        sentence2 = f"Heuristic signals revealed significant security irregularities involving {triggers_str} requiring analyst review."
        sentence3 = "Advise holding message in triage quarantine pending secondary out-of-band verification before user delivery."
    else:
        sentence1 = f"Cryptographic verification confirmed this message as authentic and {verdict} with an evaluated score of {score}/100."
        sentence2 = f"Underlying transmission headers passed security policies with zero malicious payloads or deceptive vectors detected."
        sentence3 = "Standard inbox delivery permitted with normal telemetry logging."

    return f"{sentence1} {sentence2} {sentence3}"
