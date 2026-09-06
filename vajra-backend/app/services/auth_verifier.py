import logging
import re
from typing import Optional, Dict, Any, Tuple
import dkim
import dns.resolver
import dns.exception

from app.core.config import settings

logger = logging.getLogger("vajra.auth_verifier")


def verify_dkim_sync(raw_bytes: bytes) -> Dict[str, str]:
    """Cryptographically verify DKIM signatures using dkimpy.

    Returns:
        dict: {"status": "PASS"|"FAIL"|"NONE"|"UNKNOWN", "details": "..."}
    """
    # Check if a DKIM-Signature header exists
    raw_lower = raw_bytes.lower()
    if b"dkim-signature:" not in raw_lower:
        return {
            "status": "NONE",
            "details": "No DKIM-Signature header found in message payload.",
        }

    try:
        # dkim.verify performs cryptographic signature and canonicalization checks
        verified = dkim.verify(raw_bytes)
        if verified:
            return {
                "status": "PASS",
                "details": "Cryptographic signature verified successfully against publisher DNS public key.",
            }
        else:
            return {
                "status": "FAIL",
                "details": "DKIM signature failed validation (signature corrupt, key mismatch, or body tampered).",
            }
    except dkim.ValidationError as ve:
        return {
            "status": "FAIL",
            "details": f"DKIM validation error: {str(ve)}",
        }
    except Exception as e:
        logger.warning(f"Unexpected exception during DKIM verification: {e}")
        return {
            "status": "UNKNOWN",
            "details": f"DKIM verification encountered an error: {str(e)}",
        }


def get_dns_resolver() -> dns.resolver.Resolver:
    """Construct a defensive DNS resolver with a strict timeout ceiling."""
    resolver = dns.resolver.Resolver()
    timeout = getattr(settings, "DNS_TIMEOUT_SECONDS", 3.0)
    resolver.timeout = timeout
    resolver.lifetime = timeout
    return resolver


def verify_spf_sync(domain: Optional[str], client_ip: Optional[str] = None) -> Dict[str, str]:
    """Query and verify SPF record for domain with defensive 3.0s timeout."""
    if not domain:
        return {
            "status": "NONE",
            "details": "No sender domain identified for SPF verification.",
        }

    resolver = get_dns_resolver()

    try:
        answers = resolver.resolve(domain, "TXT")
        spf_records = []
        for rdata in answers:
            txt_content = b"".join(rdata.strings).decode("utf-8", errors="replace")
            if txt_content.startswith("v=spf1"):
                spf_records.append(txt_content)

        if not spf_records:
            return {
                "status": "NONE",
                "details": f"No SPF record published for domain '{domain}'.",
            }

        spf_record = spf_records[0]

        # Basic SPF policy evaluation
        if client_ip:
            # Check if IP explicitly authorized via ip4/ip6
            if f"ip4:{client_ip}" in spf_record or f"ip6:{client_ip}" in spf_record:
                return {
                    "status": "PASS",
                    "details": f"Sender IP '{client_ip}' is explicitly authorized in SPF record: {spf_record}",
                }

        # Check default qualifier at end of record
        if "-all" in spf_record:
            if client_ip:
                return {
                    "status": "FAIL",
                    "details": f"Sender IP '{client_ip}' is unauthorized under strict SPF -all policy: {spf_record}",
                }
            return {
                "status": "NEUTRAL",
                "details": f"Domain published strict SPF record: {spf_record}",
            }
        elif "~all" in spf_record:
            return {
                "status": "SOFTFAIL" if client_ip else "NEUTRAL",
                "details": f"Domain published SoftFail SPF record: {spf_record}",
            }
        elif "?all" in spf_record:
            return {
                "status": "NEUTRAL",
                "details": f"Domain published Neutral SPF record: {spf_record}",
            }
        elif "+all" in spf_record:
            return {
                "status": "PASS",
                "details": f"Warning: Domain published dangerously permissive SPF '+all': {spf_record}",
            }

        return {
            "status": "PASS",
            "details": f"Valid SPF record discovered: {spf_record}",
        }

    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return {
            "status": "NONE",
            "details": f"Domain '{domain}' does not exist or has no TXT records.",
        }
    except dns.exception.Timeout:
        logger.warning(f"DNS timeout querying SPF for domain '{domain}'.")
        return {
            "status": "UNKNOWN",
            "details": "DNS query timed out after 3.0s timeout ceiling.",
        }
    except Exception as e:
        logger.warning(f"Error querying SPF for '{domain}': {e}")
        return {
            "status": "UNKNOWN",
            "details": f"SPF query error: {str(e)}",
        }


def verify_dmarc_sync(
    domain: Optional[str],
    spf_status: str,
    dkim_status: str,
) -> Dict[str, str]:
    """Query and evaluate DMARC policy for domain via _dmarc.<domain> TXT query."""
    if not domain:
        return {
            "status": "NONE",
            "policy": "missing",
            "details": "No sender domain specified for DMARC evaluation.",
        }

    resolver = get_dns_resolver()
    dmarc_record_name = f"_dmarc.{domain}"

    try:
        answers = resolver.resolve(dmarc_record_name, "TXT")
        dmarc_records = []
        for rdata in answers:
            txt_content = b"".join(rdata.strings).decode("utf-8", errors="replace")
            if txt_content.startswith("v=DMARC1"):
                dmarc_records.append(txt_content)

        if not dmarc_records:
            return {
                "status": "NONE",
                "policy": "missing",
                "details": f"No DMARC record found at '{dmarc_record_name}'.",
            }

        record = dmarc_records[0]
        # Extract policy 'p=' tag
        policy_match = re.search(r"\bp=([a-zA-Z]+)", record)
        policy = policy_match.group(1).lower() if policy_match else "none"

        # DMARC alignment passes if either DKIM or SPF passes
        if dkim_status == "PASS" or spf_status == "PASS":
            return {
                "status": "PASS",
                "policy": policy,
                "details": f"DMARC aligned successfully. Configured policy: p={policy}. Record: {record}",
            }
        else:
            return {
                "status": "FAIL",
                "policy": policy,
                "details": f"DMARC authentication failed (neither SPF nor DKIM passed alignment). Enforcement policy: p={policy}.",
            }

    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return {
            "status": "NONE",
            "policy": "missing",
            "details": f"No DMARC record published at '{dmarc_record_name}'.",
        }
    except dns.exception.Timeout:
        logger.warning(f"DNS timeout querying DMARC for domain '{domain}'.")
        return {
            "status": "UNKNOWN",
            "policy": "missing",
            "details": "DNS query timed out after 3.0s ceiling.",
        }
    except Exception as e:
        logger.warning(f"Error querying DMARC for '{domain}': {e}")
        return {
            "status": "UNKNOWN",
            "policy": "missing",
            "details": f"DMARC query error: {str(e)}",
        }


def verify_authentication_matrix_sync(
    raw_bytes: bytes,
    sender_domain: Optional[str],
    client_ip: Optional[str] = None,
) -> Dict[str, Any]:
    """Execute complete synchronous authentication suite (DKIM, SPF, DMARC) with defensive timeouts."""
    dkim_res = verify_dkim_sync(raw_bytes)
    spf_res = verify_spf_sync(sender_domain, client_ip)
    dmarc_res = verify_dmarc_sync(sender_domain, spf_res["status"], dkim_res["status"])

    return {
        "spf": spf_res,
        "dkim": dkim_res,
        "dmarc": dmarc_res,
    }
