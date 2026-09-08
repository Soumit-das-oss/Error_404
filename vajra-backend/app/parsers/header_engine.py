"""
VAJRA Forensic Platform - Header & Hop Intelligence Engine
Performs bottom-up Received: hop tracing, candidate origin IP identification,
MaxMind GeoIP/ASN resolution, Tor node checking, and SPF/DKIM/DMARC audits.
"""

import email.utils
import ipaddress
import logging
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple

import geoip2.database
from app.core.config import settings

logger = logging.getLogger("vajra.parsers.header_engine")

IPV4_REGEX = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"
)
IPV6_REGEX = re.compile(
    r"(?:IPv6:)?([0-9a-fA-F]{1,4}(?::[0-9a-fA-F]{1,4}){7}|(?:[0-9a-fA-F]{1,4}:){1,7}:|(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|(?:::[0-9a-fA-F]{1,4}){1,7}|::)",
    re.IGNORECASE,
)
FROM_HOST_REGEX = re.compile(r"from\s+([a-zA-Z0-9.\-_]+)", re.IGNORECASE)
BY_HOST_REGEX = re.compile(r"by\s+([a-zA-Z0-9.\-_]+)", re.IGNORECASE)

KNOWN_DATACENTER_ASNS = {
    16509: "Amazon AWS",
    14618: "Amazon AWS",
    8075: "Microsoft Azure",
    15169: "Google Cloud",
    14061: "DigitalOcean",
    16276: "OVH",
    24940: "Hetzner Online",
    63949: "Linode / Akamai",
    20473: "Choopa / Vultr",
    51167: "Contabo",
}

DATACENTER_KEYWORDS = [
    "amazon", "aws", "azure", "microsoft", "google", "digitalocean",
    "ovh", "hetzner", "linode", "vultr", "choopa", "contabo",
    "cloudflare", "fastly", "akamai", "leaseweb", "rackspace"
]

_city_reader = None
_asn_reader = None
_readers_initialized = False
_tor_exit_nodes = set()
_tor_loaded = False


def _init_databases() -> None:
    """Initialize GeoIP2 MMDB readers and Tor exit node set gracefully."""
    global _city_reader, _asn_reader, _readers_initialized, _tor_exit_nodes, _tor_loaded
    if not _readers_initialized:
        city_path = settings.GEOLITE2_CITY_PATH
        asn_path = settings.GEOLITE2_ASN_PATH

        if city_path.exists() and city_path.stat().st_size > 1024:
            try:
                _city_reader = geoip2.database.Reader(str(city_path))
            except Exception as e:
                logger.warning(f"Could not open GeoLite2-City: {e}")
                _city_reader = None
        else:
            _city_reader = None

        if asn_path.exists() and asn_path.stat().st_size > 1024:
            try:
                _asn_reader = geoip2.database.Reader(str(asn_path))
            except Exception as e:
                logger.warning(f"Could not open GeoLite2-ASN: {e}")
                _asn_reader = None
        else:
            _asn_reader = None

        _readers_initialized = True

    if not _tor_loaded:
        exit_path = getattr(settings, "TOR_EXIT_NODES_PATH", settings.DATA_DIR / "tor_exit_nodes.txt")
        if not exit_path.exists():
            exit_path = settings.DATA_DIR / "tor_exit_nodes.txt"

        if exit_path.exists():
            try:
                with open(exit_path, "r", encoding="utf-8", errors="ignore") as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith("#"):
                            _tor_exit_nodes.add(line)
            except Exception as e:
                logger.warning(f"Error reading Tor exit nodes from {exit_path}: {e}")
        _tor_loaded = True


def is_public_ip(ip_str: str) -> bool:
    """Check whether an IP address is an external routable public address."""
    try:
        ip_obj = ipaddress.ip_address(ip_str.strip())
        if (
            ip_obj.is_private
            or ip_obj.is_loopback
            or ip_obj.is_link_local
            or ip_obj.is_multicast
            or ip_obj.is_unspecified
        ):
            return False
        if ip_obj.version == 4:
            if ip_obj in ipaddress.ip_network("100.64.0.0/10"):
                return False
            if ip_obj in ipaddress.ip_network("0.0.0.0/8"):
                return False
            if ip_obj in ipaddress.ip_network("240.0.0.0/4"):
                return False
        return True
    except ValueError:
        return False


def is_tor_exit_node(ip_str: str) -> bool:
    """Check if IP matches any known Tor exit relay node."""
    _init_databases()
    return ip_str.strip() in _tor_exit_nodes


def resolve_geoip(ip_str: str) -> Dict[str, Any]:
    """Resolve IP geolocation and ASN organization using MaxMind binaries with fallback."""
    _init_databases()

    record = {
        "ip": ip_str,
        "city": None,
        "country": None,
        "country_code": None,
        "latitude": None,
        "longitude": None,
        "asn": None,
        "asn_org": None,
        "is_datacenter": False,
        "is_tor_exit": is_tor_exit_node(ip_str),
    }

    if not is_public_ip(ip_str):
        record["city"] = "Private Subnet"
        record["country"] = "Internal Network"
        record["asn_org"] = "RFC1918 / Loopback"
        return record

    # City lookup
    if _city_reader:
        try:
            city_resp = _city_reader.city(ip_str)
            record["city"] = city_resp.city.name or "Unknown City"
            record["country"] = city_resp.country.name or "Unknown Country"
            record["country_code"] = city_resp.country.iso_code
            record["latitude"] = city_resp.location.latitude
            record["longitude"] = city_resp.location.longitude
        except Exception:
            pass

    # ASN lookup
    if _asn_reader:
        try:
            asn_resp = _asn_reader.asn(ip_str)
            record["asn"] = asn_resp.autonomous_system_number
            record["asn_org"] = asn_resp.autonomous_system_organization
        except Exception:
            pass

    # Datacenter heuristics
    asn_num = record.get("asn")
    asn_org = str(record.get("asn_org") or "").lower()
    if asn_num in KNOWN_DATACENTER_ASNS:
        record["is_datacenter"] = True
    elif any(kw in asn_org for kw in DATACENTER_KEYWORDS):
        record["is_datacenter"] = True

    return record


def parse_hops_and_origin(received_headers: List[str]) -> Tuple[List[Dict[str, Any]], Optional[str]]:
    """Traverse Received headers in bottom-up chronological order to identify hops and origin IP."""
    if not received_headers:
        return [], None

    # Received headers are appended at each hop; chronologically, the earliest hop is at the bottom
    chronological_headers = list(reversed(received_headers))
    hops: List[Dict[str, Any]] = []
    earliest_public_ip: Optional[str] = None
    prev_dt: Optional[datetime] = None

    for idx, header_text in enumerate(chronological_headers, start=1):
        clean_text = " ".join(header_text.split())

        # Extract IPs
        found_ips: List[str] = []
        for m in IPV4_REGEX.findall(clean_text):
            if m not in found_ips and is_public_ip(m):
                found_ips.append(m)

        if not found_ips:
            # Check private if no public found
            for m in IPV4_REGEX.findall(clean_text):
                if m not in found_ips:
                    found_ips.append(m)

        # Candidate hop IP
        hop_ip = found_ips[0] if found_ips else "0.0.0.0"

        # Timestamp parsing
        hop_dt: Optional[datetime] = None
        if ";" in clean_text:
            date_part = clean_text.split(";")[-1].strip()
            try:
                hop_dt = email.utils.parsedate_to_datetime(date_part)
                if hop_dt.tzinfo is None:
                    hop_dt = hop_dt.replace(tzinfo=timezone.utc)
            except Exception:
                pass

        # Transit delay
        delay_sec: Optional[float] = None
        if prev_dt and hop_dt:
            diff = (hop_dt - prev_dt).total_seconds()
            delay_sec = max(0.0, diff) if diff >= 0 else None
        if hop_dt:
            prev_dt = hop_dt

        # Resolve GeoIP
        geo_info = resolve_geoip(hop_ip)

        from_m = FROM_HOST_REGEX.search(clean_text)
        by_m = BY_HOST_REGEX.search(clean_text)

        hop_record = {
            "hop_number": idx,
            "ip": hop_ip,
            "hostname": from_m.group(1) if from_m else (by_m.group(1) if by_m else None),
            "city": geo_info["city"],
            "country": geo_info["country"],
            "country_code": geo_info["country_code"],
            "latitude": geo_info["latitude"],
            "longitude": geo_info["longitude"],
            "asn": geo_info["asn"],
            "asn_org": geo_info["asn_org"],
            "is_datacenter": geo_info["is_datacenter"],
            "is_tor_exit": geo_info["is_tor_exit"],
            "delay_seconds": delay_sec,
        }
        hops.append(hop_record)

        # Set first public IP discovered as candidate origin
        if not earliest_public_ip and is_public_ip(hop_ip):
            earliest_public_ip = hop_ip

    return hops, earliest_public_ip


def audit_authentication_headers(
    auth_results: List[str],
    received_spf: List[str],
    dkim_signatures: List[str],
    raw_bytes: Optional[bytes] = None,
) -> Dict[str, Any]:
    """Audit SPF, DKIM, and DMARC claims from email headers and cryptographic signatures."""
    spf_status = "NONE"
    spf_details = "No SPF authentication claim recorded."

    dkim_status = "NONE"
    dkim_details = "No DKIM signature found."

    dmarc_status = "NONE"
    dmarc_policy = "none"
    dmarc_details = "No DMARC evaluation claim recorded."

    combined_auth = " ".join(auth_results).lower()
    combined_spf = " ".join(received_spf).lower()

    dkim_source = "recorded_mta"

    # 1. Audit SPF
    if (
        "spf=pass" in combined_auth
        or re.search(r"\bspf\s*=\s*pass\b", combined_auth)
        or any(s.strip().lower().startswith("pass") or "pass (" in s.lower() for s in received_spf)
        or "spf=pass" in combined_spf
        or re.search(r"\bpass\b", combined_spf)
    ):
        spf_status = "PASS"
        spf_details = "SPF verified: Sender IP authorized by domain policy."
    elif "spf=fail" in combined_auth or "fail" in combined_spf:
        spf_status = "FAIL"
        spf_details = "SPF rejected: Sender IP not authorized to transmit on behalf of domain."
    elif "spf=softfail" in combined_auth or "softfail" in combined_spf:
        spf_status = "SOFTFAIL"
        spf_details = "SPF softfail: Domain policy discourages transmission host."
    elif "spf=neutral" in combined_auth:
        spf_status = "NEUTRAL"
        spf_details = "SPF neutral: Domain specifies neither pass nor fail."

    # 2. Audit DKIM
    if "dkim=pass" in combined_auth or re.search(r"\bdkim\s*=\s*pass\b", combined_auth):
        dkim_status = "PASS"
        dkim_details = "DKIM verified: Valid cryptographic domain signature aligned."
    elif "dkim=fail" in combined_auth or re.search(r"\bdkim\s*=\s*fail\b", combined_auth):
        dkim_status = "FAIL"
        dkim_details = "DKIM failed: Signature verification failed or body was modified."
    elif dkim_signatures:
        # Signature is present in headers; attempt local cryptographic verification if bytes available
        if raw_bytes:
            try:
                import dkim
                if dkim.verify(raw_bytes):
                    dkim_status = "PASS"
                    dkim_details = "DKIM mathematically verified via local dkimpy engine."
                    dkim_source = "cryptographic"
                else:
                    dkim_status = "FAIL"
                    dkim_details = "DKIM signature invalid or payload altered."
            except Exception:
                dkim_status = "UNVERIFIABLE"
                dkim_details = "DKIM signature present but public DNS key lookup unresolvable."
        else:
            dkim_status = "UNVERIFIABLE"
            dkim_details = f"Discovered {len(dkim_signatures)} signature(s) awaiting DNS key verification."

    # 3. Audit DMARC
    if "dmarc=pass" in combined_auth or re.search(r"\bdmarc\s*=\s*(?:bestguess)?pass\b", combined_auth):
        dmarc_status = "PASS"
        if "p=reject" in combined_auth:
            dmarc_policy = "reject"
        elif "p=quarantine" in combined_auth:
            dmarc_policy = "quarantine"
        elif "p=none" in combined_auth:
            dmarc_policy = "none"
        dmarc_details = f"DMARC verified: SPF/DKIM identifier alignment verified (policy={dmarc_policy})."
    elif "dmarc=fail" in combined_auth or re.search(r"\bdmarc\s*=\s*fail\b", combined_auth):
        dmarc_status = "FAIL"
        if "action=reject" in combined_auth or "p=reject" in combined_auth:
            dmarc_policy = "reject"
        elif "action=quarantine" in combined_auth or "p=quarantine" in combined_auth:
            dmarc_policy = "quarantine"
        dmarc_details = f"DMARC policy enforcement failed (policy={dmarc_policy})."

    return {
        "spf": {"status": spf_status, "details": spf_details, "source": "recorded_mta"},
        "dkim": {"status": dkim_status, "details": dkim_details, "source": dkim_source},
        "dmarc": {"status": dmarc_status, "policy": dmarc_policy, "details": dmarc_details, "source": "recorded_mta"},
    }
