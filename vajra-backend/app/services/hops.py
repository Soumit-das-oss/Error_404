import email.utils
import ipaddress
import re
from datetime import datetime, timezone
from typing import List, Optional, Tuple, Dict, Any

from app.services.geoip import lookup_ip_sync

# Regex to detect IPv4 addresses
IPV4_REGEX = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"
)

# Regex to detect IPv6 addresses inside Received headers (e.g., [IPv6:2001:db8::1] or [2001:db8::1])
IPV6_REGEX = re.compile(
    r"(?:IPv6:)?([0-9a-fA-F]{1,4}(?::[0-9a-fA-F]{1,4}){7}|(?:[0-9a-fA-F]{1,4}:){1,7}:|(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|(?:::[0-9a-fA-F]{1,4}){1,7}|::)",
    re.IGNORECASE,
)

# Regex for extracting reported hostnames from Received header: 'from <hostname>' or 'by <hostname>'
FROM_HOST_REGEX = re.compile(r"from\s+([a-zA-Z0-9.\-_]+)", re.IGNORECASE)
BY_HOST_REGEX = re.compile(r"by\s+([a-zA-Z0-9.\-_]+)", re.IGNORECASE)


def is_public_ip(ip_str: str) -> bool:
    """Check whether an IP address is an external, non-RFC1918 public address."""
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
        # Discard CGNAT 100.64.0.0/10 and broadcast/zero networks if IPv4
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


def extract_ips_from_text(text: str) -> List[str]:
    """Extract all valid IP strings from a raw text snippet."""
    found_ips: List[str] = []

    # Check IPv4
    for match in IPV4_REGEX.findall(text):
        try:
            ipaddress.IPv4Address(match)
            if match not in found_ips:
                found_ips.append(match)
        except ValueError:
            pass

    # Check IPv6
    for match in IPV6_REGEX.findall(text):
        if ":" in match and len(match) > 3:
            clean = match.replace("IPv6:", "").strip("[]")
            try:
                ipaddress.IPv6Address(clean)
                if clean not in found_ips:
                    found_ips.append(clean)
            except ValueError:
                pass

    return found_ips


def parse_received_timestamp(header: str) -> Optional[datetime]:
    """Extract and parse date/time from the end of a Received header."""
    if ";" in header:
        date_str = header.split(";")[-1].strip()
        try:
            parsed_tuple = email.utils.parsedate_tz(date_str)
            if parsed_tuple:
                timestamp = email.utils.mktime_tz(parsed_tuple)
                return datetime.fromtimestamp(timestamp, timezone.utc)
        except Exception:
            pass
    return None


def parse_hops_bottom_up(received_headers: List[str]) -> Tuple[List[Dict[str, Any]], Optional[str]]:
    """Traverse Received headers in reverse chronological order (bottom-to-top).

    Returns:
        (hops_list, earliest_public_ip)
    """
    if not received_headers:
        return [], None

    # Bottom-up traversal: The bottom-most header is the earliest MTA hop closest to origin
    chronological_headers = list(reversed(received_headers))

    hops: List[Dict[str, Any]] = []
    earliest_public_ip: Optional[str] = None
    prev_timestamp: Optional[datetime] = None
    hop_counter = 1

    for header in chronological_headers:
        # Normalize whitespace in header
        normalized_header = " ".join(header.split())

        # Extract hostname
        from_match = FROM_HOST_REGEX.search(normalized_header)
        hostname = from_match.group(1) if from_match else None
        if not hostname:
            by_match = BY_HOST_REGEX.search(normalized_header)
            hostname = by_match.group(1) if by_match else None

        # Extract timestamp and transit delay
        current_timestamp = parse_received_timestamp(normalized_header)
        delay_seconds: Optional[float] = None
        if prev_timestamp and current_timestamp:
            delta = (current_timestamp - prev_timestamp).total_seconds()
            delay_seconds = max(0.0, delta)
        if current_timestamp:
            prev_timestamp = current_timestamp

        # Extract all IPs in this header
        ips = extract_ips_from_text(normalized_header)

        # Filter for public IPs
        public_ips = [ip for ip in ips if is_public_ip(ip)]

        if not public_ips:
            # If no public IP found (e.g. internal LAN hop or client submit), skip external hop record
            continue

        # Use the primary public entry IP found in this hop
        primary_ip = public_ips[0]

        if earliest_public_ip is None:
            earliest_public_ip = primary_ip

        # GeoIP & ASN lookup
        geo = lookup_ip_sync(primary_ip)

        hop_data = {
            "hop_number": hop_counter,
            "ip": primary_ip,
            "hostname": hostname,
            "country": geo.country,
            "country_code": geo.country_code,
            "city": geo.city,
            "latitude": geo.latitude,
            "longitude": geo.longitude,
            "asn": geo.asn,
            "asn_org": geo.asn_org,
            "is_datacenter": geo.is_datacenter,
            "is_tor_exit": geo.is_tor_exit,
            "delay_seconds": delay_seconds,
        }

        hops.append(hop_data)
        hop_counter += 1

    return hops, earliest_public_ip
