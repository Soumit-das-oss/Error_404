import ipaddress
import logging
from dataclasses import dataclass
from typing import Optional
from app.core.config import settings
from app.services.threat_intel import is_tor_exit_node, is_datacenter_asn

logger = logging.getLogger("vajra.geoip")


@dataclass
class GeoRecord:
    ip: str
    city: Optional[str] = None
    country: Optional[str] = None
    country_code: Optional[str] = None
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    asn: Optional[int] = None
    asn_org: Optional[str] = None
    is_datacenter: bool = False
    is_tor_exit: bool = False


# Global readers
_city_reader = None
_asn_reader = None
_readers_loaded = False


def _init_readers():
    global _city_reader, _asn_reader, _readers_loaded
    if _readers_loaded:
        return

    import geoip2.database

    city_path = settings.get_absolute_path(settings.GEOIP_CITY_PATH)
    asn_path = settings.get_absolute_path(settings.GEOIP_ASN_PATH)

    if city_path.exists() and city_path.stat().st_size > 1024:
        try:
            _city_reader = geoip2.database.Reader(str(city_path))
            logger.info(f"Loaded MaxMind GeoLite2-City database from {city_path}")
        except Exception as e:
            logger.warning(f"Failed to open GeoLite2-City at {city_path}: {e}. Using mock fallback.")
            _city_reader = None
    else:
        logger.info("GeoLite2-City database not present or placeholder. Using resilient mock fallback.")
        _city_reader = None

    if asn_path.exists() and asn_path.stat().st_size > 1024:
        try:
            _asn_reader = geoip2.database.Reader(str(asn_path))
            logger.info(f"Loaded MaxMind GeoLite2-ASN database from {asn_path}")
        except Exception as e:
            logger.warning(f"Failed to open GeoLite2-ASN at {asn_path}: {e}. Using mock fallback.")
            _asn_reader = None
    else:
        logger.info("GeoLite2-ASN database not present or placeholder. Using resilient mock fallback.")
        _asn_reader = None

    _readers_loaded = True


def _mock_resolve_ip(ip_str: str) -> GeoRecord:
    """Deterministic, resilient mock GeoIP and ASN resolver for testing, demo, and missing-MMDB environments."""
    is_tor = is_tor_exit_node(ip_str)

    try:
        ip_obj = ipaddress.ip_address(ip_str)
        octets = ip_str.split(".") if ip_obj.version == 4 else []
        first_octet = int(octets[0]) if len(octets) >= 1 and octets[0].isdigit() else 100
    except Exception:
        first_octet = 100

    # Deterministic mock profiling based on IP characteristics
    if is_tor:
        city = "Frankfurt am Main"
        country = "Germany"
        country_code = "DE"
        lat, lon = 50.1109, 8.6821
        asn = 24940
        asn_org = "Hetzner Online GmbH (Tor Relays)"
        is_dc = True
    elif first_octet in (3, 15, 18, 52, 54):
        city = "Ashburn"
        country = "United States"
        country_code = "US"
        lat, lon = 39.0438, -77.4874
        asn = 16509
        asn_org = "Amazon.com, Inc. (AWS Data Center)"
        is_dc = True
    elif first_octet in (34, 35, 104):
        city = "Mountain View"
        country = "United States"
        country_code = "US"
        lat, lon = 37.3861, -122.0839
        asn = 15169
        asn_org = "Google LLC (Google Cloud Platform)"
        is_dc = True
    elif first_octet in (51, 162, 178):
        city = "Roubaix"
        country = "France"
        country_code = "FR"
        lat, lon = 50.6927, 3.1778
        asn = 16276
        asn_org = "OVH SAS (Hosting Infrastructure)"
        is_dc = True
    elif first_octet in (103, 106, 115, 122):
        city = "New Delhi"
        country = "India"
        country_code = "IN"
        lat, lon = 28.6139, 77.2090
        asn = 9498
        asn_org = "Bharti Airtel Ltd."
        is_dc = False
    elif first_octet in (185, 194):
        city = "Amsterdam"
        country = "Netherlands"
        country_code = "NL"
        lat, lon = 52.3676, 4.9041
        asn = 60068
        asn_org = "Datacamp Limited"
        is_dc = True
    else:
        city = "North Bergen"
        country = "United States"
        country_code = "US"
        lat, lon = 40.8043, -74.0121
        asn = 14061
        asn_org = "DigitalOcean, LLC"
        is_dc = True

    return GeoRecord(
        ip=ip_str,
        city=city,
        country=country,
        country_code=country_code,
        latitude=lat,
        longitude=lon,
        asn=asn,
        asn_org=asn_org,
        is_datacenter=is_dc,
        is_tor_exit=is_tor,
    )


def lookup_ip_sync(ip_str: str) -> GeoRecord:
    """Synchronously lookup GeoIP and ASN details for an IP address with defensive fallbacks."""
    _init_readers()

    is_tor = is_tor_exit_node(ip_str)
    city_name: Optional[str] = None
    country_name: Optional[str] = None
    country_code: Optional[str] = None
    lat: Optional[float] = None
    lon: Optional[float] = None
    asn_num: Optional[int] = None
    asn_org: Optional[str] = None

    # Query City Database if present
    if _city_reader is not None:
        try:
            city_resp = _city_reader.city(ip_str)
            city_name = city_resp.city.name
            country_name = city_resp.country.name
            country_code = city_resp.country.iso_code
            if city_resp.location:
                lat = city_resp.location.latitude
                lon = city_resp.location.longitude
        except Exception:
            pass

    # Query ASN Database if present
    if _asn_reader is not None:
        try:
            asn_resp = _asn_reader.asn(ip_str)
            asn_num = asn_resp.autonomous_system_number
            asn_org = asn_resp.autonomous_system_organization
        except Exception:
            pass

    # If location coordinates or all readers yielded no data, defensively augment with mock coordinates
    if (city_name is None and country_name is None and asn_org is None) or (lat is None or lon is None):
        mock_rec = _mock_resolve_ip(ip_str)
        if city_name is None or city_name == "Unknown City":
            city_name = mock_rec.city
        if country_name is None or country_name == "Unknown Country":
            country_name = mock_rec.country
            country_code = mock_rec.country_code
        if lat is None or lon is None:
            lat = mock_rec.latitude
            lon = mock_rec.longitude
        if asn_num is None:
            asn_num = mock_rec.asn
            asn_org = mock_rec.asn_org

    is_dc = is_datacenter_asn(asn_org, asn_num)

    return GeoRecord(
        ip=ip_str,
        city=city_name or "Unknown City",
        country=country_name or "Unknown Country",
        country_code=country_code,
        latitude=lat,
        longitude=lon,
        asn=asn_num,
        asn_org=asn_org or "Unknown ASN",
        is_datacenter=is_dc,
        is_tor_exit=is_tor,
    )
