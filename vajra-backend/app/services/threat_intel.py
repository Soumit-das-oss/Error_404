import logging
import re
from pathlib import Path
from typing import Set, Optional
from app.core.config import settings

logger = logging.getLogger("vajra.threat_intel")

# In-memory cached set of Tor exit node IPs
_TOR_EXIT_NODES: Set[str] = set()
_INITIALIZED: bool = False

# Known datacenter / hosting ASN organization keywords and regex patterns
DATACENTER_ASN_PATTERNS = [
    r"amazon",
    r"aws",
    r"ovh",
    r"digitalocean",
    r"hetzner",
    r"google\s*cloud",
    r"microsoft\s*azure",
    r"azure",
    r"linode",
    r"akamai",
    r"vultr",
    r"choopa",
    r"leaseweb",
    r"contabo",
    r"hostinger",
    r"cloudflare",
    r"fastly",
    r"oracle\s*cloud",
    r"alibaba",
    r"tencent",
    r"rackspace",
]

# Common Datacenter ASN Numbers
DATACENTER_ASN_NUMBERS = {
    16509,  # Amazon.com
    14618,  # Amazon.com
    16276,  # OVH SAS
    14061,  # DigitalOcean
    24940,  # Hetzner Online GmbH
    15169,  # Google LLC
    396982, # Google Cloud
    8075,   # Microsoft Corporation
    63949,  # Linode / Akamai
    20473,  # Choopa / Vultr
    60068,  # Datacamp
    51167,  # Contabo
    46606,  # Unified Layer
    26347,  # DreamHost
}


def load_tor_exit_nodes() -> Set[str]:
    """Load Tor exit node IP addresses from the designated text file into an in-memory set."""
    global _TOR_EXIT_NODES, _INITIALIZED
    tor_file = settings.get_absolute_path(settings.TOR_EXIT_NODES_PATH)
    exit_nodes: Set[str] = set()

    if tor_file.exists():
        try:
            with open(tor_file, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        exit_nodes.add(line)
            logger.info(f"Loaded {len(exit_nodes)} Tor exit node IPs into threat intelligence cache.")
        except Exception as e:
            logger.warning(f"Error loading Tor exit nodes file at {tor_file}: {e}")
    else:
        logger.warning(f"Tor exit nodes file not found at {tor_file}. Threat intel will operate with empty Tor cache.")

    _TOR_EXIT_NODES = exit_nodes
    _INITIALIZED = True
    return _TOR_EXIT_NODES


def is_tor_exit_node(ip: str) -> bool:
    """Check whether an IP address matches an active Tor exit node."""
    global _TOR_EXIT_NODES, _INITIALIZED
    if not _INITIALIZED:
        load_tor_exit_nodes()
    return ip.strip() in _TOR_EXIT_NODES


def is_datacenter_asn(asn_org: Optional[str], asn_number: Optional[int] = None) -> bool:
    """Check if the ASN organization or ASN number corresponds to a cloud/datacenter/hosting provider."""
    if asn_number and asn_number in DATACENTER_ASN_NUMBERS:
        return True

    if not asn_org:
        return False

    normalized_org = asn_org.lower()
    for pattern in DATACENTER_ASN_PATTERNS:
        if re.search(pattern, normalized_org):
            return True

    return False
