"""Traffic analysis enums."""

from enum import Enum


class TrafficDirection(Enum):
    """Network traffic direction."""
    INBOUND = "inbound"
    OUTBOUND = "outbound"
    BIDIRECTIONAL = "bidirectional"


class ExfiltrationMethod(Enum):
    """Data exfiltration methods."""
    DNS = "dns"
    HTTP = "http"
    HTTPS = "https"
    ICMP = "icmp"
    EMAIL = "email"
    FTP = "ftp"
    CUSTOM_PROTOCOL = "custom"