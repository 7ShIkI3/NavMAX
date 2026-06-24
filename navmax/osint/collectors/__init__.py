"""
Collecteurs OSINT NavMAX.
"""

from .dns import DnsCollector, DnsRecord
from .whois import WhoisCollector, WhoisInfo
from .ssl import SslCollector, SslCertInfo
from .web import WebCollector, WebTechInfo

__all__ = [
    "DnsCollector", "DnsRecord",
    "WhoisCollector", "WhoisInfo",
    "SslCollector", "SslCertInfo",
    "WebCollector", "WebTechInfo",
]
