"""
Module Proxy — interception web (Burp Suite-like).

Fonctionnalités :
- Proxy HTTP/HTTPS MITM avec certificats auto-générés
- Interception : pause/modify/forward
- Repeater : rejouer des requêtes
- Scanner web : XSS, SQLi, path traversal, headers
- Fuzzer : injection paramétrique
"""

from .proxy_server import ProxyServer
from .interceptor import Interceptor, InterceptedFlow, FlowAction, FlowStatus
from .repeater import Repeater, RepeaterRequest, RepeaterResponse
from .scanner import WebScanner, Vulnerability
from .fuzzer import Fuzzer, FuzzResult, FuzzReport

__all__ = [
    "ProxyServer",
    "Interceptor",
    "InterceptedFlow",
    "FlowAction",
    "FlowStatus",
    "Repeater",
    "RepeaterRequest",
    "RepeaterResponse",
    "WebScanner",
    "Vulnerability",
    "Fuzzer",
    "FuzzResult",
    "FuzzReport",
]
