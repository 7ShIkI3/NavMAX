"""Module Web — fuzzing, injection SQL, et tests d'intrusion web.

Wrappers :
- sqlmap_wrapper : injection SQL automatisée
- ffuf_wrapper   : fuzzing HTTP ultra-rapide
"""

from .sqlmap_wrapper import (
    SqlmapResult,
    SqlmapStatus,
    SQLMapWrapper,
)
from .ffuf_wrapper import (
    FfufInput,
    FfufResult,
    FfufWrapper,
    FfufFilterOption,
)

__all__ = [
    # SQLMap
    "SqlmapResult",
    "SqlmapStatus",
    "SQLMapWrapper",
    # FFUF
    "FfufInput",
    "FfufResult",
    "FfufWrapper",
    "FfufFilterOption",
]
