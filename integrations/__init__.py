"""NexSolve Open-Source Integrations & Adapters Package."""
from .comparison import AnalysisComparisonReport, compare_analyses
from .nfstream_adapter import NFSTREAM_TO_NEXSOLVE_MAP, NFStreamAdapter
from .scapy_adapter import ScapyAdapter
from .suricata_adapter import SuricataAdapter
from .zeek_adapter import ZeekAdapter

__all__ = [
    "ScapyAdapter",
    "ZeekAdapter",
    "SuricataAdapter",
    "NFStreamAdapter",
    "NFSTREAM_TO_NEXSOLVE_MAP",
    "AnalysisComparisonReport",
    "compare_analyses",
]
