"""Native package for external/signature evidence normalization."""
from .suricata import (
    SuricataAlertRecord,
    SuricataEvidenceReport,
    parse_suricata_eve_json,
    build_suricata_evidence_items,
)

__all__ = [
    "SuricataAlertRecord",
    "SuricataEvidenceReport",
    "parse_suricata_eve_json",
    "build_suricata_evidence_items",
]
