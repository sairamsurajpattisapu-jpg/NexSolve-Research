"""Behavioral Intelligence package for NexSolve."""
from .beaconing import (
    BeaconingSignal,
    DnsEntropySignal,
    BehavioralIntelligenceReport,
    compute_shannon_entropy,
    analyze_beaconing,
    analyze_dns_tunneling,
    analyze_behavioral_intelligence,
)

__all__ = [
    "BeaconingSignal",
    "DnsEntropySignal",
    "BehavioralIntelligenceReport",
    "compute_shannon_entropy",
    "analyze_beaconing",
    "analyze_dns_tunneling",
    "analyze_behavioral_intelligence",
]
