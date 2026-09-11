"""Audit of canonical 46 features across UNSW-NB15, TON-IoT, and Production PCAP.

No silent zero filling. Explicit availability, source, derivation, and production-compatibility tracking.
"""
from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from nexsolve_core.state import FLOW_NAMES, PACKET_NAMES, TEMPORAL_NAMES, feature_registry

ROOT = Path(__file__).resolve().parents[2]


@dataclass(frozen=True)
class FeatureSemanticsAudit:
    group: str
    feature_name: str
    full_name: str
    unsw_availability: str
    unsw_source: str
    toniot_availability: str
    toniot_source: str
    derivation_rule: str
    units: str
    reliability: str
    production_pcap_availability: str
    production_compatible: bool

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def audit_feature_semantics() -> dict[str, Any]:
    registry = feature_registry()
    audits: list[FeatureSemanticsAudit] = []

    # Mapping of which flow features TON-IoT actually supports
    ton_supported_flows = {
        "flow_count": ("AVAILABLE", "row count in window (ts // 60)", "count active flows"),
        "total_src_bytes": ("AVAILABLE", "sum(src_bytes)", "sum of source bytes in window"),
        "total_dst_bytes": ("AVAILABLE", "sum(dst_bytes)", "sum of destination bytes in window"),
        "total_packets": ("AVAILABLE", "sum(src_pkts + dst_pkts)", "sum of packets in window"),
        "mean_duration": ("AVAILABLE", "mean(duration)", "mean flow duration in window"),
        "mean_flow_bytes": ("AVAILABLE", "mean(src_bytes + dst_bytes)", "mean bytes per flow"),
        "mean_flow_packets": ("AVAILABLE", "mean(src_pkts + dst_pkts)", "mean packets per flow"),
        "unique_src_ports": ("AVAILABLE", "cardinality(src_port)", "distinct source ports"),
        "unique_dst_ports": ("AVAILABLE", "cardinality(dst_port)", "distinct destination ports"),
        "proto_tcp_count": ("AVAILABLE", "count(proto == 'tcp')", "count TCP flows"),
        "proto_udp_count": ("AVAILABLE", "count(proto == 'udp')", "count UDP flows"),
        "proto_other_count": ("AVAILABLE", "count(proto not in ('tcp', 'udp'))", "count other proto flows"),
    }

    ton_unsupported_flows = {
        "mean_sttl": ("UNAVAILABLE", "not recorded in TON-IoT Network_dataset_23 CSV", "source TTL absent"),
        "mean_dttl": ("UNAVAILABLE", "not recorded in TON-IoT Network_dataset_23 CSV", "destination TTL absent"),
        "mean_swin": ("UNAVAILABLE", "not recorded in TON-IoT Network_dataset_23 CSV", "source TCP window absent"),
        "mean_dwin": ("UNAVAILABLE", "not recorded in TON-IoT Network_dataset_23 CSV", "destination TCP window absent"),
        "mean_iat": ("UNAVAILABLE", "flow inter-arrival time absent in TON-IoT CSV", "inter-arrival absent"),
        "mean_tcp_rtt": ("UNAVAILABLE", "TCP RTT absent in TON-IoT CSV", "round-trip time absent"),
    }

    for name in FLOW_NAMES:
        key = f"flow_features.{name}"
        spec = registry[key]
        pcap_avail = spec.availability.value
        prod_compat = pcap_avail in ("PCAP", "CANONICAL_FLOW", "TEMPORAL")

        if name in ton_supported_flows:
            t_avail, t_src, t_der = ton_supported_flows[name]
        else:
            t_avail, t_src, t_der = ton_unsupported_flows[name]

        u_avail = "AVAILABLE" if name != "mean_tcp_rtt" or True else "UNAVAILABLE" # UNSW raw has tcprtt in col 32
        u_src = "UNSW raw CSV col 1..46"
        
        audits.append(FeatureSemanticsAudit(
            group="flow_features",
            feature_name=name,
            full_name=key,
            unsw_availability="AVAILABLE",
            unsw_source=u_src,
            toniot_availability=t_avail,
            toniot_source=t_src,
            derivation_rule=spec.computation,
            units=spec.units,
            reliability="HIGH" if t_avail == "AVAILABLE" else "UNAVAILABLE",
            production_pcap_availability=pcap_avail,
            production_compatible=prod_compat,
        ))

    for name in PACKET_NAMES:
        key = f"packet_features.{name}"
        spec = registry[key]
        pcap_avail = spec.availability.value
        prod_compat = pcap_avail in ("PCAP", "CANONICAL_FLOW", "TEMPORAL")

        # In raw flow CSVs (both UNSW and TON-IoT), raw packet-level packet_features are placeholders/unavailable
        audits.append(FeatureSemanticsAudit(
            group="packet_features",
            feature_name=name,
            full_name=key,
            unsw_availability="UNAVAILABLE",
            unsw_source="flow CSV only; packet features require raw PCAP",
            toniot_availability="UNAVAILABLE",
            toniot_source="flow CSV only; packet features require raw PCAP",
            derivation_rule=spec.computation,
            units=spec.units,
            reliability="UNAVAILABLE",
            production_pcap_availability=pcap_avail,
            production_compatible=prod_compat,
        ))

    ton_temporal_supported = {
        "delta_flow_count": ("AVAILABLE", "current_flow_count - prev_flow_count"),
        "delta_total_bytes": ("AVAILABLE", "current_total_bytes - prev_total_bytes"),
        "delta_total_packets": ("AVAILABLE", "current_total_packets - prev_total_packets"),
        "delta_ports": ("AVAILABLE", "current_ports - prev_ports"),
        "rolling_total_bytes": ("AVAILABLE", "mean(last 4 windows total_bytes)"),
    }
    ton_temporal_unsupported = {
        "delta_iat": ("UNAVAILABLE", "mean_iat is unavailable in TON-IoT; delta_iat cannot be computed honestly"),
    }

    for name in TEMPORAL_NAMES:
        key = f"temporal_features.{name}"
        spec = registry[key]
        pcap_avail = spec.availability.value
        prod_compat = pcap_avail in ("PCAP", "CANONICAL_FLOW", "TEMPORAL")

        if name in ton_temporal_supported:
            t_avail, t_src = ton_temporal_supported[name]
        else:
            t_avail, t_src = ton_temporal_unsupported[name]

        audits.append(FeatureSemanticsAudit(
            group="temporal_features",
            feature_name=name,
            full_name=key,
            unsw_availability="AVAILABLE",
            unsw_source="NetworkState temporal delta",
            toniot_availability=t_avail,
            toniot_source=t_src,
            derivation_rule=spec.computation,
            units=spec.units,
            reliability="HIGH" if t_avail == "AVAILABLE" else "UNAVAILABLE",
            production_pcap_availability=pcap_avail,
            production_compatible=prod_compat,
        ))

    # Shared feature subset (features honestly available across BOTH UNSW-NB15 and TON-IoT)
    shared_flow = [a.feature_name for a in audits if a.group == "flow_features" and a.unsw_availability == "AVAILABLE" and a.toniot_availability == "AVAILABLE"]
    shared_temporal = [a.feature_name for a in audits if a.group == "temporal_features" and a.unsw_availability == "AVAILABLE" and a.toniot_availability == "AVAILABLE"]
    shared_features = shared_flow + shared_temporal

    # Production PCAP compatible features
    prod_compatible_flow = [a.feature_name for a in audits if a.group == "flow_features" and a.production_compatible]
    prod_compatible_packet = [a.feature_name for a in audits if a.group == "packet_features" and a.production_compatible]
    prod_compatible_temporal = [a.feature_name for a in audits if a.group == "temporal_features" and a.production_compatible]

    return {
        "canonical_total_features": len(audits),
        "unsw_available_features_count": sum(a.unsw_availability == "AVAILABLE" for a in audits),
        "toniot_available_features_count": sum(a.toniot_availability == "AVAILABLE" for a in audits),
        "production_pcap_available_count": sum(a.production_compatible for a in audits),
        "shared_research_features": {
            "flow_features": shared_flow,
            "temporal_features": shared_temporal,
            "total_shared_count": len(shared_features),
        },
        "production_pcap_compatible_features": {
            "flow_features": prod_compatible_flow,
            "packet_features": prod_compatible_packet,
            "temporal_features": prod_compatible_temporal,
            "total_prod_count": len(prod_compatible_flow) + len(prod_compatible_packet) + len(prod_compatible_temporal),
        },
        "feature_details": [a.to_dict() for a in audits],
        "zero_fabrication_policy": (
            "No feature marked UNAVAILABLE may be filled with numeric 0.0 to fake presence. "
            "Research models must explicitly declare their feature subset, and compatibility gates "
            "must reject sequences when required features are absent."
        ),
    }


def write_feature_compatibility_report(data: dict[str, Any] | None = None) -> None:
    report = data or audit_feature_semantics()
    rep_dir = ROOT / "reports"
    rep_dir.mkdir(parents=True, exist_ok=True)

    (rep_dir / "phase5_feature_compatibility.json").write_text(json.dumps(report, indent=2), encoding="utf-8")

    lines = [
        "# Phase 5 Feature Semantics and Compatibility Report",
        "",
        "## Summary",
        f"- **Canonical Specification Features:** {report['canonical_total_features']}",
        f"- **UNSW-NB15 Available Features:** {report['unsw_available_features_count']} (18 flow, 6 temporal; 22 packet placeholders are UNAVAILABLE in flow CSV)",
        f"- **TON-IoT Available Features:** {report['toniot_available_features_count']} (12 flow, 5 temporal; 6 flow features, 1 temporal, and 22 packet features are UNAVAILABLE)",
        f"- **Shared Non-Fabricated Feature Subset:** {report['shared_research_features']['total_shared_count']} features ({len(report['shared_research_features']['flow_features'])} flow, {len(report['shared_research_features']['temporal_features'])} temporal)",
        f"- **Production PCAP Compatible Features:** {report['production_pcap_compatible_features']['total_prod_count']} / 46 (mean_tcp_rtt is UNAVAILABLE in packet contract)",
        "",
        "## Zero-Fabrication Policy",
        "> [!IMPORTANT]",
        "> Numerical 0.0 is a legitimate measurement (e.g., 0 bytes or 0 retransmissions) and must NOT be used to represent missing/unsupported fields.",
        "> Models operating on TON-IoT must use the shared 17-feature subset or declare their explicit feature list.",
        "",
        "## Feature Availability Table",
        "| Feature | Group | UNSW Availability | TON-IoT Availability | Production PCAP Availability | Production Compatible |",
        "|---|---|---|---|---|---|",
    ]
    for item in report["feature_details"]:
        lines.append(f"| `{item['feature_name']}` | {item['group']} | **{item['unsw_availability']}** | **{item['toniot_availability']}** | **{item['production_pcap_availability']}** | {'Yes' if item['production_compatible'] else 'No'} |")

    (rep_dir / "phase5_feature_compatibility.md").write_text("\n".join(lines) + "\n", encoding="utf-8")


if __name__ == "__main__":
    report = audit_feature_semantics()
    write_feature_compatibility_report(report)
    print("Feature semantics audit written. Shared features:", report["shared_research_features"]["total_shared_count"])
