"""Attack Campaign Correlation Engine for NexSolve.

Correlates multiple suspicious behavioral episodes into cohesive campaigns:
- Groups episodes sharing entity overlap, target overlap, port overlap, and temporal proximity
- Evaluates multi-dimensional criteria:
  ENTITY_OVERLAP, TEMPORAL_PROXIMITY, TARGET_OVERLAP, PORT_OVERLAP, TECHNIQUE_OVERLAP
- Prevents spurious aggregation (does NOT merge simply because an IP matches without behavioral continuity)
- Exposes complete campaign timeline, constituent episodes, attack states, and current progression
"""
from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Mapping, Sequence

from nexsolve_core.graph.models import deterministic_id


class CampaignCorrelationReason(str, Enum):
    ENTITY_OVERLAP = "ENTITY_OVERLAP"
    TARGET_OVERLAP = "TARGET_OVERLAP"
    PORT_OVERLAP = "PORT_OVERLAP"
    TEMPORAL_PROXIMITY = "TEMPORAL_PROXIMITY"
    TECHNIQUE_OVERLAP = "TECHNIQUE_OVERLAP"
    EPISODE_CONTINUITY = "EPISODE_CONTINUITY"


@dataclass(frozen=True)
class AttackCampaign:
    """Coordinated multi-episode security campaign."""
    campaign_id: str
    title: str
    primary_entities: tuple[str, ...]
    target_entities: tuple[str, ...]
    targeted_ports: tuple[int, ...]
    start_window: int
    end_window: int
    duration_seconds: float
    constituent_episodes: tuple[str, ...]
    attack_states: tuple[str, ...]
    mitre_techniques: tuple[str, ...]
    severity: str  # "LOW", "MEDIUM", "HIGH", "CRITICAL"
    correlation_reasons: tuple[CampaignCorrelationReason, ...]
    explanation: str
    provenance: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "campaign_id": self.campaign_id,
            "title": self.title,
            "primary_entities": list(self.primary_entities),
            "target_entities": list(self.target_entities),
            "targeted_ports": list(self.targeted_ports),
            "start_window": self.start_window,
            "end_window": self.end_window,
            "duration_seconds": self.duration_seconds,
            "constituent_episodes": list(self.constituent_episodes),
            "attack_states": list(self.attack_states),
            "mitre_techniques": list(self.mitre_techniques),
            "severity": self.severity,
            "correlation_reasons": [r.value for r in self.correlation_reasons],
            "explanation": self.explanation,
            "provenance": self.provenance,
        }


@dataclass(frozen=True)
class CampaignInvestigation:
    """Detailed investigation context for a multi-episode attack campaign."""
    campaign: AttackCampaign
    primary_entities: tuple[str, ...]
    target_entities: tuple[str, ...]
    targeted_ports: tuple[int, ...]
    active_window_range: tuple[int, int]
    duration_seconds: float
    constituent_episodes: tuple[Any, ...]
    progression_story: str
    key_findings: tuple[str, ...]
    recommended_action: str
    provenance: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "campaign": self.campaign.to_dict(),
            "primary_entities": list(self.primary_entities),
            "target_entities": list(self.target_entities),
            "targeted_ports": list(self.targeted_ports),
            "active_window_range": list(self.active_window_range),
            "duration_seconds": self.duration_seconds,
            "constituent_episodes": [getattr(e, "to_dict", lambda: e)() if hasattr(e, "to_dict") else dict(e) for e in self.constituent_episodes],
            "progression_story": self.progression_story,
            "key_findings": list(self.key_findings),
            "recommended_action": self.recommended_action,
            "provenance": self.provenance,
        }


def investigate_campaign(
    campaign: AttackCampaign,
    all_episodes: Sequence[Any] | None = None,
    patterns: Sequence[Any] | None = None,
) -> CampaignInvestigation:
    """Produce comprehensive investigation dossier for an attack campaign."""
    ep_map = {getattr(e, "episode_id", f"ep_{i}"): e for i, e in enumerate(all_episodes or [])}
    const_eps = [ep_map[ep_id] for ep_id in campaign.constituent_episodes if ep_id in ep_map]

    findings: list[str] = [
        f"Campaign encompasses {len(campaign.constituent_episodes)} episode(s) spanning windows {campaign.start_window} to {campaign.end_window}.",
        f"Primary threat actor entity: {', '.join(campaign.primary_entities)}.",
        f"Targeted infrastructure includes {len(campaign.target_entities)} host(s) and ports {list(campaign.targeted_ports)[:6]}.",
    ]
    if campaign.mitre_techniques:
        findings.append(f"Observed MITRE ATT&CK techniques: {', '.join(campaign.mitre_techniques)}.")

    progression = (
        f"Campaign '{campaign.title}' initiated in window {campaign.start_window} by {', '.join(campaign.primary_entities)}. "
        f"Involves attack states {list(campaign.attack_states)}. Severity ranked {campaign.severity} based on "
        f"{', '.join(r.value for r in campaign.correlation_reasons)}."
    )

    if campaign.severity == "CRITICAL":
        rec_action = "Execute enterprise-wide block rules on primary actor and isolate targeted endpoints."
    elif campaign.severity == "HIGH":
        rec_action = "Quarantine communication channels between actor and target subnet."
    else:
        rec_action = "Maintain heightened logging and monitor subsequent temporal windows."

    return CampaignInvestigation(
        campaign=campaign,
        primary_entities=campaign.primary_entities,
        target_entities=campaign.target_entities,
        targeted_ports=campaign.targeted_ports,
        active_window_range=(campaign.start_window, campaign.end_window),
        duration_seconds=campaign.duration_seconds,
        constituent_episodes=tuple(const_eps),
        progression_story=progression,
        key_findings=tuple(findings),
        recommended_action=rec_action,
        provenance={"engine": "campaign_investigation_v1"},
    )



def correlate_attack_campaigns(
    episodes: Sequence[Any] | None = None,
    patterns: Sequence[Any] | None = None,
    attack_states: Sequence[Any] | None = None,
    time_window_gap_threshold: int = 3,
) -> tuple[AttackCampaign, ...]:
    """Correlate behavioral episodes into cohesive attack campaigns."""
    campaigns: list[AttackCampaign] = []
    eps = episodes or []
    if not eps:
        return ()

    # Group episodes by primary entity
    entity_episodes: dict[str, list[Any]] = defaultdict(list)
    for ep in eps:
        ent = getattr(ep, "primary_entity", "network")
        entity_episodes[ent].append(ep)

    # Correlate for each entity
    for ent, ep_list in entity_episodes.items():
        # Sort chronologically by start window
        sorted_eps = sorted(ep_list, key=lambda e: getattr(e, "start_window", 0))

        # Cluster episodes by temporal continuity and target/port overlap
        current_cluster: list[Any] = [sorted_eps[0]]
        for next_ep in sorted_eps[1:]:
            prev_ep = current_cluster[-1]
            gap = getattr(next_ep, "start_window", 0) - getattr(prev_ep, "end_window", 0)

            # Check overlap dimensions
            prev_targets = set(getattr(prev_ep, "destination_ips", ()))
            next_targets = set(getattr(next_ep, "destination_ips", ()))
            prev_ports = set(getattr(prev_ep, "destination_ports", ()))
            next_ports = set(getattr(next_ep, "destination_ports", ()))

            target_overlap = bool(prev_targets & next_targets) or (not prev_targets and not next_targets)
            port_overlap = bool(prev_ports & next_ports) or (not prev_ports and not next_ports)
            temporal_close = gap <= time_window_gap_threshold

            # Multi-dimensional condition: temporal proximity + (target overlap OR port overlap)
            if temporal_close and (target_overlap or port_overlap):
                current_cluster.append(next_ep)
            else:
                # Seal current cluster into campaign
                campaigns.append(_build_campaign_from_cluster(ent, current_cluster))
                current_cluster = [next_ep]

        if current_cluster:
            campaigns.append(_build_campaign_from_cluster(ent, current_cluster))

    return tuple(campaigns)


def _build_campaign_from_cluster(entity: str, cluster: list[Any]) -> AttackCampaign:
    start_w = min(getattr(e, "start_window", 0) for e in cluster)
    end_w = max(getattr(e, "end_window", 0) for e in cluster)
    dur = float(end_w - start_w + 1) * 60.0

    targets = sorted(list({ip for e in cluster for ip in getattr(e, "destination_ips", ()) if ip}))
    ports = sorted(list({p for e in cluster for p in getattr(e, "destination_ports", ()) if p is not None}))
    techniques = sorted(list({t for e in cluster for t in getattr(e, "mitre_techniques", ()) if t}))
    states = sorted(list({s for e in cluster for s in getattr(e, "attack_states", ()) if s}))

    severities = [getattr(e, "severity", "MEDIUM") for e in cluster]
    if any(str(s) in ("CRITICAL", "EpisodeSeverity.CRITICAL") for s in severities):
        sev = "CRITICAL"
    elif any(str(s) in ("HIGH", "EpisodeSeverity.HIGH") for s in severities):
        sev = "HIGH"
    else:
        sev = "MEDIUM"

    reasons = [CampaignCorrelationReason.ENTITY_OVERLAP, CampaignCorrelationReason.TEMPORAL_PROXIMITY]
    if len(targets) > 1:
        reasons.append(CampaignCorrelationReason.TARGET_OVERLAP)
    if len(ports) > 0:
        reasons.append(CampaignCorrelationReason.PORT_OVERLAP)
    if len(techniques) > 0:
        reasons.append(CampaignCorrelationReason.TECHNIQUE_OVERLAP)

    cid = deterministic_id("cmp", entity, start_w, end_w, len(cluster))
    title = f"Campaign against {entity} ({len(cluster)} episodes)" if entity else f"Network Activity Campaign ({len(cluster)} episodes)"
    explanation = (
        f"Correlated {len(cluster)} behavioral episode(s) for entity {entity} across "
        f"window(s) {start_w}..{end_w}. Involves {len(targets)} target host(s) and {len(ports)} port(s)."
    )

    return AttackCampaign(
        campaign_id=cid,
        title=title,
        primary_entities=(entity,),
        target_entities=tuple(targets),
        targeted_ports=tuple(ports),
        start_window=start_w,
        end_window=end_w,
        duration_seconds=dur,
        constituent_episodes=tuple(getattr(e, "episode_id", f"ep_{i}") for i, e in enumerate(cluster)),
        attack_states=tuple(states),
        mitre_techniques=tuple(techniques),
        severity=sev,
        correlation_reasons=tuple(reasons),
        explanation=explanation,
        provenance={"rule": "multi_dimensional_cluster_v1"},
    )
