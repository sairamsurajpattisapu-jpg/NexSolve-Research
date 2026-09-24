"""NexSolve Evidence & Provenance Command.

Displays cryptographic capture fingerprinting, verified protocol capabilities,
multi-signal evidence fusion (supporting vs contradictory), MITRE ATT&CK techniques,
and entity investigation dossiers.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from nexsolve.client.api import NexSolveClient
from nexsolve.config import DEFAULT_API_KEY, DEFAULT_API_URL
from nexsolve.errors import NexSolveError
from nexsolve.output.terminal import TerminalRenderer


def _load_or_fetch(target: str, client: NexSolveClient) -> dict[str, Any]:
    path = Path(target)
    if path.exists() and path.is_file():
        try:
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception as exc:
            raise NexSolveError(f"Failed to read local analysis file '{target}': {exc}")
    try:
        return client.get_results(target)
    except Exception as exc:
        raise NexSolveError(f"Failed to retrieve analysis for '{target}' from backend: {exc}")


def run_evidence(args: argparse.Namespace) -> int:
    """Execute evidence inspection."""
    use_color = not getattr(args, "no_color", False)
    term = TerminalRenderer(use_color=use_color)
    server_url = getattr(args, "server", DEFAULT_API_URL)
    api_key = getattr(args, "api_key", DEFAULT_API_KEY)

    client = NexSolveClient(base_url=server_url, api_key=api_key)
    data = _load_or_fetch(args.job_id, client)

    entity_filter = getattr(args, "entity", None)

    # Extract fingerprint
    fingerprint = data.get("fingerprint") or data.get("capture_fingerprint") or {}
    source = data.get("source") or {}
    sha256 = fingerprint.get("sha256") or source.get("sha256") or "N/A"

    # Extract evidence summary
    threat_assessment = data.get("threat_assessment") or {}
    evidence_items = threat_assessment.get("evidence") or []
    net_intel = data.get("network_intelligence") or {}
    ev_summary = net_intel.get("evidence_summary") or {}

    obs_techniques = ev_summary.get("observed_techniques") or threat_assessment.get("observed_techniques") or []
    fc_techniques = ev_summary.get("forecast_techniques") or threat_assessment.get("forecast_techniques") or []
    modalities = ev_summary.get("observed_modalities") or []

    # Entity investigations
    entity_investigations = data.get("entity_investigations") or {}
    prioritized_threats = data.get("prioritized_threats") or []

    if getattr(args, "json", False):
        out_payload = {
            "analysis_id": data.get("analysis_id", args.job_id),
            "fingerprint": fingerprint,
            "evidence_summary": ev_summary,
            "evidence_items": evidence_items,
            "entity_investigations": entity_investigations if not entity_filter else {entity_filter: entity_investigations.get(entity_filter)},
        }
        print(json.dumps(out_payload, indent=2))
        return 0

    print(f"\n{term.C_CYAN}{term.C_BOLD}=== NEXSOLVE EVIDENCE & CAPTURE PROVENANCE ==={term.C_RESET}\n")

    # 1. Cryptographic Fingerprint
    print(f"{term.C_BOLD}1. Cryptographic Capture Fingerprint:{term.C_RESET}")
    print(f"   SHA-256:       {term.C_WHITE}{sha256}{term.C_RESET}")
    fmt = fingerprint.get("format", data.get("upload", {}).get("format", "pcap"))
    link_type = fingerprint.get("link_type", "Ethernet")
    size_bytes = fingerprint.get("file_size_bytes", data.get("upload", {}).get("size_bytes", 0))
    print(f"   Format:        .{fmt} | Link Type: {link_type} | Size: {term.format_size(size_bytes)}")

    # Capabilities
    caps = fingerprint.get("capabilities") or {}
    if caps and caps.get("packet_count_sampled", 0) > 0:
        print(f"   Probed Protocols:")
        protocols = []
        if caps.get("has_ipv4"): protocols.append(f"IPv4 ({caps.get('ipv4_count', 0)})")
        if caps.get("has_ipv6"): protocols.append(f"IPv6 ({caps.get('ipv6_count', 0)})")
        if caps.get("has_tcp"): protocols.append(f"TCP ({caps.get('tcp_count', 0)})")
        if caps.get("has_udp"): protocols.append(f"UDP ({caps.get('udp_count', 0)})")
        if caps.get("has_icmp"): protocols.append(f"ICMP ({caps.get('icmp_count', 0)})")
        if caps.get("has_dns"): protocols.append("DNS")
        if caps.get("has_tls"): protocols.append("TLS")
        print(f"     {', '.join(protocols) if protocols else 'None detected'}")
        if caps.get("unique_dns_queries"):
            print(f"     Sample DNS Queries: {list(caps['unique_dns_queries'])[:5]}")
        if caps.get("unique_tls_sni"):
            print(f"     Sample TLS SNIs:    {list(caps['unique_tls_sni'])[:5]}")

    # 2. Multi-Signal Evidence Fusion
    print(f"\n{term.C_BOLD}2. Multi-Modal Evidence Fusion:{term.C_RESET}")
    print(f"   Total Evidence Items: {len(evidence_items)}")
    if modalities:
        print(f"   Observed Modalities:  {', '.join(modalities)}")
    if obs_techniques:
        print(f"   Observed ATT&CK IDs:  {term.C_YELLOW}{', '.join(obs_techniques)}{term.C_RESET}")
    if fc_techniques:
        print(f"   Forecast ATT&CK IDs:  {term.C_CYAN}{', '.join(fc_techniques)}{term.C_RESET}")

    # Supporting vs Contradictory evidence
    supporting = [e for e in evidence_items if e.get("polarity", "SUPPORTING") == "SUPPORTING"]
    contradictory = [e for e in evidence_items if e.get("polarity") == "CONTRADICTORY"]

    print(f"\n   {term.C_BOLD}Supporting Indicators ({len(supporting)}):{term.C_RESET}")
    for item in supporting[:5]:
        src = item.get("modality", "HEURISTIC")
        conf = item.get("confidence", 1.0)
        desc = item.get("description", item.get("summary", "Indicator observed"))
        print(f"     {term.C_GREEN}+{term.C_RESET} [{src}] ({conf:.2f} conf) {desc}")
    if len(supporting) > 5:
        print(f"     ... and {len(supporting) - 5} more items")

    if contradictory:
        print(f"\n   {term.C_BOLD}Contradictory / Disconfirming Signals ({len(contradictory)}):{term.C_RESET}")
        for item in contradictory[:5]:
            src = item.get("modality", "HEURISTIC")
            desc = item.get("description", item.get("summary", "Signal contradictory"))
            print(f"     {term.C_YELLOW}-{term.C_RESET} [{src}] {desc}")

    # 3. Entity Dossier / Prioritized Threats
    print(f"\n{term.C_BOLD}3. Entity Investigation Dossiers:{term.C_RESET}")
    if entity_filter:
        inv = entity_investigations.get(entity_filter)
        if inv:
            print(f"   Entity: {term.C_CYAN}{entity_filter}{term.C_RESET}")
            print(f"     Risk Score: {inv.get('risk_score', 'N/A')}")
            print(f"     Role:       {inv.get('role', 'N/A')}")
            findings = inv.get("findings", [])
            print(f"     Findings:   {len(findings)} events")
        else:
            print(f"   Entity '{entity_filter}' not found in active investigations.")
    elif prioritized_threats:
        print("   Top Prioritized Entities:")
        for t in prioritized_threats[:5]:
            ent = t.get("entity", "Unknown")
            pri = t.get("priority", "MEDIUM")
            score = t.get("score", 0.0)
            pri_color = term.C_RED if pri in ("CRITICAL", "HIGH") else term.C_YELLOW
            print(f"     * {term.C_WHITE}{ent:<20}{term.C_RESET} | Priority: {pri_color}{pri:<8}{term.C_RESET} | Score: {score:.1f}")
    else:
        print("   No distinct entity investigations available in this capture.")

    print()
    return 0
