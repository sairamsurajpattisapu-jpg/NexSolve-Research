"""Canonical 15-Stage Attack Progression Taxonomy and MITRE Grounding.

Defines the enterprise attack lifecycle standard:
0. BENIGN
1. RECONNAISSANCE
2. RESOURCE_DEVELOPMENT
3. INITIAL_ACCESS
4. EXECUTION
5. PERSISTENCE
6. PRIVILEGE_ESCALATION
7. DEFENSE_EVASION
8. CREDENTIAL_ACCESS
9. DISCOVERY
10. LATERAL_MOVEMENT
11. COLLECTION
12. COMMAND_AND_CONTROL
13. EXFILTRATION
14. IMPACT
Plus: UNKNOWN

Guarantees:
- Stable machine-readable enum values (no display strings as internal keys).
- Explicit backward compatibility mapping with legacy 7-state taxonomy.
- Grounded in verified MITRE ATT&CK Enterprise tactics and techniques.
- Analytical lifecycle states that accommodate non-linear, skipped, repeated, or parallel attacker actions.
"""
from __future__ import annotations

from enum import Enum
import re
from typing import Any, Mapping, Sequence


class StageCategory(str, Enum):
    """Broad architectural category of the attack lifecycle."""
    BASELINE = "BASELINE"
    PRE_ATTACK = "PRE_ATTACK"
    INTRUSION = "INTRUSION"
    EXPANSION = "EXPANSION"
    OBJECTIVE = "OBJECTIVE"
    UNKNOWN = "UNKNOWN"


class StageClassification(str, Enum):
    """Evidentiary basis for the stage assignment."""
    OBSERVED = "OBSERVED"    # Directly supported by telemetry or verified dataset ground truth
    INFERRED = "INFERRED"    # Derived from multi-signal telemetry fusion & corroboration
    FORECAST = "FORECAST"    # Predicted by temporal world model or Markovian progression
    UNKNOWN = "UNKNOWN"      # Insufficient evidence or conflicting signals


class AttackStage(str, Enum):
    """Canonical 15-Stage Enterprise Attack Lifecycle + UNKNOWN."""
    BENIGN = "BENIGN"
    RECONNAISSANCE = "RECONNAISSANCE"
    RESOURCE_DEVELOPMENT = "RESOURCE_DEVELOPMENT"
    INITIAL_ACCESS = "INITIAL_ACCESS"
    EXECUTION = "EXECUTION"
    PERSISTENCE = "PERSISTENCE"
    PRIVILEGE_ESCALATION = "PRIVILEGE_ESCALATION"
    DEFENSE_EVASION = "DEFENSE_EVASION"
    CREDENTIAL_ACCESS = "CREDENTIAL_ACCESS"
    DISCOVERY = "DISCOVERY"
    LATERAL_MOVEMENT = "LATERAL_MOVEMENT"
    COLLECTION = "COLLECTION"
    COMMAND_AND_CONTROL = "COMMAND_AND_CONTROL"
    EXFILTRATION = "EXFILTRATION"
    IMPACT = "IMPACT"
    UNKNOWN = "UNKNOWN"

    @property
    def ordinal(self) -> int:
        """Deterministic integer ordinal for lifecycle sequence (0 to 14, -1 for UNKNOWN)."""
        _ORDINALS: dict[AttackStage, int] = {
            AttackStage.BENIGN: 0,
            AttackStage.RECONNAISSANCE: 1,
            AttackStage.RESOURCE_DEVELOPMENT: 2,
            AttackStage.INITIAL_ACCESS: 3,
            AttackStage.EXECUTION: 4,
            AttackStage.PERSISTENCE: 5,
            AttackStage.PRIVILEGE_ESCALATION: 6,
            AttackStage.DEFENSE_EVASION: 7,
            AttackStage.CREDENTIAL_ACCESS: 8,
            AttackStage.DISCOVERY: 9,
            AttackStage.LATERAL_MOVEMENT: 10,
            AttackStage.COLLECTION: 11,
            AttackStage.COMMAND_AND_CONTROL: 12,
            AttackStage.EXFILTRATION: 13,
            AttackStage.IMPACT: 14,
            AttackStage.UNKNOWN: -1,
        }
        return _ORDINALS.get(self, -1)

    @property
    def display_name(self) -> str:
        """Human-readable presentation label."""
        _NAMES: dict[AttackStage, str] = {
            AttackStage.BENIGN: "Benign Network Activity",
            AttackStage.RECONNAISSANCE: "Reconnaissance",
            AttackStage.RESOURCE_DEVELOPMENT: "Resource Development",
            AttackStage.INITIAL_ACCESS: "Initial Access",
            AttackStage.EXECUTION: "Execution",
            AttackStage.PERSISTENCE: "Persistence",
            AttackStage.PRIVILEGE_ESCALATION: "Privilege Escalation",
            AttackStage.DEFENSE_EVASION: "Defense Evasion",
            AttackStage.CREDENTIAL_ACCESS: "Credential Access",
            AttackStage.DISCOVERY: "Internal Discovery",
            AttackStage.LATERAL_MOVEMENT: "Lateral Movement",
            AttackStage.COLLECTION: "Data Collection",
            AttackStage.COMMAND_AND_CONTROL: "Command and Control",
            AttackStage.EXFILTRATION: "Exfiltration",
            AttackStage.IMPACT: "Impact / Service Disruption",
            AttackStage.UNKNOWN: "Unknown / Unresolved State",
        }
        return _NAMES.get(self, self.value)

    @property
    def description(self) -> str:
        """Analytical description of attacker objectives and observable telemetry."""
        _DESCRIPTIONS: dict[AttackStage, str] = {
            AttackStage.BENIGN: "Normal baseline enterprise traffic with balanced protocol distribution and stable volume.",
            AttackStage.RECONNAISSANCE: "Active or passive scanning, port sweeps, and endpoint enumeration.",
            AttackStage.RESOURCE_DEVELOPMENT: "Infrastructure preparation, domain acquisition, and staging servers.",
            AttackStage.INITIAL_ACCESS: "Exploitation of edge services, phishing delivery, or unauthorized entry vector.",
            AttackStage.EXECUTION: "Execution of adversary-controlled code or payloads on compromised endpoints.",
            AttackStage.PERSISTENCE: "Maintaining enduring access across reboots, credential rotation, or connection drops.",
            AttackStage.PRIVILEGE_ESCALATION: "Gaining higher-level permissions (e.g. SYSTEM, root, domain admin).",
            AttackStage.DEFENSE_EVASION: "Obfuscation, telemetry suppression, log purging, or masquerading.",
            AttackStage.CREDENTIAL_ACCESS: "Dumping passwords, brute-force attempts, ticket theft, or Kerberoasting.",
            AttackStage.DISCOVERY: "Internal network mapping, host discovery, and internal service exploration.",
            AttackStage.LATERAL_MOVEMENT: "Transiting between compromised internal hosts via remote protocols.",
            AttackStage.COLLECTION: "Gathering and staging targeted data, file aggregation, and sensitive asset capture.",
            AttackStage.COMMAND_AND_CONTROL: "Establishing interactive or beaconing communication channels with adversary servers.",
            AttackStage.EXFILTRATION: "Transmitting stolen data out of the enterprise perimeter.",
            AttackStage.IMPACT: "Disrupting availability, packet flooding, service outage, or data destruction.",
            AttackStage.UNKNOWN: "Telemetry is ambiguous, conflicted, or insufficient to substantiate a distinct stage.",
        }
        return _DESCRIPTIONS.get(self, "Undefined state")

    @property
    def category(self) -> StageCategory:
        """Lifecycle grouping category."""
        _CATEGORIES: dict[AttackStage, StageCategory] = {
            AttackStage.BENIGN: StageCategory.BASELINE,
            AttackStage.RECONNAISSANCE: StageCategory.PRE_ATTACK,
            AttackStage.RESOURCE_DEVELOPMENT: StageCategory.PRE_ATTACK,
            AttackStage.INITIAL_ACCESS: StageCategory.INTRUSION,
            AttackStage.EXECUTION: StageCategory.INTRUSION,
            AttackStage.PERSISTENCE: StageCategory.INTRUSION,
            AttackStage.PRIVILEGE_ESCALATION: StageCategory.INTRUSION,
            AttackStage.DEFENSE_EVASION: StageCategory.INTRUSION,
            AttackStage.CREDENTIAL_ACCESS: StageCategory.INTRUSION,
            AttackStage.DISCOVERY: StageCategory.EXPANSION,
            AttackStage.LATERAL_MOVEMENT: StageCategory.EXPANSION,
            AttackStage.COLLECTION: StageCategory.EXPANSION,
            AttackStage.COMMAND_AND_CONTROL: StageCategory.OBJECTIVE,
            AttackStage.EXFILTRATION: StageCategory.OBJECTIVE,
            AttackStage.IMPACT: StageCategory.OBJECTIVE,
            AttackStage.UNKNOWN: StageCategory.UNKNOWN,
        }
        return _CATEGORIES.get(self, StageCategory.UNKNOWN)

    @property
    def mitre_tactics(self) -> tuple[str, ...]:
        """Associated MITRE Enterprise ATT&CK Tactics."""
        _TACTICS: dict[AttackStage, tuple[str, ...]] = {
            AttackStage.BENIGN: (),
            AttackStage.RECONNAISSANCE: ("TA0043",),         # Reconnaissance
            AttackStage.RESOURCE_DEVELOPMENT: ("TA0042",),   # Resource Development
            AttackStage.INITIAL_ACCESS: ("TA0001",),         # Initial Access
            AttackStage.EXECUTION: ("TA0002",),              # Execution
            AttackStage.PERSISTENCE: ("TA0003",),            # Persistence
            AttackStage.PRIVILEGE_ESCALATION: ("TA0004",),   # Privilege Escalation
            AttackStage.DEFENSE_EVASION: ("TA0005",),        # Defense Evasion
            AttackStage.CREDENTIAL_ACCESS: ("TA0006",),      # Credential Access
            AttackStage.DISCOVERY: ("TA0007",),              # Discovery
            AttackStage.LATERAL_MOVEMENT: ("TA0008",),       # Lateral Movement
            AttackStage.COLLECTION: ("TA0009",),            # Collection
            AttackStage.COMMAND_AND_CONTROL: ("TA0011",),    # Command and Control
            AttackStage.EXFILTRATION: ("TA0010",),           # Exfiltration
            AttackStage.IMPACT: ("TA0040",),                 # Impact
            AttackStage.UNKNOWN: (),
        }
        return _TACTICS.get(self, ())


# Backward compatibility mapping between legacy 7-state model and canonical 15-stage model
LEGACY_TO_CANONICAL: dict[str, AttackStage] = {
    "BENIGN_OBSERVATION": AttackStage.BENIGN,
    "RECONNAISSANCE": AttackStage.RECONNAISSANCE,
    "EXPLOITATION": AttackStage.INITIAL_ACCESS,
    "COMMAND_AND_CONTROL": AttackStage.COMMAND_AND_CONTROL,
    "DENIAL_OF_SERVICE": AttackStage.IMPACT,
    "LATERAL_MOVEMENT": AttackStage.LATERAL_MOVEMENT,
    "EXFILTRATION": AttackStage.EXFILTRATION,
    "UNKNOWN_STATE": AttackStage.UNKNOWN,
    # Direct identity mapping for canonical names
    "BENIGN": AttackStage.BENIGN,
    "RESOURCE_DEVELOPMENT": AttackStage.RESOURCE_DEVELOPMENT,
    "INITIAL_ACCESS": AttackStage.INITIAL_ACCESS,
    "EXECUTION": AttackStage.EXECUTION,
    "PERSISTENCE": AttackStage.PERSISTENCE,
    "PRIVILEGE_ESCALATION": AttackStage.PRIVILEGE_ESCALATION,
    "DEFENSE_EVASION": AttackStage.DEFENSE_EVASION,
    "CREDENTIAL_ACCESS": AttackStage.CREDENTIAL_ACCESS,
    "DISCOVERY": AttackStage.DISCOVERY,
    "COLLECTION": AttackStage.COLLECTION,
    "IMPACT": AttackStage.IMPACT,
    "UNKNOWN": AttackStage.UNKNOWN,
}

CANONICAL_TO_LEGACY: dict[AttackStage, str] = {
    AttackStage.BENIGN: "BENIGN_OBSERVATION",
    AttackStage.RECONNAISSANCE: "RECONNAISSANCE",
    AttackStage.RESOURCE_DEVELOPMENT: "RECONNAISSANCE",
    AttackStage.INITIAL_ACCESS: "EXPLOITATION",
    AttackStage.EXECUTION: "EXPLOITATION",
    AttackStage.PERSISTENCE: "COMMAND_AND_CONTROL",
    AttackStage.PRIVILEGE_ESCALATION: "EXPLOITATION",
    AttackStage.DEFENSE_EVASION: "COMMAND_AND_CONTROL",
    AttackStage.CREDENTIAL_ACCESS: "EXPLOITATION",
    AttackStage.DISCOVERY: "RECONNAISSANCE",
    AttackStage.LATERAL_MOVEMENT: "LATERAL_MOVEMENT",
    AttackStage.COLLECTION: "EXFILTRATION",
    AttackStage.COMMAND_AND_CONTROL: "COMMAND_AND_CONTROL",
    AttackStage.EXFILTRATION: "EXFILTRATION",
    AttackStage.IMPACT: "DENIAL_OF_SERVICE",
    AttackStage.UNKNOWN: "UNKNOWN_STATE",
}


def to_canonical_stage(val: Any) -> AttackStage:
    """Safely map any stage representation (enum, string, legacy key) to canonical AttackStage."""
    if isinstance(val, AttackStage):
        return val
    if hasattr(val, "value"):
        val_str = str(val.value).strip().upper()
    else:
        val_str = str(val).strip().upper()

    return LEGACY_TO_CANONICAL.get(val_str, AttackStage.UNKNOWN)


def to_legacy_stage_name(stage: AttackStage | str) -> str:
    """Map canonical stage to legacy string identifier for backward compatibility."""
    canonical = to_canonical_stage(stage)
    return CANONICAL_TO_LEGACY.get(canonical, "UNKNOWN_STATE")


# Verified MITRE Enterprise ATT&CK Techniques Catalog
# Grounded in repository sensors, Zeek/Suricata signatures, and flow heuristics.
VERIFIED_MITRE_TECHNIQUES: dict[str, dict[str, Any]] = {
    "T1046": {
        "name": "Network Service Discovery",
        "tactic": "TA0043",
        "primary_stage": AttackStage.RECONNAISSANCE,
        "secondary_stage": AttackStage.DISCOVERY,
        "default_confidence": 0.85,
        "description": "Adversary scanning for listening services on remote hosts across IP subnets.",
    },
    "T1190": {
        "name": "Exploit Public-Facing Application",
        "tactic": "TA0001",
        "primary_stage": AttackStage.INITIAL_ACCESS,
        "secondary_stage": AttackStage.EXECUTION,
        "default_confidence": 0.80,
        "description": "Exploiting vulnerability in internet-facing web or network service.",
    },
    "T1071": {
        "name": "Application Layer Protocol",
        "tactic": "TA0011",
        "primary_stage": AttackStage.COMMAND_AND_CONTROL,
        "secondary_stage": AttackStage.EXFILTRATION,
        "default_confidence": 0.82,
        "description": "Communicating using application-layer protocols (HTTP, HTTPS, DNS) to mimic normal traffic.",
    },
    "T1498": {
        "name": "Network Denial of Service",
        "tactic": "TA0040",
        "primary_stage": AttackStage.IMPACT,
        "secondary_stage": AttackStage.UNKNOWN,
        "default_confidence": 0.90,
        "description": "Volumetric or protocol flooding to exhaust network or service availability.",
    },
    "T1021": {
        "name": "Remote Services",
        "tactic": "TA0008",
        "primary_stage": AttackStage.LATERAL_MOVEMENT,
        "secondary_stage": AttackStage.INITIAL_ACCESS,
        "default_confidence": 0.78,
        "description": "Logging into or executing commands on remote systems via SMB, RDP, or SSH.",
    },
    "T1041": {
        "name": "Exfiltration Over C2 Channel",
        "tactic": "TA0010",
        "primary_stage": AttackStage.EXFILTRATION,
        "secondary_stage": AttackStage.COMMAND_AND_CONTROL,
        "default_confidence": 0.85,
        "description": "Transmitting sensitive stolen data through an existing command and control channel.",
    },
    "T1059": {
        "name": "Command and Scripting Interpreter",
        "tactic": "TA0002",
        "primary_stage": AttackStage.EXECUTION,
        "secondary_stage": AttackStage.INITIAL_ACCESS,
        "default_confidence": 0.75,
        "description": "Abusing command and execution environments (PowerShell, Bash, Python).",
    },
    "T1078": {
        "name": "Valid Accounts",
        "tactic": "TA0001",
        "primary_stage": AttackStage.INITIAL_ACCESS,
        "secondary_stage": AttackStage.PERSISTENCE,
        "default_confidence": 0.70,
        "description": "Adversaries obtaining and abusing existing legitimate system or domain credentials.",
    },
    "T1110": {
        "name": "Brute Force",
        "tactic": "TA0006",
        "primary_stage": AttackStage.CREDENTIAL_ACCESS,
        "secondary_stage": AttackStage.INITIAL_ACCESS,
        "default_confidence": 0.88,
        "description": "Systematic repetitive password guessing or credential stuffing against authentication endpoints.",
    },
    "T1005": {
        "name": "Data from Local System",
        "tactic": "TA0009",
        "primary_stage": AttackStage.COLLECTION,
        "secondary_stage": AttackStage.DISCOVERY,
        "default_confidence": 0.72,
        "description": "Searching local host drives, databases, or file shares for sensitive information.",
    },
    "T1566": {
        "name": "Phishing",
        "tactic": "TA0001",
        "primary_stage": AttackStage.INITIAL_ACCESS,
        "secondary_stage": AttackStage.EXECUTION,
        "default_confidence": 0.80,
        "description": "Spearphishing attachment or link delivery to gain entry.",
    },
    "T1583": {
        "name": "Acquire Infrastructure",
        "tactic": "TA0042",
        "primary_stage": AttackStage.RESOURCE_DEVELOPMENT,
        "secondary_stage": AttackStage.RECONNAISSANCE,
        "default_confidence": 0.65,
        "description": "Purchasing, leasing, or compromising domains, DNS servers, or VPS infrastructure.",
    },
    "T1562": {
        "name": "Impair Defenses",
        "tactic": "TA0005",
        "primary_stage": AttackStage.DEFENSE_EVASION,
        "secondary_stage": AttackStage.EXECUTION,
        "default_confidence": 0.75,
        "description": "Tampering with security software, stopping logging services, or modifying firewall rules.",
    },
    "T1548": {
        "name": "Abuse Elevation Control Mechanism",
        "tactic": "TA0004",
        "primary_stage": AttackStage.PRIVILEGE_ESCALATION,
        "secondary_stage": AttackStage.DEFENSE_EVASION,
        "default_confidence": 0.76,
        "description": "Bypassing UAC, sudo configuration exploits, or token manipulation.",
    },
}

_MITRE_ID_REGEX = re.compile(r"^T\d{4}(\.\d{3})?$")


def validate_mitre_technique_id(technique_id: str | None) -> bool:
    """Validate that a technique string matches canonical MITRE ATT&CK syntax and is verified."""
    if not technique_id or not isinstance(technique_id, str):
        return False
    clean = technique_id.strip().upper()
    if not _MITRE_ID_REGEX.match(clean):
        return False
    return clean in VERIFIED_MITRE_TECHNIQUES
