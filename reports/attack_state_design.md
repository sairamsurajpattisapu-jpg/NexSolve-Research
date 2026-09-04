# Attack State Design

Run timestamp (UTC): `2026-09-03T10:49:46+00:00`

## Mapping

```json
{
  "BENIGN": {
    "raw_labels": [
      "0",
      "normal",
      "<missing>"
    ],
    "mitre_status": "unmapped"
  },
  "ATTACK": {
    "raw_labels": "Any non-benign observed attack category",
    "mitre_status": "unmapped"
  }
}
```

## Principle

Observed dataset labels, NexSolve security states, and ATT&CK techniques remain separate; no automatic label-to-technique mapping is asserted.

## Unsupported States

```json
[
  "INITIAL_ACCESS",
  "EXECUTION",
  "PERSISTENCE",
  "PRIVILEGE_ESCALATION",
  "CREDENTIAL_ACCESS",
  "DISCOVERY",
  "LATERAL_MOVEMENT",
  "COMMAND_AND_CONTROL",
  "EXFILTRATION",
  "IMPACT"
]
```

## Reason

The available datasets do not directly observe MITRE lifecycle stages; any future mapping must be evidence-based and marked uncertain when unsupported.
