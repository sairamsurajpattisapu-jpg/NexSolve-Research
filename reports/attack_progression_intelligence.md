# Attack Progression Intelligence

Research-only interpretation layer over the existing NexSolve World Model. It does not modify model weights or claim ATT&CK ground truth.

## Architecture

The engine composes the existing `NetworkState`, recursive T+1 through T+5 forecast, flow features, existing ablation explanation, and local MITRE ATT&CK STIX data. MODEL PREDICTION is distinct from CONTEXTUAL SECURITY INTERPRETATION.

## Stage Taxonomy

BENIGN, RECONNAISSANCE, INITIAL_ACCESS, EXECUTION, PERSISTENCE, PRIVILEGE_ESCALATION, DEFENSE_EVASION, CREDENTIAL_ACCESS, DISCOVERY, LATERAL_MOVEMENT, COMMAND_AND_CONTROL, EXFILTRATION, IMPACT, UNKNOWN

All inferred stages are `CONTEXTUAL_HYPOTHESIS`. Dataset labels do not establish ATT&CK stages.

## Rules And Thresholds

```json
{
  "rules": {
    "port_scan_like": "unique_dst_ports >= 10 OR unique_dst_ports / flow_count >= 0.50; mean_duration <= 1,000,000 microseconds adds supporting evidence when present",
    "stage": "Only the supported PORT_SCAN_LIKE_ACTIVITY signal maps to a RECONNAISSANCE contextual hypothesis.",
    "labels": "attack_state and observed labels are never read by inference."
  },
  "thresholds": {
    "low_probability": 0.35,
    "high_probability": 0.65,
    "rising_delta": 0.1,
    "rapid_rising_delta": 0.25,
    "uncertainty_margin": 0.1
  }
}
```

## ATT&CK Methodology

T1046 is emitted only after lookup in the local STIX bundle and is marked contextual. Observed context uses `CONTEXTUAL_TECHNIQUE`; predicted behavior uses `FORECAST_CONTEXT`. Invalid or unsupported IDs produce no technique.

## Current-State And Forecast Output

```json
{
  "current_state": {
    "status": "OBSERVATION",
    "attack_probability": null,
    "risk_trend": "INSUFFICIENT_EVIDENCE",
    "stage": {
      "stage": "RECONNAISSANCE",
      "confidence": 0.8645803698435278,
      "status": "CONTEXTUAL_HYPOTHESIS",
      "evidence": [
        {
          "feature": "unique_dst_ports",
          "direction": "elevated_destination_port_diversity",
          "contribution": "supports",
          "value": 372.0,
          "evidence_source": "observed_flow_aggregate"
        },
        {
          "feature": "flow_count",
          "direction": "fan_out_context",
          "contribution": "supports",
          "value": 1406.0,
          "evidence_source": "observed_flow_aggregate"
        },
        {
          "feature": "mean_duration",
          "direction": "short_flow_context",
          "contribution": "supports",
          "value": 0.8324366564722616,
          "evidence_source": "observed_flow_aggregate"
        }
      ],
      "evidence_source": "observed_flow_aggregate",
      "behavioral_signal": "PORT_SCAN_LIKE_ACTIVITY",
      "techniques": [
        {
          "technique_id": "T1046",
          "technique_name": "Network Service Discovery",
          "tactics": [
            "discovery"
          ],
          "description": "Adversaries may attempt to get a listing of services running on remote hosts and local network infrastructure devices, including those that may be vulnerable to remote software exploitation. Common methods to acquire this information include port, vulnerability, and/or wordlist scans using tools that are brought onto a system.(Citation: CISA AR21-126A FIVEHANDS May 2021)   \n\nWithin cloud environments, adversaries may attempt to discover services running on other cloud hosts. Additionally, if the cloud environment is connected to a on-premises environment, adversaries may be able to identify services running on non-cloud systems as well.\n\nWithin macOS environments, adversaries may use the native Bonjour application to discover services running on other macOS hosts within a network. The Bonjour mDNSResponder daemon automatically registers and advertises a host\u2019s registered services on the network. For example, adversaries can use a mDNS query (such as <code>dns-sd -B _ssh._tcp .</code>) to find other systems broadcasting the ssh service.(Citation: apple doco bonjour description)(Citation: macOS APT Activity Bradley)",
          "reference": "https://attack.mitre.org/techniques/T1046",
          "status": "CONTEXTUAL_TECHNIQUE",
          "confidence": 0.8645803698435278
        }
      ]
    }
  },
  "forecast": [
    {
      "horizon": 1,
      "window_offset_seconds": 60,
      "attack_probability": 0.9836163642615755,
      "probability_delta": null,
      "trend": "STABLE_HIGH",
      "confidence": 0.967232728523151,
      "uncertainty": 0.03276727147684899,
      "stage": {
        "stage": "RECONNAISSANCE",
        "confidence": 0.8781255578354172,
        "status": "CONTEXTUAL_HYPOTHESIS",
        "evidence": [
          {
            "feature": "unique_dst_ports",
            "direction": "elevated_destination_port_diversity",
            "contribution": "supports",
            "value": 492.3860384301621,
            "evidence_source": "observed_flow_aggregate"
          },
          {
            "feature": "flow_count",
            "direction": "fan_out_context",
            "contribution": "supports",
            "value": 1770.3732165511203,
            "evidence_source": "observed_flow_aggregate"
          },
          {
            "feature": "mean_duration",
            "direction": "short_flow_context",
            "contribution": "supports",
            "value": 0.5680369568338475,
            "evidence_source": "observed_flow_aggregate"
          }
        ],
        "evidence_source": "predicted_flow_state",
        "behavioral_signal": "PORT_SCAN_LIKE_ACTIVITY",
        "techniques": [
          {
            "technique_id": "T1046",
            "technique_name": "Network Service Discovery",
            "tactics": [
              "discovery"
            ],
            "description": "Adversaries may attempt to get a listing of services running on remote hosts and local network infrastructure devices, including those that may be vulnerable to remote software exploitation. Common methods to acquire this information include port, vulnerability, and/or wordlist scans using tools that are brought onto a system.(Citation: CISA AR21-126A FIVEHANDS May 2021)   \n\nWithin cloud environments, adversaries may attempt to discover services running on other cloud hosts. Additionally, if the cloud environment is connected to a on-premises environment, adversaries may be able to identify services running on non-cloud systems as well.\n\nWithin macOS environments, adversaries may use the native Bonjour application to discover services running on other macOS hosts within a network. The Bonjour mDNSResponder daemon automatically registers and advertises a host\u2019s registered services on the network. For example, adversaries can use a mDNS query (such as <code>dns-sd -B _ssh._tcp .</code>) to find other systems broadcasting the ssh service.(Citation: apple doco bonjour description)(Citation: macOS APT Activity Bradley)",
            "reference": "https://attack.mitre.org/techniques/T1046",
            "status": "FORECAST_CONTEXT",
            "confidence": 0.8781255578354172
          }
        ]
      },
      "status": "MODEL_PREDICTION"
    },
    {
      "horizon": 2,
      "window_offset_seconds": 120,
      "attack_probability": 0.9900732602070665,
      "probability_delta": 0.006456895945491037,
      "trend": "STABLE_HIGH",
      "confidence": 0.9801465204141331,
      "uncertainty": 0.019853479585866918,
      "stage": {
        "stage": "RECONNAISSANCE",
        "confidence": 0.880828768492751,
        "status": "CONTEXTUAL_HYPOTHESIS",
        "evidence": [
          {
            "feature": "unique_dst_ports",
            "direction": "elevated_destination_port_diversity",
            "contribution": "supports",
            "value": 488.5275823724833,
            "evidence_source": "observed_flow_aggregate"
          },
          {
            "feature": "flow_count",
            "direction": "fan_out_context",
            "contribution": "supports",
            "value": 1739.5923679560406,
            "evidence_source": "observed_flow_aggregate"
          },
          {
            "feature": "mean_duration",
            "direction": "short_flow_context",
            "contribution": "supports",
            "value": 0.8535163272259885,
            "evidence_source": "observed_flow_aggregate"
          }
        ],
        "evidence_source": "predicted_flow_state",
        "behavioral_signal": "PORT_SCAN_LIKE_ACTIVITY",
        "techniques": [
          {
            "technique_id": "T1046",
            "technique_name": "Network Service Discovery",
            "tactics": [
              "discovery"
            ],
            "description": "Adversaries may attempt to get a listing of services running on remote hosts and local network infrastructure devices, including those that may be vulnerable to remote software exploitation. Common methods to acquire this information include port, vulnerability, and/or wordlist scans using tools that are brought onto a system.(Citation: CISA AR21-126A FIVEHANDS May 2021)   \n\nWithin cloud environments, adversaries may attempt to discover services running on other cloud hosts. Additionally, if the cloud environment is connected to a on-premises environment, adversaries may be able to identify services running on non-cloud systems as well.\n\nWithin macOS environments, adversaries may use the native Bonjour application to discover services running on other macOS hosts within a network. The Bonjour mDNSResponder daemon automatically registers and advertises a host\u2019s registered services on the network. For example, adversaries can use a mDNS query (such as <code>dns-sd -B _ssh._tcp .</code>) to find other systems broadcasting the ssh service.(Citation: apple doco bonjour description)(Citation: macOS APT Activity Bradley)",
            "reference": "https://attack.mitre.org/techniques/T1046",
            "status": "FORECAST_CONTEXT",
            "confidence": 0.880828768492751
          }
        ]
      },
      "status": "MODEL_PREDICTION"
    },
    {
      "horizon": 3,
      "window_offset_seconds": 180,
      "attack_probability": 0.9914917612453159,
      "probability_delta": 0.0014185010382493646,
      "trend": "STABLE_HIGH",
      "confidence": 0.9829835224906318,
      "uncertainty": 0.01701647750936819,
      "stage": {
        "stage": "RECONNAISSANCE",
        "confidence": 0.8725400377070799,
        "status": "CONTEXTUAL_HYPOTHESIS",
        "evidence": [
          {
            "feature": "unique_dst_ports",
            "direction": "elevated_destination_port_diversity",
            "contribution": "supports",
            "value": 486.021273655071,
            "evidence_source": "observed_flow_aggregate"
          },
          {
            "feature": "flow_count",
            "direction": "fan_out_context",
            "contribution": "supports",
            "value": 1783.3022910836912,
            "evidence_source": "observed_flow_aggregate"
          },
          {
            "feature": "mean_duration",
            "direction": "short_flow_context",
            "contribution": "supports",
            "value": 0.9802583813573416,
            "evidence_source": "observed_flow_aggregate"
          }
        ],
        "evidence_source": "predicted_flow_state",
        "behavioral_signal": "PORT_SCAN_LIKE_ACTIVITY",
        "techniques": [
          {
            "technique_id": "T1046",
            "technique_name": "Network Service Discovery",
            "tactics": [
              "discovery"
            ],
            "description": "Adversaries may attempt to get a listing of services running on remote hosts and local network infrastructure devices, including those that may be vulnerable to remote software exploitation. Common methods to acquire this information include port, vulnerability, and/or wordlist scans using tools that are brought onto a system.(Citation: CISA AR21-126A FIVEHANDS May 2021)   \n\nWithin cloud environments, adversaries may attempt to discover services running on other cloud hosts. Additionally, if the cloud environment is connected to a on-premises environment, adversaries may be able to identify services running on non-cloud systems as well.\n\nWithin macOS environments, adversaries may use the native Bonjour application to discover services running on other macOS hosts within a network. The Bonjour mDNSResponder daemon automatically registers and advertises a host\u2019s registered services on the network. For example, adversaries can use a mDNS query (such as <code>dns-sd -B _ssh._tcp .</code>) to find other systems broadcasting the ssh service.(Citation: apple doco bonjour description)(Citation: macOS APT Activity Bradley)",
            "reference": "https://attack.mitre.org/techniques/T1046",
            "status": "FORECAST_CONTEXT",
            "confidence": 0.8725400377070799
          }
        ]
      },
      "status": "MODEL_PREDICTION"
    },
    {
      "horizon": 4,
      "window_offset_seconds": 240,
      "attack_probability": 0.9925655113327309,
      "probability_delta": 0.0010737500874149486,
      "trend": "STABLE_HIGH",
      "confidence": 0.9851310226654617,
      "uncertainty": 0.014868977334538291,
      "stage": {
        "stage": "RECONNAISSANCE",
        "confidence": 0.8693408073283326,
        "status": "CONTEXTUAL_HYPOTHESIS",
        "evidence": [
          {
            "feature": "unique_dst_ports",
            "direction": "elevated_destination_port_diversity",
            "contribution": "supports",
            "value": 484.91330924787354,
            "evidence_source": "observed_flow_aggregate"
          },
          {
            "feature": "flow_count",
            "direction": "fan_out_context",
            "contribution": "supports",
            "value": 1800.3707423983226,
            "evidence_source": "observed_flow_aggregate"
          },
          {
            "feature": "mean_duration",
            "direction": "short_flow_context",
            "contribution": "supports",
            "value": 1.0424359868103106,
            "evidence_source": "observed_flow_aggregate"
          }
        ],
        "evidence_source": "predicted_flow_state",
        "behavioral_signal": "PORT_SCAN_LIKE_ACTIVITY",
        "techniques": [
          {
            "technique_id": "T1046",
            "technique_name": "Network Service Discovery",
            "tactics": [
              "discovery"
            ],
            "description": "Adversaries may attempt to get a listing of services running on remote hosts and local network infrastructure devices, including those that may be vulnerable to remote software exploitation. Common methods to acquire this information include port, vulnerability, and/or wordlist scans using tools that are brought onto a system.(Citation: CISA AR21-126A FIVEHANDS May 2021)   \n\nWithin cloud environments, adversaries may attempt to discover services running on other cloud hosts. Additionally, if the cloud environment is connected to a on-premises environment, adversaries may be able to identify services running on non-cloud systems as well.\n\nWithin macOS environments, adversaries may use the native Bonjour application to discover services running on other macOS hosts within a network. The Bonjour mDNSResponder daemon automatically registers and advertises a host\u2019s registered services on the network. For example, adversaries can use a mDNS query (such as <code>dns-sd -B _ssh._tcp .</code>) to find other systems broadcasting the ssh service.(Citation: apple doco bonjour description)(Citation: macOS APT Activity Bradley)",
            "reference": "https://attack.mitre.org/techniques/T1046",
            "status": "FORECAST_CONTEXT",
            "confidence": 0.8693408073283326
          }
        ]
      },
      "status": "MODEL_PREDICTION"
    },
    {
      "horizon": 5,
      "window_offset_seconds": 300,
      "attack_probability": 0.9928924319873578,
      "probability_delta": 0.00032692065462691655,
      "trend": "STABLE_HIGH",
      "confidence": 0.9857848639747155,
      "uncertainty": 0.014215136025284458,
      "stage": {
        "stage": "RECONNAISSANCE",
        "confidence": 0.8675050450357316,
        "status": "CONTEXTUAL_HYPOTHESIS",
        "evidence": [
          {
            "feature": "unique_dst_ports",
            "direction": "elevated_destination_port_diversity",
            "contribution": "supports",
            "value": 484.49854992069584,
            "evidence_source": "observed_flow_aggregate"
          },
          {
            "feature": "flow_count",
            "direction": "fan_out_context",
            "contribution": "supports",
            "value": 1811.175373742876,
            "evidence_source": "observed_flow_aggregate"
          },
          {
            "feature": "mean_duration",
            "direction": "short_flow_context",
            "contribution": "supports",
            "value": 1.0776249805458018,
            "evidence_source": "observed_flow_aggregate"
          }
        ],
        "evidence_source": "predicted_flow_state",
        "behavioral_signal": "PORT_SCAN_LIKE_ACTIVITY",
        "techniques": [
          {
            "technique_id": "T1046",
            "technique_name": "Network Service Discovery",
            "tactics": [
              "discovery"
            ],
            "description": "Adversaries may attempt to get a listing of services running on remote hosts and local network infrastructure devices, including those that may be vulnerable to remote software exploitation. Common methods to acquire this information include port, vulnerability, and/or wordlist scans using tools that are brought onto a system.(Citation: CISA AR21-126A FIVEHANDS May 2021)   \n\nWithin cloud environments, adversaries may attempt to discover services running on other cloud hosts. Additionally, if the cloud environment is connected to a on-premises environment, adversaries may be able to identify services running on non-cloud systems as well.\n\nWithin macOS environments, adversaries may use the native Bonjour application to discover services running on other macOS hosts within a network. The Bonjour mDNSResponder daemon automatically registers and advertises a host\u2019s registered services on the network. For example, adversaries can use a mDNS query (such as <code>dns-sd -B _ssh._tcp .</code>) to find other systems broadcasting the ssh service.(Citation: apple doco bonjour description)(Citation: macOS APT Activity Bradley)",
            "reference": "https://attack.mitre.org/techniques/T1046",
            "status": "FORECAST_CONTEXT",
            "confidence": 0.8675050450357316
          }
        ]
      },
      "status": "MODEL_PREDICTION"
    }
  ],
  "defender_guidance": {
    "priority": "HIGH",
    "recommendation": "Investigate hosts associated with the forecast behavior."
  }
}
```

## Evidence And Explanation

Evidence contains observed or predicted feature names, direction, and source. No numerical causal contribution is invented.
 Existing LSTM explanations are associations with the forecast, not causes; model-level attribution is unavailable.

## Abstention And Leakage Controls

- insufficient history or model abstention
- missing required flow features
- unsupported stage inference
- invalid or unavailable ATT&CK mapping
- uncertainty or confidence below documented threshold

- No target labels in inference inputs
- No future observations or labels
- Forecast stages use predicted state only
- Observed and forecast technique statuses are distinct

## Validation

Focused intelligence tests: 7 passed. The report used the existing trained model for an actual local-state run; no training or weight changes occurred.

## Limitations

- Stage outputs are CONTEXTUAL_HYPOTHESIS, not dataset-confirmed ATT&CK stages.
- Forecast probabilities are uncalibrated model outputs.
- LSTM model-level feature attribution unavailable for this forecast; existing ablation explanations are associations, not causes.
- CIC flow CSVs have no event timestamps or packet observations.
- Observed labels are excluded from inference and are evaluation metadata only.

## Recommendation

Treat this as a defensible interpretation layer, not reliable multi-stage or technique forecasting. Acquire timestamped scenario data and original PCAPs, validate packet evidence, calibrate probabilities, and expand evaluation before operational claims.
