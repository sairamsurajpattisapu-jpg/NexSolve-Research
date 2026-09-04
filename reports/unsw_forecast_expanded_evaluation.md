# UNSW Forecast Expanded Evaluation

Run timestamp (UTC): `2026-09-03T10:49:46+00:00`

## Dataset

UNSW-NB15

## Locked Contract

```json
{
  "window_seconds": 60,
  "target": "next contiguous window state",
  "states": [
    "BENIGN",
    "ATTACK"
  ],
  "chronological_only": true
}
```

## Previous 24 Pair Experiment

```json
{
  "forecast_cases": 24,
  "eligible_episode_count": 1,
  "status": "retained as the same sole eligible episode under the expanded objective rule"
}
```

## Temporal Reconstruction

```json
{
  "valid_timestamped_rows": 2540047,
  "non_empty_windows": 1441,
  "contiguous_forecast_pairs": 1436,
  "temporal_episodes": 5
}
```

## Episode Selection Rule

Before inspecting metrics, include every episode strictly after the training period that is contiguous, contains both states, has at least 20 valid contiguous forecast pairs, and has support for all three baselines.

## Eligible Episode Count

1

## Eligible Episode Indices

```json
[
  2
]
```

## Excluded Episodes

```json
[
  {
    "episode_index": 0,
    "start_utc": "2015-01-22T11:49:00+00:00",
    "end_utc_exclusive": "2015-01-22T19:22:00+00:00",
    "windows": 453,
    "benign_windows": 335,
    "attack_windows": 118,
    "attack_percentage": 0.26048565121412803,
    "valid_forecast_pairs": 452,
    "state_transitions": {
      "0->1": 1,
      "1->1": 117,
      "1->0": 1,
      "0->0": 333
    },
    "suitable_for_future_evaluation": false,
    "exclusion_reason": "before the pre-test training period"
  },
  {
    "episode_index": 1,
    "start_utc": "2015-01-22T19:35:00+00:00",
    "end_utc_exclusive": "2015-01-23T00:26:00+00:00",
    "windows": 291,
    "benign_windows": 291,
    "attack_windows": 0,
    "attack_percentage": 0.0,
    "valid_forecast_pairs": 290,
    "state_transitions": {
      "0->0": 290
    },
    "suitable_for_future_evaluation": false,
    "exclusion_reason": "before the pre-test training period"
  },
  {
    "episode_index": 3,
    "start_utc": "2015-02-18T01:06:00+00:00",
    "end_utc_exclusive": "2015-02-18T10:28:00+00:00",
    "windows": 562,
    "benign_windows": 0,
    "attack_windows": 562,
    "attack_percentage": 1.0,
    "valid_forecast_pairs": 561,
    "state_transitions": {
      "1->1": 561
    },
    "suitable_for_future_evaluation": false,
    "exclusion_reason": "does not contain both states or has fewer than 20 valid forecast pairs"
  },
  {
    "episode_index": 4,
    "start_utc": "2015-02-18T10:32:00+00:00",
    "end_utc_exclusive": "2015-02-18T12:22:00+00:00",
    "windows": 110,
    "benign_windows": 0,
    "attack_windows": 110,
    "attack_percentage": 1.0,
    "valid_forecast_pairs": 109,
    "state_transitions": {
      "1->1": 109
    },
    "suitable_for_future_evaluation": false,
    "exclusion_reason": "does not contain both states or has fewer than 20 valid forecast pairs"
  }
]
```

## Per Episode Results

```json
[
  {
    "episode_index": 2,
    "start_utc": "2015-02-18T00:23:00+00:00",
    "end_utc_exclusive": "2015-02-18T00:48:00+00:00",
    "target_windows": {
      "benign": 10,
      "attack": 15
    },
    "forecast_cases": 24,
    "current_state": {
      "precision": 0.9285714285714286,
      "recall": 0.9285714285714286,
      "f1": 0.9285714285714286,
      "macro_f1": 0.9142857142857144,
      "balanced_accuracy": 0.9142857142857144,
      "confusion_matrix": [
        [
          9,
          1
        ],
        [
          1,
          13
        ]
      ],
      "class_support": {
        "1": 14,
        "0": 10
      },
      "roc_auc": "Not computed",
      "pr_auc": "Not computed",
      "forecast_cases": 24,
      "evaluated_cases": 24,
      "coverage": 1.0,
      "abstentions": 0,
      "abstention_rate": 0.0
    },
    "persistence": {
      "precision": 0.9285714285714286,
      "recall": 0.9285714285714286,
      "f1": 0.9285714285714286,
      "macro_f1": 0.9142857142857144,
      "balanced_accuracy": 0.9142857142857144,
      "confusion_matrix": [
        [
          9,
          1
        ],
        [
          1,
          13
        ]
      ],
      "class_support": {
        "1": 14,
        "0": 10
      },
      "roc_auc": "Not computed",
      "pr_auc": "Not computed",
      "forecast_cases": 24,
      "evaluated_cases": 24,
      "coverage": 1.0,
      "abstentions": 0,
      "abstention_rate": 0.0
    },
    "empirical_transition": {
      "precision": 0.9285714285714286,
      "recall": 0.9285714285714286,
      "f1": 0.9285714285714286,
      "macro_f1": 0.9142857142857144,
      "balanced_accuracy": 0.9142857142857144,
      "confusion_matrix": [
        [
          9,
          1
        ],
        [
          1,
          13
        ]
      ],
      "class_support": {
        "1": 14,
        "0": 10
      },
      "roc_auc": "Not computed",
      "pr_auc": "Not computed",
      "forecast_cases": 24,
      "evaluated_cases": 24,
      "coverage": 1.0,
      "abstentions": 0,
      "abstention_rate": 0.0
    },
    "training_transition_counts": {
      "0": {
        "1": 1,
        "0": 474
      },
      "1": {
        "1": 117,
        "0": 1
      }
    }
  }
]
```

## Aggregate Results

```json
{
  "current_state": {
    "precision": 0.9285714285714286,
    "recall": 0.9285714285714286,
    "f1": 0.9285714285714286,
    "macro_f1": 0.9142857142857144,
    "balanced_accuracy": 0.9142857142857144,
    "confusion_matrix": [
      [
        9,
        1
      ],
      [
        1,
        13
      ]
    ],
    "class_support": {
      "1": 14,
      "0": 10
    },
    "roc_auc": "Not computed",
    "pr_auc": "Not computed",
    "forecast_cases": 24,
    "evaluated_cases": 24,
    "coverage": 1.0,
    "abstentions": 0,
    "abstention_rate": 0.0
  },
  "persistence": {
    "precision": 0.9285714285714286,
    "recall": 0.9285714285714286,
    "f1": 0.9285714285714286,
    "macro_f1": 0.9142857142857144,
    "balanced_accuracy": 0.9142857142857144,
    "confusion_matrix": [
      [
        9,
        1
      ],
      [
        1,
        13
      ]
    ],
    "class_support": {
      "1": 14,
      "0": 10
    },
    "roc_auc": "Not computed",
    "pr_auc": "Not computed",
    "forecast_cases": 24,
    "evaluated_cases": 24,
    "coverage": 1.0,
    "abstentions": 0,
    "abstention_rate": 0.0
  },
  "empirical_transition": {
    "precision": 0.9285714285714286,
    "recall": 0.9285714285714286,
    "f1": 0.9285714285714286,
    "macro_f1": 0.9142857142857144,
    "balanced_accuracy": 0.9142857142857144,
    "confusion_matrix": [
      [
        9,
        1
      ],
      [
        1,
        13
      ]
    ],
    "class_support": {
      "1": 14,
      "0": 10
    },
    "roc_auc": "Not computed",
    "pr_auc": "Not computed",
    "forecast_cases": 24,
    "evaluated_cases": 24,
    "coverage": 1.0,
    "abstentions": 0,
    "abstention_rate": 0.0
  }
}
```

## Total Forecast Cases

24

## Aggregate Target Support

```json
{
  "benign": 10,
  "attack": 14
}
```

## Episode F1 Variability

```json
{
  "current_state": {
    "mean": 0.9285714285714286,
    "median": 0.9285714285714286,
    "min": 0.9285714285714286,
    "max": 0.9285714285714286,
    "values": [
      0.9285714285714286
    ]
  },
  "persistence": {
    "mean": 0.9285714285714286,
    "median": 0.9285714285714286,
    "min": 0.9285714285714286,
    "max": 0.9285714285714286,
    "values": [
      0.9285714285714286
    ]
  },
  "empirical_transition": {
    "mean": 0.9285714285714286,
    "median": 0.9285714285714286,
    "min": 0.9285714285714286,
    "max": 0.9285714285714286,
    "values": [
      0.9285714285714286
    ]
  }
}
```

## Validation Support

```json
{
  "benign_windows": 149,
  "attack_windows": 0,
  "limitation": "Validation remains benign-only under the locked chronological construction; no attack validation samples were manufactured."
}
```

## Leakage Safeguards

```json
[
  "Training history precedes every eligible episode.",
  "Transition counts are learned from training history only and expanding history before later eligible episodes.",
  "Future episode labels are used only for scoring.",
  "Timestamp gaps are not treated as contiguous forecast pairs.",
  "No randomization or future-derived feature is used."
]
```

## Evidence Level

extremely limited

## Forecasting Value

Not demonstrated: all three baselines tie on the sole eligible episode.

## Advanced Model Decision

ADVANCED MODEL NOT JUSTIFIED

## Reason

Only one eligible future mixed-state episode and 24 total forecast pairs are available; later runs are attack-only and excluded by the pre-specified rule.
