# Forecast Split Analysis

Run timestamp (UTC): `2026-09-03T10:49:46+00:00`

## Window Seconds

60

## All Nonempty Windows

1441

## Contiguous Runs

```json
[
  {
    "start_utc": "2015-01-22T11:49:00+00:00",
    "end_utc_exclusive": "2015-01-22T19:22:00+00:00",
    "windows": 453,
    "benign_windows": 335,
    "attack_windows": 118
  },
  {
    "start_utc": "2015-01-22T19:35:00+00:00",
    "end_utc_exclusive": "2015-01-23T00:26:00+00:00",
    "windows": 291,
    "benign_windows": 291,
    "attack_windows": 0
  },
  {
    "start_utc": "2015-02-18T00:23:00+00:00",
    "end_utc_exclusive": "2015-02-18T00:48:00+00:00",
    "windows": 25,
    "benign_windows": 10,
    "attack_windows": 15
  },
  {
    "start_utc": "2015-02-18T01:06:00+00:00",
    "end_utc_exclusive": "2015-02-18T10:28:00+00:00",
    "windows": 562,
    "benign_windows": 0,
    "attack_windows": 562
  },
  {
    "start_utc": "2015-02-18T10:32:00+00:00",
    "end_utc_exclusive": "2015-02-18T12:22:00+00:00",
    "windows": 110,
    "benign_windows": 0,
    "attack_windows": 110
  }
]
```

## Original Split Failure

```json
{
  "train": {
    "benign_windows": 636,
    "attack_windows": 228
  },
  "validation": {
    "benign_windows": 0,
    "attack_windows": 288
  },
  "test": {
    "benign_windows": 0,
    "attack_windows": 289
  }
}
```

## Corrected Split

```json
{
  "train": {
    "windows": 595,
    "benign_windows": 477,
    "attack_windows": 118,
    "start_utc": "2015-01-22T11:49:00+00:00",
    "end_utc_exclusive": "2015-01-22T21:57:00+00:00"
  },
  "validation": {
    "windows": 149,
    "benign_windows": 149,
    "attack_windows": 0,
    "start_utc": "2015-01-22T21:57:00+00:00",
    "end_utc_exclusive": "2015-01-23T00:26:00+00:00"
  },
  "test": {
    "windows": 25,
    "benign_windows": 10,
    "attack_windows": 15,
    "start_utc": "2015-02-18T00:23:00+00:00",
    "end_utc_exclusive": "2015-02-18T00:48:00+00:00"
  }
}
```

## Test Run Index

2

## Minimum Eligible Pairs

20

## Episode Evaluation Rule

Evaluate all runs at or after the first future mixed-state run that contain both states and at least 20 valid contiguous pairs.

## Episodes

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
    "episode_index": 2,
    "start_utc": "2015-02-18T00:23:00+00:00",
    "end_utc_exclusive": "2015-02-18T00:48:00+00:00",
    "windows": 25,
    "benign_windows": 10,
    "attack_windows": 15,
    "attack_percentage": 0.6,
    "valid_forecast_pairs": 24,
    "state_transitions": {
      "1->1": 13,
      "1->0": 1,
      "0->0": 9,
      "0->1": 1
    },
    "suitable_for_future_evaluation": true,
    "exclusion_reason": null
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

## Boundary Crossing Transitions

```json
{
  "train_validation": "None: a gap or state boundary is not used as a forecast pair.",
  "validation_test": "None: the test run begins after a multi-week timestamp gap."
}
```

## Selection Rule

Select the first complete future contiguous run containing both BENIGN and ATTACK states; selection is episode-structure based and not metric based.
