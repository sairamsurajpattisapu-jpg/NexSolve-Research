# Cross-Dataset Comparison

Run timestamp (UTC): `2026-09-03T10:49:46+00:00`

## Common Concepts

```json
[
  "flow duration",
  "packet/byte counts",
  "protocol/service concepts",
  "labels"
]
```

## Incompatibilities

```json
[
  "CIC has an explicit header and no timestamp column; UNSW traffic is headerless with epoch Stime/Ltime.",
  "Label taxonomies and feature schemas differ."
]
```

## Shared Representation

A coarse BENIGN/ATTACK representation is defensible for descriptive comparison; a shared temporal forecasting representation is not yet established.
