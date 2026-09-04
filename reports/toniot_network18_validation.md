# TON_IoT Network 18 Validation

## 1. File

`TON-IoT/validation/GroundTruth_Network_18.csv`

## 2. Provenance and Integrity

- Source: official TON_IoT distribution
- Observed byte size: `45,787,608`
- Matches supplied downloaded-file size: **yes**
- SHA-256: `446170e48b77da494809648ebfd45c7d517ad34baf34079d200d282235878508`
- External expected hash: Not available; no comparison hash was supplied.
- Source CSV modified: **no**

## 3. Schema

- Rows: `801,188`
- Columns: `7`
- Header: `ts, src_ip, src_port, dst_ip, dst_port, proto, type`
- Datatypes: `ts` integer; `src_ip` string; `src_port` integer; `dst_ip` string; `dst_port` integer; `proto` string; `type` string
- Malformed rows: `0`
- Missing cells: `0`

Representative first five rows:

```text
1556361734,192.168.1.35,40128,192.168.1.195,80,tcp,xss
1556361734,192.168.1.35,40130,192.168.1.195,80,tcp,xss
1556361734,192.168.1.35,40132,192.168.1.195,80,tcp,xss
1556361734,192.168.1.35,40134,192.168.1.195,80,tcp,xss
1556361734,192.168.1.35,40136,192.168.1.195,80,tcp,xss
```

## 4. Timestamp Audit

- Field: `ts`
- Representation: Unix epoch seconds
- Parse success: `801,188`
- Missing timestamps: `0`
- Malformed timestamps: `0`
- Unique timestamp values: `98,710`
- Duplicate timestamp rows: `801,187` repeated-row occurrences; repeated seconds are expected for concurrent events
- Earliest: `1556361734` = `2019-04-27T10:42:14+00:00`
- Latest: `1556549129` = `2019-04-29T14:45:29+00:00`
- Timezone: UTC interpretation of epoch seconds; the integer field has no explicit offset
- Chronological ordering: **non-decreasing / sorted**

## 5. Label Audit

The state/category field is `type`. Observed values are:

| Value | Count |
|---|---:|
| `xss` | 605,685 |
| `backdoor` | 188,864 |
| `ransomware` | 5,629 |
| `mitm` | 1,010 |

- Benign rows: `0`
- Attack-event rows: `801,188`
- Attack categories: `xss`, `backdoor`, `ransomware`, `mitm`

This is a ground-truth event file containing attack names only. The attack count does not imply that it is a complete labeled traffic dataset.

## 6. Network Features

| Concept | Actual column |
|---|---|
| Source IP | `src_ip` |
| Destination IP | `dst_ip` |
| Source port | `src_port` |
| Destination port | `dst_port` |
| Protocol | `proto` |
| Bytes | Not present |
| Packets | Not present |
| Duration | Not present |
| Device identity | Not present |
| Attack category | `type` |
| Scenario/event identifier | Not present |

## 7. Locked 60-Second Feasibility Check

Using epoch-aligned 60-second buckets:

- Non-empty windows: `1,877`
- Benign windows: `0`
- Attack windows: `1,877`
- Timestamp duration: `187,395` seconds
- Contiguous forecast pairs: `1,848`
- Gaps between occupied windows: `28`
- Largest gap: `908` 60-second buckets
- BENIGN -> ATTACK transitions: `0`
- ATTACK -> BENIGN transitions: `0`
- ATTACK -> ATTACK transitions: `1,848`

The file alone cannot support the locked BENIGN/ATTACK next-window forecast because every occupied window is an attack-event window.

## 8. Leakage Risks

- `type` is the ground-truth label and must not be a historical feature.
- Source/destination IPs may encode attack environment or event identity. Observed cardinalities are 14 source IPs, 146 destination IPs, and 241 source-destination pairs.
- Fixed time periods and event timestamps may identify attack activity.
- IP/time combinations can act as scenario proxies even without an explicit scenario ID.
- This event file must not be used alone to construct benign traffic states or flow features.

## 9. Decision

**B — TIMESTAMP EXISTS BUT MORE DATA REQUIRED**

The file has genuine, ordered timestamps and attack categories, but it is attack-only ground truth and lacks traffic-flow statistics. It is not ready for the locked forecasting experiment by itself.

## 10. Exact Additional File Needed

One official TON_IoT processed network traffic CSV containing:

- a genuine timestamp field
- benign and attack labels
- network flow features such as duration, bytes, and packets
- preferably the documented linkage needed to align with the security-event ground truth

The exact filename and size are not inferred here.

No forecasting experiment or model training was run. CIC-IDS2017, UNSW-NB15, MITRE ATT&CK, and the production NexSolve repository were not modified.
