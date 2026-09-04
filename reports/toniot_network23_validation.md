# TON_IoT Network Dataset 23 Validation

## File Integrity

- File: `TON-IoT/validation/Network_dataset_23.csv`
- Bytes: `51,705,634`
- SHA-256: `e89c54673961c2b260265cdd3f6c50355369f8a80e63c31999df04b0a757f213`
- Source CSV modified: no

## Schema

- Rows: `339,021`
- Columns: `46`
- Complete header:

```text
ts,src_ip,src_port,dst_ip,dst_port,proto,service,duration,src_bytes,dst_bytes,conn_state,missed_bytes,src_pkts,src_ip_bytes,dst_pkts,dst_ip_bytes,dns_query,dns_qclass,dns_qtype,dns_rcode,dns_AA,dns_RD,dns_RA,dns_rejected,ssl_version,ssl_cipher,ssl_resumed,ssl_established,ssl_subject,ssl_issuer,http_trans_depth,http_method,http_uri,http_referrer,http_version,http_request_body_len,http_response_body_len,http_status_code,http_user_agent,http_orig_mime_types,http_resp_mime_types,weird_name,weird_addl,weird_notice,label,type
```

Observed datatypes: `ts`, ports, byte/packet counters, DNS numeric fields, HTTP lengths/status, and `label` are numeric; IP/protocol/service/state/content fields are categorical/string; optional protocol fields contain `-` markers. No empty CSV cells or malformed rows were observed.

Representative first five rows:

```text
1556485532,192.168.1.193,57139,192.168.1.33,8080,tcp,-,0.000082,0,0,REJ,0,1,48,1,40,-,0,0,0,-,-,-,-,-,-,-,-,-,-,-,-,-,-,-,0,0,0,-,-,-,-,-,-,1,backdoor
1556485532,192.168.1.193,57140,192.168.1.33,8080,tcp,-,0.011288,0,0,REJ,0,1,48,1,40,-,0,0,0,-,-,-,-,-,-,-,-,-,-,-,-,-,-,-,0,0,0,-,-,-,-,-,-,1,backdoor
1556485533,192.168.1.193,57138,192.168.1.33,80,tcp,-,0.000156,0,0,REJ,0,1,48,1,40,-,0,0,0,-,-,-,-,-,-,-,-,-,-,-,-,-,-,-,0,0,0,-,-,-,-,-,-,1,backdoor
1556485533,192.168.1.193,57140,192.168.1.33,80,tcp,-,0.0001,0,0,REJ,0,1,48,1,40,-,0,0,0,-,-,-,-,-,-,-,-,-,-,-,-,-,-,-,0,0,0,-,-,-,-,-,-,1,backdoor
1556485533,192.168.1.193,57138,192.168.1.33,80,tcp,-,0.000126,0,0,REJ,0,1,48,1,40,-,0,0,0,-,-,-,-,-,-,-,-,-,-,-,-,-,-,-,0,0,0,-,-,-,-,-,-,1,backdoor
```

## Timestamp Audit

- Field: `ts`
- Format: Unix epoch seconds
- Parse success: `339,021`
- Missing/malformed: `0 / 0`
- Duplicate timestamp rows: `291,031` across `47,990` unique timestamp values
- Range: `2019-04-28T21:05:32Z` to `2019-04-29T14:45:56Z`
- Timezone: UTC interpretation; integer field has no explicit offset
- Chronological ordering: **not globally sorted**. Rows must be grouped/sorted by `ts`; file order must not define temporal order.

## Labels and Features

- Label field: `label`
- Label counts: `0 = 33,475`, `1 = 305,546`
- `label=0` is corroborated by `type=normal`; `label=1` is used for attack categories.
- Categories: `normal` 33,475; `backdoor` 304,494; `mitm` 1,052
- Network fields: `src_ip`, `dst_ip`, `src_port`, `dst_port`, `proto`
- Duration: `duration`
- Bytes: `src_bytes`, `dst_bytes`, `src_ip_bytes`, `dst_ip_bytes`
- Packets: `src_pkts`, `dst_pkts`
- Device identity/scenario ID: not present

## Ground-Truth Overlap

`GroundTruth_Network_18.csv` spans `2019-04-27T10:42:14Z` to `2019-04-29T14:45:29Z`. Network 23 spans `2019-04-28T21:05:32Z` to `2019-04-29T14:45:56Z`; overlap is `2019-04-28T21:05:32Z` to `2019-04-29T14:45:29Z`, `63,837` seconds.

Deterministic candidate key: `(ts, src_ip, src_port, dst_ip, dst_port, proto)`.

- Network unique keys: `140,089`
- Ground-truth unique keys: `801,188`
- Exact matching key values: `114,150`
- Network rows with exact key: `305,546`
- Unmatched network rows: `33,475`
- All matched network rows are attack-labeled and have attack-category ground-truth records.
- Duplicate network-key rows: `198,932`

This supports corroborating attack-event linkage, but does not justify filling any normal row from ground truth.

## 60-Second Feasibility

Using explicit `ts` and `label`, with epoch-aligned 60-second buckets:

- Non-empty windows: `893`
- Benign windows: `30`
- Attack windows: `863`
- Timestamp span: `63,624` seconds
- Contiguous forecast pairs: `889`
- Occupied-window gaps: `3`
- Largest gap: `154` 60-second buckets
- BENIGN -> ATTACK: `11`
- ATTACK -> BENIGN: `12`
- BENIGN -> BENIGN: `18`
- ATTACK -> ATTACK: `848`

This is a feasibility calculation only; no model or forecasting comparison was run.

## Leakage Risks

- `label` and `type` are target fields and must be excluded from historical features.
- IPs and network tuples may identify the attack environment: 14 source IPs, 146 destination IPs, and 241 source-destination pairs.
- Timestamps and fixed capture periods may proxy the scenario.
- `Network_dataset_23` is a file identifier, not a feature.
- GroundTruth Network 18 is attack-event metadata and must not be used to create benign labels.
- File order is not chronological; sorting by `ts` is required and must not use future labels for historical features.

## Decision

**A - READY FOR FULL TEMPORAL EVALUATION**

Network 23 contains genuine timestamps, explicit benign/attack labels, usable flow features, 893 non-empty 60-second windows, 889 contiguous pairs, and both state transitions. The initial locked evaluation can proceed using Network 23 alone; GroundTruth Network 18 is optional corroborating metadata only. A leakage audit must precede modeling.

No datasets were modified. No additional file was downloaded. No forecasting experiment or model training was performed.
