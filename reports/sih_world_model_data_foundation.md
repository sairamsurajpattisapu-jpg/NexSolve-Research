# SIH 26153 World Model Data Foundation

Run date (UTC): `2026-09-03`

## Local Packet Evidence

The search covered `TON-IoT/`, `CIC-IDS2017/`, and `UNSW-NB15/`. No `.pcap`, `.pcapng`, Zeek `conn.log`, or packet-derived feature file exists locally. TON Network 23 is a 46-column flow table with `ts`, five-tuple fields, duration, bytes, packets, labels, and attack type. CIC local CSVs contain flow aggregates including packet/IAT statistics, TCP flag counts, and initial window-byte fields. UNSW local CSVs contain flow fields including epoch time, TTL, TCP window, and packet counts. None is a raw packet observation source.

Therefore TTL variance, per-packet payload distribution, IP fragment flags, and retransmission evidence are not locally verified. Existing aggregate columns must not be relabeled as packet-level evidence.

## Smallest Official Source

Acquire one official CIC-IDS2017 scenario capture: `Friday-WorkingHours-Afternoon-PortScan.pcap`. The authoritative source is the UNB CIC-IDS2017 page at https://www.unb.ca/cic/datasets/ids-2017.html, with access through http://cicresearch.ca/CICDataset/CIC-IDS-2017/. The page states that CIC-IDS2017 includes full packet payloads in PCAP format and labeled flows. It describes Friday as attacks plus normal activity and documents Port Scan intervals during the Friday afternoon session.

The standalone file size is **not published** on the authoritative page. The published context is 8.3 GB for the complete Friday capture day. The exact downloaded byte size and SHA-256 must be recorded after access. This is a one-scenario development fixture, not sufficient final forecasting data.

## Benign, Attack, and Time Coverage

Benign traffic is documented at the Friday day level; the scenario file's exact benign proportion must be measured. Port-scan attack traffic is documented for the selected scenario. Raw PCAP packet timestamps provide temporal information, subject to verification of precision and timezone after download.

## Alignment Decision

A packet-to-flow join can use normalized timestamp, source IP, destination IP, source port, destination port, and protocol. This is only a schema-level feasibility statement. CIC-IDS2017 and TON-IoT Network 23 are independent experiments with different dates, hosts, and address spaces. No overlap or correspondence may be claimed until packet extraction and a measured time-tolerant tuple join demonstrate it. `GroundTruth_Network_18.csv` remains attack-event corroboration only and must not manufacture labels.

## Required Next Step

Acquire only `Friday-WorkingHours-Afternoon-PortScan.pcap` from the official CIC source, record its size and SHA-256, and inspect timestamp, tuple, TTL, TCP flags/window, payload, fragment, and retransmission coverage. The companion feature and world-model designs define the subsequent deterministic extraction and five-step, 60-second rollout without training in this phase.
