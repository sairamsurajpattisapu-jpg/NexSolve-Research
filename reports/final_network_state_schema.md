# Final Network State Schema

The protected research contract is `S_t = [flow_features_t, packet_features_t, temporal_features_t]` with 46 numeric inputs, 60-second windows, lookback 8, and forecast horizon 5. Attack labels, future labels, and MITRE labels are not part of the encoded state.

The machine-readable provenance table is in `final_network_state_schema.json`. Packet features remain unavailable placeholders because no PCAP is present. CIC flow CSVs can populate only verified flow aggregates and cannot provide event chronology.
