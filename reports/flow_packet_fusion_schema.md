# Flow/Packet Fusion Schema

Flow and packet branches remain independent. Flow observations are normalized and aggregated into a flow vector. Future PCAP observations will be independently aggregated into a packet vector. Causal temporal features are derived only from prior states. The packet branch is `PENDING PCAP`; no packet vector is emitted today. Machine-readable schema and feature names are in `flow_packet_fusion_schema.json`.
