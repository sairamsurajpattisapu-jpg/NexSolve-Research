# CIC Packet Features

- pcap_path: C:\Users\saira\Downloads\Friday-WorkingHours.pcap
- pcap_size_bytes: 8839309056
- sha256: beff0dcce1eebc9b2454582f4dc8ed0ba0112b2c619a710bf03af93147254cd0
- packets_read: 1000
- packets_parsed: 1000
- malformed_packets: 0
- extraction_errors: []
- processing_time_seconds: 2.021985
- packets_per_second: 494.56
- peak_memory_bytes: 15341247
- packet_features_extracted: ['ttl_mean', 'ttl_variance', 'ttl_min', 'ttl_max', 'tcp_window_mean', 'tcp_window_variance', 'tcp_window_min', 'tcp_window_max', 'packet_size_mean', 'packet_size_variance', 'packet_size_min', 'packet_size_max', 'payload_mean', 'payload_variance', 'payload_min', 'payload_max', 'iat_mean', 'iat_variance', 'iat_min', 'iat_max', 'packet_size_median', 'packet_size_p95', 'payload_median', 'payload_p95', 'iat_median', 'iat_p95', 'payload_zero_ratio', 'syn_count', 'ack_count', 'fin_count', 'rst_count', 'psh_count', 'urg_count', 'fragment_count', 'fragment_ratio', 'tcp_count', 'udp_count', 'icmp_count', 'unique_src_ips', 'unique_dst_ips', 'unique_dst_ports', 'tcp_retransmission_count', 'tcp_retransmission_rate', 'port_scan_score', 'protocol_counts']
- packet_windows: 2
- ipv4: 610
- ipv6: 108
- output_path: data\processed\cic_ids2017_packet_windows_smoke.parquet
- output_file_size_bytes: 17419
- packet_count: 1000
- tcp: 246
- udp: 379
- icmp: 0
- ttl_available_packets: 674
- tcp_window_available_packets: 246
- payload_available_packets: 625
- fragmented_packets: 0
- retransmission_status: AVAILABLE
- port_scan_status: AVAILABLE_TRAFFIC_DERIVED
- timestamp_window_unit: UTC epoch seconds; window_start is floor(timestamp / 60) * 60

Port-scan score formula: 0.4*min(unique destination ports/100, 1) + 0.3*min(SYN attempts/100, 1) + 0.2*min(unique destinations/25, 1) + 0.1*(1 - min(response packets/SYN attempts, 1)). Scores use traffic observations only; labels and filenames are not used.
