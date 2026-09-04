# Packet Feature Specification

Run date (UTC): `2026-09-03`

## Status

Design only. No extractor has been implemented and no PCAP has been downloaded or verified.

## Source and Window

Use one official `Friday-WorkingHours-Afternoon-PortScan.pcap` capture as the initial development fixture. Assign packets to deterministic UTC-normalized 60-second windows. Canonicalize bidirectional flow keys from source/destination IP, port, and protocol while retaining direction-specific counters.

## Packet Features

Produce the requested packet features: packet count and size statistics; TTL mean, standard deviation, minimum, and maximum; TCP SYN, ACK, FIN, RST, PSH, and URG counts; TCP window statistics; fragment count; retransmission count; and mean, standard deviation, and maximum IAT.

Timestamp, packet lengths, IP/TCP headers, flags, and TCP sequence information are expected fields of a raw PCAP, but they remain **to be verified from the selected file**. Retransmission is an inference from duplicate TCP sequence ranges, not a native field, so the sequence/ACK and out-of-order rules must be specified and tested. Payload size must state whether captured length or original wire length is used and must account for snaplen and encryption.

## Flow Features

Aggregate flow count, unique endpoints and ports, protocol counts, total bytes and packets, mean duration, mean flow bytes and packets. `attack_ratio` is evaluation metadata only and is excluded from model inputs.

## Integrity Rules

Pin parser versions, sort packets by timestamp plus stable packet index, define missing versus zero, preserve source hashes, and fit any vocabulary or scaler on the training period only. Do not claim TTL, fragment, payload, or retransmission availability until the capture inspection records field coverage.
