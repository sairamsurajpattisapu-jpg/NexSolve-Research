# PCAP Compatibility Audit

Audit date: 2026-09-04

## Supported upload formats

The upload endpoint `POST /api/pcap/analyze` accepts only filenames ending in `.pcap` or `.pcapng` (case-insensitive). It writes the bytes to a generated temporary filename and passes that file to the existing Scapy `PcapNgReader`-based extractor.

The upload boundary recognizes these capture magic values before reader construction:

- PCAP classic little-endian and big-endian headers
- PCAP nanosecond-resolution little-endian and big-endian headers
- PCAPNG section header magic

Standard Ethernet PCAP captures are supported when Scapy can decode their packets. IPv4, IPv6, TCP, UDP, and ICMP observations are converted to the existing packet-window schema. Other timestamped packet types are retained as `other` traffic when the enclosing capture/link type is readable, but they may not provide IP, port, TCP flag, TTL, or payload fields.

## Explicit limitations

- This is not a universal PCAP compatibility claim. Unsupported link-layer encodings, truncated headers, corrupt block lengths, unsupported encapsulations, and captures without usable timestamps return a human-readable parse failure or produce no parseable windows.
- Empty captures are rejected.
- Invalid extension, empty content, invalid capture magic, and malformed captures are rejected before detection.
- No labels are inferred from packet contents. Findings are produced only by the existing deterministic `HeuristicDetector`.
- Uploads are limited to 64 MB and use unique temporary directories under `runtime/`; the source file is removed after extraction, including failure paths.
- Uploaded analyses are held in backend memory and disappear when the service restarts. The frontend clears stale session IDs and explicitly falls back to verified production data.

## Verification coverage

Backend tests exercise standard PCAP, PCAPNG, malformed, empty, unsupported extension, oversized, temporary isolation, cleanup, and detector invocation paths. Additional official Wireshark sample results are recorded below after live endpoint verification.

## Official sample results

| Sample | Status | Packets | Windows | Findings | Rule IDs | Severity |
|---|---|---:|---:|---:|---|---|
| `teardrop.pcap` (official `teardrop.cap`) | completed | 17 | 2 | 1 | `FRAGMENTATION_RATIO_HIGH` | low |
| `arp-storm.pcap` | completed | 622 | 1 | 0 | none | none |
| `ipv4frags.pcap` | completed | 3 | 1 | 1 | `FRAGMENTATION_RATIO_HIGH` | low |
| `dhcp.pcap` | completed | 4 | 1 | 0 | none | none |

The samples were submitted through the real multipart endpoint. No filenames are special-cased in application logic, and zero findings are preserved as valid outcomes.
