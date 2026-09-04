# NexSolve Final Architecture

## Research Data Flow

INPUT
↓
FEATURE EXTRACTION
↓
NETWORK STATE
↓
WORLD MODEL
↓
FORECAST
↓
ATTACK PROGRESSION
↓
MITRE ATT&CK CONTEXT
↓
EXPLANATION
↓
DEFENDER DECISION SUPPORT

## Research Architecture

The current research path ingests timestamped UNSW flow records into deterministic 60-second states, encodes 18 flow, 22 packet-interface, and 6 temporal values, and uses a protected NumPy LSTM for recursive five-step forecasting. Packet values are unavailable placeholders until a PCAP is audited. The CIC flow adapter is deterministic and label-preserving but cannot establish event chronology.

## Security Boundaries

Labels are targets only. Future observations are excluded. The ATT&CK bundle is read-only context. Explanations use associated-with language and do not claim causality. Defender guidance is non-autonomous; the system does not block, isolate, terminate, delete, or alter firewall rules. Raw payloads are not stored.

## Production Boundary

The production React/Vite and Node/Express repository was not modified. The research FastAPI service is local research infrastructure, not proof of production deployment.

## Limitations

No PCAP, packet/flow alignment, CIC temporal training, calibrated uncertainty, broad multi-episode evaluation, or validated production end-to-end connection is available.
