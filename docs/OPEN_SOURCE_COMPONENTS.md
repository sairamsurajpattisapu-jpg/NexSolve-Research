# Open Source Components & External Integration Specifications

**Document Version**: 1.0
**Status**: SPECIFICATION
**Scope**: Specifications for optional external providers and native reference adoptions.

---

## 1. Provider Boundary Specifications

### 1.1 Protocol Intelligence Provider (`ProtocolIntelligenceProvider`)
* **Purpose**: Ingest rich application-layer protocol metadata (DNS, HTTP, SSL/TLS, SSH) from native inspection or optional external tools (Zeek).
* **Interface**:
  ```python
  class ProtocolIntelligenceProvider(ABC):
      @abstractmethod
      def analyze(self, pcap_path: Path, context: dict[str, Any]) -> ProtocolIntelligenceResult:
          pass
  ```
* **Implementations**:
  - `NativeProtocolProvider`: Pure Python inspection of observed packet records (TLS SNI, HTTP Host, DNS queries/responses, port heuristics).
  - `ZeekProtocolProvider`: Decoupled parser for Zeek log output (`conn.log`, `dns.log`, `ssl.log`, `http.log`). Returns `status="UNAVAILABLE"` if Zeek is not installed.

### 1.2 Signature Intelligence Provider (`SignatureIntelligenceProvider`)
* **Purpose**: Ingest traditional rule/signature alerts from native rule engines or optional Suricata instances without violating ML neutrality.
* **Interface**:
  ```python
  class SignatureIntelligenceProvider(ABC):
      @abstractmethod
      def inspect(self, pcap_path: Path, context: dict[str, Any]) -> SignatureIntelligenceResult:
          pass
  ```
* **Implementations**:
  - `NativeSignatureProvider`: Built-in high-confidence protocol and anomaly rules.
  - `SuricataSignatureProvider`: Reads or executes Suricata to parse `eve.json`. Maps alerts to standardized `EvidenceItem` objects with MITRE tags. Returns `status="UNAVAILABLE"` if Suricata is not installed.

### 1.3 Behavioral Intelligence (`nexsolve_core.behavior`)
* **Status**: NATIVE REIMPLEMENTATION (RITA-inspired).
* **Capabilities**:
  - **Beaconing Analysis**: Evaluates inter-connection delta variance, coefficient of variation ($CV = \sigma/\mu$), and periodicity scores for all client-server IP pairs.
  - **Connection Regularity**: Detects robotic polling intervals and heartbeats.
  - **DNS Tunneling Indicators**: Shannon entropy of queried domain names, sub-domain length statistics, and query frequency anomalies.

### 1.4 Session Investigation Model
* **Status**: NATIVE IMPLEMENTATION (Arkime-inspired).
* **Structure**: Represents each bidirectional communication as an inspectable entity linking:
  - 5-tuple (`src_ip`, `dst_ip`, `src_port`, `dst_port`, `protocol`)
  - Temporal span (`first_seen`, `last_seen`, `duration_seconds`)
  - Volumetrics (`packets_forward`, `packets_reverse`, `bytes_forward`, `bytes_reverse`)
  - Behavioral anomalies (Beaconing score, periodicity)
  - Signatures & MITRE ATT&CK mapping
  - Observed findings vs Forecast impact
