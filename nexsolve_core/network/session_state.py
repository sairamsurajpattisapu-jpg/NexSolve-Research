"""Deterministic TCP session-state tracker inspired by Zeek's connection state machine.

Clean-room implementation grounded in RFC 793 / RFC 9293 TCP kinematics and Zeek's
conn_state semantics (S0, S1, SF, REJ, RSTO, RSTR, RSTOS0, OTH), engineered natively
for NexSolve's passive PCAP pipeline.

Key scientific constraints:
1. Operates directly on native PacketRecord streams without external runtimes.
2. Distinguishes OBSERVED flag kinematics from INFERRED terminal state.
3. Explicitly flags observation boundaries (e.g. capture truncation vs true silence).
   Never derives certainty from mere absence of observation without documenting boundaries.
4. Produces deterministic aggregate metrics and FusedEvidenceItem instances.
5. Does NOT mutate or contaminate the canonical 45-feature world model vector.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
from enum import Enum
from typing import Any, Iterable, Sequence

from nexsolve_core.schemas import PacketRecord
from nexsolve_core.fusion import EvidenceModality, FusedEvidenceItem, TemporalScope


class TCPConnectionState(str, Enum):
    """Canonical connection lifecycle classification.

    Derived from observed bidirectional flag sequences and termination events.
    """
    ATTEMPTED = "ATTEMPTED"          # SYN observed, no response observed prior to boundary (Zeek S0 candidate)
    ESTABLISHED = "ESTABLISHED"      # Successful 3-way handshake (SYN, SYN-ACK, ACK), active / unclosed (Zeek S1)
    CLOSED = "CLOSED"                # Gracefully closed via FIN exchange (Zeek SF)
    REJECTED = "REJECTED"            # Connection refused: SYN met with RST from responder (Zeek REJ)
    RESET = "RESET"                  # Connection aborted mid-stream or by originator (Zeek RSTO / RSTR)
    RESET_ATTEMPT = "RESET_ATTEMPT"  # Originator sent SYN followed by RST without responder reply (Zeek RSTOS0)
    INCOMPLETE = "INCOMPLETE"        # Handshake partially observed or mid-stream traffic lacking initial SYN (Zeek OTH/partial)
    UNKNOWN = "UNKNOWN"              # Insufficient packet evidence for deterministic classification


class ObservationBoundaryStatus(str, Enum):
    """Scientific qualification documenting capture observation boundaries."""
    COMPLETE_LIFECYCLE = "COMPLETE_LIFECYCLE"          # Both start and teardown observed
    TRUNCATED_AT_END = "TRUNCATED_AT_END"              # Started before capture boundary; silence could be truncation
    MIDSTREAM_JOIN = "MIDSTREAM_JOIN"                  # First packet lacked SYN; missed handshake
    ISOLATED_WINDOW = "ISOLATED_WINDOW"                # Observed within a single discrete evaluation window


# TCP Flag Bitmasks
FLAG_FIN = 0x01
FLAG_SYN = 0x02
FLAG_RST = 0x04
FLAG_PSH = 0x08
FLAG_ACK = 0x10
FLAG_URG = 0x20
FLAG_ECE = 0x40
FLAG_CWR = 0x80


@dataclass(frozen=True)
class TCPSessionRecord:
    """Stateful bidirectional TCP conversation record."""
    session_id: str
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    first_seen: float
    last_seen: float
    duration_seconds: float
    forward_packets: int
    reverse_packets: int
    total_packets: int
    forward_bytes: int
    reverse_bytes: int
    total_bytes: int
    # Observed flag kinematics (Forward = Originator -> Responder; Reverse = Responder -> Originator)
    orig_syn: bool
    orig_ack: bool
    orig_fin: bool
    orig_rst: bool
    resp_syn: bool
    resp_ack: bool
    resp_fin: bool
    resp_rst: bool
    handshake_completed: bool
    # State classification & boundary qualification
    connection_state: TCPConnectionState
    boundary_status: ObservationBoundaryStatus
    zeek_equivalent_state: str  # e.g. "S0", "S1", "SF", "REJ", "RSTO", "RSTR", "RSTOS0", "OTH"
    history_string: str         # Zeek-style history: S=orig SYN, h=resp SYN-ACK, A=orig ACK, F=orig FIN, etc.

    def to_dict(self) -> dict[str, Any]:
        res = asdict(self)
        res["connection_state"] = self.connection_state.value
        res["boundary_status"] = self.boundary_status.value
        return res


class _TCPSessionBuilder:
    """Mutable accumulator used during single-pass packet tracking."""
    def __init__(self, session_id: str, orig_ip: str, orig_port: int, resp_ip: str, resp_port: int, first_time: float) -> None:
        self.session_id = session_id
        self.orig_ip = orig_ip
        self.orig_port = orig_port
        self.resp_ip = resp_ip
        self.resp_port = resp_port
        self.first_seen = first_time
        self.last_seen = first_time
        self.fwd_pkts = 0
        self.rev_pkts = 0
        self.fwd_bytes = 0
        self.rev_bytes = 0
        self.orig_syn = False
        self.orig_ack = False
        self.orig_fin = False
        self.orig_rst = False
        self.resp_syn = False
        self.resp_ack = False
        self.resp_fin = False
        self.resp_rst = False
        self.handshake_ack_seen = False
        self.history_chars: list[str] = []

    def update(self, packet: PacketRecord, is_orig: bool) -> None:
        ts = packet.timestamp
        self.last_seen = max(self.last_seen, ts)
        plen = packet.packet_length or 0
        flags = packet.tcp_flags or 0

        if is_orig:
            self.fwd_pkts += 1
            self.fwd_bytes += plen
            has_syn = bool(flags & FLAG_SYN)
            has_ack = bool(flags & FLAG_ACK)
            has_fin = bool(flags & FLAG_FIN)
            has_rst = bool(flags & FLAG_RST)
            has_data = (packet.payload_length or 0) > 0

            if has_syn and not has_ack:
                if not self.orig_syn:
                    self.history_chars.append("S")
                self.orig_syn = True
            elif has_syn and has_ack:
                if not self.orig_syn:
                    self.history_chars.append("H")
                self.orig_syn = True
                self.orig_ack = True

            if has_rst:
                if not self.orig_rst:
                    self.history_chars.append("R")
                self.orig_rst = True

            if has_fin:
                if not self.orig_fin:
                    self.history_chars.append("F")
                self.orig_fin = True

            if has_ack and not has_syn:
                if not self.orig_ack:
                    self.orig_ack = True
                    # If responder sent SYN-ACK, this completes the 3-way handshake
                    if self.resp_syn and self.resp_ack:
                        self.handshake_ack_seen = True
                if "A" not in self.history_chars:
                    self.history_chars.append("A")

            if has_data and "D" not in self.history_chars:
                self.history_chars.append("D")
        else:
            self.rev_pkts += 1
            self.rev_bytes += plen
            has_syn = bool(flags & FLAG_SYN)
            has_ack = bool(flags & FLAG_ACK)
            has_fin = bool(flags & FLAG_FIN)
            has_rst = bool(flags & FLAG_RST)
            has_data = (packet.payload_length or 0) > 0

            if has_syn and has_ack:
                if not self.resp_syn:
                    self.history_chars.append("h")
                self.resp_syn = True
                self.resp_ack = True
            elif has_syn and not has_ack:
                if not self.resp_syn:
                    self.history_chars.append("s")
                self.resp_syn = True

            if has_rst:
                if not self.resp_rst:
                    self.history_chars.append("r")
                self.resp_rst = True

            if has_fin:
                if not self.resp_fin:
                    self.history_chars.append("f")
                self.resp_fin = True

            if has_ack and not has_syn:
                self.resp_ack = True
                if "a" not in self.history_chars:
                    self.history_chars.append("a")

            if has_data and "d" not in self.history_chars:
                self.history_chars.append("d")

    def finalize(self, capture_end_time: float | None = None) -> TCPSessionRecord:
        duration = max(0.0, self.last_seen - self.first_seen)
        handshake_done = (self.orig_syn and self.resp_syn and self.resp_ack and (self.handshake_ack_seen or (self.orig_ack and self.fwd_pkts >= 2)))

        # Evaluate connection state with explicit Zeek-inspired mapping
        if self.orig_syn and not self.resp_syn and not self.resp_rst and not self.orig_rst and self.rev_pkts == 0:
            # Originator sent SYN, zero packets from responder
            conn_state = TCPConnectionState.ATTEMPTED
            zeek_equiv = "S0"
            boundary = ObservationBoundaryStatus.TRUNCATED_AT_END
        elif self.orig_syn and self.resp_rst and not self.resp_syn:
            # Responder actively refused connection
            conn_state = TCPConnectionState.REJECTED
            zeek_equiv = "REJ"
            boundary = ObservationBoundaryStatus.COMPLETE_LIFECYCLE
        elif self.orig_syn and self.orig_rst and self.rev_pkts == 0:
            # Originator sent SYN then RST before receiving reply
            conn_state = TCPConnectionState.RESET_ATTEMPT
            zeek_equiv = "RSTOS0"
            boundary = ObservationBoundaryStatus.COMPLETE_LIFECYCLE
        elif handshake_done:
            # Handshake was established
            if (self.orig_fin and self.resp_fin) or (self.orig_fin and self.resp_ack and self.rev_pkts >= 2):
                conn_state = TCPConnectionState.CLOSED
                zeek_equiv = "SF"
                boundary = ObservationBoundaryStatus.COMPLETE_LIFECYCLE
            elif self.orig_rst or self.resp_rst:
                conn_state = TCPConnectionState.RESET
                zeek_equiv = "RSTO" if self.orig_rst else "RSTR"
                boundary = ObservationBoundaryStatus.COMPLETE_LIFECYCLE
            else:
                conn_state = TCPConnectionState.ESTABLISHED
                zeek_equiv = "S1"
                boundary = ObservationBoundaryStatus.TRUNCATED_AT_END
        else:
            # Incomplete or mid-stream
            if not self.orig_syn and (self.fwd_pkts > 0 or self.rev_pkts > 0):
                conn_state = TCPConnectionState.INCOMPLETE
                zeek_equiv = "OTH"
                boundary = ObservationBoundaryStatus.MIDSTREAM_JOIN
            else:
                conn_state = TCPConnectionState.INCOMPLETE
                zeek_equiv = "OTH"
                boundary = ObservationBoundaryStatus.ISOLATED_WINDOW

        return TCPSessionRecord(
            session_id=self.session_id,
            src_ip=self.orig_ip,
            dst_ip=self.resp_ip,
            src_port=self.orig_port,
            dst_port=self.resp_port,
            first_seen=round(self.first_seen, 4),
            last_seen=round(self.last_seen, 4),
            duration_seconds=round(duration, 4),
            forward_packets=self.fwd_pkts,
            reverse_packets=self.rev_pkts,
            total_packets=self.fwd_pkts + self.rev_pkts,
            forward_bytes=self.fwd_bytes,
            reverse_bytes=self.rev_bytes,
            total_bytes=self.fwd_bytes + self.rev_bytes,
            orig_syn=self.orig_syn,
            orig_ack=self.orig_ack,
            orig_fin=self.orig_fin,
            orig_rst=self.orig_rst,
            resp_syn=self.resp_syn,
            resp_ack=self.resp_ack,
            resp_fin=self.resp_fin,
            resp_rst=self.resp_rst,
            handshake_completed=handshake_done,
            connection_state=conn_state,
            boundary_status=boundary,
            zeek_equivalent_state=zeek_equiv,
            history_string="".join(self.history_chars),
        )


def track_tcp_sessions(packets: Iterable[PacketRecord]) -> tuple[TCPSessionRecord, ...]:
    """Reconstruct bidirectional TCP conversations into stateful session records."""
    sessions: dict[tuple[str, int, str, int], _TCPSessionBuilder] = {}
    pair_map: dict[tuple[Any, ...], tuple[str, int, str, int]] = {}

    for pkt in packets:
        if pkt.protocol != "TCP" or not pkt.src_ip or not pkt.dst_ip or pkt.src_port is None or pkt.dst_port is None:
            continue

        endpoint_pair = tuple(sorted([
            (pkt.src_ip, pkt.src_port),
            (pkt.dst_ip, pkt.dst_port),
        ]))

        if endpoint_pair not in pair_map:
            # First packet defines originator direction
            canonical_key = (pkt.src_ip, pkt.src_port, pkt.dst_ip, pkt.dst_port)
            pair_map[endpoint_pair] = canonical_key
            sess_id = f"tcp-{pkt.src_ip}:{pkt.src_port}-{pkt.dst_ip}:{pkt.dst_port}-{int(pkt.timestamp)}"
            builder = _TCPSessionBuilder(
                session_id=sess_id,
                orig_ip=pkt.src_ip,
                orig_port=pkt.src_port,
                resp_ip=pkt.dst_ip,
                resp_port=pkt.dst_port,
                first_time=pkt.timestamp,
            )
            sessions[canonical_key] = builder
            is_orig = True
        else:
            canonical_key = pair_map[endpoint_pair]
            builder = sessions[canonical_key]
            is_orig = (pkt.src_ip == builder.orig_ip and pkt.src_port == builder.orig_port)

        builder.update(pkt, is_orig=is_orig)

    records = [b.finalize() for b in sessions.values()]
    records.sort(key=lambda r: (r.first_seen, r.session_id))
    return tuple(records)


@dataclass(frozen=True)
class TCPSessionSummaryMetrics:
    """Aggregated protocol metrics with deterministic mathematical definitions.

    Zero smoothing is applied; all ratios explicitly handle zero denominators.
    """
    total_tcp_sessions: int
    attempted_sessions: int           # Zeek S0
    established_sessions: int         # Zeek S1 / SF
    closed_sessions: int              # Zeek SF
    rejected_sessions: int            # Zeek REJ
    reset_sessions: int               # Zeek RSTO / RSTR
    reset_attempt_sessions: int       # Zeek RSTOS0
    incomplete_sessions: int          # Zeek OTH
    syn_only_sessions: int            # No payload, no response
    failed_connection_ratio: float    # (attempted + rejected) / total (0.0 if total == 0)
    establishment_ratio: float        # established / total (0.0 if total == 0)
    reset_ratio: float                # (reset + rejected) / total (0.0 if total == 0)
    incomplete_ratio: float           # incomplete / total (0.0 if total == 0)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def aggregate_tcp_session_metrics(sessions: Sequence[TCPSessionRecord]) -> TCPSessionSummaryMetrics:
    """Aggregate individual session records into deterministic summary metrics."""
    total = len(sessions)
    if total == 0:
        return TCPSessionSummaryMetrics(
            total_tcp_sessions=0,
            attempted_sessions=0,
            established_sessions=0,
            closed_sessions=0,
            rejected_sessions=0,
            reset_sessions=0,
            reset_attempt_sessions=0,
            incomplete_sessions=0,
            syn_only_sessions=0,
            failed_connection_ratio=0.0,
            establishment_ratio=0.0,
            reset_ratio=0.0,
            incomplete_ratio=0.0,
        )

    attempted = sum(s.connection_state == TCPConnectionState.ATTEMPTED for s in sessions)
    established = sum(s.handshake_completed for s in sessions)
    closed = sum(s.connection_state == TCPConnectionState.CLOSED for s in sessions)
    rejected = sum(s.connection_state == TCPConnectionState.REJECTED for s in sessions)
    reset = sum(s.connection_state == TCPConnectionState.RESET for s in sessions)
    reset_attempts = sum(s.connection_state == TCPConnectionState.RESET_ATTEMPT for s in sessions)
    incomplete = sum(s.connection_state == TCPConnectionState.INCOMPLETE for s in sessions)
    syn_only = sum(s.orig_syn and not s.orig_ack and not s.resp_syn for s in sessions)

    failed_ratio = (attempted + rejected) / float(total)
    est_ratio = established / float(total)
    rst_ratio = (reset + rejected) / float(total)
    inc_ratio = incomplete / float(total)

    return TCPSessionSummaryMetrics(
        total_tcp_sessions=total,
        attempted_sessions=attempted,
        established_sessions=established,
        closed_sessions=closed,
        rejected_sessions=rejected,
        reset_sessions=reset,
        reset_attempt_sessions=reset_attempts,
        incomplete_sessions=incomplete,
        syn_only_sessions=syn_only,
        failed_connection_ratio=round(failed_ratio, 4),
        establishment_ratio=round(est_ratio, 4),
        reset_ratio=round(rst_ratio, 4),
        incomplete_ratio=round(inc_ratio, 4),
    )


def build_tcp_session_evidence(
    sessions: Sequence[TCPSessionRecord],
    timestamp: str | float = "observed_capture",
) -> tuple[FusedEvidenceItem, ...]:
    """Convert reconstructed TCP session intelligence into FusedEvidenceItem instances.

    Strictly marks temporal_scope as OBSERVED and modality as PROTOCOL.
    """
    metrics = aggregate_tcp_session_metrics(sessions)
    evidence: list[FusedEvidenceItem] = []

    if metrics.total_tcp_sessions == 0:
        return ()

    # High unacknowledged connection attempt ratio indicates port reconnaissance / scanning
    if metrics.failed_connection_ratio >= 0.50 and metrics.attempted_sessions >= 3:
        evidence.append(FusedEvidenceItem(
            id=f"proto-tcp-failed-conns-{int(metrics.failed_connection_ratio * 100)}",
            timestamp=timestamp,
            temporal_scope=TemporalScope.OBSERVED,
            modality=EvidenceModality.PROTOCOL,
            source="zeek_tcp_session_state_tracker",
            severity="HIGH" if metrics.failed_connection_ratio >= 0.80 else "MEDIUM",
            confidence=0.90,
            description=(
                f"High proportion of unacknowledged TCP connection attempts observed: "
                f"{metrics.attempted_sessions}/{metrics.total_tcp_sessions} ({metrics.failed_connection_ratio * 100:.1f}%) "
                f"unanswered SYN attempts (Zeek S0 state), indicating active network service scanning."
            ),
            entities={"total_sessions": metrics.total_tcp_sessions, "attempted": metrics.attempted_sessions},
            supporting_features={
                "failed_connection_ratio": metrics.failed_connection_ratio,
                "attempted_sessions": float(metrics.attempted_sessions),
                "syn_only_sessions": float(metrics.syn_only_sessions),
            },
            provenance={"analyzer": "zeek_tcp_session_state_tracker", "model_impact": "evidence_only"},
            mitre_technique_id="T1046",
        ))

    # Connection rejection ratio indicates active probing against closed service ports
    if metrics.rejected_sessions >= 3 and metrics.reset_ratio >= 0.30:
        evidence.append(FusedEvidenceItem(
            id=f"proto-tcp-rejected-conns-{metrics.rejected_sessions}",
            timestamp=timestamp,
            temporal_scope=TemporalScope.OBSERVED,
            modality=EvidenceModality.PROTOCOL,
            source="zeek_tcp_session_state_tracker",
            severity="MEDIUM",
            confidence=0.85,
            description=(
                f"Observed {metrics.rejected_sessions} rejected TCP connections (Zeek REJ state; RST response to SYN), "
                f"consistent with closed port sweeping or firewall active resets."
            ),
            entities={"rejected_count": metrics.rejected_sessions},
            supporting_features={
                "rejected_sessions": float(metrics.rejected_sessions),
                "reset_ratio": metrics.reset_ratio,
            },
            provenance={"analyzer": "zeek_tcp_session_state_tracker", "model_impact": "evidence_only"},
            mitre_technique_id="T1046",
        ))

    return tuple(evidence)
