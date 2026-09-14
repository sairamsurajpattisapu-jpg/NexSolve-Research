"""Network protocol inspection and stateful session tracking for NexSolve."""
from nexsolve_core.network.session_state import (
    ObservationBoundaryStatus,
    TCPConnectionState,
    TCPSessionRecord,
    TCPSessionSummaryMetrics,
    aggregate_tcp_session_metrics,
    build_tcp_session_evidence,
    track_tcp_sessions,
)

__all__ = [
    "ObservationBoundaryStatus",
    "TCPConnectionState",
    "TCPSessionRecord",
    "TCPSessionSummaryMetrics",
    "track_tcp_sessions",
    "aggregate_tcp_session_metrics",
    "build_tcp_session_evidence",
]
