import { FileSpreadsheet, X, CheckCircle, AlertTriangle } from 'lucide-react'

interface CsvRequirementsModalProps {
  isOpen: boolean
  onClose: () => void
}

export function CsvRequirementsModal({ isOpen, onClose }: CsvRequirementsModalProps) {
  if (!isOpen) return null

  return (
    <div
      role="dialog"
      aria-modal="true"
      aria-labelledby="csv-modal-title"
      style={{
        position: 'fixed',
        inset: 0,
        backgroundColor: 'rgba(0, 0, 0, 0.65)',
        backdropFilter: 'blur(4px)',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        zIndex: 9999,
        padding: '16px',
      }}
      onClick={onClose}
    >
      <div
        style={{
          background: 'var(--bg-surface)',
          border: '1px solid var(--border)',
          borderRadius: '10px',
          width: '100%',
          maxWidth: '680px',
          maxHeight: '85vh',
          overflowY: 'auto',
          padding: '24px',
          boxShadow: '0 20px 40px rgba(0, 0, 0, 0.4)',
        }}
        onClick={(e) => e.stopPropagation()}
      >
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '16px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
            <div style={{ padding: '8px', borderRadius: '6px', background: 'var(--button-secondary-bg)', color: 'var(--accent)' }}>
              <FileSpreadsheet size={20} />
            </div>
            <div>
              <h2 id="csv-modal-title" style={{ fontSize: '18px', fontWeight: 600, margin: 0, color: 'var(--text-primary)' }}>
                CSV Telemetry Contract & Requirements
              </h2>
              <span style={{ fontSize: '12px', color: 'var(--text-muted)' }}>
                Grounded specifications for non-PCAP aggregated telemetry ingest
              </span>
            </div>
          </div>
          <button
            onClick={onClose}
            aria-label="Close modal"
            style={{
              background: 'transparent',
              border: 0,
              color: 'var(--text-muted)',
              cursor: 'pointer',
              padding: '6px',
              borderRadius: '4px',
            }}
          >
            <X size={18} />
          </button>
        </div>

        <div style={{ display: 'flex', flexDirection: 'column', gap: '16px', fontSize: '13px', lineHeight: 1.55 }}>
          <div style={{ background: 'var(--bg-secondary)', border: '1px solid var(--border)', borderRadius: '6px', padding: '12px 16px' }}>
            <div style={{ display: 'flex', gap: '8px', alignItems: 'flex-start' }}>
              <AlertTriangle size={16} color="var(--warning)" style={{ flexShrink: 0, marginTop: '2px' }} />
              <div>
                <strong style={{ color: 'var(--text-primary)' }}>Passive PCAP vs Aggregated CSV</strong>
                <p style={{ margin: '4px 0 0 0', color: 'var(--text-secondary)' }}>
                  NexSolve extracts its canonical 45-feature representation directly from raw microsecond packet captures (<code style={{ fontFamily: 'var(--mono)' }}>.pcap</code>, <code style={{ fontFamily: 'var(--mono)' }}>.pcapng</code>). CSV files containing pre-aggregated flow records must strictly adhere to the temporal window schema below. Arbitrary network logs without continuous 60-second temporal boundaries will be rejected to prevent hallucinated predictions.
                </p>
              </div>
            </div>
          </div>

          <div>
            <h4 style={{ margin: '0 0 8px 0', color: 'var(--text-primary)', fontSize: '14px' }}>
              1. Temporal Requirements
            </h4>
            <ul style={{ margin: 0, paddingLeft: '20px', color: 'var(--text-secondary)' }}>
              <li><strong>Window Interval:</strong> Telemetry rows must correspond to continuous 60-second time bins.</li>
              <li><strong>Minimum History:</strong> At least 8 continuous windows (480 seconds) are required for state momentum estimation. Fewer than 8 windows will trigger safety abstention.</li>
              <li><strong>Timestamp Column:</strong> <code style={{ fontFamily: 'var(--mono)' }}>window_start</code> (UTC epoch seconds or ISO 8601).</li>
            </ul>
          </div>

          <div>
            <h4 style={{ margin: '0 0 8px 0', color: 'var(--text-primary)', fontSize: '14px' }}>
              2. Required Core Telemetry Columns
            </h4>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: '8px' }}>
              {[
                { col: 'window_start', desc: 'UTC epoch seconds start of 60s window' },
                { col: 'flow_count', desc: 'Number of active 5-tuple conversations' },
                { col: 'total_packets', desc: 'Total discrete packet count' },
                { col: 'total_src_bytes', desc: 'Outbound payload byte volume' },
                { col: 'total_dst_bytes', desc: 'Inbound payload byte volume' },
                { col: 'unique_src_ports', desc: 'Ephemeral source port diversity' },
                { col: 'unique_dst_ports', desc: 'Target destination port diversity' },
                { col: 'mean_iat', desc: 'Mean packet inter-arrival time (ms)' },
                { col: 'proto_tcp_count', desc: 'Active TCP flow count' },
                { col: 'proto_udp_count', desc: 'Active UDP flow count' },
              ].map((item) => (
                <div key={item.col} style={{ background: 'var(--bg-secondary)', padding: '8px 12px', borderRadius: '4px', border: '1px solid var(--border)' }}>
                  <code style={{ fontFamily: 'var(--mono)', fontWeight: 600, color: 'var(--accent)', fontSize: '12px' }}>{item.col}</code>
                  <span style={{ display: 'block', fontSize: '11px', color: 'var(--text-muted)', marginTop: '2px' }}>{item.desc}</span>
                </div>
              ))}
            </div>
          </div>

          <div>
            <h4 style={{ margin: '0 0 8px 0', color: 'var(--text-primary)', fontSize: '14px' }}>
              3. Scientific Honesty & Feature Imputation Policy
            </h4>
            <ul style={{ margin: 0, paddingLeft: '20px', color: 'var(--text-secondary)' }}>
              <li><CheckCircle size={12} color="var(--accent)" style={{ display: 'inline', marginRight: '6px' }} /><strong>No RTT Imputation:</strong> TCP round-trip latency (<code style={{ fontFamily: 'var(--mono)' }}>mean_tcp_rtt</code>) is strictly withheld in passive ingestion rather than zero-filled or guessed.</li>
              <li><CheckCircle size={12} color="var(--accent)" style={{ display: 'inline', marginRight: '6px' }} /><strong>No Synthetic Interpolation:</strong> Missing time windows will not be filled with synthetic noise; gaps cause explicit abstention.</li>
            </ul>
          </div>
        </div>

        <div style={{ marginTop: '20px', display: 'flex', justifyContent: 'flex-end' }}>
          <button className="button" onClick={onClose}>
            Understood
          </button>
        </div>
      </div>
    </div>
  )
}
