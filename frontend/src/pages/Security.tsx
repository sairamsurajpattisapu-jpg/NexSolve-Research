import { Link } from 'react-router-dom'

export function Security() {
  return (
    <div className="page-stack page-enter security-editorial-container">
      {/* Editorial Header */}
      <section className="editorial-page-header">
        <div className="editorial-meta-tag">
          RESEARCH PUBLICATION / SPECIFICATION
        </div>
        <h1 className="editorial-display-heading">
          Security
        </h1>
        <p className="editorial-lead-text">
          Verifiable inputs. Transparent forecasting. Reproducible evidence.
        </p>
      </section>

      <div className="editorial-hr" />

      {/* Overview Statement */}
      <section className="security-editorial-summary">
        <p className="security-summary-text">
          NexSolve executes exclusively within local compute environments without outbound telemetry pings,
          cloud API dependencies, or synthetic heuristic approximations. Every forecast decision derives
          from passive network wire observation under deterministic cryptographic provenance.
        </p>
      </section>

      <div className="editorial-hr" />

      {/* 5 Concise Integrity Sections */}
      <section className="security-integrity-stack">
        <div className="security-integrity-row">
          <div className="integrity-row-title">
            <span>01</span>
            <h2>INPUT INTEGRITY</h2>
          </div>
          <div className="integrity-row-content">
            <p>
              Streaming PCAP and PCAPNG wire validation enforces strict magic-byte verification, microsecond timestamp sorting, snaplen bounds clamping, and packet deduplication. Corrupted packets and truncated frames are quarantined without modifying source bytes.
            </p>
          </div>
        </div>

        <div className="editorial-hr-subtle" />

        <div className="security-integrity-row">
          <div className="integrity-row-title">
            <span>02</span>
            <h2>FEATURE INTEGRITY</h2>
          </div>
          <div className="integrity-row-content">
            <p>
              Adheres to a canonical 45-dimensional feature schema comprising 17 flow behavior metrics, 22 packet distribution statistics, and 6 temporal deltas. The disputed <code>mean_tcp_rtt</code> is strictly omitted under a zero-fabrication contract.
            </p>
          </div>
        </div>

        <div className="editorial-hr-subtle" />

        <div className="security-integrity-row">
          <div className="integrity-row-title">
            <span>03</span>
            <h2>FORECAST INTEGRITY</h2>
          </div>
          <div className="integrity-row-content">
            <p>
              Enforces calibrated abstention when temporal lookback history is insufficient (&lt; 8 discrete 60-second windows). All multi-step projections across horizons T+1 through T+5 are evaluated against the validated Persistence Champion baseline.
            </p>
          </div>
        </div>

        <div className="editorial-hr-subtle" />

        <div className="security-integrity-row">
          <div className="integrity-row-title">
            <span>04</span>
            <h2>EVIDENCE INTEGRITY</h2>
          </div>
          <div className="integrity-row-content">
            <p>
              Every forecast probability is decomposed into supporting vs contradictory telemetry indicators via Feature Perturbation Attribution. Telemetry deltas are directly attributed to physical feature shifts rather than uninterpretable scalar outputs.
            </p>
          </div>
        </div>

        <div className="editorial-hr-subtle" />

        <div className="security-integrity-row">
          <div className="integrity-row-title">
            <span>05</span>
            <h2>REPORT INTEGRITY</h2>
          </div>
          <div className="integrity-row-content">
            <p>
              Forensic analysis dossiers compile deterministic SHA-256 Content Hashes of raw source capture files, window aggregation states, and model weight checkpoints, providing immutable cryptographic chain-of-custody for audit verification.
            </p>
          </div>
        </div>
      </section>

      <div className="editorial-hr" />

      {/* Modelled Counterfactual Note */}
      <section className="security-counterfactual-note">
        <div className="editorial-meta-tag">GOVERNANCE PRINCIPLE</div>
        <p>
          Counterfactual simulations represent <strong>Modelled Counterfactuals</strong> for proactive posture evaluation under feature perturbation hypotheses. They do not constitute an absolute attack prevention guarantee.
        </p>
        <div style={{ marginTop: '24px' }}>
          <Link to="/analyze" className="button button-primary">
            Launch Console
          </Link>
        </div>
      </section>
    </div>
  )
}
