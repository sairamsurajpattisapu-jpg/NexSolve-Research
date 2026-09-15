import { Link } from 'react-router-dom'

export function Research() {
  return (
    <div className="page-stack page-enter research-editorial-container">
      {/* Paper Header */}
      <section className="editorial-page-header">
        <div className="editorial-meta-tag">
          RESEARCH PAPER / METHODOLOGY SPECIFICATION
        </div>
        <h1 className="editorial-display-heading">
          Research & Formal Methodology
        </h1>
        <p className="editorial-lead-text">
          Discrete-time network state transitions, autoregressive trajectory simulation, and empirical evaluation.
        </p>
      </section>

      <div className="editorial-hr" />

      {/* 01. Problem Formulation */}
      <section className="research-paper-section">
        <div className="research-section-header">
          <span className="research-sec-num">01</span>
          <h2>Problem Formulation</h2>
        </div>
        <p className="research-body">
          We formalize network defense as a discrete-time partially observable state transition process.
          Continuous packet streams on passive monitoring interfaces are sliced into non-overlapping temporal windows of duration
          <span className="mono-inline"> Δt = 60s</span>. The objective is to project the conditional attack probability distribution
          over multiple forward lookahead horizons without modifying wire payloads.
        </p>
      </section>

      <div className="editorial-hr-subtle" />

      {/* 02. State Representation */}
      <section className="research-paper-section">
        <div className="research-section-header">
          <span className="research-sec-num">02</span>
          <h2>State Representation (45-Feature Canonical Contract)</h2>
        </div>
        <p className="research-body">
          At each temporal epoch <span className="mono-inline">t</span>, the network state is condensed into a canonical vector
          <span className="mono-inline"> S_t ∈ ℝ^45</span> comprising:
        </p>
        <ul className="research-list">
          <li><strong>17 Bidirectional Flow Metrics:</strong> 5-tuple active counts, byte velocity ratios, TCP handshake transition states, and retransmissions.</li>
          <li><strong>22 Packet Distribution Statistics:</strong> IAT histogram moments, size percentiles, and protocol volume distributions.</li>
          <li><strong>6 Temporal Rate Derivatives:</strong> Inter-window rate deltas <span className="mono-inline">{'ΔS = S_t - S_{t-1}'}</span>.</li>
        </ul>
        <p className="research-body-note">
          <em>Zero-Fabrication Contract:</em> Passive network taps cannot verify Round-Trip Time without active probing.
          The controversial <span className="mono-inline">mean_tcp_rtt</span> metric is strictly eliminated from the model schema rather than zero-filled.
        </p>
      </section>

      <div className="editorial-hr-subtle" />

      {/* 03. Temporal Context & Lookback */}
      <section className="research-paper-section">
        <div className="research-section-header">
          <span className="research-sec-num">03</span>
          <h2>Temporal Context & Autoregressive Simulation</h2>
        </div>
        <p className="research-body">
          {'Given historical observation matrix X_t = [S_{t-K+1}, ..., S_t] in R^{8 x 45} with lookback context K = 8 (480 seconds of continuous traffic), the transition model generates recursive autoregressive state projections:'}
        </p>
        <div className="editorial-formula-box">
          <code>{'S_hat_{t+h} = T_theta( S_hat_{t+h-1}, h_{t+h-1} ),  forall h in {1, 2, ..., 5}'}</code>
        </div>
      </section>

      <div className="editorial-hr-subtle" />

      {/* 04. Forecast Horizons */}
      <section className="research-paper-section">
        <div className="research-section-header">
          <span className="research-sec-num">04</span>
          <h2>Forecast Horizons & Survival Risk</h2>
        </div>
        <p className="research-body">
          Five discrete forward horizons are evaluated: <span className="mono-inline">T+1 (+60s), T+2 (+120s), T+3 (+180s), T+4 (+240s), T+5 (+300s)</span>.
          Cumulative survival attack risk over projection horizon <span className="mono-inline">H</span> is formulated as:
        </p>
        <div className="editorial-formula-box">
          <code>{'Risk(H) = 1 - Prod_{h=1}^{H} (1 - p_h)'}</code>
        </div>
        <p className="research-body-note">
          Lead time is computed directly from packet arrival timestamps. On aggregate benchmarks, the architecture achieves a 180s median lead time.
        </p>
      </section>

      <div className="editorial-hr-subtle" />

      {/* 05. Feature Perturbation Attribution */}
      <section className="research-paper-section">
        <div className="research-section-header">
          <span className="research-sec-num">05</span>
          <h2>Feature Perturbation Attribution</h2>
        </div>
        <p className="research-body">
          Predictions avoid black-box opacity by decomposing model sensitivity through Feature Perturbation Attribution.
          Observed telemetry deltas are classified into <strong>Supporting Evidence</strong> (amplifying threat likelihood) and
          <strong>Contradictory Evidence</strong> (stabilizing signals indicating normal operations), preventing false confirmation bias.
        </p>
      </section>

      <div className="editorial-hr-subtle" />

      {/* 06. Empirical Evaluation */}
      <section className="research-paper-section">
        <div className="research-section-header">
          <span className="research-sec-num">06</span>
          <h2>Evaluation & Champion Model Governance</h2>
        </div>
        <p className="research-body">
          Evaluated on the UNSW-NB15 episodic benchmark. In temporal network domains, simple baselines frequently exhibit superior calibration:
        </p>

        <div className="editorial-table-wrap">
          <table className="editorial-table">
            <thead>
              <tr>
                <th>Model</th>
                <th>Governance</th>
                <th>T+1 AUC</th>
                <th>T+5 AUC</th>
                <th>Brier Score</th>
                <th>Latency</th>
              </tr>
            </thead>
            <tbody>
              <tr>
                <td><strong>Persistence Champion</strong></td>
                <td><span className="mono-inline">VALIDATED CHAMPION</span></td>
                <td>0.912</td>
                <td>0.841</td>
                <td>0.084 (Calibrated)</td>
                <td>&lt; 1 ms</td>
              </tr>
              <tr>
                <td>Logistic Regression</td>
                <td><span className="mono-inline">BASELINE</span></td>
                <td>0.864</td>
                <td>0.792</td>
                <td>0.118</td>
                <td>&lt; 1 ms</td>
              </tr>
              <tr>
                <td>LSTM45 Candidate</td>
                <td><span className="mono-inline">SCIENTIFIC HOLD</span></td>
                <td>0.887</td>
                <td>0.829</td>
                <td>0.142 (Overconfident)</td>
                <td>14 ms</td>
              </tr>
            </tbody>
          </table>
        </div>
        <p className="research-body-note">
          <em>Scientific Hold:</em> The deep LSTM45 candidate remains demarcated under scientific hold due to higher Brier calibration error on extended rollouts.
        </p>
      </section>

      <div className="editorial-hr-subtle" />

      {/* 07. Limitations */}
      <section className="research-paper-section">
        <div className="research-section-header">
          <span className="research-sec-num">07</span>
          <h2>Limitations</h2>
        </div>
        <p className="research-body">
          Requires unencrypted layer-4 flow metadata or pre-extracted window summaries. Counterfactual simulations represent
          modelled sensitivities rather than physical intervention guarantees. Telemetry with fewer than 8 windows triggers calibrated abstention.
        </p>
      </section>

      <div className="editorial-hr" />

      {/* Bottom CTA */}
      <section className="editorial-footer-cta">
        <div className="editorial-cta-wrap">
          <span className="editorial-eyebrow">REPRODUCIBLE RESEARCH</span>
          <h2>Verify findings against live network captures.</h2>
          <div className="editorial-btn-group" style={{ marginTop: '20px' }}>
            <Link to="/analyze" className="button button-primary">
              Launch Console
            </Link>
            <Link to="/security" className="button button-secondary">
              Security Architecture
            </Link>
          </div>
        </div>
      </section>
    </div>
  )
}
