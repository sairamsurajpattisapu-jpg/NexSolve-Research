import { Link } from 'react-router-dom'
import { ArrowRight } from 'lucide-react'

export function Research() {
  return (
    <div className="page-stack page-enter research-editorial-container">
      {/* Paper Header */}
      <section className="editorial-page-header">
        <div className="editorial-meta-tag">
          RESEARCH PUBLICATION &middot; FORMAL METHODOLOGY SPECIFICATION
        </div>
        <h1 className="editorial-display-heading">
          Research &amp; Methodology
        </h1>
        <p className="editorial-lead-text">
          Discrete-time network state transitions, autoregressive trajectory simulation, and empirical evaluation across multi-step lookahead horizons.
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
          Network defense is formalized as a discrete-time partially observable state transition process. Continuous packet streams on passive monitoring interfaces are discretized into non-overlapping temporal windows of duration <span className="mono-inline">&Delta;t = 60s</span>. The objective is projecting conditional attack probability distributions across forward horizons without payload modification or active probing.
        </p>
        <div className="editorial-formula-box">
          <code>&Delta;t = 60s &nbsp;&middot;&nbsp; S_t &isin; &reals;^{'{45}'} &nbsp;&middot;&nbsp; h &isin; {'{1, 2, 3, 5}'} &nbsp;&middot;&nbsp; P(A_{'{t+h}'} | X_t)</code>
        </div>
      </section>

      <div className="editorial-hr-subtle" />

      {/* 02. State Representation */}
      <section className="research-paper-section">
        <div className="research-section-header">
          <span className="research-sec-num">02</span>
          <h2>State Representation (45-Feature Contract)</h2>
        </div>
        <p className="research-body">
          At each temporal epoch <span className="mono-inline">t</span>, the observed network state is condensed into a canonical vector <span className="mono-inline">S_t &isin; &reals;^{'{45}'}</span> strictly adhering to passive observability:
        </p>
        <div className="research-feature-grid">
          <div className="feature-group-card">
            <span className="feature-group-num">17</span>
            <strong>Flow Behavior Metrics</strong>
            <p>Active 5-tuple counts, byte velocity ratios, TCP handshake state transitions, and flag distributions.</p>
          </div>
          <div className="feature-group-card">
            <span className="feature-group-num">22</span>
            <strong>Packet Statistics</strong>
            <p>Inter-arrival time (IAT) moments, payload size percentiles, and protocol volume distributions.</p>
          </div>
          <div className="feature-group-card">
            <span className="feature-group-num">06</span>
            <strong>Temporal Rate Deltas</strong>
            <p>First-order inter-window derivative differences &Delta;S_t = S_t &minus; S_{'{t-1}'} capturing kinematic velocity.</p>
          </div>
        </div>
        <p className="research-body-note">
          <strong>Zero-Fabrication Contract:</strong> Passive network taps cannot verify TCP Round Trip Time without active injection. The disputed Mean TCP RTT metric (<span className="mono-inline">mean_tcp_rtt</span>) is strictly omitted from the canonical schema rather than synthetically imputed.
        </p>
      </section>

      <div className="editorial-hr-subtle" />

      {/* 03. Temporal Forecasting (T+1..T+5) */}
      <section className="research-paper-section">
        <div className="research-section-header">
          <span className="research-sec-num">03</span>
          <h2>Temporal Forecasting (T+1 .. T+5)</h2>
        </div>
        <p className="research-body">
          Given historical observation matrix <span className="mono-inline">{'X_t = [S_{t-7}, ..., S_t] in R^{8 x 45}'}</span> with lookback context <span className="mono-inline">K = 8</span> (480s continuous telemetry), the transition model projects forward states and cumulative risk bounds:
        </p>
        <div className="editorial-formula-box" style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
          <code>{'Autoregressive Rollout: S_hat_{t+h} = T_theta( S_hat_{t+h-1} ),  h in {1..5}'}</code>
          <code>{'Cumulative Horizon Risk: Risk(H) = 1 - Prod_{h=1}^{H} (1 - p_h)'}</code>
          <code>{'Attribution Sensitivity: Delta p = Sum_i ( partial p / partial x_i ) * Delta x_i'}</code>
        </div>
        <p className="research-body-note">
          Attribution deltas separate into <strong>Supporting Evidence</strong> (amplifying threat likelihood) and <strong>Contradictory Evidence</strong> (stabilizing normal operations), eliminating confirmation bias.
        </p>
      </section>

      <div className="editorial-hr-subtle" />

      {/* 04. Evaluation & Benchmarks */}
      <section className="research-paper-section">
        <div className="research-section-header">
          <span className="research-sec-num">04</span>
          <h2>Evaluation &amp; Benchmarks</h2>
        </div>
        <p className="research-body">
          Empirically evaluated on episodic network traffic benchmarks (UNSW-NB15 and CIC-IDS2017). Model calibration is quantified using the Brier Score metric:
        </p>
        <div className="editorial-formula-box">
          <code>{'Brier Score (BS) = (1 / N) * Sum_{n=1}^{N} (f_n - o_n)^2  (Lower = Superior Calibration)'}</code>
        </div>

        <div className="editorial-table-wrap" style={{ marginTop: '14px' }}>
          <table className="editorial-table">
            <thead>
              <tr>
                <th>Model Architecture</th>
                <th>Governance Status</th>
                <th>T+1 AUROC</th>
                <th>T+5 AUROC</th>
                <th>Brier Score</th>
                <th>Inference Latency</th>
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
                <td><span className="mono-inline">LINEAR BASELINE</span></td>
                <td>0.864</td>
                <td>0.792</td>
                <td>0.118</td>
                <td>&lt; 1 ms</td>
              </tr>
              <tr>
                <td>LSTM45 Candidate</td>
                <td><span className="mono-inline">HOLD DISCLOSURE</span></td>
                <td>0.887</td>
                <td>0.829</td>
                <td>0.142 (Overconfident)</td>
                <td>14 ms</td>
              </tr>
            </tbody>
          </table>
        </div>
        <p className="research-body-note">
          <strong>Champion Governance:</strong> In temporal network domains, state momentum frequently yields superior probabilistic calibration than over-parameterized recurrent networks. LSTM45 remains held in disclosure until outperforming across all lookahead horizons.
        </p>
      </section>

      <div className="editorial-hr-subtle" />

      {/* 05. Limitations & Future Work */}
      <section className="research-paper-section">
        <div className="research-section-header">
          <span className="research-sec-num">05</span>
          <h2>Limitations &amp; Future Work</h2>
        </div>
        <p className="research-body">
          Requires unencrypted Layer 4 flow metadata or continuous window summaries. Counterfactual simulations represent modelled sensitivities under feature perturbation hypotheses rather than physical causal guarantees. Telemetry captures with fewer than 8 continuous windows (&lt;480s) trigger deterministic calibrated abstention. Future work explores adaptive streaming calibration and cross-domain zero-shot transfer.
        </p>
      </section>

      <div className="editorial-hr" />

      {/* Editorial CTA - Single Canonical Action */}
      <section className="editorial-footer-cta">
        <div className="editorial-cta-wrap">
          <span className="editorial-eyebrow">REPRODUCIBLE RESEARCH</span>
          <h2>Verify findings against live network captures.</h2>
          <p>
            Upload standard PCAP wire captures or inspect pre-computed verification benchmarks in the console.
          </p>
          <div className="editorial-btn-group">
            <Link to="/console/analyze" className="button button-primary" style={{ gap: '6px' }}>
              <span>START</span> <ArrowRight size={13} />
            </Link>
          </div>
        </div>
      </section>
    </div>
  )
}
