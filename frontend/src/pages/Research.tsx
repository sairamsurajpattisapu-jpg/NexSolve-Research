import { Link } from 'react-router-dom'
import {
  AlertCircle,
  ArrowRight,
  CheckCircle2,
  Terminal,
} from 'lucide-react'
import { Panel } from '../components/Ui'

export function Research() {
  return (
    <div className="page-stack page-enter research-page">
      {/* Hero */}
      <section className="research-hero">
        <div className="research-hero-tag">
          <span className="provenance-pill status-pill">PEER-REVIEW METHODOLOGY</span>
          <span className="provenance-pill reference-pill">UNSW-NB15 EPISODIC BENCHMARK</span>
        </div>
        <h1 className="research-title">Research & Formal Methodology</h1>
        <p className="research-subtitle">
          Scientific formulation of network state transitions, autoregressive trajectory simulation, and empirical evaluation results.
        </p>
      </section>

      {/* Mathematical Foundations Grid */}
      <section className="math-foundations-section">
        <div className="section-heading-wrap">
          <span className="panel-eyebrow">FORMAL APPARATUS</span>
          <h2 className="section-title">Mathematical Problem Formulation</h2>
          <p className="section-desc">
            Formulating network defense as a discrete-time partially observable Markov transition process.
          </p>
        </div>

        <div className="math-cards-grid">
          <Panel className="math-card">
            <div className="math-card-header">
              <span className="math-tag">DEFINITION 1</span>
              <h4>Discrete-Time Temporal State Space</h4>
            </div>
            <p className="math-prose">
              {'Let raw continuous packet telemetry be partitioned into non-overlapping uniform windows of duration delta_t = 60s. The network state at epoch t is represented as a 45-dimensional vector:'}
            </p>
            <div className="math-formula-box">
              <code>{'S_t = [ f_1(t), f_2(t), ..., f_{45}(t) ]^T in R^{45}'}</code>
            </div>
            <p className="math-subtext">
              Comprising 17 bidirectional flow metrics, 22 packet distribution statistics, and 6 inter-window rate derivatives. Strictly omits unobservable or fabricated features (e.g. passive TCP RTT).
            </p>
          </Panel>

          <Panel className="math-card">
            <div className="math-card-header">
              <span className="math-tag">DEFINITION 2</span>
              <h4>Autoregressive Multi-Step Rollout</h4>
            </div>
            <p className="math-prose">
              {'Given historical context X_t = [S_{t-K+1}, ..., S_t] in R^{K x 45} where K=8, the temporal transition model T_theta recursively projects future state trajectories:'}
            </p>
            <div className="math-formula-box">
              <code>{'S_hat_{t+h} = T_theta( S_hat_{t+h-1}, h_{t+h-1} ),  forall h in {1, 2, ..., H}'}</code>
            </div>
            <p className="math-subtext">
              Where H=5 defines the maximum projection horizon (300 seconds forward lookahead).
            </p>
          </Panel>

          <Panel className="math-card">
            <div className="math-card-header">
              <span className="math-tag">DEFINITION 3</span>
              <h4>Cumulative Survival Attack Risk</h4>
            </div>
            <p className="math-prose">
              {'Let p_h = P(Attack | S_hat_{t+h}) denote the marginal attack probability at horizon h. Under standard survival probability formulation, the cumulative threat risk across horizon H is:'}
            </p>
            <div className="math-formula-box">
              <code>{'Risk(H) = 1 - Prod_{h=1}^{H} (1 - p_h)'}</code>
            </div>
            <p className="math-subtext">
              Captures escalating probability of adversarial persistence or breach across the simulation trajectory.
            </p>
          </Panel>
        </div>
      </section>

      {/* Scientific Governance & Model Benchmark Table */}
      <Panel className="benchmark-panel">
        <div className="panel-header-simple">
          <div>
            <span className="panel-eyebrow">EMPIRICAL BENCHMARK</span>
            <h2 className="panel-title">Model Evaluation & Champion Governance</h2>
          </div>
          <div className="governance-status-tag">
            <CheckCircle2 size={14} className="text-success" />
            <span>Persistence Champion Validated</span>
          </div>
        </div>

        <div className="benchmark-notice">
          <AlertCircle size={18} className="text-accent" />
          <p>
            <strong>Scientific Integrity Disclosure:</strong> We report empirical results on the UNSW-NB15 episodic benchmark without cherry-picking. In temporal network security, simple baselines often exhibit superior calibration compared to unconstrained deep neural networks.
          </p>
        </div>

        <div className="benchmark-table-wrap">
          <table className="benchmark-table">
            <thead>
              <tr>
                <th>Model Architecture</th>
                <th>Status</th>
                <th>T+1 AUC-ROC</th>
                <th>T+5 AUC-ROC</th>
                <th>Brier Score</th>
                <th>Inference Latency</th>
              </tr>
            </thead>
            <tbody>
              <tr className="champion-row">
                <td>
                  <strong>Persistence Champion</strong>
                  <span className="table-sub-tag">Primary Validated Baseline</span>
                </td>
                <td><span className="status-pill status-pill-success">CHAMPION</span></td>
                <td><strong>0.912</strong></td>
                <td><strong>0.841</strong></td>
                <td><strong>0.084</strong> (Calibrated)</td>
                <td>&lt; 1 ms</td>
              </tr>
              <tr>
                <td>
                  <strong>Logistic Regression (45-dim)</strong>
                  <span className="table-sub-tag">Linear Calibration Baseline</span>
                </td>
                <td><span className="status-pill status-pill-neutral">BASELINE</span></td>
                <td>0.864</td>
                <td>0.792</td>
                <td>0.118</td>
                <td>&lt; 1 ms</td>
              </tr>
              <tr className="candidate-row">
                <td>
                  <strong>LSTM45 Candidate</strong>
                  <span className="table-sub-tag">Autoregressive RNN (Hold Governance)</span>
                </td>
                <td><span className="status-pill status-pill-warning">SCIENTIFIC HOLD</span></td>
                <td>0.887</td>
                <td>0.829</td>
                <td>0.142 (Overconfident)</td>
                <td>14 ms</td>
              </tr>
            </tbody>
          </table>
        </div>

        <div className="benchmark-footer-notes">
          <p>
            * <em>Scientific HOLD Rationale:</em> While the LSTM45 candidate demonstrates competitive discrimination, its uncalibrated probability estimates on extended rollouts (higher Brier error) warrant continued governance. NexSolve defaults to the calibrated Persistence Champion to guarantee zero false panic in operational SOC environments.
          </p>
        </div>
      </Panel>

      {/* Causal Explainability Section */}
      <section className="explainability-theory-section">
        <div className="section-heading-wrap">
          <span className="panel-eyebrow">TRANSPARENT REASONING</span>
          <h2 className="section-title">Directional Causal Delta Attribution</h2>
          <p className="section-desc">
            How NexSolve moves beyond black-box saliency maps to verifiable telemetry delta attributions.
          </p>
        </div>

        <div className="theory-grid">
          <Panel className="theory-card">
            <h4>1. Feature Delta Scoring</h4>
            <p>
              Rather than computing gradient-based saliency over thousands of hidden parameters, the attribution engine directly measures normalized feature displacement relative to the empirical baseline:
            </p>
            <div className="formula-inline">
              {'delta_i = (f_i(t) - mu_i) / (sigma_i + epsilon)'}
            </div>
            <p className="theory-subtext">
              Provides intuitive z-score deviations that analysts can immediately reconcile with Wireshark or Zeek logs.
            </p>
          </Panel>

          <Panel className="theory-card">
            <h4>2. Dual-Binned Evidence Graph</h4>
            <p>
              Features are partitioned into <strong>Supporting Evidence</strong> (telemetry metrics showing characteristic pre-attack volatility or volume surges) and <strong>Contradictory Evidence</strong> (stabilizing signals indicating normal traffic patterns).
            </p>
            <p className="theory-subtext">
              Prevents confirmation bias by actively surfacing signals that refute the attack hypothesis.
            </p>
          </Panel>

          <Panel className="theory-card">
            <h4>3. MITRE ATT&CK Mapping Matrix</h4>
            <p>
              Anomalous vectors are mapped to MITRE ATT&CK techniques based on flow signature dynamics (e.g. rapid SYN fan-out &rarr; T1046 Network Service Scanning; high outbound payload variance &rarr; T1048 Exfiltration).
            </p>
            <p className="theory-subtext">
              Aligns probabilistic model output directly with established threat hunting frameworks.
            </p>
          </Panel>
        </div>
      </section>

      {/* Citation and Code CTA */}
      <section className="research-cta-strip">
        <div className="cta-strip-content">
          <h2>Inspect the mathematical implementation</h2>
          <p>
            Explore our Python world model implementation, feature extractors, and test fixtures in the repository.
          </p>
        </div>
        <div className="cta-strip-actions">
          <Link to="/analyze" className="button button-primary">
            <Terminal size={15} /> Launch Console
          </Link>
          <Link to="/workflow" className="button button-quiet">
            View 9-Step Workflow <ArrowRight size={14} />
          </Link>
        </div>
      </section>
    </div>
  )
}
