import { useState } from 'react'
import { Link } from 'react-router-dom'
import {
  ArrowRight,
  CheckCircle2,
  Terminal,
} from 'lucide-react'
import { Panel } from '../components/Ui'

interface StepDetail {
  step: string
  id: string
  title: string
  phase: string
  subheadline: string
  description: string
  contract: string
  features: string[]
  inputs: string
  outputs: string
}

const WORKFLOW_STEPS: StepDetail[] = [
  {
    step: '01',
    id: 'ingest',
    title: 'PCAP Ingestion & Wire Parsing',
    phase: 'INGEST',
    subheadline: 'Streaming packet parsing from live captures and offline files',
    description:
      'Ingests raw standard PCAP and PCAPNG capture formats. Enforces strict magic byte validation, microsecond wire timestamp preservation, wire length bounds checking, and packet deduplication without modifying source bytes.',
    contract: 'Libpcap / PcapNG wire format standard',
    features: ['Magic byte verification', 'Microsecond precision timestamps', 'Snaplen clamp validation', 'IPv4 & IPv6 dual-stack support'],
    inputs: 'Raw .pcap / .pcapng binary stream',
    outputs: 'Validated sequential packet stream with layer headers',
  },
  {
    step: '02',
    id: 'flows',
    title: 'Bidirectional Flow Assembly',
    phase: 'EXTRACT',
    subheadline: '5-tuple stream reassembly & TCP state machine tracking',
    description:
      'Reconstructs conversation sessions indexed by (src_ip, src_port, dst_ip, dst_port, protocol). Tracks full TCP connection lifecycles (SYN, SYN-ACK, ESTABLISHED, FIN/RST), byte transfers in forward/backward directions, inter-arrival times, and retransmissions.',
    contract: 'Bidirectional Flow Record Standard',
    features: ['5-tuple flow hashing', 'TCP 3-way handshake state machine', 'Forward / backward IAT computation', 'Window size scaling analysis'],
    inputs: 'Sequential packet stream',
    outputs: 'Reconstructed bidirectional flow records',
  },
  {
    step: '03',
    id: 'windows',
    title: 'Temporal Window Aggregation',
    phase: 'REPRESENT',
    subheadline: 'Deterministic time discretization into sliding observation epochs',
    description:
      'Aggregates asynchronous flow telemetry into fixed-duration (60s) observation epochs. Slices continuous network activity into structured temporal windows, measuring packet volume velocity, flow churn rate, and protocol distribution.',
    contract: 'Uniform Temporal Epoch Discretization (Δt = 60s)',
    features: ['Uniform 60-second windowing', 'Sub-millisecond epoch alignment', 'Flow birth & termination counting', 'Protocol ratio distribution'],
    inputs: 'Bidirectional flow records',
    outputs: 'Ordered temporal window telemetry summaries',
  },
  {
    step: '04',
    id: 'state',
    title: '45-Dimensional Network State Vector',
    phase: 'UNDERSTAND',
    subheadline: 'Zero-fabrication passive feature extraction contract',
    description:
      'Constructs the canonical 45-dimensional numerical state vector S_t. Comprises 17 flow behavior metrics, 22 packet distribution moments, and 6 temporal deltas. Strictly excludes synthetic approximations: mean_tcp_rtt is omitted under a validated zero-fabrication contract.',
    contract: 'NexSolve 45-Feature Passive PCAP Vector (zero fabrication)',
    features: ['17 flow behavior metrics', '22 packet distribution moments', '6 temporal rate deltas', 'Zero synthetic RTT interpolation'],
    inputs: 'Window telemetry summaries',
    outputs: 'Dense 45-dimensional feature vector S_t ∈ R^45',
  },
  {
    step: '05',
    id: 'simulation',
    title: 'World Model Simulation',
    phase: 'SIMULATE',
    subheadline: 'Recursive autoregressive state projection into future horizons',
    description:
      'Given an observation history window [S_{t-7}, ..., S_t], the temporal world model simulates plausible future network states [S_{t+1}, ..., S_{t+5}]. Rollouts preserve physical conservation laws while projecting attack perturbation trajectories.',
    contract: 'Autoregressive Discrete-Time Markov Transition Model',
    features: ['8-window historical context lookback', 'Multi-step autoregressive rollout', 'Physical feature boundary enforcement', 'State delta uncertainty bounds'],
    inputs: 'Lookback matrix X_t ∈ R^{8 × 45}',
    outputs: 'Simulated future state trajectory [S_{t+1}, ..., S_{t+5}]',
  },
  {
    step: '06',
    id: 'forecast',
    title: 'Multi-Horizon Threat Forecasting',
    phase: 'FORECAST',
    subheadline: 'Calibrated attack probability distribution across T+1 through T+5',
    description:
      'Computes risk probabilities across 5 discrete forecast horizons. Quantifies whether an active or emerging pattern will escalate into a sustained attack. Benchmarked against the validated Persistence Champion, with LSTM45 candidate under scientific governance.',
    contract: 'Multi-Horizon Forecast Probability Vector P(Attack | S_{t+h})',
    features: ['5-horizon probability vector (T+1..T+5)', 'Cumulative survival attack risk', 'Expected Attack Horizon onset lead-time', 'Calibrated confidence intervals'],
    inputs: 'Simulated state sequence [S_{t+1}..S_{t+5}]',
    outputs: 'Multi-horizon risk curves & Attack Horizon onset lead-time',
  },
  {
    step: '07',
    id: 'mitre',
    title: 'MITRE ATT&CK Behavioral Mapping',
    phase: 'INTERPRET',
    subheadline: 'Structural mapping of projected anomalies to adversary tactics',
    description:
      'Maps projected network state anomalies to MITRE ATT&CK Enterprise Matrix tactics and techniques. Distinguishes reconnaissance, initial access, command-and-control beaconing, lateral movement, and data exfiltration patterns.',
    contract: 'MITRE ATT&CK Enterprise v14 Matrix Mapping',
    features: ['Reconnaissance (T1595, T1046)', 'Discovery & Lateral Movement (T1018, T1021)', 'Command & Control (T1071, T1573)', 'Exfiltration (T1048)'],
    inputs: 'Projected anomaly vector & flow signatures',
    outputs: 'Ranked MITRE ATT&CK tactical classifications',
  },
  {
    step: '08',
    id: 'evidence',
    title: 'Feature Perturbation Attribution & Drivers',
    phase: 'EXPLAIN',
    subheadline: 'Decomposing forecast drivers into supporting vs contradictory signals',
    description:
      'Identifies the empirical feature shifts driving the threat forecast. Bins observed telemetry changes into supporting evidence (accelerating risk) vs contradictory evidence (stabilizing factors), preventing black-box opacity.',
    contract: 'Feature Perturbation Attribution Model (Directional Weights)',
    features: ['Supporting evidence identification', 'Contradictory dampening factors', 'Magnitude & percent deviation scoring', 'Domain-grounded feature explanations'],
    inputs: 'Temporal state delta ΔS = S_t - S_{t-1}',
    outputs: 'Dual-binned forensic evidence graph with feature rationales',
  },
  {
    step: '09',
    id: 'governance',
    title: 'Audit Trail & Actionable Guidance',
    phase: 'ACT',
    subheadline: 'Deterministic report generation and cryptographic reproducibility',
    description:
      'Generates SHA-256 content-hashed audit dossiers containing packet capture hashes, extraction parameters, model version hashes, and recommended proactive posture adjustments.',
    contract: 'Cryptographic Audit & Zero-Trust Governance Protocol',
    features: ['SHA-256 payload & model hash', 'Calibrated abstention safety gate', 'Exportable JSON, CSV & Markdown dossier', 'Automated containment recommendations'],
    inputs: 'Forecast, MITRE tags, and feature drivers',
    outputs: 'Cryptographic forensic audit dossier & actionable containment plan',
  },
]

export function Workflow() {
  const [selectedIdx, setSelectedIdx] = useState(0)
  const current = WORKFLOW_STEPS[selectedIdx]

  return (
    <div className="page-stack page-enter workflow-page">
      {/* Header */}
      <section className="workflow-hero">
        <div className="workflow-hero-tag">
          <span className="provenance-pill status-pill">ARCHITECTURE SPECIFICATION</span>
          <span className="provenance-pill reference-pill">9-STEP FORECASTING ENGINE</span>
        </div>
        <h1 className="workflow-title">The NexSolve Workflow</h1>
        <p className="workflow-subtitle">
          From raw network wires to multi-horizon attack forecasting. How passive packet telemetry becomes explainable threat foresight.
        </p>
      </section>

      {/* Interactive Central Pipeline Visualizer */}
      <Panel className="pipeline-orchestrator-panel">
        <div className="orchestrator-header">
          <div>
            <span className="panel-eyebrow">INTERACTIVE SYSTEM PIPELINE</span>
            <h2 className="panel-title">End-to-End Telemetry Pipeline</h2>
          </div>
          <div className="orchestrator-step-indicator">
            STEP {current.step} / 09 · <span className="text-accent">{current.phase}</span>
          </div>
        </div>

        {/* Linear Step Bar */}
        <div className="pipeline-stepper-bar" role="tablist" aria-label="Pipeline Steps">
          {WORKFLOW_STEPS.map((s, idx) => {
            const isActive = idx === selectedIdx
            return (
              <button
                key={s.id}
                type="button"
                role="tab"
                aria-selected={isActive}
                onClick={() => setSelectedIdx(idx)}
                className={`step-bubble ${isActive ? 'active' : ''}`}
                title={`Step ${s.step}: ${s.title}`}
              >
                <span className="bubble-num">{s.step}</span>
                <span className="bubble-label">{s.phase}</span>
              </button>
            )
          })}
        </div>

        {/* Active Stage Detailed View */}
        <div className="stage-detail-card">
          <div className="stage-meta-row">
            <span className="provenance-pill live-pill">PHASE: {current.phase}</span>
            <span className="stage-contract-tag">{current.contract}</span>
          </div>

          <h3 className="stage-title">{current.step}. {current.title}</h3>
          <p className="stage-subheadline">{current.subheadline}</p>
          <p className="stage-desc">{current.description}</p>

          <div className="stage-io-grid">
            <div className="io-box">
              <span className="io-label">INPUT CONTRACT</span>
              <span className="io-val">{current.inputs}</span>
            </div>
            <div className="io-box">
              <span className="io-label">OUTPUT ARTIFACT</span>
              <span className="io-val">{current.outputs}</span>
            </div>
          </div>

          <div className="stage-features-wrap">
            <span className="features-label">KEY ARCHITECTURAL GUARANTEES</span>
            <div className="features-chips">
              {current.features.map((f, i) => (
                <div key={i} className="feature-chip">
                  <CheckCircle2 size={13} className="text-accent" />
                  <span>{f}</span>
                </div>
              ))}
            </div>
          </div>

          <div className="stage-nav-actions">
            <button
              type="button"
              className="button button-quiet"
              disabled={selectedIdx === 0}
              onClick={() => setSelectedIdx((prev) => Math.max(0, prev - 1))}
            >
              Previous Step
            </button>
            <span className="stage-counter">{selectedIdx + 1} of {WORKFLOW_STEPS.length}</span>
            <button
              type="button"
              className="button button-primary"
              disabled={selectedIdx === WORKFLOW_STEPS.length - 1}
              onClick={() => setSelectedIdx((prev) => Math.min(WORKFLOW_STEPS.length - 1, prev + 1))}
            >
              Next Step <ArrowRight size={14} />
            </button>
          </div>
        </div>
      </Panel>

      {/* Narrative 9-Step Story Grid */}
      <section className="workflow-narrative-section">
        <div className="section-heading-wrap">
          <span className="panel-eyebrow">IN-DEPTH SPECIFICATION</span>
          <h2 className="section-title">The Complete Pipeline Architecture</h2>
          <p className="section-desc">
            A step-by-step breakdown of how data moves from passive wire captures to predictive SOC early warning.
          </p>
        </div>

        <div className="narrative-cards-grid">
          {WORKFLOW_STEPS.map((s, idx) => (
            <div
              key={s.id}
              className={`narrative-step-card ${selectedIdx === idx ? 'focused' : ''}`}
              onClick={() => setSelectedIdx(idx)}
            >
              <div className="step-card-header">
                <span className="step-badge">{s.step}</span>
                <span className="step-phase-tag">{s.phase}</span>
              </div>
              <h3 className="step-card-title">{s.title}</h3>
              <p className="step-card-desc">{s.description}</p>
              <div className="step-card-footer">
                <span className="contract-chip">{s.contract}</span>
              </div>
            </div>
          ))}
        </div>
      </section>

      {/* CTA Strip */}
      <section className="workflow-cta-strip">
        <div className="cta-strip-content">
          <h2>Test the pipeline with your own capture file</h2>
          <p>
            Upload any standard .pcap or .pcapng capture to verify feature extraction, multi-horizon rollouts, and feature driver attribution in real time.
          </p>
        </div>
        <div className="cta-strip-actions">
          <Link to="/analyze" className="button button-primary">
            <Terminal size={15} /> Launch Console
          </Link>
          <Link to="/research" className="button button-quiet">
            View Research & Benchmarks
          </Link>
        </div>
      </section>
    </div>
  )
}
