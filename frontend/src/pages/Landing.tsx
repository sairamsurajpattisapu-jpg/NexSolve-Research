import { useState } from 'react'
import { Link } from 'react-router-dom'
import {
  Activity,
  ArrowRight,
  CheckCircle2,
  Layers,
  Radar,
  ShieldAlert,
  ShieldCheck,
  Sparkles,
  TrendingUp,
} from 'lucide-react'
import { Panel } from '../components/Ui'

const PIPELINE_STEPS = [
  {
    step: '01',
    id: 'ingest',
    title: 'Packet Ingestion & Integrity',
    eyebrow: 'CANONICAL VALIDATION',
    description:
      'Zero-loss streaming parser ingests .pcap and .pcapng captures up to 64 MB. Enforces magic-byte verification, microsecond timestamp sorting, snaplen bounds, and deterministic deduplication.',
    tech: 'Magic byte check · IPv4/IPv6 · TCP/UDP/ICMP · VLAN handling',
  },
  {
    step: '02',
    id: 'flows',
    title: 'Flow Assembly & TCP Telemetry',
    eyebrow: 'TELEMETRY RECONSTRUCTION',
    description:
      'Reconstructs bidirectional 5-tuple flow records from raw packet sequences. Tracks TCP handshake state transitions, payload byte ratios, retransmissions, and inter-arrival timing without synthetic assumptions.',
    tech: '5-tuple flow hashing · SYN/ACK/FIN tracking · IAT histograms',
  },
  {
    step: '03',
    id: 'windows',
    title: 'Temporal Window Aggregation',
    eyebrow: 'TEMPORAL DISCRETIZATION',
    description:
      'Slices reconstructed flow telemetry into deterministic 60-second sliding analysis windows. Tracks packet rates, active flow counts, and volume velocity across continuous time intervals.',
    tech: '60-second windows · Microsecond window boundaries · Rate evolution',
  },
  {
    step: '04',
    id: 'state',
    title: '45-Feature Network State Vector',
    eyebrow: 'DIMENSIONAL STATE VECTOR',
    description:
      'Constructs canonical 45-feature state representations: 17 flow behavior metrics, 22 packet distribution statistics, and 6 temporal deltas. Strictly omits mean_tcp_rtt under a zero-fabrication contract.',
    tech: '17 flow features · 22 packet features · 6 temporal deltas · Zero RTT fabrication',
  },
  {
    step: '05',
    id: 'forecast',
    title: 'Multi-Step Threat Forecasting',
    eyebrow: 'TEMPORAL TRAJECTORY (T+1..T+5)',
    description:
      'Evaluates 8 historical windows (X_t) to project attack probability across horizons T+1 through T+5. Benchmarked against the validated Persistence champion model, with the LSTM45 candidate disclosed under scientific HOLD.',
    tech: 'Persistence Champion · LSTM45 Candidate · 5-horizon projection · Calibration error bounds',
  },
  {
    step: '06',
    id: 'horizon',
    title: 'Attack Horizon Synthesis',
    eyebrow: 'PREDICTIVE TIMELINE',
    description:
      'Calculates the earliest sustained threat onset horizon, estimated lead time in seconds, temporal consistency, and confidence intervals to provide proactive defense posture before incidents materialize.',
    tech: 'Lead-time computation · Onset window detection · Dynamic severity rating',
  },
  {
    step: '07',
    id: 'evidence',
    title: 'Causal Evidence Chain',
    eyebrow: 'EXPLAINABLE ATTRIBUTION',
    description:
      'Maps observed feature shifts directly to forecast decisions. Classifies telemetry deltas into supporting vs contradictory evidence nodes with magnitude, direction, and domain-grounded rationale.',
    tech: 'Supporting vs contradictory · Feature delta weights · Forensic causal graph',
  },
  {
    step: '08',
    id: 'trust',
    title: 'Trust Guardrails & Signed Reports',
    eyebrow: 'SCIENTIFIC INTEGRITY',
    description:
      'Enforces calibrated abstention when capture history is insufficient (< 8 windows) or capture quality degrades. Compiles immutable SHA-256 signed forensic reports for auditability.',
    tech: 'Calibrated abstention · Out-of-distribution detection · SHA-256 cryptographic audit',
  },
]

export function Landing() {
  const [activeStep, setActiveStep] = useState(0)
  const currentStep = PIPELINE_STEPS[activeStep]

  return (
    <div className="page-stack page-enter landing-container">
      {/* Hero Section */}
      <section className="landing-hero">
        <div className="landing-hero-content">
          <div className="landing-badge-row">
            <span className="provenance-pill status-pill">SIH PROBLEM STATEMENT 26153</span>
            <span className="provenance-pill reference-pill">ENTERPRISE TELEMETRY ENGINE</span>
            <span className="provenance-pill live-pill">PCAP & PCAPNG COMPATIBLE</span>
          </div>

          <h1 className="landing-title">
            NEXSOLVE <span className="text-gradient">— Network Attack Forecasting</span>
          </h1>

          <p className="landing-tagline">
            See where the network is heading — <span className="highlight-tag">not just where it has been.</span>
          </p>

          <p className="landing-lead">
            NexSolve transforms raw network packet captures into multi-step temporal state trajectories.
            By projecting attack probabilities across <strong>T+1 to T+5</strong> horizons, estimating an <strong>Attack Horizon</strong>,
            and attributing causal shifts via an <strong>Evidence Chain</strong>, security teams gain actionable lead time before threats strike.
          </p>

          <div className="landing-cta-row">
            <Link to="/analyze" className="button landing-primary-btn">
              <Radar size={16} /> Analyze a PCAP Capture
            </Link>
            <Link to="/demo" className="button button-quiet landing-demo-btn">
              <Sparkles size={16} color="var(--accent)" /> Explore Judge Demo
            </Link>
            <a href="#pipeline-tour" className="button button-quiet landing-tour-btn">
              How it works <ArrowRight size={14} />
            </a>
          </div>
        </div>

        {/* Hero Interactive Engine Widget */}
        <div className="landing-hero-widget">
          <Panel className="engine-card">
            <div className="engine-card-header">
              <div className="engine-status-pulse">
                <span className="status-dot status-success" />
                <span className="engine-status-text">PIPELINE CORE ACTIVE</span>
              </div>
              <span className="engine-ver">v2.4.1 · 45-DIM CONTRACT</span>
            </div>

            <div className="engine-flow-diagram" aria-label="Interactive pipeline stages">
              <div className="flow-nodes-row">
                <button
                  type="button"
                  className={`flow-node ${activeStep === 0 || activeStep === 1 ? 'active' : ''}`}
                  onClick={() => setActiveStep(0)}
                  title="Step 1: Capture & Ingestion"
                >
                  <Activity size={18} />
                  <span>Packets</span>
                </button>
                <div className="flow-arrow">→</div>
                <button
                  type="button"
                  className={`flow-node ${activeStep === 2 || activeStep === 3 ? 'active' : ''}`}
                  onClick={() => setActiveStep(2)}
                  title="Step 2: 60s Windows & 45-Feature State"
                >
                  <Layers size={18} />
                  <span>Windows</span>
                </button>
                <div className="flow-arrow">→</div>
                <button
                  type="button"
                  className={`flow-node ${activeStep === 4 ? 'active' : ''}`}
                  onClick={() => setActiveStep(4)}
                  title="Step 3: Multi-Step Forecasting (T+1..T+5)"
                >
                  <TrendingUp size={18} />
                  <span>Forecast</span>
                </button>
                <div className="flow-arrow">→</div>
                <button
                  type="button"
                  className={`flow-node ${activeStep === 5 || activeStep === 6 ? 'active' : ''}`}
                  onClick={() => setActiveStep(5)}
                  title="Step 4: Attack Horizon & Evidence"
                >
                  <ShieldAlert size={18} />
                  <span>Horizon</span>
                </button>
              </div>

              <div className="engine-preview-box">
                <div className="preview-eyebrow">STAGE {currentStep.step} / 08 · {currentStep.eyebrow}</div>
                <h4 className="preview-title">{currentStep.title}</h4>
                <p className="preview-desc">{currentStep.description}</p>
                <div className="preview-tech">
                  <strong>Mechanisms:</strong> {currentStep.tech}
                </div>
              </div>

              <div className="engine-card-footer">
                <div className="engine-stat">
                  <span className="engine-stat-label">Temporal Window</span>
                  <span className="engine-stat-val">60s Discrete</span>
                </div>
                <div className="engine-stat">
                  <span className="engine-stat-label">Model Contract</span>
                  <span className="engine-stat-val">45 Features</span>
                </div>
                <div className="engine-stat">
                  <span className="engine-stat-label">Forecast Horizons</span>
                  <span className="engine-stat-val">T+1 .. T+5</span>
                </div>
              </div>
            </div>
          </Panel>
        </div>
      </section>

      {/* Scientific Principles & Guarantees */}
      <section className="landing-principles">
        <div className="section-title-wrap">
          <span className="eyebrow" style={{ color: 'var(--accent)' }}>SCIENTIFIC HONESTY & DEFENSIVE GUARANTEES</span>
          <h2>Built for Real Security Operations, Not Benchmark Theater</h2>
          <p>
            Unlike black-box detectors that output arbitrary future guesses, NexSolve adheres to verifiable statistical contracts
            and transparent defense principles.
          </p>
        </div>

        <div className="principles-grid">
          <Panel className="principle-card">
            <div className="principle-icon-wrap" style={{ color: 'var(--accent)' }}>
              <CheckCircle2 size={22} />
            </div>
            <h3>Zero-Fabrication Feature Contract</h3>
            <p>
              Passive PCAPs cannot observe TCP round-trip times without client-side assumptions.
              NexSolve eliminates <code>mean_tcp_rtt</code> from the PCAP model schema, strictly refusing to zero-fill or fabricate missing physical metrics.
            </p>
          </Panel>

          <Panel className="principle-card">
            <div className="principle-icon-wrap" style={{ color: 'var(--warning)' }}>
              <TrendingUp size={22} />
            </div>
            <h3>Persistence Champion Baseline</h3>
            <p>
              All ML candidates must empirically outperform a strict temporal Persistence baseline without temporal leakage.
              When our research LSTM45 candidate failed to beat Persistence across all 5 horizons, it was placed on scientific <code>HOLD</code>.
            </p>
          </Panel>

          <Panel className="principle-card">
            <div className="principle-icon-wrap" style={{ color: 'var(--danger)' }}>
              <ShieldCheck size={22} />
            </div>
            <h3>Calibrated Forecast Abstention</h3>
            <p>
              If a capture has fewer than 8 temporal windows ($&lt; 8$ minutes of history) or degraded capture quality,
              NexSolve explicitly withholds its forecast rather than hallucinating unreliable future risk.
            </p>
          </Panel>
        </div>
      </section>

      {/* 8-Stage Interactive Product Tour */}
      <section id="pipeline-tour" className="landing-pipeline-section">
        <div className="section-title-wrap">
          <span className="eyebrow" style={{ color: 'var(--accent)' }}>INTERACTIVE PRODUCT TOUR</span>
          <h2>From Packets to Prediction: The 8-Stage Pipeline</h2>
          <p>
            Follow how NexSolve processes raw network traffic deterministically from the wire to actionable foresight.
          </p>
        </div>

        <div className="pipeline-tour-grid">
          <div className="tour-nav-list" role="tablist">
            {PIPELINE_STEPS.map((s, idx) => (
              <button
                key={s.id}
                type="button"
                role="tab"
                aria-selected={activeStep === idx}
                className={`tour-nav-item ${activeStep === idx ? 'active' : ''}`}
                onClick={() => setActiveStep(idx)}
              >
                <span className="tour-step-num">{s.step}</span>
                <div className="tour-nav-text">
                  <strong>{s.title}</strong>
                  <small>{s.eyebrow}</small>
                </div>
              </button>
            ))}
          </div>

          <div className="tour-detail-card">
            <Panel>
              <div className="tour-detail-header">
                <span className="eyebrow" style={{ color: 'var(--accent)' }}>
                  STAGE {currentStep.step} OF 08 · {currentStep.eyebrow}
                </span>
                <h3>{currentStep.title}</h3>
              </div>

              <p className="tour-detail-body">{currentStep.description}</p>

              <div className="tour-tech-callout">
                <span className="eyebrow">VERIFIED SPECIFICATIONS</span>
                <p>{currentStep.tech}</p>
              </div>

              <div className="tour-actions-row">
                <button
                  type="button"
                  className="button button-quiet"
                  disabled={activeStep === 0}
                  onClick={() => setActiveStep(Math.max(0, activeStep - 1))}
                >
                  Previous Stage
                </button>
                <button
                  type="button"
                  className="button"
                  disabled={activeStep === PIPELINE_STEPS.length - 1}
                  onClick={() => setActiveStep(Math.min(PIPELINE_STEPS.length - 1, activeStep + 1))}
                >
                  Next Stage <ArrowRight size={14} />
                </button>
              </div>
            </Panel>
          </div>
        </div>
      </section>

      {/* SIH Judge Callout */}
      <section className="judge-callout-section">
        <Panel className="judge-banner">
          <div className="judge-banner-content">
            <div className="judge-badge-wrap">
              <Sparkles size={20} color="var(--accent)" />
              <span className="eyebrow" style={{ color: 'var(--accent)', margin: 0 }}>
                EVALUATION READY · SIH JURY QUICK START
              </span>
            </div>
            <h2>Evaluate NexSolve in 60 Seconds</h2>
            <p>
              Explore our 7 deterministic evaluation scenarios covering normal traffic baselines, early attack signals,
              sustained attack forecasts, contradictory indicators, unknown protocol shifts, abstention guardrails, and poor capture quality.
            </p>
            <div className="judge-actions">
              <Link to="/demo" className="button">
                Open Judge Demo Explorer <ArrowRight size={15} />
              </Link>
              <Link to="/analyze" className="button button-quiet">
                Inspect Real PCAP Pipeline
              </Link>
            </div>
          </div>
        </Panel>
      </section>
    </div>
  )
}
