import { useState } from 'react'
import { Link } from 'react-router-dom'
import { Panel } from '../components/Ui'

const PIPELINE_STEPS = [
  {
    step: '01',
    id: 'ingest',
    title: 'Packet Ingestion & Integrity',
    eyebrow: 'CANONICAL VALIDATION',
    description:
      'Streaming PCAP and PCAPNG parser with deterministic validation. Enforces magic-byte verification, microsecond timestamp sorting, snaplen bounds, and packet deduplication.',
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
      'Slices reconstructed flow telemetry into deterministic 60-second analysis windows. Tracks packet rates, active flow counts, and volume velocity across continuous time intervals.',
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
      'Calculates the earliest sustained threat onset horizon, estimated lead time in seconds, temporal consistency, and confidence intervals to provide proactive decision support before incidents materialize.',
    tech: 'Lead-time computation · Onset window detection · Dynamic severity rating',
  },
  {
    step: '07',
    id: 'evidence',
    title: 'Feature Drivers & Evidence Analysis',
    eyebrow: 'EXPLAINABLE ATTRIBUTION',
    description:
      'Maps observed feature shifts directly to forecast decisions. Classifies telemetry deltas into supporting vs contradictory evidence nodes using Feature Perturbation Attribution and domain-grounded rationale.',
    tech: 'Supporting vs contradictory · Feature perturbation attribution · Ablation analysis',
  },
  {
    step: '08',
    id: 'trust',
    title: 'Trust Guardrails & Cryptographic Reports',
    eyebrow: 'SCIENTIFIC INTEGRITY',
    description:
      'Enforces calibrated abstention when capture history is insufficient (< 8 windows) or capture quality degrades. Compiles immutable SHA-256 cryptographic reports for forensic auditability.',
    tech: 'Calibrated abstention · Out-of-distribution detection · SHA-256 cryptographic hash',
  },
]

export function Landing() {
  const [activeStep, setActiveStep] = useState(0)
  const [openFaq, setOpenFaq] = useState<number | null>(null)
  const currentStep = PIPELINE_STEPS[activeStep]

  const faqs = [
    {
      q: 'What does NexSolve forecast?',
      a: 'NexSolve models continuous network behavior from passive packet telemetry and predicts future attack probabilities and stage transitions across multiple discrete forward horizons (T+1 through T+5).',
    },
    {
      q: 'What data does NexSolve accept?',
      a: 'NexSolve ingests raw standard PCAP and PCAPNG capture files, as well as 60-second windowed flow telemetry CSV files.',
    },
    {
      q: 'What is the 45-feature contract?',
      a: 'A canonical schema comprising 17 flow behavior metrics, 22 packet distribution statistics, and 6 temporal derivatives. Unobservable metrics like mean_tcp_rtt are strictly excluded under a zero-fabrication contract.',
    },
    {
      q: 'What are T+1 through T+5?',
      a: 'Discrete 60-second forward lookahead horizons, representing projected network risk states at +60s, +120s, +180s, +240s, and +300s into the future.',
    },
    {
      q: 'How does NexSolve explain a forecast?',
      a: 'Predictions are decomposed into supporting vs contradictory telemetry indicators using Feature Perturbation Attribution, revealing exact state drivers without black-box opacity.',
    },
    {
      q: 'What does lead time mean?',
      a: 'The temporal delta in seconds between forecast detection and projected threat onset. For individual captures, lead time is computed directly from packet arrival timestamps.',
    },
    {
      q: 'Is the counterfactual simulation a guarantee of attack prevention?',
      a: 'No. Simulation is a Modelled Counterfactual that evaluates future rollout sensitivity under synthetic feature perturbations to provide decision support.',
    },
    {
      q: 'What happens when input data is insufficient?',
      a: 'If a capture contains fewer than 8 temporal windows (< 8 minutes of context) or severe packet loss, NexSolve enforces calibrated abstention and withholds the forecast.',
    },
  ]

  return (
    <div className="page-stack page-enter landing-container">
      {/* Hero Section */}
      <section className="landing-hero">
        <div className="landing-hero-content">
          <span className="provenance-pill status-pill" style={{ alignSelf: 'flex-start' }}>
            SIH PROBLEM STATEMENT 26153
          </span>

          <h1 className="landing-title">
            NEXSOLVE <span className="text-gradient">— Network Attack Forecasting</span>
          </h1>

          <p className="landing-lead">
            Forecast how network attack-state behavior may evolve across multiple future horizons.
          </p>

          <div className="landing-cta-row">
            <Link to="/analyze" className="button landing-primary-btn">
              Analyze PCAP
            </Link>
            <Link to="/workflow" className="button button-quiet landing-tour-btn">
              Explore Workflow
            </Link>
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
              <span className="engine-ver">45-FEATURE CANONICAL CONTRACT</span>
            </div>

            <div className="engine-flow-diagram" aria-label="Interactive pipeline stages">
              <div className="flow-nodes-row">
                <button
                  type="button"
                  className={`flow-node ${activeStep === 0 || activeStep === 1 ? 'active' : ''}`}
                  onClick={() => setActiveStep(0)}
                >
                  <span>Packets</span>
                </button>
                <div className="flow-arrow">→</div>
                <button
                  type="button"
                  className={`flow-node ${activeStep === 2 || activeStep === 3 ? 'active' : ''}`}
                  onClick={() => setActiveStep(2)}
                >
                  <span>Windows</span>
                </button>
                <div className="flow-arrow">→</div>
                <button
                  type="button"
                  className={`flow-node ${activeStep === 4 ? 'active' : ''}`}
                  onClick={() => setActiveStep(4)}
                >
                  <span>Forecast</span>
                </button>
                <div className="flow-arrow">→</div>
                <button
                  type="button"
                  className={`flow-node ${activeStep === 5 || activeStep === 6 ? 'active' : ''}`}
                  onClick={() => setActiveStep(5)}
                >
                  <span>Horizon</span>
                </button>
              </div>

              <div className="engine-preview-box">
                <div className="preview-eyebrow">STAGE {currentStep.step} / 08 · {currentStep.eyebrow}</div>
                <h4 className="preview-title">{currentStep.title}</h4>
                <p className="preview-desc">{currentStep.description}</p>
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
          <span className="eyebrow" style={{ color: 'var(--accent)' }}>SCIENTIFIC INTEGRITY</span>
          <h2>Built for Defensive Security Operations</h2>
          <p>Adheres to verifiable statistical contracts and transparent defense principles.</p>
        </div>

        <div className="principles-grid">
          <Panel className="principle-card">
            <h3>Zero-Fabrication Contract</h3>
            <p>
              Eliminates <code>mean_tcp_rtt</code> from the PCAP model schema, strictly refusing to zero-fill or fabricate missing physical metrics.
            </p>
          </Panel>

          <Panel className="principle-card">
            <h3>Persistence Champion Baseline</h3>
            <p>
              All ML candidates must empirically outperform a strict temporal Persistence baseline without data leakage.
            </p>
          </Panel>

          <Panel className="principle-card">
            <h3>Calibrated Forecast Abstention</h3>
            <p>
              If a capture has fewer than 8 temporal windows (&lt; 8 minutes of history), NexSolve explicitly withholds its forecast.
            </p>
          </Panel>
        </div>
      </section>

      {/* 8-Stage Interactive Product Tour */}
      <section id="pipeline-tour" className="landing-pipeline-section">
        <div className="section-title-wrap">
          <span className="eyebrow" style={{ color: 'var(--accent)' }}>PIPELINE ARCHITECTURE</span>
          <h2>8-Stage Processing Pipeline</h2>
          <p>How NexSolve processes raw network traffic from the wire to multi-horizon forecasts.</p>
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
                <span className="eyebrow">MECHANISMS</span>
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
                  Next Stage
                </button>
              </div>
            </Panel>
          </div>
        </div>
      </section>

      {/* FAQ Accordion Section */}
      <section className="faq-section" style={{ marginTop: '24px' }}>
        <div className="section-title-wrap">
          <span className="eyebrow" style={{ color: 'var(--accent)' }}>FREQUENTLY ASKED QUESTIONS</span>
          <h2>System Operations & Methodology</h2>
        </div>

        <div className="faq-accordion" style={{ display: 'flex', flexDirection: 'column', gap: '10px', marginTop: '16px' }}>
          {faqs.map((faq, idx) => {
            const isOpen = openFaq === idx
            return (
              <div key={idx} className="panel" style={{ padding: '16px 20px', cursor: 'pointer' }} onClick={() => setOpenFaq(isOpen ? null : idx)}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <h4 style={{ fontSize: '14px', fontWeight: 600, color: 'var(--text-primary)', margin: 0 }}>{faq.q}</h4>
                  <span style={{ fontFamily: 'var(--mono)', fontSize: '14px', color: 'var(--text-muted)' }}>{isOpen ? '-' : '+'}</span>
                </div>
                {isOpen && (
                  <p style={{ marginTop: '10px', fontSize: '13px', lineHeight: '1.55', color: 'var(--text-secondary)', marginBottom: 0 }}>
                    {faq.a}
                  </p>
                )}
              </div>
            )
          })}
        </div>
      </section>

      {/* SIH Judge Callout */}
      <section className="judge-callout-section">
        <Panel className="judge-banner">
          <div className="judge-banner-content">
            <span className="eyebrow" style={{ color: 'var(--accent)', margin: 0 }}>
              SIH JURY QUICK START
            </span>
            <h2>Evaluate NexSolve Scenarios</h2>
            <p>
              Explore pre-computed deterministic evaluation scenarios covering normal traffic baselines, early attack signals,
              sustained attack forecasts, and abstention guardrails.
            </p>
            <div className="judge-actions">
              <Link to="/demo" className="button">
                Open Judge Demo
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
