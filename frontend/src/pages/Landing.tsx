import { useState } from 'react'
import { Link } from 'react-router-dom'

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
      {/* Hero Section — Spacious Editorial Hierarchy */}
      <section className="landing-hero-editorial">
        <div className="landing-meta-line">
          <span>NETWORK SECURITY</span>
          <span className="meta-sep">/</span>
          <span>SIH PROBLEM STATEMENT 26153</span>
        </div>

        <h1 className="landing-editorial-title">
          NEXSOLVE
        </h1>

        <div className="landing-editorial-subheading">
          Network Attack Forecasting
        </div>

        <p className="landing-editorial-lead">
          Forecast how network attack-state behavior may evolve across multiple future horizons.
          See where the network is heading — not just where it has been.
        </p>

        <div className="landing-editorial-cta-row">
          <Link to="/analyze" className="button button-primary landing-main-cta">
            Analyze PCAP
          </Link>
          <Link to="/workflow" className="button button-secondary landing-sub-cta">
            Explore Workflow
          </Link>
        </div>

        <div className="landing-contract-strip">
          <div className="contract-item">
            <span className="contract-label">CONTRACT</span>
            <span className="contract-val">45 Canonical Features</span>
          </div>
          <div className="contract-divider" />
          <div className="contract-item">
            <span className="contract-label">EPOCH</span>
            <span className="contract-val">60s Discrete Windows</span>
          </div>
          <div className="contract-divider" />
          <div className="contract-item">
            <span className="contract-label">HORIZONS</span>
            <span className="contract-val">T+1 through T+5</span>
          </div>
          <div className="contract-divider" />
          <div className="contract-item">
            <span className="contract-label">TELEMETRY</span>
            <span className="contract-val">Zero RTT Fabrication</span>
          </div>
        </div>
      </section>

      {/* Editorial Rule */}
      <div className="editorial-hr" />

      {/* What NexSolve Does — Architectural Columns */}
      <section className="landing-statement-section">
        <div className="statement-col-header">
          <span className="editorial-eyebrow">PREDICTIVE WORLD MODEL</span>
          <h2 className="editorial-h2">Anticipating threat progression before physical breach onset.</h2>
        </div>
        <div className="statement-col-body">
          <p>
            Standard intrusion detection systems operate retrospectively after packets have delivered exploits.
            NexSolve learns the temporal dynamics of network traffic to project future attack state transitions
            with verifiable statistical governance.
          </p>
        </div>
      </section>

      {/* Scientific Principles — Editorial Wireframe Columns */}
      <section className="landing-principles-editorial">
        <div className="principles-header">
          <span className="editorial-eyebrow">SCIENTIFIC INTEGRITY</span>
          <h2 className="editorial-h2">Defensive Security Guarantees</h2>
        </div>

        <div className="editorial-tri-grid">
          <div className="editorial-tri-col">
            <span className="col-index">01</span>
            <h3 className="col-title">Zero-Fabrication Contract</h3>
            <p className="col-text">
              Eliminates <code>mean_tcp_rtt</code> from the canonical model schema, strictly refusing to synthesize unobservable passive metrics.
            </p>
          </div>

          <div className="editorial-tri-col">
            <span className="col-index">02</span>
            <h3 className="col-title">Persistence Champion Baseline</h3>
            <p className="col-text">
              All forecasting candidates must empirically outperform a strict temporal Persistence baseline without data leakage.
            </p>
          </div>

          <div className="editorial-tri-col">
            <span className="col-index">03</span>
            <h3 className="col-title">Calibrated Forecast Abstention</h3>
            <p className="col-text">
              Explicitly withholds forecasting output when capture history contains fewer than 8 temporal windows or degraded fidelity.
            </p>
          </div>
        </div>
      </section>

      {/* Editorial Rule */}
      <div className="editorial-hr" />

      {/* 8-Stage Processing Pipeline Tour */}
      <section id="pipeline-tour" className="landing-pipeline-editorial">
        <div className="pipeline-header-editorial">
          <span className="editorial-eyebrow">PIPELINE ARCHITECTURE</span>
          <h2 className="editorial-h2">8-Stage Processing Pipeline</h2>
        </div>

        <div className="pipeline-editorial-layout">
          {/* Timeline navigation */}
          <div className="pipeline-editorial-list" role="tablist">
            {PIPELINE_STEPS.map((s, idx) => (
              <button
                key={s.id}
                type="button"
                role="tab"
                aria-selected={activeStep === idx}
                className={`pipeline-nav-row ${activeStep === idx ? 'active' : ''}`}
                onClick={() => setActiveStep(idx)}
              >
                <span className="pipeline-num">{s.step}</span>
                <span className="pipeline-title">{s.title}</span>
              </button>
            ))}
          </div>

          {/* Stage detail pane */}
          <div className="pipeline-editorial-detail">
            <div className="detail-meta">
              STAGE {currentStep.step} OF 08 · {currentStep.eyebrow}
            </div>
            <h3 className="detail-title">{currentStep.title}</h3>
            <p className="detail-desc">{currentStep.description}</p>

            <div className="detail-tech">
              <span className="tech-label">MECHANISMS:</span>
              <span className="tech-body">{currentStep.tech}</span>
            </div>

            <div className="detail-actions">
              <button
                type="button"
                className="button button-secondary"
                disabled={activeStep === 0}
                onClick={() => setActiveStep(Math.max(0, activeStep - 1))}
              >
                Previous Stage
              </button>
              <button
                type="button"
                className="button button-primary"
                disabled={activeStep === PIPELINE_STEPS.length - 1}
                onClick={() => setActiveStep(Math.min(PIPELINE_STEPS.length - 1, activeStep + 1))}
              >
                Next Stage
              </button>
            </div>
          </div>
        </div>
      </section>

      {/* Editorial Rule */}
      <div className="editorial-hr" />

      {/* FAQ Accordion Section — Bottom of Page */}
      <section className="faq-editorial-section">
        <div className="faq-header-editorial">
          <span className="editorial-eyebrow">FREQUENTLY ASKED QUESTIONS</span>
          <h2 className="editorial-h2">System Operations & Methodology</h2>
        </div>

        <div className="faq-editorial-list">
          {faqs.map((faq, idx) => {
            const isOpen = openFaq === idx
            return (
              <div
                key={idx}
                className="faq-editorial-item"
                onClick={() => setOpenFaq(isOpen ? null : idx)}
                tabIndex={0}
                role="button"
                aria-expanded={isOpen}
                onKeyDown={(e) => {
                  if (e.key === 'Enter' || e.key === ' ') {
                    e.preventDefault()
                    setOpenFaq(isOpen ? null : idx)
                  }
                }}
              >
                <div className="faq-editorial-question-row">
                  <h4 className="faq-editorial-q">{faq.q}</h4>
                  <span className="faq-editorial-toggle">{isOpen ? '—' : '+'}</span>
                </div>
                {isOpen && (
                  <p className="faq-editorial-a">
                    {faq.a}
                  </p>
                )}
              </div>
            )
          })}
        </div>
      </section>

      {/* SIH Jury Evaluation Footer Callout */}
      <section className="jury-strip-editorial">
        <div className="jury-strip-inner">
          <div className="jury-strip-text">
            <span className="editorial-eyebrow">SIH JURY EVALUATION</span>
            <h3>Evaluate Pre-Computed Scenarios</h3>
            <p>
              Inspect deterministic benchmarks covering normal telemetry baselines, early signals, sustained horizons, and abstention guardrails.
            </p>
          </div>
          <div className="jury-strip-actions">
            <Link to="/demo" className="button button-primary">
              Open Judge Demo
            </Link>
            <Link to="/analyze" className="button button-secondary">
              Inspect PCAP Pipeline
            </Link>
          </div>
        </div>
      </section>
    </div>
  )
}
