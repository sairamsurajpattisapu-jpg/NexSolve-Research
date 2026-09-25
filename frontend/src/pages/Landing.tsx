import { useState, useEffect } from 'react'
import { Link } from 'react-router-dom'
import {
  ArrowLeft,
  ArrowRight,
  ExternalLink,
  Terminal,
} from 'lucide-react'
import '../styles/landing.css'
import { HeroTemporalVisualization } from '../components/landing/HeroTemporalVisualization'
import { ProgressionLifecycleVisual } from '../components/landing/ProgressionLifecycleVisual'
import { CliQuickstartSection } from '../components/landing/CliQuickstartSection'

const PIPELINE_STEPS = [
  {
    id: 'capture',
    step: '01',
    title: 'Capture (PCAP / PCAPNG)',
    eyebrow: 'Microsecond Wire Ingestion',
    description:
      'Reads raw microsecond packet streams or standard capture files (.pcap, .pcapng). Enforces snaplen bounds clamping, strict magic-byte verification, and packet deduplication without payload tampering.',
    tech: 'libpcap wire ingestion · Zero payload modification · 1 GiB boundary clamping',
  },
  {
    id: 'reconstruct',
    step: '02',
    title: 'Reconstruct (Packets → Flows → Windows)',
    eyebrow: '5-Tuple Temporal Aggregation',
    description:
      'Aggregates packets into bidirectional 5-tuple conversations and partitions traffic into discrete 60-second non-overlapping temporal windows, tracking active session duration and TCP flags.',
    tech: '5-tuple flow aggregation · TCP handshake state tracking · Byte velocity metrics',
  },
  {
    id: 'understand',
    step: '03',
    title: 'Understand (Network-State Representation)',
    eyebrow: '45-Dimensional Continuous Schema',
    description:
      'Condenses network behavior into an audited 45-feature vector S_t across discrete 60-second tumbling windows: 17 flow behavior metrics, 22 packet distribution moments, and 6 temporal rate deltas.',
    tech: 'Audited 45-dim contract · Strictly omits Mean TCP RTT under data integrity contract',
  },
  {
    id: 'detect',
    step: '04',
    title: 'Detect (Threat Behavior & Techniques)',
    eyebrow: 'Grounded MITRE Alignment',
    description:
      'Computes time-indexed interaction graphs, node out-degree centrality, fan-out ratios, and anomalous flag dynamics mapped to grounded MITRE ATT&CK techniques (T1046, T1190, T1071).',
    tech: 'Dynamic graph decomposition · Communication centrality · MITRE technique alignment',
  },
  {
    id: 'forecast',
    step: '05',
    title: 'Forecast (T+1 → T+5 Attack Progression)',
    eyebrow: 'Autoregressive Temporal Simulation',
    description:
      'Autoregressive network state model simulates prospective future network states across forward lookaheads T+1 (+60s), T+2 (+120s), T+3 (+180s), T+4 (+240s), and T+5 (+300s).',
    tech: 'Deep recurrent state model · State trajectory simulation · Multi-horizon forecast',
  },
  {
    id: 'explain',
    step: '06',
    title: 'Explain (Evidence + Confidence + Uncertainty)',
    eyebrow: 'Counterfactual Attribution',
    description:
      'Evaluates point attack probabilities alongside compounding cumulative threat exposure Risk(K) = 1 - ∏_{h=1}^K (1 - p_h) with calibrated uncertainty bounds and counterfactual feature attribution.',
    tech: 'Counterfactual perturbation attribution · Point probability vs cumulative risk',
  },
  {
    id: 'investigate',
    step: '07',
    title: 'Investigate (Web Console + Forensic Report)',
    eyebrow: '16-Section Structured Audit Package',
    description:
      'Comprehensive executive and forensic audit packages with cryptographic SHA-256 provenance hashes, self-contained HTML/Markdown/JSON exports, and deep web console timeline exploration.',
    tech: '16-section forensic report · Self-contained air-gapped export · Interactive drilldown',
  },
  {
    id: 'abstain',
    step: '08',
    title: 'Calibrated Abstention & Governance',
    eyebrow: 'Epistemic Honesty Contract',
    description:
      'When historical context contains fewer than 8 discrete 60-second windows (< 8 minutes), NexSolve explicitly withholds prospective forecasts rather than outputting speculative hallucinations.',
    tech: 'Calibrated abstention contract · Zero synthetic imputation · Strict integrity',
  },
]

const FORECAST_HORIZONS = [
  {
    step: 'T+1',
    sec: '+60s Lookahead',
    stage: 'Command & Control',
    pointProb: '34%',
    cumRisk: '34%',
    uncertainty: '0.12 (Low)',
    uncertWidth: '24%',
    evidence: 'C2 beacon cadence on port 8443; TLS SNI entropy elevation.',
  },
  {
    step: 'T+2',
    sec: '+120s Lookahead',
    stage: 'Defense Evasion',
    pointProb: '52%',
    cumRisk: '68%',
    uncertainty: '0.22 (Moderate)',
    uncertWidth: '44%',
    evidence: 'Predicted suppression of outbound syslog events; masqueraded protocol headers.',
  },
  {
    step: 'T+3',
    sec: '+180s Lookahead',
    stage: 'Credential Access',
    pointProb: '65%',
    cumRisk: '89%',
    uncertainty: '0.31 (Elevated)',
    uncertWidth: '62%',
    evidence: 'Anticipated SMB session multiplexing on port 445 targeting domain controllers.',
  },
  {
    step: 'T+4',
    sec: '+240s Lookahead',
    stage: 'Lateral Movement',
    pointProb: '78%',
    cumRisk: '97%',
    uncertainty: '0.38 (Elevated)',
    uncertWidth: '76%',
    evidence: 'East-west flow expansion across /24 subnet; inter-host admin share access.',
  },
  {
    step: 'T+5',
    sec: '+300s Lookahead',
    stage: 'Exfiltration / Impact',
    pointProb: '84%',
    cumRisk: '99%',
    uncertainty: '0.45 (Substantial)',
    uncertWidth: '90%',
    evidence: 'High-volume egress stream across external TLS pipe; egress bandwidth saturation.',
  },
]

export function Landing() {
  const [activeStep, setActiveStep] = useState<number>(0)

  useEffect(() => {
    if (typeof IntersectionObserver === 'undefined') {
      document.querySelectorAll('.landing-section').forEach((s) => s.classList.add('in-view'))
      return
    }

    const observer = new IntersectionObserver(
      (entries) => {
        entries.forEach((entry) => {
          if (entry.isIntersecting) {
            entry.target.classList.add('in-view')
          }
        })
      },
      {
        threshold: 0.12,
        rootMargin: '0px 0px -40px 0px',
      }
    )

    const sections = document.querySelectorAll('.landing-section')
    sections.forEach((s) => observer.observe(s))

    return () => observer.disconnect()
  }, [])

  const currentStep = PIPELINE_STEPS[activeStep]

  return (
    <div className="landing-root page-enter">
      {/* -----------------------------------------------------------------------------
          1. HERO SECTION
          ----------------------------------------------------------------------------- */}
      <section className="landing-hero" id="hero">
        <div className="hero-veil-backdrop" aria-hidden="true" />

        <div className="hero-text-block">
          <div className="hero-pill-badge">
            <span className="pill-dot" />
            <span>AI-POWERED NETWORK ATTACK FORECASTING FROM NETWORK TRAFFIC</span>
          </div>

          <h1 className="hero-headline">
            <span className="hero-brand-label">NEXSOLVE</span>
            <span className="headline-accent">Network attack forecasting</span>
            <br />
            from network traffic.
          </h1>

          <p className="hero-subheadline">
            NexSolve reconstructs temporal network behavior from traffic captures,
            identifies attack progression, and forecasts how that behavior may evolve
            across future horizons.
          </p>

          <div className="hero-cta-container">
            {/* PRIMARY: Analyze a PCAP → */}
            <a
              href="#cli-quickstart"
              className="hero-btn-primary"
              aria-label="Use NexSolve CLI — Analyze a PCAP"
            >
              <span>Analyze a PCAP</span>
              <ArrowRight size={15} />
            </a>

            {/* SECONDARY: View CLI Commands */}
            <a
              href="#cli-quickstart"
              className="hero-btn-secondary"
              aria-label="View CLI Commands"
            >
              <Terminal size={14} />
              <span>View CLI Commands</span>
            </a>

            {/* TERTIARY: Open Console ↗ */}
            <Link
              to="/console"
              className="hero-btn-tertiary"
              aria-label="Open Console"
            >
              <span>Open Console</span>
              <ExternalLink size={13} />
            </Link>
          </div>

          {/* Clean terminal cue & workflow link */}
          <div className="hero-cta-cue">
            <span className="cue-terminal-text">
              Run <code className="cli-inline-code">nexsolve analyze</code> from your terminal
            </span>
            <span className="cue-divider">&middot;</span>
            <Link to="/workflow" className="cue-workflow-link" aria-label="View workflow">
              <span>View Workflow</span>
              <ArrowRight size={12} />
            </Link>
          </div>
        </div>

        <div className="hero-trust-line">
          <span>PCAP</span>
          &rarr;
          <span>Temporal Network State</span>
          &rarr;
          <span>Attack Progression</span>
          &rarr;
          <span>Forecast</span>
        </div>

        {/* Hero Temporal Visualization */}
        <HeroTemporalVisualization />
      </section>

      {/* -----------------------------------------------------------------------------
          2. HOW IT WORKS (PIPELINE ARCHITECTURE STEPPER)
          ----------------------------------------------------------------------------- */}
      <section className="landing-section" id="how-it-works">
        <span className="section-eyebrow">SYSTEM ARCHITECTURE</span>
        <h2 className="section-heading-large">
          The 8-Stage End-to-End Pipeline
        </h2>
        <p className="section-desc" style={{ maxWidth: 720 }}>
          From raw microsecond wire captures to mathematical counterfactual evidence and 16-section forensic audit packages.
        </p>

        {/* Interactive Pipeline Stepper */}
        <div style={{ marginTop: 28, background: '#09090b', border: '1px solid rgba(255,255,255,0.1)', borderRadius: 10, padding: 24 }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16 }}>
            <span style={{ fontFamily: 'var(--mono)', fontSize: 11, color: '#a1a1aa', fontWeight: 700 }}>
              STAGE {currentStep.step} OF 08 &middot; {currentStep.eyebrow}
            </span>
            <div style={{ display: 'flex', gap: 8 }}>
              <button
                type="button"
                className="button button-quiet"
                style={{ fontSize: 11, padding: '4px 10px', gap: 4 }}
                disabled={activeStep === 0}
                onClick={() => setActiveStep(Math.max(0, activeStep - 1))}
              >
                <ArrowLeft size={12} /> Previous
              </button>
              <button
                type="button"
                className="button button-primary"
                style={{ fontSize: 11, padding: '4px 10px', gap: 4 }}
                disabled={activeStep === PIPELINE_STEPS.length - 1}
                onClick={() => setActiveStep(Math.min(PIPELINE_STEPS.length - 1, activeStep + 1))}
              >
                Next Stage <ArrowRight size={12} />
              </button>
            </div>
          </div>

          <h3 style={{ fontSize: 19, fontWeight: 700, color: '#ffffff', margin: '0 0 8px 0' }}>
            {currentStep.title}
          </h3>
          <p style={{ fontSize: 13.5, color: '#a1a1aa', lineHeight: 1.6, margin: '0 0 14px 0' }}>
            {currentStep.description}
          </p>
          <div style={{ fontFamily: 'var(--mono)', fontSize: 11.5, color: '#e4e4e7', background: 'rgba(255, 255, 255, 0.04)', border: '1px solid rgba(255, 255, 255, 0.08)', padding: '8px 12px', borderRadius: 4 }}>
            {currentStep.tech}
          </div>
        </div>
      </section>

      {/* -----------------------------------------------------------------------------
          3. CLI WORKFLOW
          ----------------------------------------------------------------------------- */}
      <CliQuickstartSection />

      {/* -----------------------------------------------------------------------------
          4. FORECAST / INVESTIGATION (HORIZONS & 15-STAGE PROGRESSION)
          ----------------------------------------------------------------------------- */}
      <section className="landing-section" id="forecasting">
        <span className="section-eyebrow">PROSPECTIVE INTELLIGENCE</span>
        <h2 className="section-heading-large">
          Multi-Horizon Forward Forecasting (T+1 to T+5)
        </h2>
        <p className="section-desc" style={{ maxWidth: 740 }}>
          Autoregressive models simulate prospective network states across forward lookahead horizons.
          Point attack probabilities are strictly separated from cumulative compounding risk.
        </p>

        <div className="forecast-horizon-grid">
          {FORECAST_HORIZONS.map((h) => (
            <div key={h.step} className="horizon-card">
              <div className="horizon-header">
                <span className="horizon-step">{h.step}</span>
                <span className="horizon-sec">{h.sec}</span>
              </div>
              <div className="horizon-stage-title">{h.stage}</div>

              <div className="horizon-prob-row">
                <span style={{ color: '#71717a' }}>Point P(Atk):</span>
                <span className="horizon-prob-val">{h.pointProb}</span>
              </div>

              <div className="horizon-prob-row">
                <span style={{ color: '#71717a' }}>Cumulative Risk:</span>
                <span className="horizon-risk-val">{h.cumRisk}</span>
              </div>

              <div>
                <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 10, fontFamily: 'var(--mono)', color: '#71717a', marginBottom: 2 }}>
                  <span>UNCERTAINTY ENVELOPE</span>
                  <span>{h.uncertainty}</span>
                </div>
                <div className="horizon-uncertainty-bar">
                  <div className="horizon-uncertainty-fill" style={{ width: h.uncertWidth }} />
                </div>
              </div>

              <p style={{ fontSize: 11.5, color: '#a1a1aa', margin: '4px 0 0 0', lineHeight: 1.5 }}>
                {h.evidence}
              </p>
            </div>
          ))}
        </div>

        <div className="philosophy-banner" style={{ marginTop: 24 }}>
          <strong>Calibrated Abstention Principle:</strong>
          <br />
          "Every forecast carries uncertainty. Insufficient evidence produces calibrated abstention — not fabricated certainty."
          When captures contain fewer than 8 discrete 60s windows, NexSolve withholds forward forecasts to prevent speculative extrapolation.
        </div>

        {/* 15-Stage Adversarial Progression Visualization */}
        <div style={{ marginTop: 40 }}>
          <div style={{ textAlign: 'center', marginBottom: 20 }}>
            <span className="section-eyebrow">ATTACK LIFECYCLE REASONING</span>
            <h3 style={{ fontSize: 'clamp(18px, 2.2vw, 24px)', fontWeight: 700, margin: '6px 0 6px 0', color: '#ffffff' }}>
              15-Stage Adversarial Progression Model
            </h3>
            <p style={{ fontSize: 13.5, color: '#a1a1aa', maxWidth: 680, margin: '0 auto' }}>
              Transitions grounded in observed network kinematics categorized as OBSERVED, INFERRED, FORECAST, or UNKNOWN.
            </p>
          </div>
          <ProgressionLifecycleVisual />
        </div>
      </section>

      {/* -----------------------------------------------------------------------------
          5. EVIDENCE (COUNTERFACTUAL ATTRIBUTION TRACE)
          ----------------------------------------------------------------------------- */}
      <section className="landing-section" id="evidence">
        <span className="section-eyebrow">COUNTERFACTUAL ATTRIBUTION</span>
        <h2 className="section-heading-large">
          Verifiable Evidence & Attribution Trail
        </h2>
        <p className="section-desc" style={{ maxWidth: 740 }}>
          NexSolve connects every analytical conclusion, stage assessment, and forward risk probability directly back
          to physical wire telemetry without black-box opacity.
        </p>

        <div className="evidence-trace-strip">
          <div className="trace-item">
            <span className="trace-item-tag">INPUT</span>
            <span className="trace-item-title">PCAP</span>
          </div>
          <ArrowRight size={14} className="trace-arrow" />
          <div className="trace-item">
            <span className="trace-item-tag">WIRE</span>
            <span className="trace-item-title">Packet</span>
          </div>
          <ArrowRight size={14} className="trace-arrow" />
          <div className="trace-item">
            <span className="trace-item-tag">5-TUPLE</span>
            <span className="trace-item-title">Flow</span>
          </div>
          <ArrowRight size={14} className="trace-arrow" />
          <div className="trace-item">
            <span className="trace-item-tag">TEMPORAL</span>
            <span className="trace-item-title">Window (60s)</span>
          </div>
          <ArrowRight size={14} className="trace-arrow" />
          <div className="trace-item">
            <span className="trace-item-tag">CONTINUOUS</span>
            <span className="trace-item-title">Feature (S_t)</span>
          </div>
          <ArrowRight size={14} className="trace-arrow" />
          <div className="trace-item">
            <span className="trace-item-tag">ANOMALY</span>
            <span className="trace-item-title">Detection</span>
          </div>
          <ArrowRight size={14} className="trace-arrow" />
          <div className="trace-item">
            <span className="trace-item-tag">BEHAVIOR</span>
            <span className="trace-item-title">MITRE Technique</span>
          </div>
          <ArrowRight size={14} className="trace-arrow" />
          <div className="trace-item">
            <span className="trace-item-tag">LIFECYCLE</span>
            <span className="trace-item-title">Attack Stage</span>
          </div>
          <ArrowRight size={14} className="trace-arrow" />
          <div className="trace-item">
            <span className="trace-item-tag">PROJECTION</span>
            <span className="trace-item-title">Forecast</span>
          </div>
        </div>
      </section>

      {/* -----------------------------------------------------------------------------
          6. FINAL CALL TO ACTION
          ----------------------------------------------------------------------------- */}
      <section className="landing-final-cta" id="cta">
        <h2 className="cta-title">Network attack forecasting from network traffic.</h2>
        <p className="cta-subtitle">
          Analyze a capture. Trace the evidence. Understand the trajectory.
        </p>

        <div className="hero-cta-container" style={{ margin: 0 }}>
          <a
            href="#cli-quickstart"
            className="hero-btn-primary"
            style={{ padding: '0 32px', height: 48 }}
            aria-label="Use NexSolve CLI — Analyze a PCAP"
          >
            <span>Analyze a PCAP</span>
            <ArrowRight size={16} />
          </a>
          <Link
            to="/console"
            className="hero-btn-secondary"
            style={{ padding: '0 28px', height: 48 }}
            aria-label="Open Console"
          >
            <span>Open Console</span>
            <ExternalLink size={14} />
          </Link>
        </div>
      </section>
    </div>
  )
}

export default Landing
