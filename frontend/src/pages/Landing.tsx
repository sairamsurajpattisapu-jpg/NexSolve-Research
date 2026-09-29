import { useState, useEffect } from 'react'
import { Link } from 'react-router-dom'
import {
  ArrowLeft,
  ArrowRight,
  Clock,
  ExternalLink,
  Layers,
  Shield,
  Terminal,
  TrendingUp,
  Workflow,
} from 'lucide-react'
import '../styles/landing.css'
import { HeroTemporalVisualization } from '../components/landing/HeroTemporalVisualization'
import { ProgressionLifecycleVisual } from '../components/landing/ProgressionLifecycleVisual'
import { ConsoleProductPreview } from '../components/landing/ConsoleProductPreview'

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
  { step: 'T+1', sec: '+60s', stage: 'Command & Control', prob: '34%', risk: '34%' },
  { step: 'T+2', sec: '+120s', stage: 'Defense Evasion', prob: '52%', risk: '68%' },
  { step: 'T+3', sec: '+180s', stage: 'Credential Access', prob: '65%', risk: '89%' },
  { step: 'T+4', sec: '+240s', stage: 'Lateral Movement', prob: '78%', risk: '97%' },
  { step: 'T+5', sec: '+300s', stage: 'Exfiltration / Impact', prob: '84%', risk: '99%' },
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
      { threshold: 0.12, rootMargin: '0px 0px -40px 0px' }
    )

    const sections = document.querySelectorAll('.landing-section')
    sections.forEach((s) => observer.observe(s))

    return () => observer.disconnect()
  }, [])

  const currentStep = PIPELINE_STEPS[activeStep]

  const handleScrollTo = (id: string) => (e: React.MouseEvent) => {
    e.preventDefault()
    const element = document.getElementById(id)
    if (element) {
      element.scrollIntoView({ behavior: 'smooth' })
      window.history.pushState(null, '', `#${id}`)
    }
  }

  return (
    <div className="landing-root page-enter">
      {/* -----------------------------------------------------------------------------
          1. HERO — STRONG, VISUAL, EDITORIAL
          "SEE THE ATTACK BEFORE THE COMPROMISE."
          ----------------------------------------------------------------------------- */}
      <section className="landing-hero" id="hero">
        <div className="hero-text-block">
          <div className="hero-pill-badge">
            <span className="pill-dot" />
            <span>NEXSOLVE &middot; NETWORK ATTACK FORECASTING</span>
          </div>

          <h1 className="hero-headline">
            <span className="hero-brand-label">NEXSOLVE</span>
            See the attack<br />
            <em>before the compromise.</em>
          </h1>

          <p className="hero-subheadline">
            From network traffic captures, NexSolve reconstructs temporal network behavior,
            identifies attack progression, and forecasts how that behavior may evolve across future horizons.
          </p>

          <div className="hero-cta-container">
            {/* PRIMARY CTA: Analyze a PCAP → (routes to /console) */}
            <Link
              to="/console"
              className="hero-btn-primary"
              aria-label="Analyze a PCAP"
            >
              <span>Analyze a PCAP</span>
              <ArrowRight size={15} />
            </Link>

            {/* SECONDARY CTA: How It Works (scrolls to #how-it-works) */}
            <a
              href="#how-it-works"
              onClick={handleScrollTo('how-it-works')}
              className="hero-btn-secondary"
              aria-label="How NexSolve Works"
            >
              <span>How It Works</span>
            </a>

            {/* SECONDARY CLI ACTION (preserves exact test role & name) */}
            <a
              href="#cli-quickstart"
              onClick={handleScrollTo('cli-quickstart')}
              className="hero-btn-secondary"
              aria-label="View CLI Commands"
            >
              <Terminal size={14} />
              <span>View CLI Commands</span>
            </a>

            {/* TERTIARY CTA: Open Console → */}
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
            <a
              href="#cli-quickstart"
              onClick={handleScrollTo('cli-quickstart')}
              className="cue-terminal-text"
              aria-label="Use NexSolve CLI"
              style={{ textDecoration: 'none' }}
            >
              Run <code className="cli-inline-code">nexsolve analyze</code> from your terminal
            </a>
            <span className="cue-divider">&middot;</span>
            <a
              href="#how-it-works"
              onClick={handleScrollTo('how-it-works')}
              className="cue-workflow-link"
              aria-label="View workflow"
            >
              <span>View workflow</span>
              <ArrowRight size={12} />
            </a>
          </div>
        </div>

        {/* Conceptual Ribbon: PAST → NOW → T+1 → T+2 → T+3 → T+4 → T+5 */}
        <div className="hero-conceptual-flow" aria-label="Temporal Flow Ribbon">
          <div className="hero-flow-pill">
            <span>PAST (OBSERVED)</span>
          </div>
          <span className="flow-arrow">&rarr;</span>
          <div className="hero-flow-pill active">
            <span>NOW (T_0)</span>
          </div>
          <span className="flow-arrow">&rarr;</span>
          <span className="hero-flow-pill dashed">T+1</span>
          <span className="flow-arrow" style={{ opacity: 0.45 }}>&rarr;</span>
          <span className="hero-flow-pill dashed">T+2</span>
          <span className="flow-arrow" style={{ opacity: 0.45 }}>&rarr;</span>
          <span className="hero-flow-pill dashed">T+3</span>
          <span className="flow-arrow" style={{ opacity: 0.45 }}>&rarr;</span>
          <span className="hero-flow-pill dashed">T+4</span>
          <span className="flow-arrow" style={{ opacity: 0.45 }}>&rarr;</span>
          <span className="hero-flow-pill dashed" style={{ borderColor: '#ffffff', color: '#ffffff' }}>T+5</span>
        </div>

        {/* Hero Temporal Visualization */}
        <HeroTemporalVisualization />
      </section>

      {/* -----------------------------------------------------------------------------
          2. PROBLEM SECTION — EXTREMELY SIMPLE
          "DETECTION TELLS YOU WHAT HAPPENED. NEXSOLVE ASKS: WHAT HAPPENS NEXT?"
          ----------------------------------------------------------------------------- */}
      <section className="landing-section" id="problem">
        <span className="section-eyebrow">THE DISTINCTION</span>
        <h2 className="section-heading-editorial">
          Detection tells you what happened.<br />
          <em>NexSolve asks: what happens next?</em>
        </h2>
        <p className="section-desc" style={{ maxWidth: 720 }}>
          Traditional network monitoring identifies suspicious activity in observed traffic.
          NexSolve focuses on the forward temporal question: what could this network state evolve into?
        </p>

        {/* Visual Contrast: OBSERVE vs FORECAST */}
        <div className="observe-vs-forecast-container">
          <div className="contrast-card">
            <div>
              <span style={{ fontSize: '10.5px', fontFamily: 'var(--mono)', color: '#737373', letterSpacing: '0.08em', textTransform: 'uppercase' }}>
                TRADITIONAL SOC
              </span>
              <h3 style={{ fontSize: '20px', fontWeight: 700, color: '#ffffff', margin: '6px 0 10px 0' }}>
                OBSERVE
              </h3>
              <p style={{ fontSize: '13.5px', color: '#8e8e93', lineHeight: 1.6, margin: 0 }}>
                Detects known signatures, anomalous heuristics, and port scans in past traffic up to the observation timestamp.
              </p>
            </div>
            <div style={{ borderTop: '1px solid #1a1a1a', paddingTop: '12px', marginTop: '20px', fontSize: '11px', fontFamily: 'var(--mono)', color: '#666' }}>
              Scope: Historical traffic through boundary T_0
            </div>
          </div>

          <div className="contrast-card forecast-card">
            <div>
              <span style={{ fontSize: '10.5px', fontFamily: 'var(--mono)', color: '#ffffff', letterSpacing: '0.08em', textTransform: 'uppercase', fontWeight: 700 }}>
                NEXSOLVE
              </span>
              <h3 style={{ fontSize: '20px', fontWeight: 700, color: '#ffffff', margin: '6px 0 10px 0' }}>
                FORECAST
              </h3>
              <p style={{ fontSize: '13.5px', color: '#e5e5e5', lineHeight: 1.6, margin: 0 }}>
                Simulates prospective network state trajectories across future temporal horizons (T+1 to T+5) before compromise.
              </p>
            </div>
            <div style={{ borderTop: '1px solid #282828', paddingTop: '12px', marginTop: '20px', fontSize: '11px', fontFamily: 'var(--mono)', color: '#aaa' }}>
              Scope: Forward lookaheads (+60s to +300s)
            </div>
          </div>
        </div>
      </section>

      {/* -----------------------------------------------------------------------------
          3. NEXSOLVE WORKFLOW — EXACTLY FIVE STEPS
          01 PCAP → 02 TEMPORAL STATE → 03 PROGRESSION → 04 FORECAST → 05 EVIDENCE
          ----------------------------------------------------------------------------- */}
      <section className="landing-section" id="how-it-works">
        <span className="section-eyebrow">HOW IT WORKS</span>
        <h2 className="section-heading-editorial">
          Five stages from wire to forecast.
        </h2>
        <p className="section-desc" style={{ maxWidth: 720 }}>
          Reconstructing temporal network behavior and forecasting its evolution across time.
        </p>

        {/* 5 Clean Steps */}
        <div className="workflow-5steps-grid">
          {/* Step 1 */}
          <div className="workflow-step-card">
            <span className="step-card-num">01</span>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '8px' }}>
              <Layers size={15} color="#ffffff" />
              <div className="step-card-title">PCAP</div>
            </div>
            <div className="step-card-desc">
              Network traffic capture. Passive wire ingestion with SHA-256 provenance and zero payload tampering.
            </div>
            <div className="step-card-visual">
              .pcap / .pcapng &middot; 1 GiB
            </div>
          </div>

          {/* Step 2 */}
          <div className="workflow-step-card">
            <span className="step-card-num">02</span>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '8px' }}>
              <Clock size={15} color="#ffffff" />
              <div className="step-card-title">TEMPORAL STATE</div>
            </div>
            <div className="step-card-desc">
              Packet and flow behavior aggregated into continuous 60-second temporal windows.
            </div>
            <div className="step-card-visual">
              5-Tuple &middot; State S_t
            </div>
          </div>

          {/* Step 3 */}
          <div className="workflow-step-card">
            <span className="step-card-num">03</span>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '8px' }}>
              <Workflow size={15} color="#ffffff" />
              <div className="step-card-title">PROGRESSION</div>
            </div>
            <div className="step-card-desc">
              Observed behavior and grounded attack-stage signals mapped to MITRE ATT&CK techniques.
            </div>
            <div className="step-card-visual">
              Graph Centrality &middot; MITRE
            </div>
          </div>

          {/* Step 4 */}
          <div className="workflow-step-card">
            <span className="step-card-num">04</span>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '8px' }}>
              <TrendingUp size={15} color="#ffffff" />
              <div className="step-card-title">FORECAST</div>
            </div>
            <div className="step-card-desc">
              Autoregressive state model simulates forward lookaheads across T+1 through T+5 future horizons.
            </div>
            <div className="step-card-visual">
              T+1 .. T+5 &middot; +300s
            </div>
          </div>

          {/* Step 5 */}
          <div className="workflow-step-card">
            <span className="step-card-num">05</span>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '8px' }}>
              <Shield size={15} color="#ffffff" />
              <div className="step-card-title">EVIDENCE</div>
            </div>
            <div className="step-card-desc">
              Forecasts connected directly back to observable physical telemetry and feature drivers.
            </div>
            <div className="step-card-visual">
              Attribution &middot; Grounding
            </div>
          </div>
        </div>

        {/* Technical Stepper Tour Panel (Preserves Test Compatibility for newPages.test.tsx) */}
        <div style={{ marginTop: 24, background: '#09090b', border: '1px solid rgba(255,255,255,0.08)', borderRadius: 8, padding: 20 }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 12 }}>
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

          <h3 style={{ fontSize: 16, fontWeight: 700, color: '#ffffff', margin: '0 0 6px 0' }}>
            {currentStep.title}
          </h3>
          <p style={{ fontSize: 13, color: '#a1a1aa', lineHeight: 1.5, margin: '0 0 10px 0' }}>
            {currentStep.description}
          </p>
          <div style={{ fontFamily: 'var(--mono)', fontSize: 11, color: '#e4e4e7', background: 'rgba(255, 255, 255, 0.04)', border: '1px solid rgba(255, 255, 255, 0.08)', padding: '6px 10px', borderRadius: 4 }}>
            {currentStep.tech}
          </div>
        </div>
      </section>

      {/* -----------------------------------------------------------------------------
          4. ATTACK HORIZON — CORE DIFFERENTIATOR
          Large Visual Section
          ----------------------------------------------------------------------------- */}
      <section className="landing-section" id="forecasting">
        <span className="section-eyebrow">CORE DIFFERENTIATOR</span>
        <h2 className="section-heading-editorial">
          From detection to attack horizon.
        </h2>
        <p className="section-desc" style={{ maxWidth: 720 }}>
          NexSolve projects the learned network state across future temporal horizons.
        </p>

        {/* Large Grand Horizon Visual */}
        <div className="horizon-concept-card">
          <div
            style={{
              padding: '24px 20px',
              background: '#030303',
              border: '1px solid #1c1c1c',
              borderRadius: '6px',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
              overflowX: 'auto',
              gap: '20px',
            }}
          >
            {/* PAST */}
            <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
              <div>
                <span style={{ fontSize: '11px', fontFamily: 'var(--mono)', color: '#737373', display: 'block' }}>PAST</span>
                <div style={{ display: 'flex', alignItems: 'center', gap: '6px', margin: '8px 0' }}>
                  <span style={{ width: '8px', height: '8px', borderRadius: '50%', background: '#555' }} />
                  <span style={{ width: '8px', height: '8px', borderRadius: '50%', background: '#555' }} />
                  <span style={{ width: '8px', height: '8px', borderRadius: '50%', background: '#555' }} />
                  <span style={{ width: '8px', height: '8px', borderRadius: '50%', background: '#888' }} />
                </div>
                <span style={{ fontSize: '10px', color: '#555' }}>Observed</span>
              </div>
              <div style={{ width: '36px', height: '1px', background: '#333' }} />
            </div>

            {/* NOW */}
            <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
              <div>
                <span style={{ fontSize: '11px', fontFamily: 'var(--mono)', color: '#ffffff', fontWeight: 700, display: 'block' }}>NOW</span>
                <div style={{ margin: '6px 0' }}>
                  <span style={{ width: '12px', height: '12px', borderRadius: '50%', background: '#ffffff', display: 'inline-block' }} />
                </div>
                <span style={{ fontSize: '10px', color: '#aaa' }}>Boundary T_0</span>
              </div>
              <div style={{ width: '36px', height: '1px', borderTop: '1px dashed #666' }} />
            </div>

            {/* FUTURE HORIZONS */}
            <div>
              <span style={{ fontSize: '11px', fontFamily: 'var(--mono)', color: '#e5e5e5', display: 'block', marginBottom: '6px' }}>FUTURE</span>
              <div style={{ display: 'flex', gap: '20px', alignItems: 'center' }}>
                {FORECAST_HORIZONS.map((h) => (
                  <div key={h.step} style={{ textAlign: 'center' }}>
                    <span style={{ fontSize: '11px', fontFamily: 'var(--mono)', color: '#888', display: 'block' }}>{h.step}</span>
                    <span style={{ width: '10px', height: '10px', borderRadius: '50%', border: '1px dashed #fff', display: 'inline-block', margin: '4px 0' }} />
                    <span style={{ fontSize: '9px', color: '#666', display: 'block' }}>{h.sec}</span>
                  </div>
                ))}
              </div>
            </div>
          </div>

          <div style={{ marginTop: '20px', display: 'grid', gridTemplateColumns: 'repeat(5, 1fr)', gap: '10px' }}>
            {FORECAST_HORIZONS.map((h) => (
              <div key={h.step} style={{ background: '#0a0a0a', border: '1px solid #1a1a1a', borderRadius: '4px', padding: '10px', textAlign: 'center' }}>
                <span style={{ fontFamily: 'var(--mono)', fontSize: '11px', color: '#737373' }}>{h.step}</span>
                <div style={{ fontSize: '15px', fontWeight: 700, color: '#ffffff', margin: '2px 0' }}>{h.prob}</div>
                <div style={{ fontSize: '10px', color: '#888' }}>{h.stage}</div>
              </div>
            ))}
          </div>

          <p style={{ marginTop: '16px', fontSize: '12.5px', color: '#888', lineHeight: 1.5, margin: '16px 0 0 0' }}>
            NexSolve projects the learned network state across future temporal horizons, separating single-step point probabilities from cumulative compounding risk.
          </p>
        </div>
      </section>

      {/* -----------------------------------------------------------------------------
          5. EVIDENCE — NOT JUST PREDICTIONS
          "A FORECAST WITHOUT EVIDENCE IS JUST A NUMBER."
          ----------------------------------------------------------------------------- */}
      <section className="landing-section" id="evidence">
        <span className="section-eyebrow">EXPLAINABILITY</span>
        <h2 className="section-heading-editorial">
          A forecast without evidence is just a number.
        </h2>
        <p className="section-desc" style={{ maxWidth: 720 }}>
          NexSolve connects every predicted transition back to observable physical network telemetry.
        </p>

        {/* Visual Evidence Chain */}
        <div className="evidence-chain-diagram">
          <div className="evidence-chain-cell">
            <span style={{ fontSize: '9px', fontFamily: 'var(--mono)', color: '#737373', display: 'block' }}>01</span>
            <strong style={{ fontSize: '12px', color: '#ffffff' }}>NETWORK TRAFFIC</strong>
          </div>
          <span style={{ color: '#555' }}>&rarr;</span>
          <div className="evidence-chain-cell">
            <span style={{ fontSize: '9px', fontFamily: 'var(--mono)', color: '#737373', display: 'block' }}>02</span>
            <strong style={{ fontSize: '12px', color: '#ffffff' }}>FLOW BEHAVIOR</strong>
          </div>
          <span style={{ color: '#555' }}>&rarr;</span>
          <div className="evidence-chain-cell">
            <span style={{ fontSize: '9px', fontFamily: 'var(--mono)', color: '#737373', display: 'block' }}>03</span>
            <strong style={{ fontSize: '12px', color: '#ffffff' }}>TEMPORAL CHANGE</strong>
          </div>
          <span style={{ color: '#555' }}>&rarr;</span>
          <div className="evidence-chain-cell">
            <span style={{ fontSize: '9px', fontFamily: 'var(--mono)', color: '#737373', display: 'block' }}>04</span>
            <strong style={{ fontSize: '12px', color: '#ffffff' }}>NETWORK STATE</strong>
          </div>
          <span style={{ color: '#555' }}>&rarr;</span>
          <div className="evidence-chain-cell">
            <span style={{ fontSize: '9px', fontFamily: 'var(--mono)', color: '#737373', display: 'block' }}>05</span>
            <strong style={{ fontSize: '12px', color: '#ffffff' }}>EVIDENCE</strong>
          </div>
          <span style={{ color: '#555' }}>&rarr;</span>
          <div className="evidence-chain-cell" style={{ background: '#141414', borderColor: '#444' }}>
            <span style={{ fontSize: '9px', fontFamily: 'var(--mono)', color: '#ffffff', display: 'block', fontWeight: 700 }}>06</span>
            <strong style={{ fontSize: '12px', color: '#ffffff' }}>FORECAST</strong>
          </div>
        </div>

        <p style={{ marginTop: '16px', fontSize: '13px', color: '#888', lineHeight: 1.6, textAlign: 'center' }}>
          Rather than delivering ungrounded probabilities, NexSolve evaluates mathematical feature sensitivities and links findings directly to communicating 5-tuple flows.
        </p>
      </section>

      {/* -----------------------------------------------------------------------------
          6. ATTACK PROGRESSION
          "REPRESENTING ATTACK BEHAVIOR TEMPORALLY."
          ----------------------------------------------------------------------------- */}
      <section className="landing-section" id="progression">
        <span className="section-eyebrow">TEMPORAL ADVERSARY REASONING</span>
        <h2 className="section-heading-editorial">
          Representing attack behavior temporally.
        </h2>
        <p className="section-desc" style={{ maxWidth: 720 }}>
          Adversary campaigns develop in sequential stages. NexSolve models that evolution across MITRE ATT&CK tactics.
        </p>

        {/* Conceptual Timeline */}
        <div
          style={{
            margin: '24px auto',
            maxWidth: '680px',
            padding: '18px 24px',
            background: '#070707',
            border: '1px solid #1f1f1f',
            borderRadius: '6px',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            flexWrap: 'wrap',
            gap: '12px',
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <span style={{ fontSize: '9.5px', fontFamily: 'var(--mono)', border: '1px solid #fff', padding: '1px 6px', borderRadius: '2px', color: '#fff' }}>OBSERVED</span>
            <strong style={{ fontSize: '13.5px', color: '#fff' }}>Reconnaissance</strong>
          </div>
          <span style={{ color: '#555' }}>&rarr;</span>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <span style={{ fontSize: '9.5px', fontFamily: 'var(--mono)', border: '1px dashed #aaa', padding: '1px 6px', borderRadius: '2px', color: '#ccc' }}>FORECAST</span>
            <strong style={{ fontSize: '13.5px', color: '#e5e5e5' }}>Discovery</strong>
          </div>
          <span style={{ color: '#555' }}>&rarr;</span>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <span style={{ fontSize: '9.5px', fontFamily: 'var(--mono)', border: '1px dashed #aaa', padding: '1px 6px', borderRadius: '2px', color: '#ccc' }}>FORECAST</span>
            <strong style={{ fontSize: '13.5px', color: '#e5e5e5' }}>Command &amp; Control</strong>
          </div>
        </div>

        <div style={{ textAlign: 'center', marginBottom: 20 }}>
          <span style={{ fontSize: '10.5px', fontFamily: 'var(--mono)', color: '#737373', letterSpacing: '0.08em', textTransform: 'uppercase' }}>
            [ CONCEPTUAL EXAMPLE &middot; ATTACK-STAGE INTERPRETATION IS GROUNDED IN NETWORK EVIDENCE ]
          </span>
        </div>

        <ProgressionLifecycleVisual />
      </section>

      {/* -----------------------------------------------------------------------------
          7. PRODUCT PREVIEW
          The Real Console Frame (Threat, Horizon, Forecast, Evidence)
          ----------------------------------------------------------------------------- */}
      <section className="landing-section" id="product-preview">
        <span className="section-eyebrow">PRODUCT PREVIEW</span>
        <h2 className="section-heading-editorial">
          The NexSolve Console
        </h2>
        <p className="section-desc" style={{ maxWidth: 720 }}>
          An operational SOC investigation workspace uniting PCAP ingestion, multi-horizon rollouts, and deep forensic auditing.
        </p>

        <div style={{ marginTop: '24px' }}>
          <ConsoleProductPreview />
        </div>
      </section>

      {/* -----------------------------------------------------------------------------
          8. WORK FROM THE TERMINAL (CLI) — COMPACT SECTION
          ----------------------------------------------------------------------------- */}
      <section className="landing-section" id="cli-quickstart">
        <div className="terminal-compact-box">
          <div>
            <span style={{ fontSize: '10.5px', fontFamily: 'var(--mono)', color: '#737373', letterSpacing: '0.08em', textTransform: 'uppercase' }}>
              POWER-USER INTERFACE
            </span>
            <h3 style={{ fontSize: '18px', fontWeight: 700, color: '#ffffff', margin: '4px 0 6px 0' }}>
              Work from the terminal
            </h3>
            <p style={{ fontSize: '13px', color: '#8e8e93', margin: 0, maxWidth: '440px' }}>
              Analyze captures from the NexSolve CLI with automatic terminal progress and browser launching.
            </p>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: '14px', flexWrap: 'wrap' }}>
            <div className="terminal-code-snippet">
              $ nexsolve analyze &lt;capture.pcap&gt;
            </div>
            <a
              href="#cli-quickstart"
              className="button button-quiet"
              style={{ fontSize: '12px', height: '36px', padding: '0 14px' }}
            >
              <Terminal size={13} />
              <span>View CLI &rarr;</span>
            </a>
          </div>
        </div>
      </section>

      {/* -----------------------------------------------------------------------------
          9. RESEARCH — COMPACT SECTION
          ----------------------------------------------------------------------------- */}
      <section className="landing-section" id="research">
        <div className="research-compact-box">
          <div>
            <span style={{ fontSize: '10.5px', fontFamily: 'var(--mono)', color: '#737373', letterSpacing: '0.08em', textTransform: 'uppercase' }}>
              FOUNDATIONAL ARCHITECTURE
            </span>
            <h3 style={{ fontSize: '18px', fontWeight: 700, color: '#ffffff', margin: '4px 0 6px 0' }}>
              Research
            </h3>
            <p style={{ fontSize: '13px', color: '#8e8e93', margin: 0, maxWidth: '520px', lineHeight: 1.5 }}>
              NexSolve is built around temporal network-state modeling, multi-horizon forecasting, evidence grounding, and calibrated abstention contracts.
            </p>
          </div>

          <Link
            to="/research"
            className="button button-quiet"
            style={{ fontSize: '12px', height: '36px', padding: '0 16px' }}
          >
            <span>View Research &rarr;</span>
          </Link>
        </div>
      </section>

      {/* -----------------------------------------------------------------------------
          10. FINAL CALL TO ACTION
          "START WITH A PACKET CAPTURE."
          ----------------------------------------------------------------------------- */}
      <section className="landing-final-cta" id="cta">
        <h2 className="section-heading-editorial" style={{ fontSize: 'clamp(38px, 4.8vw, 64px)', marginBottom: '12px' }}>
          Start with a packet capture.
        </h2>
        <p className="cta-subtitle" style={{ maxWidth: 560, margin: '0 auto 24px auto' }}>
          Explore how network behavior evolves across time.
        </p>

        <div className="hero-cta-container" style={{ margin: 0 }}>
          <Link
            to="/console"
            className="hero-btn-primary"
            style={{ padding: '0 30px', height: 46 }}
            aria-label="Analyze a PCAP"
          >
            <span>Analyze a PCAP</span>
            <ArrowRight size={15} />
          </Link>

          <Link
            to="/console"
            className="hero-btn-secondary"
            style={{ padding: '0 22px', height: 46 }}
            aria-label="Open Console"
          >
            <span>Open Console</span>
            <ExternalLink size={13} />
          </Link>
        </div>
      </section>
    </div>
  )
}

export default Landing
