import { useState, useEffect } from 'react'
import { Link } from 'react-router-dom'
import {
  Activity,
  ArrowLeft,
  ArrowRight,
  Clock,
  ExternalLink,
  Layers,
  Network,
  Shield,
  ShieldAlert,
  Terminal,
  TrendingUp,
  Workflow,
} from 'lucide-react'
import '../styles/landing.css'
import { HeroTemporalVisualization } from '../components/landing/HeroTemporalVisualization'
import { ProgressionLifecycleVisual } from '../components/landing/ProgressionLifecycleVisual'
import { CliQuickstartSection } from '../components/landing/CliQuickstartSection'
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

    // Handle scroll for /cli-quickstart and #cli-quickstart
    let timerId: ReturnType<typeof setTimeout> | null = null
    if (window.location.pathname.includes('cli') || window.location.hash.includes('cli')) {
      timerId = setTimeout(() => {
        const el = document.getElementById('cli-quickstart')
        if (el) {
          el.scrollIntoView({ behavior: 'smooth' })
        }
      }, 100)
    }

    return () => {
      observer.disconnect()
      if (timerId) clearTimeout(timerId)
    }
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
          1. HERO SECTION
          Answers:
          - What is it? Network attack forecasting from network traffic.
          - What does it do? Reconstructs temporal network behavior and forecasts progression.
          - What can I do? Upload a PCAP and run an analysis.
          ----------------------------------------------------------------------------- */}
      <section className="landing-hero" id="hero">
        <div className="hero-text-block">
          <div className="hero-pill-badge">
            <span className="pill-dot" />
            <span>AI-BASED NETWORK ATTACK FORECASTING PLATFORM</span>
          </div>

          <h1 className="hero-headline">
            <span className="hero-brand-label">NEXSOLVE &middot; CYBERSECURITY RESEARCH</span>
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

            {/* SECONDARY CTA: How NexSolve Works (scrolls to #how-it-works) */}
            <a
              href="#how-it-works"
              onClick={handleScrollTo('how-it-works')}
              className="hero-btn-secondary"
              aria-label="How NexSolve Works"
            >
              <span>How NexSolve Works</span>
            </a>

            {/* CLI QUICKSTART ACTION (preserves accessible labels for test suite) */}
            <a
              href="#cli-quickstart"
              onClick={handleScrollTo('cli-quickstart')}
              className="hero-btn-secondary"
              aria-label="Use NexSolve CLI — View CLI Commands"
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
            <span className="cue-terminal-text">
              Run <code className="cli-inline-code">nexsolve analyze</code> from your terminal
            </span>
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

        {/* Visual Workflow Breadcrumb Strip */}
        <div className="hero-trust-line" style={{ margin: '20px 0 28px 0', flexWrap: 'wrap', justifyContent: 'center' }}>
          <span>PCAP</span>
          &rarr;
          <span>Temporal Network State</span>
          &rarr;
          <span>Attack Progression</span>
          &rarr;
          <span>Forecast</span>
          &rarr;
          <span>Evidence</span>
        </div>

        {/* Hero Temporal Visualization (Graph & Tree Views) */}
        <HeroTemporalVisualization />
      </section>

      {/* -----------------------------------------------------------------------------
          2. THE PROBLEM SECTION: DETECTION VS FORECASTING
          "Detection tells you what happened. NexSolve asks what happens next."
          ----------------------------------------------------------------------------- */}
      <section className="landing-section" id="problem">
        <span className="section-eyebrow">THE CORE DISTINCTION</span>
        <h2 className="section-heading-editorial">
          Detection tells you what happened.<br />
          <em>NexSolve asks what happens next.</em>
        </h2>
        <p className="section-desc" style={{ maxWidth: 760 }}>
          Traditional network monitoring and detection systems identify suspicious or malicious activity in observed traffic.
          NexSolve focuses on the forward temporal question: <strong>&ldquo;What could this network state evolve into?&rdquo;</strong>
        </p>

        <div className="problem-comparison-grid">
          {/* Column A: Traditional Detection */}
          <div className="problem-side-card">
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '4px' }}>
              <span style={{ fontSize: '10.5px', fontFamily: 'var(--mono)', color: '#737373', letterSpacing: '0.08em', textTransform: 'uppercase' }}>
                OBSERVED TRAFFIC
              </span>
            </div>
            <h3 style={{ fontSize: '18px', fontWeight: 700, color: '#ffffff', margin: 0 }}>
              Traditional Detection &amp; Telemetry
            </h3>
            <p style={{ fontSize: '13.5px', color: '#a3a3a3', lineHeight: 1.6, margin: 0 }}>
              IDS, IPS, and SIEM sensors scan observed packets and system logs to identify known attack signatures, anomalous heuristics, or policy violations after packets traverse the wire.
            </p>
            <div style={{ borderTop: '1px solid #1c1c1c', paddingTop: '12px', marginTop: 'auto', fontSize: '12px', fontFamily: 'var(--mono)', color: '#737373' }}>
              Boundary: Terminates at observation point (T_0)
            </div>
          </div>

          {/* Column B: NexSolve Temporal Forecasting */}
          <div className="problem-side-card contrast">
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '4px' }}>
              <span style={{ fontSize: '10.5px', fontFamily: 'var(--mono)', color: '#ffffff', letterSpacing: '0.08em', textTransform: 'uppercase', fontWeight: 700 }}>
                TEMPORAL PROJECTION
              </span>
            </div>
            <h3 style={{ fontSize: '18px', fontWeight: 700, color: '#ffffff', margin: 0 }}>
              NexSolve Network Attack Forecasting
            </h3>
            <p style={{ fontSize: '13.5px', color: '#d4d4d8', lineHeight: 1.6, margin: 0 }}>
              Reconstructs continuous network kinematics across discrete observation windows and projects learned state distributions across future temporal horizons (T+1 to T+5) before perimeter compromise.
            </p>
            <div style={{ borderTop: '1px solid #282828', paddingTop: '12px', marginTop: 'auto', fontSize: '12px', fontFamily: 'var(--mono)', color: '#a3a3a3' }}>
              Boundary: Simulates +60s through +300s lookahead intervals
            </div>
          </div>
        </div>

        <div style={{ marginTop: '20px', padding: '16px 20px', background: '#0a0a0a', border: '1px solid #1e1e1e', borderRadius: '6px', fontSize: '12.5px', color: '#888888', lineHeight: 1.6 }}>
          <strong style={{ color: '#ffffff' }}>Technical Grounding Contract:</strong> NexSolve does not replace IDS/IPS, SIEM, or EDR sensors. It operates downstream from passive telemetry captures to answer the forward-looking temporal question before lateral movement, privilege escalation, or data exfiltration occur.
        </div>
      </section>

      {/* -----------------------------------------------------------------------------
          3. ACTUAL NEXSOLVE PIPELINE (01 to 05)
          PCAP → TEMPORAL NETWORK STATE → ATTACK PROGRESSION → FORECAST → EVIDENCE
          ----------------------------------------------------------------------------- */}
      <section className="landing-section" id="how-it-works">
        <span className="section-eyebrow">THE OPERATIONAL PIPELINE</span>
        <h2 className="section-heading-editorial">
          How NexSolve Works
        </h2>
        <p className="section-desc" style={{ maxWidth: 760 }}>
          From raw microsecond wire captures to mathematical state representations, multi-horizon rollouts, and verifiable evidence attribution.
        </p>

        {/* 5-Step Visual Pipeline Cards */}
        <div className="pipeline-flow-grid">
          {/* 01 PCAP */}
          <div className="pipeline-flow-card">
            <span className="pipeline-step-badge">STAGE 01</span>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '8px' }}>
              <Layers size={16} color="#ffffff" />
              <strong style={{ fontSize: '14.5px', color: '#ffffff' }}>PCAP</strong>
            </div>
            <div style={{ fontSize: '11px', fontFamily: 'var(--mono)', color: '#737373', marginBottom: '8px' }}>
              Network traffic capture
            </div>
            <p style={{ fontSize: '12.5px', color: '#a3a3a3', lineHeight: 1.5, margin: 0 }}>
              Passive Layer 3/4 packet ingestion (.pcap, .pcapng) with cryptographic SHA-256 provenance and zero payload tampering.
            </p>
          </div>

          {/* 02 TEMPORAL NETWORK STATE */}
          <div className="pipeline-flow-card">
            <span className="pipeline-step-badge">STAGE 02</span>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '8px' }}>
              <Clock size={16} color="#ffffff" />
              <strong style={{ fontSize: '14.5px', color: '#ffffff' }}>TEMPORAL STATE</strong>
            </div>
            <div style={{ fontSize: '11px', fontFamily: 'var(--mono)', color: '#737373', marginBottom: '8px' }}>
              5-tuple aggregation
            </div>
            <p style={{ fontSize: '12.5px', color: '#a3a3a3', lineHeight: 1.5, margin: 0 }}>
              Reconstructs packet streams into discrete 60-second temporal windows and an audited 45-feature continuous state vector S_t.
            </p>
          </div>

          {/* 03 ATTACK PROGRESSION */}
          <div className="pipeline-flow-card">
            <span className="pipeline-step-badge">STAGE 03</span>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '8px' }}>
              <Workflow size={16} color="#ffffff" />
              <strong style={{ fontSize: '14.5px', color: '#ffffff' }}>PROGRESSION</strong>
            </div>
            <div style={{ fontSize: '11px', fontFamily: 'var(--mono)', color: '#737373', marginBottom: '8px' }}>
              Grounded attack signals
            </div>
            <p style={{ fontSize: '12.5px', color: '#a3a3a3', lineHeight: 1.5, margin: 0 }}>
              Computes node out-degree centrality, fan-out velocity, and anomalous flags mapped to grounded MITRE ATT&CK techniques.
            </p>
          </div>

          {/* 04 FORECAST */}
          <div className="pipeline-flow-card">
            <span className="pipeline-step-badge">STAGE 04</span>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '8px' }}>
              <TrendingUp size={16} color="#ffffff" />
              <strong style={{ fontSize: '14.5px', color: '#ffffff' }}>FORECAST</strong>
            </div>
            <div style={{ fontSize: '11px', fontFamily: 'var(--mono)', color: '#737373', marginBottom: '8px' }}>
              T+1 &rarr; T+5 horizons
            </div>
            <p style={{ fontSize: '12.5px', color: '#a3a3a3', lineHeight: 1.5, margin: 0 }}>
              Autoregressive state model simulates forward lookaheads (+60s to +300s), separating point probability from cumulative risk.
            </p>
          </div>

          {/* 05 EVIDENCE */}
          <div className="pipeline-flow-card">
            <span className="pipeline-step-badge">STAGE 05</span>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '8px' }}>
              <Shield size={16} color="#ffffff" />
              <strong style={{ fontSize: '14.5px', color: '#ffffff' }}>EVIDENCE</strong>
            </div>
            <div style={{ fontSize: '11px', fontFamily: 'var(--mono)', color: '#737373', marginBottom: '8px' }}>
              Wire telemetry attribution
            </div>
            <p style={{ fontSize: '12.5px', color: '#a3a3a3', lineHeight: 1.5, margin: 0 }}>
              Connects forward state transitions back to physical flow features, uncertainty envelopes, and calibrated abstention contracts.
            </p>
          </div>
        </div>

        {/* Interactive Pipeline Stepper (Retained for Test Suite Compatibility) */}
        <div style={{ marginTop: 36, background: '#09090b', border: '1px solid rgba(255,255,255,0.1)', borderRadius: 8, padding: 24 }}>
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

          <h3 style={{ fontSize: 18, fontWeight: 700, color: '#ffffff', margin: '0 0 8px 0' }}>
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
          4. THE ATTACK HORIZON CONCEPT
          "From detection to attack horizon."
          ----------------------------------------------------------------------------- */}
      <section className="landing-section" id="forecasting">
        <span className="section-eyebrow">ATTACK HORIZON CONCEPT</span>
        <h2 className="section-heading-editorial">
          From detection to attack horizon.
        </h2>
        <p className="section-desc" style={{ maxWidth: 760 }}>
          NexSolve projects the learned network state across future temporal horizons rather than stopping at the current observed state.
        </p>

        {/* Visual Horizon Track Diagram */}
        <div className="horizon-concept-card">
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px', flexWrap: 'wrap', gap: '8px' }}>
            <span style={{ fontSize: '11px', fontFamily: 'var(--mono)', color: '#737373', letterSpacing: '0.08em', textTransform: 'uppercase' }}>
              HORIZON PROJECTION ARCHITECTURE
            </span>
            <span style={{ fontSize: '11px', fontFamily: 'var(--mono)', color: '#a3a3a3' }}>
              LOOKAHEAD K &in; [1..5] &middot; &Delta;t = 60s
            </span>
          </div>

          {/* ASCII / Graphical Timeline Strip */}
          <div
            style={{
              padding: '24px 20px',
              background: '#040404',
              border: '1px solid #1c1c1c',
              borderRadius: '6px',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
              position: 'relative',
              overflowX: 'auto',
              gap: '16px',
            }}
          >
            {/* Observed */}
            <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
              <div style={{ textAlign: 'center' }}>
                <span style={{ display: 'block', fontSize: '10.5px', fontFamily: 'var(--mono)', color: '#888' }}>OBSERVED</span>
                <span style={{ display: 'inline-block', width: '12px', height: '12px', borderRadius: '50%', background: '#666666', margin: '6px 0' }} />
                <span style={{ display: 'block', fontSize: '10px', color: '#666' }}>-480s to 0s</span>
              </div>
              <div style={{ width: '40px', height: '2px', background: '#333333' }} />
            </div>

            {/* Current State */}
            <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
              <div style={{ textAlign: 'center' }}>
                <span style={{ display: 'block', fontSize: '10.5px', fontFamily: 'var(--mono)', color: '#ffffff', fontWeight: 700 }}>CURRENT STATE</span>
                <span style={{ display: 'inline-block', width: '14px', height: '14px', borderRadius: '50%', background: '#ffffff', margin: '5px 0' }} />
                <span style={{ display: 'block', fontSize: '10px', color: '#aaa' }}>Boundary T_0</span>
              </div>
              <div style={{ width: '40px', height: '2px', borderTop: '2px dashed #666666' }} />
            </div>

            {/* Forecast Horizons (T+1 .. T+5) */}
            <div style={{ display: 'flex', gap: '24px', alignItems: 'center' }}>
              {['T+1 (+60s)', 'T+2 (+120s)', 'T+3 (+180s)', 'T+4 (+240s)', 'T+5 (+300s)'].map((h) => (
                <div key={h} style={{ textAlign: 'center' }}>
                  <span style={{ display: 'block', fontSize: '10px', fontFamily: 'var(--mono)', color: '#a3a3a3' }}>{h.split(' ')[0]}</span>
                  <span style={{ display: 'inline-block', width: '12px', height: '12px', borderRadius: '50%', border: '2px dashed #ffffff', background: '#0a0a0a', margin: '6px 0' }} />
                  <span style={{ display: 'block', fontSize: '9px', color: '#737373' }}>{h.split(' ')[1]}</span>
                </div>
              ))}
            </div>
          </div>

          <div style={{ marginTop: '20px', display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: '16px' }}>
            <div style={{ fontSize: '13px', color: '#a3a3a3', lineHeight: 1.6 }}>
              Rather than collapsing findings into a static indicator, NexSolve simulates forward state distributions.
              Each horizon represents an <strong>estimated future state</strong> conditioned on preceding temporal windows.
            </div>
            <div style={{ fontSize: '13px', color: '#a3a3a3', lineHeight: 1.6 }}>
              Defenders gain the operational margin required to stage containment, isolate compromised subnets, or inspect active C2 beacons prior to full execution.
            </div>
          </div>
        </div>

        {/* 5 Forecast Horizon Detail Cards */}
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

        {/* Honest Abstention Contract */}
        <div className="philosophy-banner" style={{ marginTop: 24 }}>
          <strong>Calibrated Abstention Principle:</strong>
          <br />
          &ldquo;Every forecast carries uncertainty. Insufficient evidence produces calibrated abstention — not fabricated certainty.&rdquo;
          When captures contain fewer than 8 discrete 60-second windows (&lt; 8 minutes), NexSolve explicitly withholds prospective forecasts to prevent speculative extrapolation.
        </div>
      </section>

      {/* -----------------------------------------------------------------------------
          5. EVIDENCE — NOT JUST PREDICTIONS
          "A forecast without evidence is just a number."
          ----------------------------------------------------------------------------- */}
      <section className="landing-section" id="evidence">
        <span className="section-eyebrow">GROUNDED EXPLAINABILITY</span>
        <h2 className="section-heading-editorial">
          A forecast without evidence is just a number.
        </h2>
        <p className="section-desc" style={{ maxWidth: 760 }}>
          NexSolve connects every analytical conclusion, stage assessment, and forward risk probability directly back to observable physical network behavior.
        </p>

        {/* Visual Evidence Chain */}
        <div className="evidence-chain-diagram">
          <div className="evidence-chain-cell">
            <span style={{ fontSize: '9.5px', fontFamily: 'var(--mono)', color: '#737373', display: 'block', textTransform: 'uppercase' }}>INPUT</span>
            <strong style={{ fontSize: '13px', color: '#ffffff' }}>NETWORK TRAFFIC</strong>
          </div>
          <ArrowRight size={14} color="#555" />
          <div className="evidence-chain-cell">
            <span style={{ fontSize: '9.5px', fontFamily: 'var(--mono)', color: '#737373', display: 'block', textTransform: 'uppercase' }}>AGGREGATION</span>
            <strong style={{ fontSize: '13px', color: '#ffffff' }}>FLOW BEHAVIOR</strong>
          </div>
          <ArrowRight size={14} color="#555" />
          <div className="evidence-chain-cell">
            <span style={{ fontSize: '9.5px', fontFamily: 'var(--mono)', color: '#737373', display: 'block', textTransform: 'uppercase' }}>DYNAMICS</span>
            <strong style={{ fontSize: '13px', color: '#ffffff' }}>TEMPORAL CHANGE</strong>
          </div>
          <ArrowRight size={14} color="#555" />
          <div className="evidence-chain-cell">
            <span style={{ fontSize: '9.5px', fontFamily: 'var(--mono)', color: '#737373', display: 'block', textTransform: 'uppercase' }}>REPRESENTATION</span>
            <strong style={{ fontSize: '13px', color: '#ffffff' }}>OBSERVED STATE</strong>
          </div>
          <ArrowRight size={14} color="#555" />
          <div className="evidence-chain-cell">
            <span style={{ fontSize: '9.5px', fontFamily: 'var(--mono)', color: '#737373', display: 'block', textTransform: 'uppercase' }}>EXPLAINABILITY</span>
            <strong style={{ fontSize: '13px', color: '#ffffff' }}>EVIDENCE DRIVERS</strong>
          </div>
          <ArrowRight size={14} color="#555" />
          <div className="evidence-chain-cell" style={{ background: '#141414', borderColor: '#444' }}>
            <span style={{ fontSize: '9.5px', fontFamily: 'var(--mono)', color: '#ffffff', display: 'block', textTransform: 'uppercase', fontWeight: 700 }}>PROJECTION</span>
            <strong style={{ fontSize: '13px', color: '#ffffff' }}>FORECAST</strong>
          </div>
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(300px, 1fr))', gap: '16px', marginTop: '24px' }}>
          <div style={{ background: '#0a0a0a', border: '1px solid #1e1e1e', borderRadius: '6px', padding: '20px' }}>
            <h4 style={{ margin: '0 0 6px 0', fontSize: '14.5px', color: '#ffffff', fontWeight: 700 }}>
              45 Continuous Flow Features
            </h4>
            <p style={{ margin: 0, fontSize: '12.5px', color: '#888888', lineHeight: 1.5 }}>
              Calculates packet distribution moments, byte velocity, and TCP flag dynamics across tumbling windows without synthetic RTT fabrication.
            </p>
          </div>

          <div style={{ background: '#0a0a0a', border: '1px solid #1e1e1e', borderRadius: '6px', padding: '20px' }}>
            <h4 style={{ margin: '0 0 6px 0', fontSize: '14.5px', color: '#ffffff', fontWeight: 700 }}>
              Counterfactual Attribution
            </h4>
            <p style={{ margin: 0, fontSize: '12.5px', color: '#888888', lineHeight: 1.5 }}>
              Identifies which specific continuous features drove the predicted state change, allowing analysts to verify hypotheses directly in raw flow logs.
            </p>
          </div>

          <div style={{ background: '#0a0a0a', border: '1px solid #1e1e1e', borderRadius: '6px', padding: '20px' }}>
            <h4 style={{ margin: '0 0 6px 0', fontSize: '14.5px', color: '#ffffff', fontWeight: 700 }}>
              Truthful Validation Ledger
            </h4>
            <p style={{ margin: 0, fontSize: '12.5px', color: '#888888', lineHeight: 1.5 }}>
              When future windows exist in the capture, NexSolve compares forecast predictions against ground truth. When captures end, it explicitly marks validation unavailable.
            </p>
          </div>
        </div>
      </section>

      {/* -----------------------------------------------------------------------------
          6. ATTACK PROGRESSION
          "Representing attack behavior temporally."
          ----------------------------------------------------------------------------- */}
      <section className="landing-section" id="progression">
        <span className="section-eyebrow">ADVERSARIAL PROGRESSION</span>
        <h2 className="section-heading-editorial">
          Representing attack behavior temporally.
        </h2>
        <p className="section-desc" style={{ maxWidth: 760 }}>
          Attacks are sequential campaigns, not point-in-time anomalies. NexSolve reasons across kill-chain transitions grounded in observed kinematics.
        </p>

        {/* Clean Progression Sequence Banner */}
        <div
          style={{
            margin: '28px 0',
            padding: '20px 24px',
            background: '#070707',
            border: '1px solid #1f1f1f',
            borderRadius: '8px',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            gap: '20px',
            flexWrap: 'wrap',
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
            <span style={{ fontSize: '10px', fontFamily: 'var(--mono)', border: '1px solid #ffffff', padding: '2px 7px', borderRadius: '3px', color: '#ffffff' }}>OBSERVED</span>
            <strong style={{ fontSize: '14px', color: '#ffffff' }}>Reconnaissance</strong>
          </div>
          <ArrowRight size={16} color="#777" />
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
            <span style={{ fontSize: '10px', fontFamily: 'var(--mono)', border: '1px dashed #aaa', padding: '2px 7px', borderRadius: '3px', color: '#ccc' }}>FORECAST</span>
            <strong style={{ fontSize: '14px', color: '#e5e5e5' }}>Discovery</strong>
          </div>
          <ArrowRight size={16} color="#777" />
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
            <span style={{ fontSize: '10px', fontFamily: 'var(--mono)', border: '1px dashed #aaa', padding: '2px 7px', borderRadius: '3px', color: '#ccc' }}>FORECAST</span>
            <strong style={{ fontSize: '14px', color: '#e5e5e5' }}>Command &amp; Control</strong>
          </div>
        </div>

        <div style={{ textAlign: 'center', marginBottom: 20 }}>
          <p style={{ fontSize: 13, color: '#888888', maxWidth: 680, margin: '0 auto' }}>
            <em>&ldquo;Attack-stage interpretation is grounded in the available network evidence.&rdquo;</em><br />
            Progression models do not assume uniform adversary execution, mapping transitions dynamically across observed, inferred, and projected states.
          </p>
        </div>

        <ProgressionLifecycleVisual />
      </section>

      {/* -----------------------------------------------------------------------------
          7. PRODUCT DEMONSTRATION SECTION
          Visual preview of the actual /console
          ----------------------------------------------------------------------------- */}
      <section className="landing-section" id="console-preview">
        <span className="section-eyebrow">PRODUCT PREVIEW</span>
        <h2 className="section-heading-editorial">
          Designed for the analyst command center.
        </h2>
        <p className="section-desc" style={{ maxWidth: 760 }}>
          The NexSolve web console provides an operational SOC investigation workspace uniting PCAP ingestion, multi-horizon trajectories, 5-tuple flow filtering, and forensic reports.
        </p>

        <div style={{ marginTop: '28px' }}>
          <ConsoleProductPreview />
        </div>
      </section>

      {/* -----------------------------------------------------------------------------
          8. WHO IT IS FOR
          Security Analysts, Incident Responders, Security Researchers
          ----------------------------------------------------------------------------- */}
      <section className="landing-section" id="audience">
        <span className="section-eyebrow">OPERATIONAL ROLES</span>
        <h2 className="section-heading-editorial">
          Built for defenders who need to see ahead.
        </h2>
        <p className="section-desc" style={{ maxWidth: 760 }}>
          Providing network-level foresight across three specialized cybersecurity disciplines.
        </p>

        <div className="who-for-grid">
          {/* 1. Security Analysts */}
          <div className="who-for-card">
            <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
              <Activity size={18} color="#ffffff" />
              <h3>Security Analysts</h3>
            </div>
            <p style={{ fontSize: '13px', color: '#8e8e93', lineHeight: 1.6, margin: 0 }}>
              Investigate network behavior, evaluate anomalous 5-tuple flow metrics, and forecast potential attack progression before perimeter compromise.
            </p>
          </div>

          {/* 2. Incident Responders */}
          <div className="who-for-card">
            <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
              <ShieldAlert size={18} color="#ffffff" />
              <h3>Incident Responders</h3>
            </div>
            <p style={{ fontSize: '13px', color: '#8e8e93', lineHeight: 1.6, margin: 0 }}>
              Understand temporal evidence surrounding an emerging threat, inspect window-by-window kinematics, and isolate affected communication pairs.
            </p>
          </div>

          {/* 3. Security Researchers */}
          <div className="who-for-card">
            <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
              <Network size={18} color="#ffffff" />
              <h3>Security Researchers</h3>
            </div>
            <p style={{ fontSize: '13px', color: '#8e8e93', lineHeight: 1.6, margin: 0 }}>
              Study network-state evolution, calibrate autoregressive world models from traffic captures, and audit mathematical counterfactual attribution traces.
            </p>
          </div>
        </div>
      </section>

      {/* -----------------------------------------------------------------------------
          9. THE PROBLEM (FOUNDATIONAL RESEARCH / SIH CONNECTION)
          ----------------------------------------------------------------------------- */}
      <section className="landing-section" id="research-problem">
        <div className="sih-problem-card">
          <span className="section-eyebrow">FOUNDATIONAL THESIS</span>
          <h2 className="section-heading-editorial" style={{ margin: '8px 0 16px 0' }}>
            The problem
          </h2>
          <p style={{ fontSize: '17px', color: '#ffffff', lineHeight: 1.7, margin: '0 0 16px 0', maxWidth: '780px' }}>
            Network attacks do not appear as isolated events. <strong>They evolve.</strong>
          </p>
          <p style={{ fontSize: '14px', color: '#a3a3a3', lineHeight: 1.6, margin: 0, maxWidth: '780px' }}>
            Reconnaissance leads to initial discovery, internal credential multiplexing, and eventual exfiltration across distinct temporal phases.
            Yet traditional systems evaluate alerts as static snapshots. NexSolve models that evolution directly from network traffic captures and forecasts potential future states—giving defenders the temporal advantage.
          </p>
        </div>
      </section>

      {/* -----------------------------------------------------------------------------
          10. CLI QUICKSTART SECTION
          ----------------------------------------------------------------------------- */}
      <CliQuickstartSection />

      {/* -----------------------------------------------------------------------------
          11. FINAL CALL TO ACTION
          "Start with a packet capture."
          ----------------------------------------------------------------------------- */}
      <section className="landing-final-cta" id="cta">
        <h2 className="section-heading-editorial" style={{ fontSize: 'clamp(40px, 5vw, 68px)', marginBottom: '12px' }}>
          Start with a packet capture.
        </h2>
        <p className="cta-subtitle" style={{ maxWidth: 640, margin: '0 auto 28px auto' }}>
          Give NexSolve a network capture and explore how its behavior evolves across time.
        </p>

        <div className="hero-cta-container" style={{ margin: 0 }}>
          {/* Primary CTA: Analyze a PCAP → */}
          <Link
            to="/console"
            className="hero-btn-primary"
            style={{ padding: '0 32px', height: 48 }}
            aria-label="Analyze a PCAP"
          >
            <span>Analyze a PCAP</span>
            <ArrowRight size={16} />
          </Link>

          {/* Secondary CTA: View How It Works */}
          <a
            href="#how-it-works"
            onClick={handleScrollTo('how-it-works')}
            className="hero-btn-secondary"
            style={{ padding: '0 24px', height: 48 }}
            aria-label="View How It Works"
          >
            <span>View How It Works</span>
          </a>

          {/* Tertiary CTA: Open Console */}
          <Link
            to="/console"
            className="hero-btn-tertiary"
            style={{ padding: '0 20px', height: 48 }}
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
