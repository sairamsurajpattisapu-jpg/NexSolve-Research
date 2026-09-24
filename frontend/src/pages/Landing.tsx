import { useState, useEffect } from 'react'
import { Link } from 'react-router-dom'
import {
  ArrowLeft,
  ArrowRight,
  ChevronDown,
  ExternalLink,
} from 'lucide-react'
import '../styles/landing.css'
import { HeroTemporalVisualization } from '../components/landing/HeroTemporalVisualization'
import { ProgressionLifecycleVisual } from '../components/landing/ProgressionLifecycleVisual'

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

const SENSOR_ADAPTERS = [
  {
    name: 'Scapy',
    type: 'Packet Wire Dissector',
    desc: 'Ingests raw pcap frames, detects link types, parses IPv4/IPv6, TCP, UDP, ICMP, DNS queries, and TLS ClientHello SNI.',
  },
  {
    name: 'Zeek',
    type: 'Network Security Monitor',
    desc: 'Normalizes conn.log, dns.log, ssl.log, weird.log, and notice.log into unified telemetry observations.',
  },
  {
    name: 'Suricata',
    type: 'NIDS Alert Engine',
    desc: 'Parses eve.json alert streams, extracting MITRE ATT&CK technique IDs, signature severity, and flow timestamps.',
  },
  {
    name: 'NFStream',
    type: 'Bidirectional Flow Engine',
    desc: 'Extracts statistical flow moments, inter-arrival times (IAT), and byte velocities mapped to the 45-feature schema.',
  },
]

const REPORT_SECTIONS = [
  { num: '01', title: 'Executive Summary', status: 'INFERRED' },
  { num: '02', title: 'Capture Identity', status: 'OBSERVED' },
  { num: '03', title: 'Network Overview', status: 'OBSERVED' },
  { num: '04', title: 'Threat Assessment', status: 'INFERRED' },
  { num: '05', title: 'Current Network State', status: 'OBSERVED' },
  { num: '06', title: 'Attack Progression', status: 'INFERRED' },
  { num: '07', title: 'Attack Horizon', status: 'FORECAST' },
  { num: '08', title: 'Evidence', status: 'OBSERVED' },
  { num: '09', title: 'Feature Drivers', status: 'INFERRED' },
  { num: '10', title: 'MITRE Mapping', status: 'INFERRED' },
  { num: '11', title: 'Sensor Agreement', status: 'OBSERVED' },
  { num: '12', title: 'Uncertainty', status: 'INFERRED' },
  { num: '13', title: 'Abstention', status: 'INFERRED' },
  { num: '14', title: 'Provenance', status: 'OBSERVED' },
  { num: '15', title: 'Model Information', status: 'OBSERVED' },
  { num: '16', title: 'Limitations & Governance', status: 'OBSERVED' },
]

const TOP_FAQS = [
  {
    q: 'What does NexSolve actually do?',
    a: 'NexSolve analyzes network traffic captures, reconstructs temporal network behavior, identifies attack progression, and forecasts how an attack may evolve before compromise — while showing the evidence and uncertainty behind the forecast.',
  },
  {
    q: 'How is NexSolve different from traditional IDS/IPS or SIEMs?',
    a: 'Traditional tools alert on events that have already transpired (T0 reactive posture). NexSolve formalizes network defense as temporal state forecasting, simulating prospective network dynamics across future lookahead horizons (T+1 through T+5) to provide defenders with actionable early-warning lead time.',
  },
  {
    q: 'Does NexSolve fabricate unobservable passive metrics?',
    a: 'Never. Under a strict data integrity contract, metrics that cannot be genuinely observed from passive packet taps—most notably Mean TCP RTT—are permanently excluded from the 45-feature schema rather than zero-filled or guessed.',
  },
  {
    q: 'What is the calibrated abstention contract?',
    a: 'When an input capture contains fewer than 8 discrete 60-second windows (< 8 minutes of context), NexSolve explicitly withholds prospective forecasts rather than outputting speculative hallucinations. Insufficient evidence produces abstention, not false certainty.',
  },
]

const TECHNICAL_PILLARS = [
  {
    id: 'state-model',
    category: 'REPRESENTATION',
    title: '45-Dimensional Continuous Schema',
    description:
      'Aggregates packets into discrete 60-second tumbling windows S_t. Captures 17 flow behavior metrics, 22 packet distribution moments, and 6 temporal rate deltas.',
    meta: 'Audited 45-feature schema · Passive tap integrity',
  },
  {
    id: 'multi-horizon',
    category: 'SIMULATION',
    title: 'Multi-Horizon Rollout (T+1 → T+5)',
    description:
      'Autoregressive state models project future attack states across forward intervals (+60s, +120s, +180s, +240s, +300s) with separated point and cumulative risks.',
    meta: 'Point P(Atk) vs Cumulative Risk(K) = 1 - ∏(1 - p_h)',
  },
  {
    id: 'kinematics',
    category: 'ATTACK REASONING',
    title: '15-Stage Kinematic Transitions',
    description:
      'Grounded transition validation between reconnaissance, lateral movement, C2 beaconing, and exfiltration prevents speculative stage leaps.',
    meta: 'Markov transition priors · MITRE ATT&CK alignment',
  },
  {
    id: 'provenance',
    category: 'CRYPTO INTEGRITY',
    title: 'SHA-256 Cryptographic Provenance',
    description:
      'Every wire packet, extracted flow, feature vector, and forecast step is immutably hashed for verifiable chain-of-custody and peer review.',
    meta: 'Deterministic SHA-256 digests · Zero payload tampering',
  },
  {
    id: 'abstention',
    category: 'EPISTEMIC HONESTY',
    title: 'Calibrated Abstention Contract',
    description:
      'When historical captures contain fewer than 8 discrete 60-second windows (< 8 minutes), NexSolve explicitly withholds prospective forecasts.',
    meta: 'Zero synthetic hallucination · Integrity guarantees',
  },
  {
    id: 'adapters',
    category: 'INGESTION',
    title: 'Zero-Hard-Dependency Adapters',
    description:
      'Seamlessly consumes and normalizes telemetry streams from Scapy wire frames, Zeek logs, Suricata eve.json, and NFStream flow records.',
    meta: 'Unified telemetry ingestion · Schema mapping',
  },
  {
    id: 'forensics',
    category: 'AUDIT REPORTING',
    title: '16-Section Structured Dossiers',
    description:
      'Produces standardized forensic audit reports in self-contained HTML, Markdown, and JSON with explicit epistemic tagging across all sections.',
    meta: 'OBSERVED · INFERRED · FORECAST segregation',
  },
  {
    id: 'offline',
    category: 'DEPLOYMENT',
    title: 'Air-Gapped Offline Edge Execution',
    description:
      'Runs 100% locally on sovereign infrastructure or secure enclaves with zero outbound telemetry, telemetry phoning home, or external cloud calls.',
    meta: '100% Local execution · Sovereign air-gapped readiness',
  },
]

export function Landing() {
  const [activeStep, setActiveStep] = useState<number>(0)
  const [openFaq, setOpenFaq] = useState<number | null>(null)
  const [activeSection, setActiveSection] = useState<string>('problem')

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
            if (entry.target.id) {
              setActiveSection(entry.target.id)
            }
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
        <div className="hero-pill-badge">
          <span className="pill-dot" />
          <span>AI-POWERED NETWORK ATTACK FORECASTING FROM NETWORK TRAFFIC</span>
        </div>

        <h1 className="hero-headline">
          <span style={{ display: 'block', fontSize: 'clamp(20px, 2.6vw, 30px)', fontWeight: 800, letterSpacing: '0.08em', color: '#a1a1aa', marginBottom: 10 }}>
            NEXSOLVE
          </span>
          <span className="headline-accent">See the attack</span>
          <br />
          before it unfolds.
        </h1>

        <p className="hero-subheadline">
          NexSolve turns network traffic captures into temporal attack intelligence —
          reconstructing what happened, where an attack is progressing, and what may happen next.
          Forecast how network attack-state behavior may evolve across multiple future horizons.
        </p>

        <div className="hero-cta-container">
          {/* Primary CTA (Preserves START for tests & analyst expectations) */}
          <Link
            to="/console/analyze"
            className="hero-btn-primary"
            aria-label="START — Launch Console"
          >
            <span>START</span>
            <ArrowRight size={15} />
          </Link>

          <Link to="/console/analyze" className="hero-btn-secondary">
            <span>Analyze PCAP</span>
            <ExternalLink size={14} />
          </Link>

          <Link to="/workflow" className="hero-btn-secondary">
            <span>Explore Workflow</span>
          </Link>

          <Link to="/console" className="hero-btn-secondary">
            <span>Open Console</span>
          </Link>
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

        {/* Quick Section Anchor Navigation */}
        <nav aria-label="Section shortcuts" style={{ display: 'flex', gap: 8, flexWrap: 'wrap', justifyContent: 'center', marginTop: 18, marginBottom: 8 }}>
          <a href="#problem" className={`landing-anchor-pill ${activeSection === 'problem' ? 'active' : ''}`}>Problem</a>
          <a href="#how-it-works" className={`landing-anchor-pill ${activeSection === 'how-it-works' ? 'active' : ''}`}>Pipeline</a>
          <a href="#progression" className={`landing-anchor-pill ${activeSection === 'progression' ? 'active' : ''}`}>15-Stage Lifecycle</a>
          <a href="#forecasting" className={`landing-anchor-pill ${activeSection === 'forecasting' ? 'active' : ''}`}>Forecasting</a>
          <a href="#evidence" className={`landing-anchor-pill ${activeSection === 'evidence' ? 'active' : ''}`}>Evidence Trace</a>
          <a href="#sensors" className={`landing-anchor-pill ${activeSection === 'sensors' ? 'active' : ''}`}>Sensors</a>
          <a href="#workflow" className={`landing-anchor-pill ${activeSection === 'workflow' ? 'active' : ''}`}>CLI Tooling</a>
          <a href="#reporting" className={`landing-anchor-pill ${activeSection === 'reporting' ? 'active' : ''}`}>Reports</a>
          <a href="#technology" className={`landing-anchor-pill ${activeSection === 'technology' ? 'active' : ''}`}>Technology</a>
          <a href="#faq" className={`landing-anchor-pill ${activeSection === 'faq' ? 'active' : ''}`}>FAQ</a>
        </nav>

        {/* -----------------------------------------------------------------------------
            2. HERO VISUALIZATION (TEMPORAL GRAPH & ATTACK HORIZON)
            ----------------------------------------------------------------------------- */}
        <HeroTemporalVisualization />
      </section>

      {/* -----------------------------------------------------------------------------
          3. PROBLEM SECTION: DETECTION VS TRAJECTORY
          ----------------------------------------------------------------------------- */}
      <section className="landing-section" id="problem">
        <span className="section-eyebrow">THE OPERATIONAL DILEMMA</span>
        <h2 className="section-heading-large">
          Detection tells you what happened.
          <br />
          NexSolve asks what happens next.
        </h2>
        <p className="section-desc" style={{ maxWidth: 740 }}>
          Traditional security monitoring relies on reactive signatures, alerts, and post-breach indicators.
          NexSolve introduces temporal reasoning to project forward adversarial trajectories before full operational compromise.
        </p>

        <div className="problem-grid">
          <div className="problem-card reactive">
            <div className="problem-card-header">
              <span className="problem-tag">TRADITIONAL REACTIVE MONITORING</span>
              <h3 className="problem-card-title">Alert After Detonation (Lead Time = 0s)</h3>
              <p style={{ fontSize: 13.5, color: '#a1a1aa', lineHeight: 1.55, margin: 0 }}>
                Traditional IDS/IPS and SIEM tools inspect isolated frames or match signatures after packets trigger a firewall rule.
                Defenders scramble to investigate events that have already transpired.
              </p>
            </div>

            <div className="chain-flow">
              <div className="chain-step">
                <span className="step-title">1. Raw Packets</span>
                <span className="step-tag">Wire Frame (T0)</span>
              </div>
              <div className="chain-step">
                <span className="step-title">2. Signature Match</span>
                <span className="step-tag">Rule Alert (T0)</span>
              </div>
              <div className="chain-step">
                <span className="step-title">3. Incident Response</span>
                <span className="step-tag">Post-Breach Investigation</span>
              </div>
            </div>
          </div>

          <div className="problem-card proactive">
            <div className="problem-card-header">
              <span className="problem-tag" style={{ color: '#10b981' }}>NEXSOLVE TEMPORAL FORECASTING</span>
              <h3 className="problem-card-title">Predictive Lead Time (T+1 to T+5 Horizons)</h3>
              <p style={{ fontSize: 13.5, color: '#a1a1aa', lineHeight: 1.55, margin: 0 }}>
                NexSolve models evolving network states across discrete 60s windows, mapping early reconnaissance and probing stages
                to forecast future lateral movement, C2 beaconing, and exfiltration before compromise.
              </p>
            </div>

            <div className="chain-flow">
              <div className="chain-step" style={{ borderColor: 'rgba(16, 185, 129, 0.3)' }}>
                <span className="step-title">1. Packet Telemetry</span>
                <span className="step-tag" style={{ color: '#34d399' }}>[OBSERVED]</span>
              </div>
              <div className="chain-step" style={{ borderColor: 'rgba(56, 189, 248, 0.3)' }}>
                <span className="step-title">2. 45-Dim State Vector S_t</span>
                <span className="step-tag" style={{ color: '#38bdf8' }}>[INFERRED]</span>
              </div>
              <div className="chain-step" style={{ borderColor: 'rgba(245, 158, 11, 0.3)' }}>
                <span className="step-title">3. Multi-Horizon Rollout</span>
                <span className="step-tag" style={{ color: '#fbbf24' }}>[FORECAST T+1..T+5]</span>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* -----------------------------------------------------------------------------
          4. HOW IT WORKS (PIPELINE ARCHITECTURE & INTERACTIVE STEPPER)
          ----------------------------------------------------------------------------- */}
      <section className="landing-section" id="how-it-works">
        <span className="section-eyebrow">SYSTEM ARCHITECTURE</span>
        <h2 className="section-heading-large">
          The 7-Stage End-to-End Intelligence Pipeline
        </h2>
        <p className="section-desc" style={{ maxWidth: 740 }}>
          From raw microsecond wire captures to mathematical counterfactual evidence and 16-section forensic audit packages.
        </p>

        {/* Interactive Pipeline Stepper for Test Assertions & Engagement */}
        <div style={{ marginTop: 32, background: '#09090b', border: '1px solid rgba(255,255,255,0.1)', borderRadius: 10, padding: 24 }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16 }}>
            <span style={{ fontFamily: 'monospace', fontSize: 11, color: '#a1a1aa', fontWeight: 700 }}>
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

          <h3 style={{ fontSize: 20, fontWeight: 700, color: '#ffffff', margin: '0 0 8px 0' }}>
            {currentStep.title}
          </h3>
          <p style={{ fontSize: 14, color: '#a1a1aa', lineHeight: 1.6, margin: '0 0 16px 0' }}>
            {currentStep.description}
          </p>
          <div style={{ fontFamily: 'monospace', fontSize: 11.5, color: '#38bdf8', background: 'rgba(56, 189, 248, 0.06)', padding: '8px 12px', borderRadius: 4 }}>
            {currentStep.tech}
          </div>
        </div>

        {/* All Pipeline Cards Grid */}
        <div className="pipeline-track-cards">
          {PIPELINE_STEPS.slice(0, 7).map((step) => (
            <div key={step.id} className="pipeline-card">
              <span className="pipeline-step-num">{step.step}</span>
              <h4 className="pipeline-step-title">{step.title}</h4>
              <p className="pipeline-step-desc">{step.description}</p>
              <div className="pipeline-step-meta">{step.eyebrow}</div>
            </div>
          ))}
        </div>
      </section>

      {/* -----------------------------------------------------------------------------
          5. 15-STAGE ATTACK PROGRESSION
          ----------------------------------------------------------------------------- */}
      <section className="landing-section" id="progression">
        <span className="section-eyebrow">ATTACK LIFECYCLE REASONING</span>
        <h2 className="section-heading-large">
          15-Stage Attack Progression & Kinematics
        </h2>
        <p className="section-desc" style={{ maxWidth: 760 }}>
          Rather than reducing complex security events to binary "malicious or benign" tags, NexSolve evaluates traffic
          against a structured 15-stage adversarial progression lifecycle grounded in empirical transition kinematics.
        </p>

        <ProgressionLifecycleVisual />
      </section>

      {/* -----------------------------------------------------------------------------
          6. FORECASTING & UNCERTAINTY SECTION
          ----------------------------------------------------------------------------- */}
      <section className="landing-section" id="forecasting">
        <span className="section-eyebrow">PROSPECTIVE INTELLIGENCE</span>
        <h2 className="section-heading-large">
          Forecast the Next State (T+1 to T+5 Horizons)
        </h2>
        <div style={{ display: 'inline-flex', alignItems: 'center', gap: 6, padding: '2px 8px', background: 'rgba(255,255,255,0.04)', border: '1px solid rgba(255,255,255,0.1)', borderRadius: 4, fontSize: 10.5, fontFamily: 'monospace', color: '#a1a1aa', marginBottom: 12 }}>
          Illustrative example &middot; Demonstrates multi-horizon schema
        </div>
        <p className="section-desc" style={{ maxWidth: 760 }}>
          Autoregressive LSTM network state models simulate forward trajectory steps.
          Point probabilities p_h are strictly distinguished from cumulative compounding threat exposure Risk(K) = 1 - &prod;(1 - p_h).
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
                <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 10, fontFamily: 'monospace', color: '#71717a', marginBottom: 2 }}>
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

        <div className="philosophy-banner">
          <strong>The NexSolve Uncertainty & Abstention Principle:</strong>
          <br />
          "Every forecast carries uncertainty. Insufficient evidence should produce calibrated abstention — not fabricated certainty."
          When captures contain fewer than 8 discrete 60s windows, NexSolve withholds forward forecasts to protect analysts from false confidence.
        </div>
      </section>

      {/* -----------------------------------------------------------------------------
          7. EVIDENCE-FIRST ATTRIBUTION TRACE
          ----------------------------------------------------------------------------- */}
      <section className="landing-section" id="evidence">
        <span className="section-eyebrow">COUNTERFACTUAL ATTRIBUTION</span>
        <h2 className="section-heading-large">
          Every Conclusion Must Have a Verifiable Trail
        </h2>
        <p className="section-desc" style={{ maxWidth: 760 }}>
          NexSolve connects every analytical conclusion, stage assessment, and forward risk probability directly back
          to observed physical wire telemetry without black-box opacity.
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
          8. MULTI-SENSOR INTEGRATION MATRIX
          ----------------------------------------------------------------------------- */}
      <section className="landing-section" id="sensors">
        <span className="section-eyebrow">SENSOR ECOSYSTEM</span>
        <h2 className="section-heading-large">
          Multi-Sensor Telemetry Normalization & Fusion
        </h2>
        <p className="section-desc" style={{ maxWidth: 760 }}>
          NexSolve features zero-hard-dependency adapters that ingest standard telemetry streams and map them to the
          45-feature canonical world model contract.
        </p>

        <div className="sensor-adapter-grid">
          {SENSOR_ADAPTERS.map((sensor) => (
            <div key={sensor.name} className="sensor-card">
              <div className="sensor-name">{sensor.name}</div>
              <div className="sensor-type">{sensor.type}</div>
              <p className="sensor-desc">{sensor.desc}</p>
            </div>
          ))}
        </div>
      </section>

      {/* -----------------------------------------------------------------------------
          9. CLI + WEB CONSOLE UNIFIED WORKFLOW
          ----------------------------------------------------------------------------- */}
      <section className="landing-section" id="workflow">
        <span className="section-eyebrow">DEVELOPER & ANALYST EXPERIENCE</span>
        <h2 className="section-heading-large">
          Start from the Terminal. Investigate in the Console.
        </h2>
        <p className="section-desc" style={{ maxWidth: 760 }}>
          Run high-speed forensic audits directly in CI/CD or your terminal shell, and automatically pivot to the
          interactive React web console when multi-horizon visual investigation is required.
        </p>

        <div className="workflow-grid">
          {/* Terminal Mockup */}
          <div className="terminal-mockup">
            <div className="terminal-header">
              <span className="term-dot" />
              <span className="term-dot" />
              <span className="term-dot" />
              <span className="term-title">nexsolve-cli — bash</span>
            </div>
            <div className="terminal-body">
              <div>
                <span className="terminal-prompt">$ </span>
                <span>nexsolve analyze captures/incident.pcap --open</span>
              </div>
              <div className="terminal-dim">[01/08] Ingesting wire packet capture...</div>
              <div><span className="terminal-stage">[INGESTION]</span> Parsed 2,277 frames (100% verified)</div>
              <div><span className="terminal-stage">[RECONSTRUCTION]</span> 283 bidirectional TCP/UDP flows</div>
              <div><span className="terminal-stage">[WINDOWING]</span> 10 discrete 60s windows partitioned</div>
              <div><span className="terminal-stage">[STATE VECTOR]</span> 45 continuous features extracted</div>
              <div><span className="terminal-stage">[SIMULATION]</span> Multi-horizon LSTM rollout T+1..T+5</div>
              <div><span className="terminal-stage">[EVIDENCE]</span> Counterfactual sensitivity delta computed</div>
              <div style={{ color: '#10b981', marginTop: 6 }}>[OK] Analysis job completed: job-88f7b12080e5</div>
              <div style={{ marginTop: 6 }}>
                <span className="terminal-dim">&rarr; Launching Web Console: </span>
                <span style={{ color: '#ffffff', textDecoration: 'underline' }}>http://localhost:5173/console/forecast</span>
              </div>
            </div>
          </div>

          <div>
            <h3 style={{ fontSize: 22, fontWeight: 700, color: '#ffffff', margin: '0 0 12px 0' }}>
              Full Command-Line Tooling Suite
            </h3>
            <p style={{ fontSize: 14, color: '#a1a1aa', lineHeight: 1.6, margin: '0 0 20px 0' }}>
              NexSolve CLI provides dedicated commands for every phase of security operations:
            </p>
            <ul style={{ paddingLeft: 18, margin: 0, fontSize: 13.5, color: '#a1a1aa', lineHeight: 1.7 }}>
              <li><code>nexsolve investigate &lt;job_id&gt;</code> &mdash; Full terminal investigation dossier</li>
              <li><code>nexsolve explain &lt;job_id&gt;</code> &mdash; Feature deltas & sensor agreement</li>
              <li><code>nexsolve export &lt;job_id&gt;</code> &mdash; Self-contained HTML, Markdown, and JSON</li>
              <li><code>nexsolve progression &lt;job_id&gt;</code> &mdash; 15-stage lifecycle state and kinematics</li>
              <li><code>nexsolve doctor</code> &mdash; System diagnostics and dependency verification</li>
            </ul>
          </div>
        </div>
      </section>

      {/* -----------------------------------------------------------------------------
          10. STANDARDIZED 16-SECTION FORENSIC REPORTING
          ----------------------------------------------------------------------------- */}
      <section className="landing-section" id="reporting">
        <span className="section-eyebrow">FORENSIC GOVERNANCE</span>
        <h2 className="section-heading-large">
          Standardized 16-Section Forensic Reports
        </h2>
        <div style={{ display: 'inline-flex', alignItems: 'center', gap: 6, padding: '2px 8px', background: 'rgba(255,255,255,0.04)', border: '1px solid rgba(255,255,255,0.1)', borderRadius: 4, fontSize: 10.5, fontFamily: 'monospace', color: '#a1a1aa', marginBottom: 12 }}>
          Illustrative example &middot; Demonstrates structured 16-section report layout
        </div>
        <p className="section-desc" style={{ maxWidth: 760 }}>
          Every completed analysis compiles into a standalone, air-gapped forensic report adhering to 16 rigorously
          defined and epistemic labeled sections across HTML, JSON, and Markdown formats.
        </p>

        <div className="reporting-grid">
          <div className="report-sections-list">
            {REPORT_SECTIONS.map((sec) => (
              <div key={sec.num} className="report-sec-pill">
                <span className="report-sec-num">{sec.num}</span>
                <span className="report-sec-label">{sec.title}</span>
                <span className={`tag-badge ${sec.status.toLowerCase()}`} style={{ fontSize: 8 }}>
                  {sec.status}
                </span>
              </div>
            ))}
          </div>

          <div className="report-preview-sheet">
            <div className="report-sheet-header">
              <div>
                <div style={{ fontSize: 9.5, fontFamily: 'monospace', color: '#64748b', textTransform: 'uppercase' }}>
                  NEXSOLVE &middot; FORENSIC INTELLIGENCE DOSSIER
                </div>
                <div className="report-sheet-title">Security Assessment Report</div>
              </div>
              <div style={{ textAlign: 'right', fontSize: 10, fontFamily: 'monospace', color: '#64748b' }}>
                ID: REP-88F7B120
                <br />
                SHA-256 VERIFIED
              </div>
            </div>

            <div style={{ fontSize: 12, color: '#334155', marginBottom: 12 }}>
              <strong>Executive Threat Posture:</strong> <span style={{ color: '#0f172a', fontWeight: 700 }}>ELEVATED [INFERRED]</span>
              <br />
              <strong>Projected Kill-Chain Stage:</strong> <span style={{ color: '#0f172a', fontWeight: 700 }}>Lateral Movement &rarr; Exfiltration [FORECAST]</span>
            </div>

            <div style={{ background: '#f8fafc', border: '1px solid #e2e8f0', borderRadius: 4, padding: 10, fontSize: 11, fontFamily: 'monospace', color: '#475569' }}>
              &bull; 02 CAPTURE IDENTITY: friday_10windows_slice.pcap (2,277 frames) [OBSERVED]<br />
              &bull; 05 CURRENT NETWORK STATE: 45 Continuous Features across 10 60s Windows [OBSERVED]<br />
              &bull; 08 EVIDENCE: SYN-ACK asymmetry (+420% vs baseline) [OBSERVED]<br />
              &bull; 13 ABSTENTION: Valid history requirement met (&ge; 8 windows) [INFERRED]
            </div>
          </div>
        </div>
      </section>

      {/* -----------------------------------------------------------------------------
          11. TECHNICAL CREDIBILITY & ARCHITECTURAL RIGOR
          ----------------------------------------------------------------------------- */}
      <section className="landing-section" id="technology">
        <span className="section-eyebrow">SCIENTIFIC RIGOR & ARCHITECTURE</span>
        <h2 className="section-heading-large">
          Engineering & Modeling Credibility
        </h2>
        <p className="section-desc" style={{ maxWidth: 760 }}>
          Built upon verifiable machine learning formulations, strict temporal causality, and an unyielding commitment
          to epistemic honesty over speculative hallucinations.
        </p>

        <div className="tech-credibility-grid">
          {TECHNICAL_PILLARS.map((pillar) => (
            <div key={pillar.id} className="tech-credibility-card">
              <span className="tech-credibility-pill">{pillar.category}</span>
              <h3 className="tech-credibility-title">{pillar.title}</h3>
              <p className="tech-credibility-desc">{pillar.description}</p>
              <div className="tech-credibility-badge">{pillar.meta}</div>
            </div>
          ))}
        </div>
      </section>

      {/* -----------------------------------------------------------------------------
          12. FREQUENTLY ASKED QUESTIONS
          ----------------------------------------------------------------------------- */}
      <section className="landing-section" id="faq">
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: 12, marginBottom: 24 }}>
          <div>
            <span className="section-eyebrow">COMMON INQUIRIES</span>
            <h2 className="section-heading-large" style={{ margin: 0 }}>
              Frequently Asked Questions
            </h2>
          </div>
          <Link to="/faq" className="button button-quiet" style={{ fontSize: 12, gap: 4 }}>
            View Full Documentation <ArrowRight size={12} />
          </Link>
        </div>

        <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
          {TOP_FAQS.map((faq, idx) => {
            const isOpen = openFaq === idx
            return (
              <div
                key={idx}
                style={{
                  background: '#0d0d10',
                  border: '1px solid rgba(255, 255, 255, 0.08)',
                  borderRadius: 6,
                  overflow: 'hidden',
                }}
              >
                <button
                  type="button"
                  onClick={() => setOpenFaq(isOpen ? null : idx)}
                  aria-expanded={isOpen}
                  style={{
                    width: '100%',
                    padding: '16px 20px',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'space-between',
                    background: 'none',
                    border: 'none',
                    cursor: 'pointer',
                    textAlign: 'left',
                    color: '#ffffff',
                    fontSize: 14.5,
                    fontWeight: 600,
                    gap: 12,
                  }}
                >
                  <span>{faq.q}</span>
                  <ChevronDown
                    size={16}
                    style={{
                      color: '#71717a',
                      transform: isOpen ? 'rotate(180deg)' : 'rotate(0deg)',
                      transition: 'transform 0.2s ease',
                      flexShrink: 0,
                    }}
                  />
                </button>
                {isOpen && (
                  <div style={{ padding: '0 20px 16px 20px', fontSize: 13.5, color: '#a1a1aa', lineHeight: 1.6, borderTop: '1px solid rgba(255, 255, 255, 0.06)', paddingTop: 12 }}>
                    {faq.a}
                  </div>
                )}
              </div>
            )
          })}
        </div>
      </section>

      {/* -----------------------------------------------------------------------------
          13. FINAL CALL TO ACTION
          ----------------------------------------------------------------------------- */}
      <section className="landing-final-cta" id="cta">
        <h2 className="cta-title">Turn network traffic into a forecast.</h2>
        <p className="cta-subtitle">
          Analyze a capture. Trace the evidence. Understand the trajectory.
        </p>

        <div className="hero-cta-container" style={{ margin: 0 }}>
          <Link
            to="/console/analyze"
            className="hero-btn-primary"
            style={{ padding: '0 32px', height: 48 }}
          >
            <span>Analyze a PCAP</span>
            <ArrowRight size={16} />
          </Link>
          <Link
            to="/console"
            className="hero-btn-secondary"
            style={{ padding: '0 28px', height: 48 }}
          >
            <span>Open Console</span>
          </Link>
        </div>
      </section>
    </div>
  )
}
