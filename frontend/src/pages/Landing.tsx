import { useState } from 'react'
import { Link } from 'react-router-dom'
import {
  Activity,
  ArrowRight,
  ChevronDown,
  Clock,
  FileText,
  GitBranch,
  Shield,
  Sparkles,
  TrendingUp,
  Workflow,
} from 'lucide-react'

const PIPELINE_STEPS = [
  {
    id: 'ingest',
    step: '01',
    title: 'Passive Ingest & Validation',
    eyebrow: 'Boundary Verification',
    description:
      'Reads raw microsecond packet streams or packet captures (.pcap, .pcapng). Enforces snaplen bounds clamping, strict magic-byte verification, and packet deduplication without payload tampering.',
    tech: 'libpcap wire ingestion · Zero payload modification · 250 MB boundary clamping',
  },
  {
    id: 'normalize',
    step: '02',
    title: 'Header Normalization',
    eyebrow: 'Protocol Dissection',
    description:
      'Decodes IP packet structures, isolates transport headers (TCP, UDP, ICMP), standardizes microsecond timestamp intervals, and filters truncated frames.',
    tech: 'Layer 3/4 header normalization · Strict temporal ordering · Zero heuristic interpolation',
  },
  {
    id: 'reconstruct',
    step: '03',
    title: 'Flow Reconstruction',
    eyebrow: 'Bidirectional Sessions',
    description:
      'Aggregates packets into bidirectional 5-tuple conversations. Tracks active session duration, packet inter-arrival timing (IAT), byte volume distribution, and TCP state flags.',
    tech: '5-tuple flow aggregation · TCP handshake state tracking · Byte velocity metrics',
  },
  {
    id: 'represent',
    step: '04',
    title: 'Canonical State Representation',
    eyebrow: '45-Dimensional Continuous Schema',
    description:
      'Condenses network behavior into an audited 45-feature vector S_t across discrete 60-second tumbling windows: 17 flow behavior metrics, 22 packet distribution moments, and 6 temporal rate deltas.',
    tech: 'Audited 45-dim contract · Strictly omits mean_tcp_rtt under Zero-Fabrication Contract',
  },
  {
    id: 'analyze',
    step: '05',
    title: 'Topology & Behavioral Analysis',
    eyebrow: 'Graph Structure G_t',
    description:
      'Computes time-indexed interaction graphs G_t = (V_t, E_t), node out-degree centrality, fan-out ratios, and baseline statistical behavior across the rolling 8-window context.',
    tech: 'Dynamic graph decomposition · Communication centrality · Temporal presence tracking',
  },
  {
    id: 'simulate',
    step: '06',
    title: 'World Model Simulation',
    eyebrow: 'Autoregressive Multi-Step Rollout',
    description:
      'Recursive LSTM World Model ingests sequence history S_{t-7..t} and projects future continuous state vectors S_{t+1}, S_{t+2}, S_{t+3}, and S_{t+5} into the prospective horizon.',
    tech: 'Deep recurrent World Model · State trajectory simulation · Multi-horizon rollout',
  },
  {
    id: 'forecast',
    step: '07',
    title: 'Multi-Horizon Forecasting',
    eyebrow: 'Attack Trajectory & Cumulative Risk',
    description:
      'Evaluates point attack probabilities p_h across discrete forward steps alongside compounding cumulative threat exposure Risk(K) = 1 - ∏_{h=1}^K (1 - p_h) with calibrated uncertainty bounds.',
    tech: 'Point probability vs compounding risk · Horizon stepping T+1..T+5 · Calibration warnings',
  },
  {
    id: 'explain',
    step: '08',
    title: 'Counterfactual Attribution',
    eyebrow: 'Forensic Evidence & MITRE Correlates',
    description:
      'Isolates top predictive drivers via mathematical counterfactual sensitivity analysis (∂p/∂x_i) and contextualizes findings with MITRE ATT&CK behavioral interpretations.',
    tech: 'Counterfactual perturbation attribution · MITRE tactic alignment · Immutable audit provenance',
  },
]

const CAPABILITIES = [
  {
    icon: <Activity size={20} color="var(--text-primary)" />,
    title: 'Passive Network Analysis',
    desc: 'Ingests standard .pcap and .pcapng files passively without inline packet dropping, active probes, or host agent installation.',
  },
  {
    icon: <Clock size={20} color="var(--text-primary)" />,
    title: 'Temporal State Modeling',
    desc: 'Transforms raw wire telemetry into ordered 60-second continuous 45-feature state vectors with historical 8-window context.',
  },
  {
    icon: <TrendingUp size={20} color="var(--text-primary)" />,
    title: 'Multi-Horizon Attack Forecasting',
    desc: 'Autoregressive World Model simulates prospective network states across forward lookaheads T+1, T+2, T+3, and T+5.',
  },
  {
    icon: <GitBranch size={20} color="var(--text-primary)" />,
    title: 'Attack Progression Tracking',
    desc: 'Maps detected adversarial behavior to sequential kill-chain stages: Reconnaissance, Probe Scan, Weaponization, and Lateral Traversal.',
  },
  {
    icon: <Shield size={20} color="var(--text-primary)" />,
    title: 'Evidence & Attribution',
    desc: 'Counterfactual sensitivity perturbation isolates exact wire telemetry drivers responsible for elevating the predicted risk curve.',
  },
  {
    icon: <FileText size={20} color="var(--text-primary)" />,
    title: 'Forensic Intelligence Reports',
    desc: 'Comprehensive executive and forensic audit packages with cryptographic SHA-256 provenance hashes and structured JSON exports.',
  },
]

const TOP_FAQS = [
  {
    q: 'What is NexSolve and how does attack forecasting work?',
    a: 'NexSolve is an AI-based network attack forecasting platform. Rather than merely detecting intrusions after exploits detonate, it reconstructs continuous network-state representations across discrete 60-second windows, simulates forward dynamics with a World Model, and forecasts attack progression across T+1 through T+5 horizons.',
  },
  {
    q: 'Does NexSolve replace an IDS or firewall?',
    a: 'No. NexSolve operates as a complementary temporal predictive layer. It does not perform active inline packet dropping or signature matching, but provides security analysts with proactive lead time before full kill-chain execution.',
  },
  {
    q: 'Does NexSolve fabricate unavailable passive metrics?',
    a: 'Never. Under a strict Zero-Fabrication Contract, metrics that cannot be genuinely observed from passive packet taps—most notably mean_tcp_rtt—are permanently excluded from the 45-feature schema rather than zero-filled or guessed.',
  },
  {
    q: 'What happens when input data contains fewer than 8 windows?',
    a: 'NexSolve enforces calibrated abstention. When capture history contains fewer than 8 discrete 60-second windows (< 8 minutes of context), the system withholds prospective forecasts rather than outputting speculative predictions.',
  },
]

export function Landing() {
  const [activeStep, setActiveStep] = useState<number>(0)
  const [openFaq, setOpenFaq] = useState<number | null>(null)

  const currentStep = PIPELINE_STEPS[activeStep]

  return (
    <div className="page-stack page-enter landing-container" style={{ maxWidth: '1200px', margin: '0 auto', width: '100%', padding: '0 16px' }}>
      {/* 1. HERO SECTION */}
      <section className="landing-hero-editorial" style={{ textAlign: 'center', padding: '56px 0 40px 0' }}>
        <div className="landing-meta-line" style={{ display: 'inline-flex', alignItems: 'center', gap: '8px', fontSize: '11px', fontFamily: 'var(--mono)', color: 'var(--text-muted)', letterSpacing: '0.08em', marginBottom: '16px' }}>
          <span>NETWORK SECURITY</span>
          <span className="meta-sep">/</span>
          <span>AUTONOMOUS ATTACK FORECASTING</span>
        </div>

        <h1 className="landing-editorial-title" style={{ fontSize: 'clamp(38px, 6vw, 64px)', fontWeight: 800, margin: '0 0 8px 0', letterSpacing: '-0.03em', color: 'var(--text-primary)' }}>
          NEXSOLVE
        </h1>

        <div className="landing-editorial-subheading" style={{ fontSize: 'clamp(20px, 3vw, 28px)', fontWeight: 600, color: 'var(--text-secondary)', letterSpacing: '-0.02em', marginBottom: '16px' }}>
          Network Attack Forecasting
        </div>

        <p className="landing-editorial-lead" style={{ fontSize: '16px', color: 'var(--text-secondary)', maxWidth: '680px', margin: '0 auto 28px auto', lineHeight: 1.6 }}>
          Forecast how network attack-state behavior may evolve across multiple future horizons.
          See where the network is heading — not just where it has been.
        </p>

        {/* Primary CTA Row */}
        <div style={{ display: 'flex', gap: '12px', alignItems: 'center', justifyContent: 'center', flexWrap: 'wrap', marginBottom: '40px' }}>
          <Link to="/console/analyze" className="button button-primary" style={{ padding: '12px 28px', fontSize: '14px', fontWeight: 600, gap: '8px' }}>
            <Sparkles size={16} /> Launch Console
          </Link>
          <Link to="/console/analyze" className="button button-quiet" style={{ padding: '12px 24px', fontSize: '14px', gap: '6px' }}>
            Analyze PCAP
          </Link>
          <Link to="/workflow" className="button button-quiet" style={{ padding: '12px 24px', fontSize: '14px', gap: '6px' }}>
            <Workflow size={16} /> Explore Workflow
          </Link>
        </div>

        {/* Visual Architecture Flow Diagram: Traffic -> Behavior -> Detection -> Forecast -> Explanation */}
        <div style={{ background: 'var(--bg-secondary)', border: '1px solid var(--border)', borderRadius: '8px', padding: '20px', maxWidth: '980px', margin: '0 auto 36px auto' }}>
          <span style={{ fontSize: '10px', fontFamily: 'var(--mono)', fontWeight: 700, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.08em', display: 'block', marginBottom: '14px' }}>
            CORE OPERATIONAL ARCHITECTURE FLOW
          </span>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '10px' }}>
            <div style={{ flex: '1 1 140px', padding: '12px 8px', background: 'var(--bg-surface)', border: '1px solid var(--border)', borderRadius: '6px', textAlign: 'center' }}>
              <span style={{ fontSize: '10px', fontFamily: 'var(--mono)', color: 'var(--text-muted)', display: 'block' }}>INPUT</span>
              <strong style={{ fontSize: '12.5px', color: 'var(--text-primary)' }}>NETWORK TRAFFIC</strong>
            </div>

            <ArrowRight size={16} color="var(--text-muted)" />

            <div style={{ flex: '1 1 140px', padding: '12px 8px', background: 'var(--bg-surface)', border: '1px solid var(--border)', borderRadius: '6px', textAlign: 'center' }}>
              <span style={{ fontSize: '10px', fontFamily: 'var(--mono)', color: 'var(--text-muted)', display: 'block' }}>TEMPORALITY</span>
              <strong style={{ fontSize: '12.5px', color: 'var(--text-primary)' }}>BEHAVIOR</strong>
            </div>

            <ArrowRight size={16} color="var(--text-muted)" />

            <div style={{ flex: '1 1 140px', padding: '12px 8px', background: 'var(--bg-surface)', border: '1px solid var(--border)', borderRadius: '6px', textAlign: 'center' }}>
              <span style={{ fontSize: '10px', fontFamily: 'var(--mono)', color: 'var(--text-muted)', display: 'block' }}>EVALUATION</span>
              <strong style={{ fontSize: '12.5px', color: 'var(--text-primary)' }}>ATTACK DETECTION</strong>
            </div>

            <ArrowRight size={16} color="var(--text-muted)" />

            <div style={{ flex: '1 1 140px', padding: '12px 8px', background: 'var(--bg-surface)', border: '1px solid var(--border)', borderRadius: '6px', textAlign: 'center' }}>
              <span style={{ fontSize: '10px', fontFamily: 'var(--mono)', color: 'var(--text-muted)', display: 'block' }}>PROJECTION</span>
              <strong style={{ fontSize: '12.5px', color: 'var(--text-primary)' }}>TEMPORAL FORECAST</strong>
            </div>

            <ArrowRight size={16} color="var(--text-muted)" />

            <div style={{ flex: '1 1 140px', padding: '12px 8px', background: 'var(--bg-surface)', border: '1px solid var(--border)', borderRadius: '6px', textAlign: 'center' }}>
              <span style={{ fontSize: '10px', fontFamily: 'var(--mono)', color: 'var(--text-muted)', display: 'block' }}>REASONING</span>
              <strong style={{ fontSize: '12.5px', color: 'var(--text-primary)' }}>EXPLANATION</strong>
            </div>
          </div>
        </div>

        {/* Contract Metadata Strip */}
        <div className="landing-contract-strip" style={{ display: 'flex', justifyContent: 'center', alignItems: 'center', flexWrap: 'wrap', gap: '20px', fontSize: '12px', fontFamily: 'var(--mono)', color: 'var(--text-secondary)' }}>
          <div>
            <span style={{ color: 'var(--text-muted)', marginRight: '6px' }}>SCHEMA:</span>
            <strong style={{ color: 'var(--text-primary)' }}>45 Canonical Features</strong>
          </div>
          <div>&middot;</div>
          <div>
            <span style={{ color: 'var(--text-muted)', marginRight: '6px' }}>WINDOW:</span>
            <strong style={{ color: 'var(--text-primary)' }}>60s Discrete Windows</strong>
          </div>
          <div>&middot;</div>
          <div>
            <span style={{ color: 'var(--text-muted)', marginRight: '6px' }}>LOOKAHEAD:</span>
            <strong style={{ color: 'var(--text-primary)' }}>T+1 to T+5 Horizons</strong>
          </div>
          <div>&middot;</div>
          <div>
            <span style={{ color: 'var(--text-muted)', marginRight: '6px' }}>INTEGRITY:</span>
            <strong style={{ color: 'var(--text-primary)' }}>Zero RTT Fabrication</strong>
          </div>
        </div>
      </section>

      <div className="editorial-hr" />

      {/* 2. THE PROBLEM & THE APPROACH */}
      <section style={{ padding: '36px 0' }}>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))', gap: '32px' }}>
          <div>
            <span style={{ fontSize: '11px', fontFamily: 'var(--mono)', fontWeight: 700, color: 'var(--text-primary)', textTransform: 'uppercase', letterSpacing: '0.08em' }}>
              THE CORE PROBLEM
            </span>
            <h2 style={{ fontSize: '24px', fontWeight: 700, color: 'var(--text-primary)', margin: '8px 0 12px 0', letterSpacing: '-0.02em' }}>
              Network attacks evolve across time. Reactive alerts arrive too late.
            </h2>
            <p style={{ fontSize: '14.5px', color: 'var(--text-secondary)', lineHeight: 1.6, margin: 0 }}>
              Traditional intrusion detection systems alert defenders after packets have delivered exploits and hosts have been compromised.
              Adversaries operate in progressive multi-step stages: early network scanning, service probing, and lateral traversal before bulk impact occurs.
              Without temporal modeling, defenders remain stuck in reactive posture.
            </p>
          </div>

          <div>
            <span style={{ fontSize: '11px', fontFamily: 'var(--mono)', fontWeight: 700, color: 'var(--text-primary)', textTransform: 'uppercase', letterSpacing: '0.08em' }}>
              THE NEXSOLVE APPROACH
            </span>
            <h2 style={{ fontSize: '24px', fontWeight: 700, color: 'var(--text-primary)', margin: '8px 0 12px 0', letterSpacing: '-0.02em' }}>
              Traffic &rarr; State &rarr; Temporal Model &rarr; Forecast &rarr; Evidence
            </h2>
            <p style={{ fontSize: '14.5px', color: 'var(--text-secondary)', lineHeight: 1.6, margin: 0 }}>
              NexSolve formalizes network defense as an autoregressive state simulation problem. Continuous packet streams are sliced into discrete 60-second temporal windows.
              An internal World Model recursively projects prospective future network states, outputting calibrated attack probabilities and cumulative risk curves backed by mathematical counterfactual evidence.
            </p>
          </div>
        </div>
      </section>

      <div className="editorial-hr" />

      {/* 3. PRODUCT CAPABILITIES */}
      <section style={{ padding: '36px 0' }}>
        <div style={{ textAlign: 'center', marginBottom: '32px' }}>
          <span style={{ fontSize: '11px', fontFamily: 'var(--mono)', fontWeight: 700, color: 'var(--text-primary)', textTransform: 'uppercase', letterSpacing: '0.08em' }}>
            PLATFORM CAPABILITIES
          </span>
          <h2 style={{ fontSize: '28px', fontWeight: 700, color: 'var(--text-primary)', margin: '6px 0 0 0', letterSpacing: '-0.02em' }}>
            Built for Defensive Cyber Operations
          </h2>
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))', gap: '16px' }}>
          {CAPABILITIES.map((cap, idx) => (
            <div
              key={idx}
              style={{
                background: 'var(--bg-surface)',
                border: '1px solid var(--border)',
                borderRadius: '8px',
                padding: '24px',
              }}
            >
              <div style={{ marginBottom: '14px' }}>{cap.icon}</div>
              <h3 style={{ fontSize: '16px', fontWeight: 600, color: 'var(--text-primary)', margin: '0 0 8px 0' }}>
                {cap.title}
              </h3>
              <p style={{ fontSize: '13.5px', color: 'var(--text-secondary)', lineHeight: 1.55, margin: 0 }}>
                {cap.desc}
              </p>
            </div>
          ))}
        </div>
      </section>

      <div className="editorial-hr" />

      {/* 4. VISUAL PROCESS: 8-STAGE PROCESSING PIPELINE */}
      <section id="pipeline-tour" style={{ padding: '36px 0' }}>
        <div style={{ marginBottom: '24px' }}>
          <span style={{ fontSize: '11px', fontFamily: 'var(--mono)', fontWeight: 700, color: 'var(--text-primary)', textTransform: 'uppercase', letterSpacing: '0.08em' }}>
            PIPELINE ARCHITECTURE
          </span>
          <h2 style={{ fontSize: '28px', fontWeight: 700, color: 'var(--text-primary)', margin: '6px 0 0 0', letterSpacing: '-0.02em' }}>
            8-Stage Telemetry Processing Pipeline
          </h2>
        </div>

        <div className="pipeline-editorial-layout" style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: '20px' }}>
          {/* Stage selector list */}
          <div className="pipeline-editorial-list" role="tablist" style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
            {PIPELINE_STEPS.map((s, idx) => (
              <button
                key={s.id}
                type="button"
                role="tab"
                aria-selected={activeStep === idx}
                className={`pipeline-nav-row ${activeStep === idx ? 'active' : ''}`}
                onClick={() => setActiveStep(idx)}
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: '12px',
                  padding: '12px 16px',
                  background: activeStep === idx ? 'var(--bg-secondary)' : 'var(--bg-surface)',
                  border: `1px solid ${activeStep === idx ? 'var(--text-primary)' : 'var(--border)'}`,
                  borderRadius: '6px',
                  cursor: 'pointer',
                  textAlign: 'left',
                }}
              >
                <span style={{ fontSize: '11px', fontFamily: 'var(--mono)', fontWeight: 700, color: 'var(--text-muted)' }}>{s.step}</span>
                <span style={{ fontSize: '13px', fontWeight: 600, color: 'var(--text-primary)' }}>{s.title}</span>
              </button>
            ))}
          </div>

          {/* Stage detail card */}
          <div style={{ background: 'var(--bg-surface)', border: '1px solid var(--border)', borderRadius: '8px', padding: '28px', display: 'flex', flexDirection: 'column', justifyContent: 'space-between' }}>
            <div>
              <div style={{ fontSize: '11px', fontFamily: 'var(--mono)', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.08em', marginBottom: '8px' }}>
                STAGE {currentStep.step} OF 08 &middot; {currentStep.eyebrow}
              </div>
              <h3 style={{ fontSize: '22px', fontWeight: 700, color: 'var(--text-primary)', margin: '0 0 12px 0' }}>
                {currentStep.title}
              </h3>
              <p style={{ fontSize: '14px', color: 'var(--text-secondary)', lineHeight: 1.6, margin: '0 0 20px 0' }}>
                {currentStep.description}
              </p>
              <div style={{ background: 'var(--bg-secondary)', border: '1px solid var(--border)', borderRadius: '6px', padding: '12px 16px', fontSize: '12px', fontFamily: 'var(--mono)', color: 'var(--text-primary)' }}>
                {currentStep.tech}
              </div>
            </div>

            <div style={{ display: 'flex', gap: '10px', marginTop: '24px' }}>
              <button
                type="button"
                className="button button-quiet"
                disabled={activeStep === 0}
                onClick={() => setActiveStep(Math.max(0, activeStep - 1))}
                style={{ fontSize: '12px' }}
              >
                Previous Stage
              </button>
              <button
                type="button"
                className="button button-primary"
                disabled={activeStep === PIPELINE_STEPS.length - 1}
                onClick={() => setActiveStep(Math.min(PIPELINE_STEPS.length - 1, activeStep + 1))}
                style={{ fontSize: '12px' }}
              >
                Next Stage
              </button>
            </div>
          </div>
        </div>
      </section>

      <div className="editorial-hr" />

      {/* 5. FORECASTING: OBSERVED HISTORY VS PREDICTED FUTURE */}
      <section style={{ padding: '36px 0' }}>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))', gap: '28px', alignItems: 'center' }}>
          <div>
            <span style={{ fontSize: '11px', fontFamily: 'var(--mono)', fontWeight: 700, color: 'var(--text-primary)', textTransform: 'uppercase', letterSpacing: '0.08em' }}>
              TEMPORAL BOUNDARY
            </span>
            <h2 style={{ fontSize: '26px', fontWeight: 700, color: 'var(--text-primary)', margin: '8px 0 12px 0', letterSpacing: '-0.02em' }}>
              Strict Division Between Observed Telemetry and Future Simulation
            </h2>
            <p style={{ fontSize: '14px', color: 'var(--text-secondary)', lineHeight: 1.6, margin: '0 0 16px 0' }}>
              NexSolve maintains an immutable temporal boundary. Everything up to T_0 represents verified passive telemetry observed from raw packet headers.
              Everything past T_0 represents prospective multi-step neural simulations across horizons T+1 (+60s), T+2 (+120s), T+3 (+180s), and T+5 (+300s).
            </p>
            <div style={{ display: 'flex', gap: '10px' }}>
              <Link to="/console/forecast" className="button button-primary" style={{ fontSize: '12px', gap: '6px' }}>
                <TrendingUp size={14} /> View Forecast Console
              </Link>
            </div>
          </div>

          {/* Graphical Representation of Forecast Curve */}
          <div style={{ background: 'var(--bg-secondary)', border: '1px solid var(--border)', borderRadius: '8px', padding: '24px' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px' }}>
              <span style={{ fontSize: '11px', fontFamily: 'var(--mono)', fontWeight: 700, color: 'var(--text-primary)' }}>
                FORWARD HORIZON SIMULATION
              </span>
              <span style={{ fontSize: '10px', fontFamily: 'var(--mono)', color: 'var(--text-muted)' }}>
                WINDOW Δt = 60 SECONDS
              </span>
            </div>

            <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', padding: '8px 12px', background: 'var(--bg-surface)', border: '1px solid var(--border)', borderRadius: '4px' }}>
                <span style={{ fontSize: '12px', fontFamily: 'var(--mono)', color: 'var(--text-muted)' }}>T_0 (Observed Baseline)</span>
                <span style={{ fontSize: '12px', fontFamily: 'var(--mono)', fontWeight: 700, color: 'var(--text-primary)' }}>Risk: 12% &middot; Normal</span>
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between', padding: '8px 12px', background: 'var(--bg-surface)', border: '1px solid var(--border)', borderRadius: '4px' }}>
                <span style={{ fontSize: '12px', fontFamily: 'var(--mono)', color: 'var(--accent)' }}>T+1 (+60s Lookahead)</span>
                <span style={{ fontSize: '12px', fontFamily: 'var(--mono)', fontWeight: 700, color: 'var(--accent)' }}>p_1: 0.34 &middot; Recon</span>
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between', padding: '8px 12px', background: 'var(--bg-surface)', border: '1px solid var(--border)', borderRadius: '4px' }}>
                <span style={{ fontSize: '12px', fontFamily: 'var(--mono)', color: 'var(--amber)' }}>T+2 (+120s Lookahead)</span>
                <span style={{ fontSize: '12px', fontFamily: 'var(--mono)', fontWeight: 700, color: 'var(--amber)' }}>p_2: 0.58 &middot; Probe Scan</span>
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between', padding: '8px 12px', background: 'var(--bg-surface)', border: '1px solid var(--border)', borderRadius: '4px' }}>
                <span style={{ fontSize: '12px', fontFamily: 'var(--mono)', color: 'var(--danger)' }}>T+5 (+300s Compounding)</span>
                <span style={{ fontSize: '12px', fontFamily: 'var(--mono)', fontWeight: 700, color: 'var(--danger)' }}>Risk(5): 88% &middot; Lateral</span>
              </div>
            </div>
          </div>
        </div>
      </section>

      <div className="editorial-hr" />

      {/* 6. EVIDENCE & COUNTERFACTUAL EXPLANATION */}
      <section style={{ padding: '36px 0' }}>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))', gap: '32px' }}>
          <div>
            <span style={{ fontSize: '11px', fontFamily: 'var(--mono)', fontWeight: 700, color: 'var(--text-primary)', textTransform: 'uppercase', letterSpacing: '0.08em' }}>
              EXPLAINABILITY & EVIDENCE
            </span>
            <h2 style={{ fontSize: '24px', fontWeight: 700, color: 'var(--text-primary)', margin: '8px 0 12px 0', letterSpacing: '-0.02em' }}>
              Why Did the System Forecast an Attack?
            </h2>
            <p style={{ fontSize: '14px', color: 'var(--text-secondary)', lineHeight: 1.6, margin: '0 0 16px 0' }}>
              NexSolve rejects opaque black-box outputs. Predictions are accompanied by counterfactual sensitivity perturbation analysis.
              By evaluating the model's partial derivatives with respect to canonical wire metrics, analysts can immediately see which specific flow behaviors (such as packet size variance or SYN-ACK asymmetry) are driving the prospective risk curve.
            </p>
            <Link to="/console/evidence" className="button button-quiet" style={{ fontSize: '12px', gap: '6px' }}>
              <Shield size={14} /> Explore Evidence Suite
            </Link>
          </div>

          <div style={{ background: 'var(--bg-surface)', border: '1px solid var(--border)', borderRadius: '8px', padding: '24px' }}>
            <h3 style={{ fontSize: '15px', fontWeight: 600, color: 'var(--text-primary)', margin: '0 0 12px 0' }}>
              Scientific Integrity & Responsible Interpretation
            </h3>
            <ul style={{ paddingLeft: '18px', margin: 0, fontSize: '13px', color: 'var(--text-secondary)', lineHeight: 1.6 }}>
              <li style={{ marginBottom: '8px' }}><strong>Zero RTT Fabrication:</strong> Does not synthesize unobservable round-trip times.</li>
              <li style={{ marginBottom: '8px' }}><strong>Persistence Champion Baseline:</strong> Evaluates models against strict temporal persistence baselines.</li>
              <li style={{ marginBottom: '8px' }}><strong>Calibrated Abstention:</strong> Explicitly withholds forecasts when historical context is &lt; 8 windows.</li>
              <li><strong>Behavioral Alignment:</strong> MITRE ATT&CK mappings represent contextual correlations, not payload proofs.</li>
            </ul>
          </div>
        </div>
      </section>

      <div className="editorial-hr" />

      {/* 7. ARCHITECTURE & SPECIFICATION PREVIEWS */}
      <section style={{ padding: '36px 0' }}>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: '16px' }}>
          <div style={{ background: 'var(--bg-surface)', border: '1px solid var(--border)', borderRadius: '8px', padding: '24px' }}>
            <span style={{ fontSize: '10px', fontFamily: 'var(--mono)', color: 'var(--text-muted)', textTransform: 'uppercase' }}>SPECIFICATION</span>
            <h3 style={{ fontSize: '18px', fontWeight: 600, color: 'var(--text-primary)', margin: '4px 0 8px 0' }}>Security Architecture</h3>
            <p style={{ fontSize: '13px', color: 'var(--text-secondary)', lineHeight: 1.5, margin: '0 0 16px 0' }}>
              Read our technical documentation on zero-telemetry local processing, input validation, and air-gapped guarantees.
            </p>
            <Link to="/security" className="button button-quiet" style={{ fontSize: '12px', gap: '4px' }}>
              Security Specification <ArrowRight size={12} />
            </Link>
          </div>

          <div style={{ background: 'var(--bg-surface)', border: '1px solid var(--border)', borderRadius: '8px', padding: '24px' }}>
            <span style={{ fontSize: '10px', fontFamily: 'var(--mono)', color: 'var(--text-muted)', textTransform: 'uppercase' }}>FORMAL METHODOLOGY</span>
            <h3 style={{ fontSize: '18px', fontWeight: 600, color: 'var(--text-primary)', margin: '4px 0 8px 0' }}>Research Paper</h3>
            <p style={{ fontSize: '13px', color: 'var(--text-secondary)', lineHeight: 1.5, margin: '0 0 16px 0' }}>
              Explore the mathematical problem formulation, state representation S_t ∈ ℝ^45, and autoregressive rollout dynamics.
            </p>
            <Link to="/research" className="button button-quiet" style={{ fontSize: '12px', gap: '4px' }}>
              Research Methodology <ArrowRight size={12} />
            </Link>
          </div>

          <div style={{ background: 'var(--bg-surface)', border: '1px solid var(--border)', borderRadius: '8px', padding: '24px' }}>
            <span style={{ fontSize: '10px', fontFamily: 'var(--mono)', color: 'var(--text-muted)', textTransform: 'uppercase' }}>COMPANY & VISION</span>
            <h3 style={{ fontSize: '18px', fontWeight: 600, color: 'var(--text-primary)', margin: '4px 0 8px 0' }}>About NexSolve</h3>
            <p style={{ fontSize: '13px', color: 'var(--text-secondary)', lineHeight: 1.5, margin: '0 0 16px 0' }}>
              Learn why NexSolve exists, our defensive technology philosophy, and our core engineering development principles.
            </p>
            <Link to="/about" className="button button-quiet" style={{ fontSize: '12px', gap: '4px' }}>
              About Platform <ArrowRight size={12} />
            </Link>
          </div>
        </div>
      </section>

      <div className="editorial-hr" />

      {/* 8. FAQ PREVIEW */}
      <section style={{ padding: '36px 0' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '12px', marginBottom: '24px' }}>
          <div>
            <span style={{ fontSize: '11px', fontFamily: 'var(--mono)', fontWeight: 700, color: 'var(--text-primary)', textTransform: 'uppercase', letterSpacing: '0.08em' }}>
              COMMON INQUIRIES
            </span>
            <h2 style={{ fontSize: '26px', fontWeight: 700, color: 'var(--text-primary)', margin: '4px 0 0 0', letterSpacing: '-0.02em' }}>
              Frequently Asked Questions
            </h2>
          </div>
          <Link to="/faq" className="button button-quiet" style={{ fontSize: '12px', gap: '4px' }}>
            View All 20 Questions <ArrowRight size={12} />
          </Link>
        </div>

        <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
          {TOP_FAQS.map((faq, idx) => {
            const isOpen = openFaq === idx
            return (
              <div
                key={idx}
                style={{
                  background: 'var(--bg-surface)',
                  border: '1px solid var(--border)',
                  borderRadius: '6px',
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
                    color: 'var(--text-primary)',
                    fontSize: '14.5px',
                    fontWeight: 600,
                    gap: '12px',
                  }}
                >
                  <span>{faq.q}</span>
                  <ChevronDown
                    size={16}
                    style={{
                      color: 'var(--text-muted)',
                      transform: isOpen ? 'rotate(180deg)' : 'rotate(0deg)',
                      transition: 'transform 0.2s ease',
                      flexShrink: 0,
                    }}
                  />
                </button>
                {isOpen && (
                  <div style={{ padding: '0 20px 16px 20px', fontSize: '13.5px', color: 'var(--text-secondary)', lineHeight: 1.6, borderTop: '1px solid var(--border)', paddingTop: '12px' }}>
                    {faq.a}
                  </div>
                )}
              </div>
            )
          })}
        </div>
      </section>

      {/* 9. FINAL CALL TO ACTION */}
      <section style={{ margin: '20px 0 50px 0', padding: '40px 28px', background: 'var(--bg-surface)', border: '1px solid var(--border)', borderRadius: '8px', textAlign: 'center' }}>
        <h2 style={{ fontSize: '26px', fontWeight: 700, margin: '0 0 10px 0', color: 'var(--text-primary)', letterSpacing: '-0.02em' }}>
          Begin Network Attack Forecasting
        </h2>
        <p style={{ fontSize: '14.5px', color: 'var(--text-secondary)', maxWidth: '540px', margin: '0 auto 24px auto', lineHeight: 1.6 }}>
          Upload live packet telemetry to reconstruct network-state representations and project forward adversarial progression.
        </p>
        <Link to="/console" className="button button-primary" style={{ padding: '12px 28px', fontSize: '14px', fontWeight: 600, gap: '8px' }}>
          <Sparkles size={16} /> Enter Security Console
        </Link>
      </section>
    </div>
  )
}
