import { Link } from 'react-router-dom'
import { ArrowRight, Activity, Clock, ShieldAlert, TrendingUp, Search } from 'lucide-react'

interface PipelineStage {
  num: string
  title: string
  sentence: string
  detail: string
  badges: string[]
  icon: typeof Activity
}

const STAGES: PipelineStage[] = [
  {
    num: '01',
    title: 'NETWORK TRAFFIC',
    sentence: 'Wire packet ingestion, microsecond timestamps, magic-byte validation, zero packet drops.',
    detail: 'Continuous packet capture streaming parses standard PCAP and PCAPNG headers with microsecond timing fidelity and snaplen clamping.',
    badges: ['PCAP/PCAPNG', 'ZERO DROPS', 'MAGIC-BYTE VALIDATED'],
    icon: Activity,
  },
  {
    num: '02',
    title: 'TEMPORAL STATE',
    sentence: '45-feature aggregation, 60s sliding window, flow + packet distributions, RTT strictly omitted.',
    detail: 'Telemetry is structured into 60-second tumbling epochs comprising 17 flow metrics, 22 packet stats, and 6 temporal deltas without synthetic imputation.',
    badges: ['45-FEATURE SCHEMA', '60s WINDOWS', 'NO RTT FABRICATION'],
    icon: Clock,
  },
  {
    num: '03',
    title: 'ATTACK DETECTION',
    sentence: 'T+0 baseline classification, persistence champion benchmark, calibrated confidence scoring.',
    detail: 'Evaluates current observed state against the Persistence Champion baseline to establish confirmed baseline threat posture and signal deviation.',
    badges: ['T+0 STATE', 'AUROC 0.893', 'CALIBRATED SCORING'],
    icon: ShieldAlert,
  },
  {
    num: '04',
    title: 'TEMPORAL FORECAST',
    sentence: 'Horizons T+1 to T+5 multi-step projection, early warning indicator, onset lead time estimation.',
    detail: 'Simulates prospective multi-step network trajectory, computing Step Attack Probabilities and Cumulative Risk with explicit uncertainty bounds.',
    badges: ['HORIZONS T+1 → T+5', 'LEAD TIME ESTIMATION', 'CUMULATIVE RISK'],
    icon: TrendingUp,
  },
  {
    num: '05',
    title: 'EVIDENCE & REASONING',
    sentence: 'Feature perturbation attribution, directional shift ranking, SHA-256 tamper-evident export.',
    detail: 'Isolates primary telemetry drivers via partial derivative perturbation analysis and compiles an immutable cryptographic audit dossier.',
    badges: ['PERTURBATION ATTRIBUTION', 'SHA-256 PROVENANCE', 'AUDIT READY'],
    icon: Search,
  },
]

export function Workflow() {
  return (
    <div className="page-stack page-enter workflow-editorial-container">
      {/* Editorial Header */}
      <section className="editorial-page-header">
        <div className="editorial-meta-tag">
          SPECIFICATION / PIPELINE ARCHITECTURE
        </div>
        <h1 className="editorial-display-heading">
          Workflow
        </h1>
        <p className="editorial-lead-text">
          A continuous 5-stage engineering pipeline transforming passive wire telemetry into multi-horizon predictive threat intelligence.
        </p>
      </section>

      <div className="editorial-hr" />

      {/* 5-Stage Engineering Pipeline Grid */}
      <section className="workflow-pipeline-grid">
        {STAGES.map((stage) => {
          const IconComponent = stage.icon
          return (
            <div key={stage.num} className="workflow-stage-card">
              <div className="stage-header">
                <span className="stage-step-num">{stage.num}</span>
                <IconComponent size={16} color="var(--text-muted)" />
              </div>
              <h2 className="stage-title">{stage.title}</h2>
              <p className="stage-sentence">{stage.sentence}</p>
              <p className="stage-detail">{stage.detail}</p>
              <div className="stage-badges">
                {stage.badges.map((b) => (
                  <span key={b} className="editorial-badge">
                    {b}
                  </span>
                ))}
              </div>
            </div>
          )
        })}
      </section>

      <div className="editorial-hr" />

      {/* Editorial CTA */}
      <section className="editorial-footer-cta">
        <div className="editorial-cta-wrap">
          <span className="editorial-eyebrow">TELEMETRY CONSOLE</span>
          <h2>Execute the pipeline with standard PCAP captures.</h2>
          <p>
            Upload any standard PCAP / PCAPNG capture or evaluate pre-computed benchmarks in real time.
          </p>
          <div className="editorial-btn-group">
            <Link to="/console/analyze" className="button button-primary" style={{ gap: '6px' }}>
              <span>START</span> <ArrowRight size={13} />
            </Link>
            <Link to="/research" className="button button-secondary">
              Read Research Paper
            </Link>
          </div>
        </div>
      </section>
    </div>
  )
}
