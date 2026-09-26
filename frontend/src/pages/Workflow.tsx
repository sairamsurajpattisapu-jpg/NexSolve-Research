import { Link } from 'react-router-dom'
import { ArrowRight, Activity, Cpu, Layers, ShieldAlert, TrendingUp } from 'lucide-react'

interface ProcessStage {
  num: string
  title: string
  description: string
  attributes: string[]
  icon: typeof Activity
}

const STAGES: ProcessStage[] = [
  {
    num: '01',
    title: 'Ingest & Validate',
    description: 'Continuous wire capture streaming parses PCAP/PCAPNG headers with microsecond timing and magic-byte verification.',
    attributes: ['PCAP / PCAPNG', 'Zero Drops', 'Magic-Byte Validated'],
    icon: Activity,
  },
  {
    num: '02',
    title: 'Header Normalization',
    description: 'Protocol decapsulation and packet header extraction without payload retention or synthetic imputation.',
    attributes: ['L3/L4 Normalization', 'Snaplen Clamping', 'Zero Payload Leakage'],
    icon: Cpu,
  },
  {
    num: '03',
    title: 'Canonical State Extraction',
    description: 'Telemetry structured into the canonical 45-feature state vector across continuous 60-second observation epochs.',
    attributes: ['45-Feature Schema', '60s Windows', 'No RTT Fabrication'],
    icon: Layers,
  },
  {
    num: '04',
    title: 'Threat Assessment',
    description: 'T+0 baseline threat posture evaluated against calibrated criteria with strict safety abstention gating.',
    attributes: ['T+0 State Baseline', 'Calibrated Scoring', 'Safety Abstention'],
    icon: ShieldAlert,
  },
  {
    num: '05',
    title: 'Multi-Horizon Forecast',
    description: 'Forward rollout projecting T+1 to T+5 network state trajectories with step-specific and cumulative risk bounds.',
    attributes: ['Horizons T+1 → T+5', 'Early Warning', 'Cumulative Risk'],
    icon: TrendingUp,
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

      {/* Compact Engineering Process Flow with Directional Arrows */}
      <section className="workflow-flow-section" aria-label="Pipeline Architecture Process Flow">
        <div className="workflow-flow-strip">
          {STAGES.map((stage, index) => {
            const IconComponent = stage.icon
            return (
              <div key={stage.num} className="workflow-step-wrapper">
                <div className="workflow-stage-card">
                  <div className="stage-header">
                    <span className="stage-step-num">{stage.num}</span>
                    <IconComponent size={15} color="var(--text-muted)" />
                  </div>
                  <h2 className="stage-title">{stage.title}</h2>
                  <p className="stage-sentence">{stage.description}</p>
                  <div className="stage-badges">
                    {stage.attributes.map((attr) => (
                      <span key={attr} className="editorial-badge">
                        {attr}
                      </span>
                    ))}
                  </div>
                </div>
                {index < STAGES.length - 1 && (
                  <div className="workflow-flow-arrow" aria-hidden="true">
                    <ArrowRight size={16} />
                  </div>
                )}
              </div>
            )
          })}
        </div>
      </section>

      <div className="editorial-hr" />

      {/* Editorial CTA - Single Canonical Action */}
      <section className="editorial-footer-cta">
        <div className="editorial-cta-wrap telemetry-console-card">
          <span className="editorial-eyebrow">TELEMETRY CONSOLE</span>
          <h2 className="telemetry-card-title">Execute the pipeline with standard PCAP captures.</h2>
          <p className="telemetry-card-desc">
            Upload a PCAP / PCAPNG capture and run the NexSolve pipeline.
          </p>
          <div className="editorial-btn-group" style={{ margin: '18px 0 20px 0' }}>
            <Link to="/console/analyze" className="button button-primary telemetry-start-btn" style={{ gap: '8px', padding: '10px 22px', fontSize: '12px' }}>
              <span>START ANALYSIS</span> <ArrowRight size={14} />
            </Link>
          </div>
          <div className="telemetry-meta-row">
            <span>PCAP / PCAPNG</span>
            <span className="telemetry-meta-dot">&middot;</span>
            <span>45-FEATURE CONTRACT</span>
            <span className="telemetry-meta-dot">&middot;</span>
            <span>T+1 &rarr; T+5</span>
            <span className="telemetry-meta-dot">&middot;</span>
            <span>OFFLINE-FIRST</span>
          </div>
        </div>
      </section>
    </div>
  )
}
