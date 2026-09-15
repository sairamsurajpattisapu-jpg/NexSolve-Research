import { Link } from 'react-router-dom'

interface WorkflowStep {
  num: string
  title: string
  sentence: string
  detail: string
}

const STEPS: WorkflowStep[] = [
  {
    num: '01',
    title: 'ANALYZE',
    sentence: 'Inspect the network capture with deterministic wire parsing.',
    detail: 'Enforces magic-byte validation, microsecond wire timestamp preservation, snaplen bounds, and packet deduplication.',
  },
  {
    num: '02',
    title: 'VALIDATE',
    sentence: 'Verify input integrity and structural completeness.',
    detail: 'Ensures minimum temporal requirements (>= 8 discrete windows) and rejects corrupted or synthetic payloads.',
  },
  {
    num: '03',
    title: 'EXTRACT',
    sentence: 'Build the canonical 45-feature state vector from passive telemetry.',
    detail: 'Aggregates 17 flow behavior metrics, 22 packet distribution statistics, and 6 temporal deltas without synthetic RTT fabrication.',
  },
  {
    num: '04',
    title: 'WINDOW',
    sentence: 'Discretize continuous packet flow into uniform 60-second temporal epochs.',
    detail: 'Provides sliding window state representation across historical sequence context.',
  },
  {
    num: '05',
    title: 'FORECAST',
    sentence: 'Project future attack-state progression across horizons T+1 through T+5.',
    detail: 'Evaluated against the validated Persistence Champion baseline with calibrated confidence bounds.',
  },
  {
    num: '06',
    title: 'EVIDENCE',
    sentence: 'Analyze feature perturbation drivers into supporting vs contradictory signals.',
    detail: 'Identifies exact directional shifts driving risk escalation without black-box opacity.',
  },
  {
    num: '07',
    title: 'REPLAY',
    sentence: 'Compare observed temporal progression against projected horizons.',
    detail: 'Enables deterministic side-by-side trajectory inspection of historical epochs.',
  },
  {
    num: '08',
    title: 'SIMULATION',
    sentence: 'Evaluate a modelled counterfactual under controlled feature perturbations.',
    detail: 'Simulates trajectory sensitivity under hypothetical defense adjustments without promising absolute prevention.',
  },
  {
    num: '09',
    title: 'REPORT',
    sentence: 'Generate reproducible forensic analysis output with SHA-256 integrity verification.',
    detail: 'Exports tamper-evident forensic dossiers with cryptographic hashes of all input telemetry and model checkpoints.',
  },
]

export function Workflow() {
  return (
    <div className="page-stack page-enter workflow-editorial-container">
      {/* Editorial Header */}
      <section className="editorial-page-header">
        <div className="editorial-meta-tag">
          SPECIFICATION / PIPELINE
        </div>
        <h1 className="editorial-display-heading">
          Workflow
        </h1>
        <p className="editorial-lead-text">
          A 9-step deterministic progression from raw network wire capture to multi-horizon threat foresight.
        </p>
      </section>

      <div className="editorial-hr" />

      {/* Editorial Timeline Sequence */}
      <section className="workflow-sequence-list">
        {STEPS.map((step) => (
          <div key={step.num} className="workflow-sequence-row">
            <div className="workflow-seq-num">{step.num}</div>
            <div className="workflow-seq-body">
              <div className="workflow-seq-title">{step.title}</div>
              <p className="workflow-seq-sentence">{step.sentence}</p>
              <p className="workflow-seq-detail">{step.detail}</p>
            </div>
          </div>
        ))}
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
            <Link to="/analyze" className="button button-primary">
              Launch Console
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
