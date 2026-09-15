import { useState } from 'react'
import { Link } from 'react-router-dom'
import {
  FileText,
  GitCommit,
  Radar,
  Sparkles,
  TrendingUp,
} from 'lucide-react'
import { DemoModeSelector } from '../components/DemoModeSelector'
import { LiveDemoWizard } from '../components/LiveDemoWizard'
import { JobResult } from '../components/JobResult'
import { Panel, SectionHeading } from '../components/Ui'
import { useProductionData } from '../hooks/useProductionData'
import type { UploadedAnalysisResponse } from '../types/api'

export function Demo() {
  const { data, setUploadedAnalysis, clearUploadedAnalysis, provenance } = useProductionData()
  const [selectedScenario, setSelectedScenario] = useState<UploadedAnalysisResponse | null>(null)

  const activeResult = selectedScenario ?? (provenance === 'demo' ? (data?.results as unknown as UploadedAnalysisResponse) : null)

  const handleSelectScenario = async (res: UploadedAnalysisResponse) => {
    setSelectedScenario(res)
    await setUploadedAnalysis(res)
  }

  const handleReset = () => {
    setSelectedScenario(null)
    void clearUploadedAnalysis()
  }

  return (
    <div className="page-stack page-enter">
      {/* Header */}
      <SectionHeading
        eyebrow="SMART INDIA HACKATHON 2026 · JURY EVALUATION WORKSPACE"
        title="SIH Judge Demo Explorer & Evaluation Journey"
        description="Deterministic forward evaluation across 7 attack and edge scenarios. Validates temporal forecasting, attack horizon, evidence chain, and abstention behavior without external dependencies."
        action={
          <div className="heading-actions">
            {activeResult && (
              <button className="button button-quiet" onClick={handleReset}>
                Reset to Scenario Picker
              </button>
            )}
            <Link to="/analyze" className="button button-quiet">
              <Radar size={14} /> Analyze Live PCAP
            </Link>
          </div>
        }
      />

      {/* 60-Second Judge Tour Guide */}
      <Panel style={{ border: '1px solid var(--accent)', background: 'radial-gradient(circle at top right, var(--accent-muted), var(--bg-surface) 60%)' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '8px' }}>
          <Sparkles size={18} color="var(--accent)" />
          <span className="eyebrow" style={{ color: 'var(--accent)', margin: 0 }}>
            60-SECOND JURY EVALUATION JOURNEY
          </span>
        </div>
        <h3 style={{ margin: '0 0 8px 0', color: 'var(--text-primary)', fontSize: '18px' }}>
          How to Evaluate NexSolve's Core Innovations
        </h3>
        <p style={{ margin: '0 0 16px 0', color: 'var(--text-secondary)', fontSize: '14px', lineHeight: '1.55', maxWidth: '850px' }}>
          Select any of the 7 scenarios below to observe how the engine handles real-world operational conditions.
          Notice the strict separation between <strong>observed telemetry</strong> and <strong>future forecasts</strong>,
          as well as the engine's refusal to hallucinate when data is uninstrumented.
        </p>

        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))', gap: '12px' }}>
          <div style={{ background: 'var(--bg-secondary)', border: '1px solid var(--border)', borderRadius: '6px', padding: '12px' }}>
            <strong style={{ color: 'var(--text-primary)', fontSize: '13px', display: 'block', marginBottom: '4px' }}>
              1. Early Attack Signal
            </strong>
            <span style={{ fontSize: '12px', color: 'var(--text-secondary)', lineHeight: '1.4', display: 'block' }}>
              Tests whether the system detects nascent scans before volumetric flooding begins. Look for lead time in seconds.
            </span>
          </div>

          <div style={{ background: 'var(--bg-secondary)', border: '1px solid var(--border)', borderRadius: '6px', padding: '12px' }}>
            <strong style={{ color: 'var(--text-primary)', fontSize: '13px', display: 'block', marginBottom: '4px' }}>
              2. Contradictory Evidence
            </strong>
            <span style={{ fontSize: '12px', color: 'var(--text-secondary)', lineHeight: '1.4', display: 'block' }}>
              Tests scientific honesty when signals conflict. Evaluates confidence decay and uncertainty widening.
            </span>
          </div>

          <div style={{ background: 'var(--bg-secondary)', border: '1px solid var(--border)', borderRadius: '6px', padding: '12px' }}>
            <strong style={{ color: 'var(--text-primary)', fontSize: '13px', display: 'block', marginBottom: '4px' }}>
              3. Forecast Abstained
            </strong>
            <span style={{ fontSize: '12px', color: 'var(--text-secondary)', lineHeight: '1.4', display: 'block' }}>
              Verifies safety gates. When history is &lt; 8 windows, prediction is withheld rather than guessed.
            </span>
          </div>
        </div>
      </Panel>

      {/* One-Click Automated 8-Step Interactive Live Demo Wizard */}
      <LiveDemoWizard onComplete={handleSelectScenario} />

      {/* Scenario Selector */}
      <DemoModeSelector
        onSelectScenario={handleSelectScenario}
        onClose={() => {}}
      />

      {/* Active Evaluation Scenario Results View */}
      {activeResult && (
        <div style={{ marginTop: '16px', display: 'flex', flexDirection: 'column', gap: '16px' }}>
          <div className="provenance-banner demo-mode" data-testid="demo-provenance-banner">
            <div className="provenance-badge-group">
              <span className="provenance-pill demo-pill">DEMO DATA</span>
              <span className="provenance-pill status-pill">{activeResult.demo_scenario_name || 'Evaluation Scenario'}</span>
              <span className="provenance-pill reference-pill">DETERMINISTIC EVALUATION</span>
            </div>
            <div className="provenance-details">
              <p>
                Currently evaluating deterministic scenario: <strong>{activeResult.demo_scenario_name}</strong>.
                Inspect the Attack Horizon, Evidence Chain, and Multi-Step rollout below.
              </p>
            </div>
          </div>

          <div style={{ display: 'flex', gap: '10px', flexWrap: 'wrap' }}>
            <Link to="/forecast" className="button button-quiet">
              <TrendingUp size={14} /> Open Dedicated Forecast Page
            </Link>
            <Link to="/evidence" className="button button-quiet">
              <GitCommit size={14} /> Open Dedicated Evidence Page
            </Link>
            <Link to="/reports" className="button button-quiet">
              <FileText size={14} /> Open Forensic Reports
            </Link>
          </div>

          <JobResult result={activeResult} onReset={handleReset} />
        </div>
      )}
    </div>
  )
}
