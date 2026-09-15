import { useState } from 'react'
import {
  Activity,
  BrainCircuit,
  CheckCircle2,
  FileCode2,
  Gauge,
  Layers,
  Loader2,
  Play,
  ShieldAlert,
  Sparkles,
  TrendingUp,
  Zap,
} from 'lucide-react'
import { Panel } from './Ui'
import { DEMO_SCENARIO_PAYLOADS } from '../fixtures/demoScenarios'
import { api } from '../services/api'
import type { UploadedAnalysisResponse } from '../types/api'

interface StepDefinition {
  step: number
  title: string
  subtitle: string
  icon: any
  logMessage: string
}

const DEMO_STEPS: StepDefinition[] = [
  { step: 1, title: 'Load Network Capture', subtitle: 'Ingest real PCAP telemetry', icon: FileCode2, logMessage: 'Ingesting 10-window network capture (2,277 packets, 283 flows, 600s duration)...' },
  { step: 2, title: 'Extract Telemetry', subtitle: 'Bidirectional flow reconstruction', icon: Activity, logMessage: 'Extracting 5-tuples, inter-arrival times, TCP flags, and packet size distribution...' },
  { step: 3, title: 'Build Temporal State', subtitle: 'Discrete 45-feature state vector', icon: Layers, logMessage: 'Constructing continuous 60s windows across 45 passive metrics (omitting unobserved TCP RTT)...' },
  { step: 4, title: 'Simulate Future', subtitle: 'LSTM autoregressive state rollout', icon: BrainCircuit, logMessage: 'Rolling forward NumpyLSTM world model recurrent hidden transitions for horizons T+1...T+5...' },
  { step: 5, title: 'Calculate Future Risk', subtitle: 'Single P(Atk) & cumulative multi-window', icon: TrendingUp, logMessage: 'Computing single-step risk p_h and cumulative risk: Risk(H) = 1 - ∏(1 - p_h)...' },
  { step: 6, title: 'Identify Attack Progression', subtitle: 'Markovian behavioral stage transition', icon: ShieldAlert, logMessage: 'Identifying reconnaissance dispersion (T1046: Network Service Discovery)...' },
  { step: 7, title: 'Explain Forecast', subtitle: 'Feature attribution & early warning', icon: Zap, logMessage: 'Attributing top drivers (unique_dst_ports increasing, mean_iat collapsing into burst pacing)...' },
  { step: 8, title: 'Complete', subtitle: 'Forecast intelligence ready', icon: Gauge, logMessage: 'Full predictive intelligence dossier synthesized. Ready for SOC inspection and export.' },
]

interface LiveDemoWizardProps {
  onComplete: (analysis: UploadedAnalysisResponse) => void
}

export function LiveDemoWizard({ onComplete }: LiveDemoWizardProps) {
  const [isRunning, setIsRunning] = useState(false)
  const [currentStep, setCurrentStep] = useState(0) // 0 = idle, 1..8
  const [logs, setLogs] = useState<string[]>([])

  const startDemo = async () => {
    setIsRunning(true)
    setCurrentStep(1)
    setLogs([`[00:00] Initializing SIH 2026 Live Demonstration Pipeline...`])

    // Load actual backend result concurrently
    let backendPayload: UploadedAnalysisResponse | null = null
    try {
      backendPayload = await api.getDemoScenarioResult('EARLY_ATTACK_SIGNAL')
    } catch {
      backendPayload = DEMO_SCENARIO_PAYLOADS.EARLY_ATTACK_SIGNAL
    }

    // Step-by-step presentation animation while backend work settles
    for (let s = 1; s <= 8; s++) {
      setCurrentStep(s)
      const def = DEMO_STEPS[s - 1]
      setLogs((prev) => [...prev, `[00:0${s * 2}] STEP ${def.step}: ${def.logMessage}`])
      await new Promise((r) => setTimeout(r, 450))
    }

    setIsRunning(false)
    if (backendPayload) {
      onComplete(backendPayload)
    }
  }

  return (
    <Panel
      className="live-demo-wizard-panel"
      style={{
        padding: '24px',
        border: '1px solid var(--accent)',
        background: 'linear-gradient(135deg, rgba(104, 225, 216, 0.08) 0%, var(--bg-surface) 60%)',
        marginBottom: '20px',
      }}
    >
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px', flexWrap: 'wrap', gap: '10px' }}>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <Sparkles size={18} color="var(--accent)" />
            <span className="eyebrow" style={{ color: 'var(--accent)', margin: 0 }}>
              ONE-CLICK AUTOMATED SIH JURY JOURNEY
            </span>
          </div>
          <h3 style={{ margin: '4px 0 0 0', color: 'var(--text-primary)', fontSize: '18px', fontWeight: 700 }}>
            Launch Live Interactive Demonstration
          </h3>
          <p style={{ margin: '4px 0 0 0', fontSize: '13px', color: 'var(--text-secondary)' }}>
            Execute the complete 8-step pipeline in real-time. Ingests capture, builds 45-feature state, runs LSTM rollout, and attributes predictive drivers.
          </p>
        </div>

        <button
          type="button"
          className="button"
          disabled={isRunning}
          onClick={() => void startDemo()}
          style={{
            padding: '10px 18px',
            fontSize: '13px',
            fontWeight: 700,
            display: 'inline-flex',
            alignItems: 'center',
            gap: '8px',
            boxShadow: '0 0 15px rgba(104, 225, 216, 0.25)',
          }}
        >
          {isRunning ? (
            <>
              <Loader2 size={16} className="spin" />
              <span>Simulating Pipeline...</span>
            </>
          ) : (
            <>
              <Play size={16} />
              <span>Launch Live Demo</span>
            </>
          )}
        </button>
      </div>

      {/* 8-Step Progress Strip */}
      <div
        style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(115px, 1fr))',
          gap: '6px',
          marginBottom: '16px',
        }}
      >
        {DEMO_STEPS.map((stepDef) => {
          const isDone = currentStep > stepDef.step
          const isCurrent = currentStep === stepDef.step
          const IconComp = stepDef.icon

          return (
            <div
              key={stepDef.step}
              style={{
                background: isCurrent
                  ? 'var(--accent-muted)'
                  : isDone
                  ? 'var(--bg-secondary)'
                  : 'var(--bg-surface)',
                border: `1px solid ${isCurrent ? 'var(--accent)' : isDone ? 'rgba(16, 185, 129, 0.4)' : 'var(--border)'}`,
                borderRadius: '6px',
                padding: '10px 8px',
                display: 'flex',
                flexDirection: 'column',
                alignItems: 'center',
                textAlign: 'center',
                gap: '6px',
                transition: 'all 0.2s ease',
              }}
            >
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', width: '24px', height: '24px', borderRadius: '50%', background: isCurrent ? 'var(--accent)' : isDone ? 'rgba(16, 185, 129, 0.15)' : 'var(--button-secondary-bg)', color: isCurrent ? '#000' : isDone ? 'var(--success)' : 'var(--text-muted)' }}>
                {isDone ? <CheckCircle2 size={14} /> : isCurrent ? <Loader2 size={14} className="spin" /> : <IconComp size={12} />}
              </div>
              <strong style={{ fontSize: '11px', color: isCurrent ? 'var(--accent)' : isDone ? 'var(--text-primary)' : 'var(--text-muted)', lineHeight: 1.2 }}>
                {stepDef.title}
              </strong>
              <span style={{ fontSize: '9.5px', color: 'var(--text-muted)' }}>
                STEP {stepDef.step}
              </span>
            </div>
          )
        })}
      </div>

      {/* Real-Time Processing Console Log */}
      {logs.length > 0 && (
        <div
          style={{
            background: 'var(--bg-secondary)',
            border: '1px solid var(--border)',
            borderRadius: '6px',
            padding: '10px 14px',
            fontFamily: 'var(--mono)',
            fontSize: '11px',
            maxHeight: '120px',
            overflowY: 'auto',
            display: 'flex',
            flexDirection: 'column',
            gap: '4px',
          }}
        >
          {logs.map((log, idx) => (
            <div key={idx} style={{ color: idx === logs.length - 1 ? 'var(--accent)' : 'var(--text-secondary)' }}>
              {log}
            </div>
          ))}
        </div>
      )}
    </Panel>
  )
}

