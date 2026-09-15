import { useEffect, useState } from 'react'
import {
  AlertTriangle,
  Layers,
  Play,
  RotateCcw,
  ShieldCheck,
  Sliders,
  TrendingDown,
} from 'lucide-react'
import { Panel } from '../components/Ui'
import { api } from '../services/api'
import type { SimulationInterventionPayload, SimulationResponsePayload } from '../types/api'

interface InterventionConfig {
  id: string
  type: 'isolate_host' | 'block_port' | 'rate_limit' | 'contain_ip'
  title: string
  description: string
  target: string
  intensity: number
  enabled: boolean
}

const DEFAULT_INTERVENTIONS: InterventionConfig[] = [
  {
    id: 'inv-isolate',
    type: 'isolate_host',
    title: 'Egress Host Isolation',
    description: 'Sever lateral communication links for compromised internal endpoints; suppresses flow initiation deltas (-100%).',
    target: '10.0.1.5',
    intensity: 0.9,
    enabled: true,
  },
  {
    id: 'inv-block',
    type: 'block_port',
    title: 'Perimeter Port Cluster Block',
    description: 'Enforce boundary firewall filter on target port 80/443; mitigates incoming TCP SYN burst volume by 85%.',
    target: '80',
    intensity: 0.85,
    enabled: true,
  },
  {
    id: 'inv-rate',
    type: 'rate_limit',
    title: 'Adaptive Bandwidth Rate-Limiting',
    description: 'Clamp throughput and burst packet quotas on suspicious subnet perimeter.',
    target: '10.0.1.0/24',
    intensity: 0.6,
    enabled: false,
  },
  {
    id: 'inv-contain',
    type: 'contain_ip',
    title: 'Zero-Trust Quarantine Barrier',
    description: 'Terminate active external C2 command-and-control beaconing channels.',
    target: '198.51.100.4',
    intensity: 0.75,
    enabled: false,
  },
]

export function Simulation() {
  const [interventions, setInterventions] = useState<InterventionConfig[]>(DEFAULT_INTERVENTIONS)
  const [simulationResult, setSimulationResult] = useState<SimulationResponsePayload | null>(null)
  const [isRunning, setIsRunning] = useState<boolean>(false)
  const [error, setError] = useState<string | null>(null)

  const toggleIntervention = (id: string) => {
    setInterventions((prev) =>
      prev.map((item) => (item.id === id ? { ...item, enabled: !item.enabled } : item))
    )
  }

  const updateIntensity = (id: string, intensity: number) => {
    setInterventions((prev) =>
      prev.map((item) => (item.id === id ? { ...item, intensity } : item))
    )
  }

  const updateTarget = (id: string, target: string) => {
    setInterventions((prev) =>
      prev.map((item) => (item.id === id ? { ...item, target } : item))
    )
  }

  const handleRunSimulation = async () => {
    setIsRunning(true)
    setError(null)
    try {
      const activePayload: SimulationInterventionPayload[] = interventions
        .filter((inv) => inv.enabled)
        .map((inv) => ({
          type: inv.type,
          target: inv.target,
          intensity: inv.intensity,
        }))

      const res = await api.runSimulation({
        analysis_id: 'current',
        interventions: activePayload,
      })
      setSimulationResult(res)
    } catch (err: any) {
      setError(err?.message || 'Failed to calculate counterfactual simulation')
    } finally {
      setIsRunning(false)
    }
  }

  // Run initial simulation on mount
  useEffect(() => {
    handleRunSimulation()
  }, [])

  const activeCount = interventions.filter((i) => i.enabled).length

  return (
    <div className="page-stack page-enter" style={{ maxWidth: '1200px', margin: '0 auto', width: '100%', padding: '24px 16px' }}>
      {/* Header */}
      <div style={{ display: 'flex', flexDirection: 'column', gap: '8px', marginBottom: '20px' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
          <span style={{ fontSize: '11px', fontFamily: 'var(--mono)', fontWeight: 700, color: 'var(--accent)', textTransform: 'uppercase', letterSpacing: '0.08em' }}>
            COUNTERFACTUAL STATE MODELING
          </span>
          <span
            style={{
              fontSize: '10px',
              background: 'rgba(234, 179, 8, 0.15)',
              border: '1px solid rgba(234, 179, 8, 0.3)',
              color: 'var(--warning)',
              padding: '2px 8px',
              borderRadius: '4px',
              fontFamily: 'var(--mono)',
              fontWeight: 700,
            }}
          >
            MODELLED COUNTERFACTUAL
          </span>
        </div>
        <h1 style={{ fontSize: '26px', fontWeight: 700, color: 'var(--text-primary)', margin: 0 }}>
          What-If Defence Simulator
        </h1>
        <p style={{ fontSize: '13px', color: 'var(--text-muted)', margin: 0, maxWidth: '820px', lineHeight: 1.5 }}>
          Simulate the dampening effect of defensive interventions on forward network attack trajectories before physical execution.
          Compare the baseline progression against the counterfactual rollout under active mitigations.
        </p>
      </div>

      {error && (
        <div style={{ background: 'rgba(239, 68, 68, 0.1)', border: '1px solid var(--danger)', padding: '12px', borderRadius: '6px', marginBottom: '16px', display: 'flex', alignItems: 'center', gap: '8px', color: 'var(--danger)', fontSize: '13px' }}>
          <AlertTriangle size={16} />
          <span>{error}</span>
        </div>
      )}

      {/* Strict Scientific Notice / Modelled Counterfactual Banner */}
      <div
        style={{
          background: 'rgba(56, 189, 248, 0.08)',
          border: '1px solid rgba(56, 189, 248, 0.25)',
          borderRadius: '8px',
          padding: '14px 18px',
          display: 'flex',
          alignItems: 'center',
          gap: '12px',
          marginBottom: '20px',
        }}
      >
        <ShieldCheck size={20} color="var(--accent)" style={{ flexShrink: 0 }} />
        <div style={{ fontSize: '12px', color: 'var(--text-primary)', lineHeight: 1.5 }}>
          <strong>MODELLED COUNTERFACTUAL NOTICE:</strong> This module mathematically perturbs the autoregressive state transition
          matrix based on known firewall, routing, and endpoint intervention dampening coefficients. It models potential threat reduction
          and does not execute live network blocking.
        </div>
      </div>

      {/* Main Grid: Interventions Config vs Results View */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(420px, 1fr))', gap: '20px' }}>
        {/* Left Column: Interventions Configuration */}
        <Panel>
          <div style={{ padding: '20px', display: 'flex', flexDirection: 'column', gap: '20px' }}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                <Sliders size={16} color="var(--accent)" />
                <h2 style={{ fontSize: '16px', fontWeight: 600, color: 'var(--text-primary)', margin: 0 }}>
                  Defensive Policy Controls
                </h2>
              </div>
              <span style={{ fontSize: '11px', fontFamily: 'var(--mono)', color: 'var(--text-muted)' }}>
                {activeCount} active intervention{activeCount === 1 ? '' : 's'}
              </span>
            </div>

            {/* List of Intervention Cards */}
            <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
              {interventions.map((inv) => (
                <div
                  key={inv.id}
                  style={{
                    background: inv.enabled ? 'var(--bg-secondary)' : 'rgba(0,0,0,0.15)',
                    border: `1px solid ${inv.enabled ? 'var(--accent)' : 'var(--border)'}`,
                    borderRadius: '8px',
                    padding: '14px',
                    transition: 'all 0.15s ease',
                    opacity: inv.enabled ? 1 : 0.6,
                  }}
                >
                  <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '8px' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                      <input
                        type="checkbox"
                        checked={inv.enabled}
                        onChange={() => toggleIntervention(inv.id)}
                        id={inv.id}
                        style={{ accentColor: 'var(--accent)', cursor: 'pointer', width: '16px', height: '16px' }}
                      />
                      <label htmlFor={inv.id} style={{ fontSize: '13px', fontWeight: 600, color: 'var(--text-primary)', cursor: 'pointer' }}>
                        {inv.title}
                      </label>
                    </div>
                    <span style={{ fontSize: '10px', fontFamily: 'var(--mono)', padding: '2px 6px', background: 'var(--border)', borderRadius: '3px', color: 'var(--text-muted)' }}>
                      {inv.type}
                    </span>
                  </div>

                  <p style={{ fontSize: '11px', color: 'var(--text-muted)', margin: '0 0 10px 0', lineHeight: 1.4 }}>
                    {inv.description}
                  </p>

                  {inv.enabled && (
                    <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '12px', marginTop: '8px', paddingTop: '8px', borderTop: '1px solid var(--border)' }}>
                      <div>
                        <label style={{ fontSize: '10px', fontFamily: 'var(--mono)', color: 'var(--text-muted)', display: 'block', marginBottom: '4px' }}>
                          TARGET ENTITY / PORT
                        </label>
                        <input
                          type="text"
                          value={inv.target}
                          onChange={(e) => updateTarget(inv.id, e.target.value)}
                          style={{
                            width: '100%',
                            fontSize: '11px',
                            fontFamily: 'var(--mono)',
                            padding: '4px 8px',
                            background: 'var(--bg-primary)',
                            border: '1px solid var(--border)',
                            borderRadius: '4px',
                            color: 'var(--text-primary)',
                          }}
                        />
                      </div>

                      <div>
                        <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '4px' }}>
                          <span style={{ fontSize: '10px', fontFamily: 'var(--mono)', color: 'var(--text-muted)' }}>INTENSITY</span>
                          <span style={{ fontSize: '10px', fontFamily: 'var(--mono)', fontWeight: 600, color: 'var(--accent)' }}>
                            {(inv.intensity * 100).toFixed(0)}%
                          </span>
                        </div>
                        <input
                          type="range"
                          min="0.1"
                          max="1.0"
                          step="0.05"
                          value={inv.intensity}
                          onChange={(e) => updateIntensity(inv.id, parseFloat(e.target.value))}
                          style={{ width: '100%', cursor: 'pointer', accentColor: 'var(--accent)' }}
                        />
                      </div>
                    </div>
                  )}
                </div>
              ))}
            </div>

            {/* Run Button */}
            <button
              type="button"
              className="button button-primary"
              onClick={handleRunSimulation}
              disabled={isRunning}
              style={{ width: '100%', padding: '10px', display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '8px' }}
            >
              {isRunning ? <RotateCcw size={16} className="spin" /> : <Play size={16} />}
              Compute Counterfactual Trajectory
            </button>
          </div>
        </Panel>

        {/* Right Column: Comparative Trajectory Visualizer */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
          {/* KPI Card: Risk Reduction */}
          <Panel>
            <div style={{ padding: '20px', display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
              <div>
                <span style={{ fontSize: '11px', fontFamily: 'var(--mono)', fontWeight: 700, color: 'var(--text-muted)' }}>
                  PROJECTED THREAT MITIGATION
                </span>
                <div style={{ display: 'flex', alignItems: 'baseline', gap: '8px', marginTop: '4px' }}>
                  <span style={{ fontSize: '28px', fontWeight: 800, fontFamily: 'var(--mono)', color: (simulationResult?.risk_reduction_pct || 0) > 0 ? 'var(--success)' : 'var(--text-primary)' }}>
                    -{(simulationResult?.risk_reduction_pct || 0).toFixed(1)}%
                  </span>
                  <span style={{ fontSize: '12px', color: 'var(--text-muted)' }}>Peak Horizon Attack Probability</span>
                </div>
              </div>
              <div
                style={{
                  width: '52px',
                  height: '52px',
                  borderRadius: '10px',
                  background: 'rgba(34, 197, 94, 0.12)',
                  border: '1px solid rgba(34, 197, 94, 0.25)',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                }}
              >
                <TrendingDown size={28} color="var(--success)" />
              </div>
            </div>
          </Panel>

          {/* Comparative Rollout Chart */}
          <Panel>
            <div style={{ padding: '20px', display: 'flex', flexDirection: 'column', gap: '16px' }}>
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                <h3 style={{ fontSize: '14px', fontWeight: 600, color: 'var(--text-primary)', margin: 0, display: 'flex', alignItems: 'center', gap: '8px' }}>
                  <Layers size={16} color="var(--accent)" /> Horizon Progression: Baseline vs Counterfactual
                </h3>
                <div style={{ display: 'flex', alignItems: 'center', gap: '12px', fontSize: '11px', fontFamily: 'var(--mono)' }}>
                  <span style={{ display: 'flex', alignItems: 'center', gap: '4px', color: 'var(--danger)' }}>
                    <span style={{ width: '8px', height: '8px', borderRadius: '50%', background: 'var(--danger)' }} /> Baseline
                  </span>
                  <span style={{ display: 'flex', alignItems: 'center', gap: '4px', color: 'var(--success)' }}>
                    <span style={{ width: '8px', height: '8px', borderRadius: '50%', background: 'var(--success)' }} /> Counterfactual
                  </span>
                </div>
              </div>

              {/* Step by step horizon comparative bars */}
              <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
                {simulationResult?.baseline_trajectory?.map((pt, idx) => {
                  const cfPt = simulationResult.counterfactual_trajectory[idx]
                  const baseProb = pt.attackProbability || 0
                  const cfProb = cfPt?.attackProbability || 0
                  const delta = Math.round((baseProb - cfProb) * 100)

                  return (
                    <div key={pt.horizon} style={{ background: 'var(--bg-secondary)', padding: '12px', borderRadius: '6px', border: '1px solid var(--border)' }}>
                      <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '11px', fontFamily: 'var(--mono)', marginBottom: '8px' }}>
                        <span style={{ fontWeight: 700, color: 'var(--text-primary)' }}>
                          T+{pt.horizon} ({pt.lookaheadSeconds}s / {pt.horizon} min)
                        </span>
                        <span style={{ color: delta > 0 ? 'var(--success)' : 'var(--text-muted)' }}>
                          {delta > 0 ? `-${delta}% threat dampening` : 'Stationary'}
                        </span>
                      </div>

                      {/* Baseline Bar */}
                      <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '6px' }}>
                        <span style={{ fontSize: '10px', fontFamily: 'var(--mono)', color: 'var(--text-muted)', width: '70px' }}>Baseline:</span>
                        <div style={{ flex: 1, height: '8px', background: 'rgba(255,255,255,0.05)', borderRadius: '4px', overflow: 'hidden' }}>
                          <div style={{ width: `${Math.min(100, baseProb * 100)}%`, height: '100%', background: 'var(--danger)', borderRadius: '4px' }} />
                        </div>
                        <span style={{ fontSize: '11px', fontFamily: 'var(--mono)', width: '45px', textAlign: 'right', color: 'var(--danger)' }}>
                          {(baseProb * 100).toFixed(0)}%
                        </span>
                      </div>

                      {/* Counterfactual Bar */}
                      <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                        <span style={{ fontSize: '10px', fontFamily: 'var(--mono)', color: 'var(--text-muted)', width: '70px' }}>Mitigated:</span>
                        <div style={{ flex: 1, height: '8px', background: 'rgba(255,255,255,0.05)', borderRadius: '4px', overflow: 'hidden' }}>
                          <div style={{ width: `${Math.min(100, cfProb * 100)}%`, height: '100%', background: 'var(--success)', borderRadius: '4px' }} />
                        </div>
                        <span style={{ fontSize: '11px', fontFamily: 'var(--mono)', width: '45px', textAlign: 'right', color: 'var(--success)', fontWeight: 700 }}>
                          {(cfProb * 100).toFixed(0)}%
                        </span>
                      </div>
                    </div>
                  )
                })}
              </div>

              {/* Applied Effects Breakdown */}
              <div style={{ marginTop: '12px', borderTop: '1px solid var(--border)', paddingTop: '16px' }}>
                <span style={{ fontSize: '11px', fontFamily: 'var(--mono)', fontWeight: 700, color: 'var(--text-muted)', display: 'block', marginBottom: '8px' }}>
                  ACTIVE MITIGATION IMPACTS:
                </span>
                <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
                  {simulationResult?.applied_interventions?.map((eff, i) => (
                    <div key={i} style={{ fontSize: '11px', fontFamily: 'var(--mono)', color: 'var(--text-muted)', display: 'flex', alignItems: 'flex-start', gap: '6px' }}>
                      <span style={{ color: 'var(--success)' }}>&check;</span>
                      <div>
                        <strong style={{ color: 'var(--text-primary)' }}>{eff.action}</strong> &mdash; {eff.feature_impact}
                      </div>
                    </div>
                  ))}
                  {(!simulationResult?.applied_interventions || simulationResult.applied_interventions.length === 0) && (
                    <span style={{ fontSize: '11px', color: 'var(--text-muted)' }}>No interventions applied. Baseline trajectory matches unmodified state dynamics.</span>
                  )}
                </div>
              </div>
            </div>
          </Panel>
        </div>
      </div>
    </div>
  )
}
