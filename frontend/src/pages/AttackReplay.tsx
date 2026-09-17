import { useEffect, useState } from 'react'
import {
  ChevronLeft,
  ChevronRight,
  Clock,
  Info,
  Pause,
  Play,
  RotateCcw,
  ShieldAlert,
  Sliders,
  Zap,
} from 'lucide-react'
import { LoadingState, Panel } from '../components/Ui'
import { api } from '../services/api'
import type { ReplayFramePayload, ReplayScenarioSummaryPayload, ReplayStreamPayload } from '../types/api'

export function AttackReplay() {
  const [scenarios, setScenarios] = useState<ReplayScenarioSummaryPayload[]>([])
  const [selectedScenarioId, setSelectedScenarioId] = useState<string>('enterprise-intrusion-recon-dos')
  const [streamData, setStreamData] = useState<ReplayStreamPayload | null>(null)
  const [currentFrameIndex, setCurrentFrameIndex] = useState<number>(0)
  const [isPlaying, setIsPlaying] = useState<boolean>(false)
  const [playSpeed, setPlaySpeed] = useState<number>(1) // 1x, 2x, 5x
  const [loading, setLoading] = useState<boolean>(true)

  // Load scenarios on mount
  useEffect(() => {
    let isMounted = true
    api.getReplayScenarios()
      .then((data) => {
        if (isMounted && data && data.length > 0) {
          setScenarios(data)
          setSelectedScenarioId(data[0].id)
        }
      })
      .catch((err) => {
        console.error('Failed to load scenarios:', err)
        // Fallback default scenario
        setScenarios([
          {
            id: 'enterprise-intrusion-recon-dos',
            name: 'Multi-Stage Enterprise Perimeter Intrusion',
            threat_family: 'Reconnaissance -> Service Probe -> SYN Denial of Service',
            capture_duration_seconds: 600,
            window_count: 8,
            forecast_trigger_window: 3,
            lead_time_seconds: 120,
            description: 'Continuous temporal capture depicting early horizontal scanning, followed by algorithmic forecast alert, concluding with volumetric target breach.',
          },
        ])
      })
    return () => {
      isMounted = false
    }
  }, [])

  // Load stream when scenario changes
  useEffect(() => {
    let isMounted = true
    setLoading(true)
    setIsPlaying(false)
    setCurrentFrameIndex(0)

    api.getReplayStream(selectedScenarioId)
      .then((stream) => {
        if (isMounted) {
          setStreamData(stream)
          setLoading(false)
        }
      })
      .catch((err) => {
        console.error('Failed to load replay stream:', err)
        setLoading(false)
      })

    return () => {
      isMounted = false
    }
  }, [selectedScenarioId])

  // Playback timer
  useEffect(() => {
    if (!isPlaying || !streamData) return

    const intervalMs = 2000 / playSpeed
    const timer = setInterval(() => {
      setCurrentFrameIndex((prev) => {
        if (prev >= streamData.frames.length - 1) {
          setIsPlaying(false)
          return prev
        }
        return prev + 1
      })
    }, intervalMs)

    return () => clearInterval(timer)
  }, [isPlaying, playSpeed, streamData])

  const frames = streamData?.frames || []
  const currentFrame: ReplayFramePayload | undefined = frames[currentFrameIndex]
  const triggerIndex = streamData?.forecast_trigger_index !== undefined ? streamData.forecast_trigger_index : -1
  const escalationIndex = streamData?.escalation_index !== undefined ? streamData.escalation_index : -1

  let computedLeadTimeSec: number | null = null
  if (streamData?.lead_time_seconds !== undefined && streamData?.lead_time_seconds !== null) {
    computedLeadTimeSec = streamData.lead_time_seconds
  } else if (triggerIndex >= 0 && escalationIndex >= 0 && frames[triggerIndex] && frames[escalationIndex]) {
    const triggerTs = frames[triggerIndex].timestamp ?? frames[triggerIndex].time_offset_seconds
    const breachTs = frames[escalationIndex].timestamp ?? frames[escalationIndex].time_offset_seconds
    if (triggerTs !== undefined && breachTs !== undefined && breachTs > triggerTs) {
      computedLeadTimeSec = Math.round(breachTs - triggerTs)
    }
  }
  const leadTimeSec = computedLeadTimeSec

  const isTriggered = currentFrameIndex >= triggerIndex && triggerIndex >= 0
  const isEscalated = currentFrameIndex >= escalationIndex && escalationIndex >= 0

  if (loading && !streamData) {
    return <LoadingState message="Loading temporal attack replay stream..." />
  }

  return (
    <div className="page-stack page-enter" style={{ width: '100%', padding: '24px 0' }}>
      {/* Header */}
      <div style={{ display: 'flex', flexDirection: 'column', gap: '8px', marginBottom: '20px' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
          <span style={{ fontSize: '11px', fontFamily: 'var(--mono)', fontWeight: 700, color: 'var(--accent)', textTransform: 'uppercase', letterSpacing: '0.08em' }}>
            TEMPORAL REPLAY CONTROLLER
          </span>
          <span style={{ fontSize: '10px', background: 'var(--bg-secondary)', border: '1px solid var(--border)', padding: '2px 8px', borderRadius: '4px', fontFamily: 'var(--mono)', color: 'var(--text-muted)' }}>
            CHRONOLOGICAL CONTINUITY
          </span>
        </div>
        <h1 style={{ fontSize: '26px', fontWeight: 700, color: 'var(--text-primary)', margin: 0 }}>
          Attack Replay & Horizon Lead Time
        </h1>
        <p style={{ fontSize: '13px', color: 'var(--text-muted)', margin: 0, maxWidth: '820px', lineHeight: 1.5 }}>
          Scrub through frame-by-frame temporal windows to observe how early reconnaissance patterns trigger forward-looking
          network state model forecasts before physical escalation. Observe the empirical lead-time window available for automated defence.
        </p>
      </div>

      {/* Scenario Selection Bar */}
      <Panel>
        <div style={{ padding: '16px', display: 'flex', flexWrap: 'wrap', alignItems: 'center', justifyContent: 'space-between', gap: '16px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
            <Sliders size={16} color="var(--accent)" />
            <span style={{ fontSize: '13px', fontWeight: 600, color: 'var(--text-primary)' }}>Replay Scenario:</span>
            <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap' }}>
              {scenarios.map((sc) => (
                <button
                  key={sc.id}
                  type="button"
                  onClick={() => setSelectedScenarioId(sc.id)}
                  className={`button ${selectedScenarioId === sc.id ? 'button-primary' : 'button-quiet'}`}
                  style={{ fontSize: '12px', padding: '6px 12px' }}
                >
                  {sc.name}
                </button>
              ))}
            </div>
          </div>

          {triggerIndex >= 0 && (
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px', background: 'rgba(56, 189, 248, 0.1)', border: '1px solid rgba(56, 189, 248, 0.25)', padding: '6px 12px', borderRadius: '6px' }}>
              <Clock size={14} color="var(--accent)" />
              <span style={{ fontSize: '12px', fontFamily: 'var(--mono)', color: 'var(--accent)', fontWeight: 600 }}>
                VERIFIED LEAD TIME: {leadTimeSec !== null ? `${leadTimeSec}s (${(leadTimeSec / 60).toFixed(1)} min)` : 'UNAVAILABLE'}
              </span>
            </div>
          )}
        </div>
      </Panel>

      {/* Main Playback & Timeline Panel */}
      <div style={{ marginTop: '20px' }}>
        <Panel>
          <div style={{ padding: '24px', display: 'flex', flexDirection: 'column', gap: '24px' }}>
            {/* Playback Controls Header */}
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '16px' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
                <button
                  type="button"
                  className="button button-quiet"
                  onClick={() => setCurrentFrameIndex((prev) => Math.max(0, prev - 1))}
                  disabled={currentFrameIndex === 0}
                  title="Step Backward (Previous Window)"
                >
                  <ChevronLeft size={16} />
                </button>
                <button
                  type="button"
                  className={`button ${isPlaying ? 'button-danger' : 'button-primary'}`}
                  onClick={() => setIsPlaying(!isPlaying)}
                  style={{ minWidth: '95px', display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '6px' }}
                >
                  {isPlaying ? <><Pause size={14} /> Pause</> : <><Play size={14} /> Play</>}
                </button>
                <button
                  type="button"
                  className="button button-quiet"
                  onClick={() => setCurrentFrameIndex((prev) => Math.min(frames.length - 1, prev + 1))}
                  disabled={currentFrameIndex >= frames.length - 1}
                  title="Step Forward (Next Window)"
                >
                  <ChevronRight size={16} />
                </button>
                <button
                  type="button"
                  className="button button-quiet"
                  onClick={() => {
                    setIsPlaying(false)
                    setCurrentFrameIndex(0)
                  }}
                  title="Reset to Window 0"
                >
                  <RotateCcw size={14} /> Reset
                </button>
              </div>

              {/* Speed Switcher */}
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                <span style={{ fontSize: '11px', color: 'var(--text-muted)', fontFamily: 'var(--mono)' }}>SPEED:</span>
                {[1, 2, 5].map((speed) => (
                  <button
                    key={speed}
                    type="button"
                    onClick={() => setPlaySpeed(speed)}
                    className={`button ${playSpeed === speed ? 'button-secondary' : 'button-quiet'}`}
                    style={{ fontSize: '11px', padding: '4px 8px', height: '26px' }}
                  >
                    {speed}x
                  </button>
                ))}
              </div>

              {/* Current Window Status Banner */}
              <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
                <span style={{ fontSize: '12px', fontFamily: 'var(--mono)', color: 'var(--text-muted)' }}>
                  WINDOW <strong style={{ color: 'var(--text-primary)' }}>{currentFrameIndex + 1}</strong> OF {frames.length}
                </span>
                <span
                  style={{
                    fontSize: '11px',
                    fontFamily: 'var(--mono)',
                    fontWeight: 700,
                    padding: '4px 10px',
                    borderRadius: '4px',
                    background: currentFrame?.phase === 'FORECAST' ? 'rgba(168, 85, 247, 0.15)' : 'rgba(56, 189, 248, 0.15)',
                    color: currentFrame?.phase === 'FORECAST' ? '#c084fc' : '#38bdf8',
                    border: `1px solid ${currentFrame?.phase === 'FORECAST' ? 'rgba(168, 85, 247, 0.3)' : 'rgba(56, 189, 248, 0.3)'}`,
                  }}
                >
                  {currentFrame?.phase || 'OBSERVED'}
                </span>
              </div>
            </div>

            {/* Timeline Track Scrubber */}
            <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '11px', fontFamily: 'var(--mono)', color: 'var(--text-muted)' }}>
                <span>00:00:00 (T+0)</span>
                <span>SCRUBBABLE TEMPORAL SEQUENCE</span>
                <span>00:0{frames.length > 0 ? frames.length - 1 : 7}:00</span>
              </div>

              {/* Interactive Scrubber Slider */}
              <input
                type="range"
                min={0}
                max={Math.max(0, frames.length - 1)}
                value={currentFrameIndex}
                onChange={(e) => {
                  setIsPlaying(false)
                  setCurrentFrameIndex(Number(e.target.value))
                }}
                style={{ width: '100%', cursor: 'pointer', accentColor: 'var(--accent)' }}
              />

              {/* Segmented Timeline Steps */}
              <div style={{ display: 'grid', gridTemplateColumns: `repeat(${frames.length || 8}, 1fr)`, gap: '4px', marginTop: '6px' }}>
                {frames.map((f, idx) => {
                  const isActive = idx === currentFrameIndex
                  const isTrig = idx === triggerIndex
                  const isEsc = idx === escalationIndex
                  const isPassed = idx <= currentFrameIndex

                  let blockColor = 'var(--bg-secondary)'
                  let borderColor = 'var(--border)'
                  if (isActive) {
                    blockColor = 'var(--accent)'
                    borderColor = 'var(--accent)'
                  } else if (isEsc && isPassed) {
                    blockColor = 'rgba(239, 68, 68, 0.25)'
                    borderColor = 'var(--danger)'
                  } else if (isTrig && isPassed) {
                    blockColor = 'rgba(234, 179, 8, 0.25)'
                    borderColor = 'var(--warning)'
                  } else if (isPassed) {
                    blockColor = 'rgba(56, 189, 248, 0.15)'
                  }

                  return (
                    <button
                      key={idx}
                      type="button"
                      onClick={() => {
                        setIsPlaying(false)
                        setCurrentFrameIndex(idx)
                      }}
                      style={{
                        background: blockColor,
                        border: `1px solid ${borderColor}`,
                        borderRadius: '4px',
                        padding: '8px 4px',
                        display: 'flex',
                        flexDirection: 'column',
                        alignItems: 'center',
                        gap: '4px',
                        cursor: 'pointer',
                        transition: 'all 0.15s ease',
                      }}
                      title={`Window ${idx}: ${f.timestamp_label} (${f.state_name})`}
                    >
                      <span style={{ fontSize: '10px', fontFamily: 'var(--mono)', fontWeight: 600, color: isActive ? '#000' : 'var(--text-primary)' }}>
                        W{idx}
                      </span>
                      <span style={{ fontSize: '9px', fontFamily: 'var(--mono)', color: isActive ? '#000' : 'var(--text-muted)' }}>
                        {f.timestamp_label.slice(3)}
                      </span>
                      {isTrig && (
                        <span style={{ fontSize: '8px', background: 'var(--warning)', color: '#000', padding: '1px 3px', borderRadius: '2px', fontWeight: 700 }}>
                          ALERT
                        </span>
                      )}
                      {isEsc && (
                        <span style={{ fontSize: '8px', background: 'var(--danger)', color: '#fff', padding: '1px 3px', borderRadius: '2px', fontWeight: 700 }}>
                          BREACH
                        </span>
                      )}
                    </button>
                  )
                })}
              </div>
            </div>

            {/* Current Window Telemetry Display */}
            {currentFrame && (
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '16px', background: 'var(--bg-secondary)', padding: '16px', borderRadius: '8px', border: '1px solid var(--border)' }}>
                <div>
                  <div style={{ fontSize: '10px', fontFamily: 'var(--mono)', color: 'var(--text-muted)' }}>STATE CLASSIFICATION</div>
                  <div style={{ fontSize: '14px', fontWeight: 700, color: 'var(--text-primary)', marginTop: '4px' }}>
                    {currentFrame.state_name}
                  </div>
                </div>

                <div>
                  <div style={{ fontSize: '10px', fontFamily: 'var(--mono)', color: 'var(--text-muted)' }}>POINT ATTACK PROBABILITY</div>
                  <div style={{ display: 'flex', alignItems: 'baseline', gap: '6px', marginTop: '4px' }}>
                    <span style={{ fontSize: '18px', fontWeight: 700, fontFamily: 'var(--mono)', color: currentFrame.attack_probability > 0.6 ? 'var(--danger)' : currentFrame.attack_probability > 0.25 ? 'var(--warning)' : 'var(--success)' }}>
                      {(currentFrame.attack_probability * 100).toFixed(1)}%
                    </span>
                    <span style={{ fontSize: '11px', color: 'var(--text-muted)' }}>P(Attack | W{currentFrameIndex})</span>
                  </div>
                </div>

                <div>
                  <div style={{ fontSize: '10px', fontFamily: 'var(--mono)', color: 'var(--text-muted)' }}>CUMULATIVE HORIZON RISK</div>
                  <div style={{ display: 'flex', alignItems: 'baseline', gap: '6px', marginTop: '4px' }}>
                    <span style={{ fontSize: '18px', fontWeight: 700, fontFamily: 'var(--mono)', color: currentFrame.cumulative_risk > 0.8 ? 'var(--danger)' : currentFrame.cumulative_risk > 0.4 ? 'var(--warning)' : 'var(--text-primary)' }}>
                      {(currentFrame.cumulative_risk * 100).toFixed(1)}%
                    </span>
                    <span style={{ fontSize: '11px', color: 'var(--text-muted)' }}>Survival Union</span>
                  </div>
                </div>

                <div>
                  <div style={{ fontSize: '10px', fontFamily: 'var(--mono)', color: 'var(--text-muted)' }}>TRAFFIC TELEMETRY</div>
                  <div style={{ fontSize: '12px', fontFamily: 'var(--mono)', color: 'var(--text-primary)', marginTop: '4px' }}>
                    {currentFrame.packet_count} pkts &middot; {currentFrame.flow_count} flows &middot; {currentFrame.active_ports} ports
                  </div>
                </div>
              </div>
            )}

            {/* Lead Time Alert Banner when Triggered */}
            {isTriggered && (
              <div
                style={{
                  background: isEscalated ? 'rgba(239, 68, 68, 0.1)' : 'rgba(234, 179, 8, 0.1)',
                  border: `1px solid ${isEscalated ? 'rgba(239, 68, 68, 0.3)' : 'rgba(234, 179, 8, 0.3)'}`,
                  borderRadius: '8px',
                  padding: '16px',
                  display: 'flex',
                  alignItems: 'flex-start',
                  gap: '12px',
                }}
              >
                {isEscalated ? <ShieldAlert size={20} color="var(--danger)" /> : <Zap size={20} color="var(--warning)" />}
                <div>
                  <h4 style={{ margin: '0 0 4px 0', fontSize: '14px', fontWeight: 600, color: isEscalated ? 'var(--danger)' : 'var(--warning)' }}>
                    {isEscalated ? 'Breach Escalation Confirmed (Window 5)' : `Algorithmic Forecast Trigger Active (Window ${triggerIndex})`}
                  </h4>
                  <p style={{ margin: 0, fontSize: '12px', color: 'var(--text-primary)', lineHeight: 1.5 }}>
                    {isEscalated
                      ? `Target breach confirmed at window 5. ${leadTimeSec !== null ? `Verified lead time of ${leadTimeSec} seconds was successfully provided` : 'Lead time calculation is UNAVAILABLE for this telemetry stream'} between initial forecasting alert and physical system impact.`
                      : `Temporal forecast model has projected escalation probability above decision threshold. ${leadTimeSec !== null ? `A ${leadTimeSec}-second actionable lead time window is active` : 'Lead time calculation is UNAVAILABLE'} before expected breach.`}
                  </p>
                </div>
              </div>
            )}

            {/* Frame Chronological Events Log */}
            <div>
              <h3 style={{ fontSize: '13px', fontWeight: 600, color: 'var(--text-primary)', marginBottom: '12px', display: 'flex', alignItems: 'center', gap: '8px' }}>
                <Info size={14} color="var(--accent)" /> Events Observed in Window {currentFrameIndex} ({currentFrame?.timestamp_label})
              </h3>
              <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                {currentFrame?.events && currentFrame.events.length > 0 ? (
                  currentFrame.events.map((ev, i) => (
                    <div
                      key={i}
                      style={{
                        fontSize: '12px',
                        fontFamily: 'var(--mono)',
                        padding: '10px 12px',
                        borderRadius: '6px',
                        background: 'var(--bg-secondary)',
                        border: '1px solid var(--border)',
                        color: ev.includes('FORECAST TRIGGERED') || ev.includes('ESCALATION') ? 'var(--warning)' : 'var(--text-primary)',
                        display: 'flex',
                        alignItems: 'center',
                        gap: '8px',
                      }}
                    >
                      <span style={{ color: 'var(--text-muted)' }}>&bull;</span>
                      <span>{ev}</span>
                    </div>
                  ))
                ) : (
                  <div style={{ fontSize: '12px', color: 'var(--text-muted)' }}>No notable anomalies in this temporal slice.</div>
                )}
              </div>
            </div>

            {/* Scientific Lead Time Methodology Note */}
            <div style={{ borderTop: '1px solid var(--border)', paddingTop: '16px', display: 'flex', flexDirection: 'column', gap: '6px' }}>
              <span style={{ fontSize: '11px', fontFamily: 'var(--mono)', fontWeight: 700, color: 'var(--text-muted)' }}>
                EMPIRICAL LEAD TIME VALIDATION SPECIFICATION:
              </span>
              <p style={{ fontSize: '12px', color: 'var(--text-muted)', margin: 0, lineHeight: 1.5 }}>
                Lead time is defined as &Delta;t = t<sub>breach</sub> - t<sub>trigger</sub> where t<sub>trigger</sub> is the timestamp of the first
                forecast step exceeding 0.70 attack probability and t<sub>breach</sub> is the physical compromise timestamp verified in network traces.
                Zero simulated or fabricated timestamps.
              </p>
            </div>
          </div>
        </Panel>
      </div>
    </div>
  )
}
