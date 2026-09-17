import { useState, useMemo } from 'react'
import type {
  TemporalNetworkWorldStatePayload,
  WorldStateSnapshotPayload,
  WorldStateDiffPayload,
  EntityTemporalStatePayload,
  RelationshipTemporalStatePayload,
} from '../../types/api'
import { Panel } from '../Ui'
import {
  Clock,
  Layers,
  Search,
  ArrowRight,
  TrendingUp,
  AlertTriangle,
  GitCommit,
  ShieldAlert,
} from 'lucide-react'

interface TemporalWorldViewProps {
  worldState?: TemporalNetworkWorldStatePayload | null
  analysisId?: string
  onSelectEntityForHunt?: (ip: string) => void
  onInspectEntity?: (ip: string) => void
}

export function TemporalWorldView({
  worldState,
  analysisId: _analysisId,
  onSelectEntityForHunt,
  onInspectEntity,
}: TemporalWorldViewProps) {
  const [selectedWindowIndex, setSelectedWindowIndex] = useState<number>(0)
  const [diffWindowA, setDiffWindowA] = useState<number>(0)
  const [diffWindowB, setDiffWindowB] = useState<number>(1)
  const [activeTab, setActiveTab] = useState<'SNAPSHOT' | 'DIFF' | 'TRAJECTORIES'>('SNAPSHOT')
  const [entityFilter, setEntityFilter] = useState<string>('')
  const hasData = Boolean(worldState && worldState.windows && worldState.windows.length > 0)
  const windows = worldState?.windows || []
  const snapshots = worldState?.snapshots || {}
  const totalWindows = worldState?.total_windows || windows.length
  const currentSnapshot: WorldStateSnapshotPayload | undefined = snapshots[String(selectedWindowIndex)]

  // Compute local diff between diffWindowA and diffWindowB
  const diff: WorldStateDiffPayload = useMemo(() => {
    if (!hasData) {
      return {
        window_a: 0,
        window_b: 0,
        entities_added: [],
        entities_persisted: [],
        entities_not_observed: [],
        relationships_added: [],
        relationships_not_observed: [],
        attack_state_transitions: [],
        fanout_surges: [],
        volume_deltas: [],
        new_evidence_keys: [],
      }
    }
    const snapA = snapshots[String(diffWindowA)]
    const snapB = snapshots[String(diffWindowB)]
    const entsA = snapA ? snapA.entities || {} : {}
    const entsB = snapB ? snapB.entities || {} : {}
    const relsA = snapA ? snapA.relationships || {} : {}
    const relsB = snapB ? snapB.relationships || {} : {}

    const keysA = new Set(Object.keys(entsA))
    const keysB = new Set(Object.keys(entsB))

    const entities_added = Array.from(keysB).filter((x) => !keysA.has(x)).sort()
    const entities_persisted = Array.from(keysB).filter((x) => keysA.has(x)).sort()
    const entities_not_observed = Array.from(keysA).filter((x) => !keysB.has(x)).sort()

    const relKeysA = new Set(Object.keys(relsA))
    const relKeysB = new Set(Object.keys(relsB))
    const relationships_added = Array.from(relKeysB).filter((x) => !relKeysA.has(x)).sort()
    const relationships_not_observed = Array.from(relKeysA).filter((x) => !relKeysB.has(x)).sort()

    const attack_state_transitions: WorldStateDiffPayload['attack_state_transitions'] = []
    const fanout_surges: WorldStateDiffPayload['fanout_surges'] = []
    const volume_deltas: WorldStateDiffPayload['volume_deltas'] = []

    for (const ent of entities_persisted) {
      const eA = entsA[ent]
      const eB = entsB[ent]
      if (eA && eB) {
        if (eA.attack_state !== eB.attack_state) {
          attack_state_transitions.push({
            entity: ent,
            from_state: eA.attack_state,
            to_state: eB.attack_state,
            from_window: diffWindowA,
            to_window: diffWindowB,
          })
        }
        if (eB.fanout > eA.fanout && (eB.fanout - eA.fanout >= 2 || (eA.fanout > 0 && eB.fanout / eA.fanout >= 1.5))) {
          fanout_surges.push({
            entity: ent,
            baseline_fanout: eA.fanout,
            current_fanout: eB.fanout,
            increase: eB.fanout - eA.fanout,
          })
        }
        if (eB.packets !== eA.packets || (eB.bytes_sent + eB.bytes_recv) !== (eA.bytes_sent + eA.bytes_recv)) {
          volume_deltas.push({
            entity: ent,
            delta_packets: eB.packets - eA.packets,
            delta_bytes: (eB.bytes_sent + eB.bytes_recv) - (eA.bytes_sent + eA.bytes_recv),
          })
        }
      }
    }

    const evA = new Set(snapA?.evidence_keys || [])
    const evB = new Set(snapB?.evidence_keys || [])
    const new_evidence_keys = Array.from(evB).filter((x) => !evA.has(x)).sort()

    return {
      window_a: diffWindowA,
      window_b: diffWindowB,
      entities_added,
      entities_persisted,
      entities_not_observed,
      relationships_added,
      relationships_not_observed,
      attack_state_transitions,
      fanout_surges,
      volume_deltas,
      new_evidence_keys,
    }
  }, [snapshots, diffWindowA, diffWindowB])

  // Filter entities in current snapshot
  const filteredEntities = useMemo(() => {
    if (!currentSnapshot || !currentSnapshot.entities) return []
    const list = Object.values(currentSnapshot.entities)
    if (!entityFilter) return list
    const q = entityFilter.toLowerCase()
    return list.filter(
      (e) =>
        e.entity_key.toLowerCase().includes(q) ||
        e.attack_state.toLowerCase().includes(q) ||
        e.presence.toLowerCase().includes(q)
    )
  }, [currentSnapshot, entityFilter])

  // Relationships in current snapshot
  const snapshotRelationships = useMemo(() => {
    if (!currentSnapshot || !currentSnapshot.relationships) return []
    return Object.values(currentSnapshot.relationships)
  }, [currentSnapshot])

  if (!worldState || !worldState.windows || worldState.windows.length === 0) {
    return null
  }

  return (
    <Panel style={{ border: '1px solid var(--border)', borderRadius: '8px', overflow: 'hidden' }}>
      {/* Header */}
      <div
        style={{
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          padding: '16px 20px',
          background: 'var(--surface-overlay)',
          borderBottom: '1px solid var(--border)',
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
          <Clock size={20} color="var(--accent)" />
          <div>
            <div style={{ fontSize: '15px', fontWeight: 700, color: 'var(--text-primary)' }}>
              Temporal Network World Model
            </div>
            <div style={{ fontSize: '11px', color: 'var(--text-muted)' }}>
              Deterministic multi-window world states &bull; Ground-truth observed network evolution
            </div>
          </div>
        </div>

        {/* Global Stats Badge */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '12px', fontSize: '11px', fontFamily: 'var(--mono)' }}>
          <span style={{ padding: '3px 8px', borderRadius: '4px', background: 'var(--surface-ground)', border: '1px solid var(--border)' }}>
            Windows: <strong>{totalWindows}</strong>
          </span>
          <span style={{ padding: '3px 8px', borderRadius: '4px', background: 'var(--surface-ground)', border: '1px solid var(--border)' }}>
            Packets: <strong>{worldState.total_packets.toLocaleString()}</strong>
          </span>
          <span style={{ padding: '3px 8px', borderRadius: '4px', background: 'var(--surface-ground)', border: '1px solid var(--border)' }}>
            Flows: <strong>{worldState.total_flows.toLocaleString()}</strong>
          </span>
          <span style={{ padding: '3px 8px', borderRadius: '4px', background: 'var(--surface-ground)', border: '1px solid var(--border)' }}>
            Duration: <strong>{worldState.duration_seconds}s</strong>
          </span>
        </div>
      </div>

      {/* Temporal Scrubber / Timeline Bar */}
      <div style={{ padding: '16px 20px', background: 'var(--surface-ground)', borderBottom: '1px solid var(--border)' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
          <span style={{ fontSize: '11px', fontFamily: 'var(--mono)', textTransform: 'uppercase', color: 'var(--text-muted)', fontWeight: 600 }}>
            Observation Sequence (T₀ ... T_Final)
          </span>
          <span style={{ fontSize: '11px', fontFamily: 'var(--mono)', color: 'var(--accent)' }}>
            Selected: Window #{selectedWindowIndex} ({currentSnapshot ? `${currentSnapshot.packet_count} packets, ${currentSnapshot.flow_count} flows` : ''})
          </span>
        </div>

        {/* Window Cells */}
        <div style={{ display: 'grid', gridTemplateColumns: `repeat(${windows.length}, 1fr)`, gap: '6px' }}>
          {windows.map((w, idx) => {
            const isSelected = selectedWindowIndex === idx
            const isBoundary = w.is_capture_boundary
            const hasChanges = w.change_signals_count > 0
            const hasAttack = Boolean(w.dominant_attack_stage && w.dominant_attack_stage !== 'BENIGN')

            return (
              <button
                key={w.window_id}
                onClick={() => setSelectedWindowIndex(idx)}
                style={{
                  padding: '10px 6px',
                  borderRadius: '6px',
                  border: isSelected
                    ? '2px solid var(--accent)'
                    : isBoundary
                    ? '1px solid rgba(239, 68, 68, 0.4)'
                    : '1px solid var(--border)',
                  background: isSelected
                    ? 'rgba(59, 130, 246, 0.12)'
                    : isBoundary
                    ? 'rgba(239, 68, 68, 0.05)'
                    : 'var(--surface-card)',
                  cursor: 'pointer',
                  textAlign: 'center',
                  transition: 'all 0.15s ease',
                  position: 'relative',
                }}
              >
                <div style={{ fontSize: '11px', fontWeight: 700, fontFamily: 'var(--mono)', color: isSelected ? 'var(--accent)' : 'var(--text-primary)' }}>
                  W{idx}
                </div>
                <div style={{ fontSize: '9px', color: 'var(--text-muted)', marginTop: '2px' }}>
                  {w.active_entity_count} ents
                </div>

                {/* Status indicators */}
                <div style={{ display: 'flex', justifyContent: 'center', gap: '3px', marginTop: '4px' }}>
                  {hasAttack && (
                    <span title={`Attack stage: ${w.dominant_attack_stage}`} style={{ width: '6px', height: '6px', borderRadius: '50%', background: 'var(--critical)' }} />
                  )}
                  {hasChanges && (
                    <span title={`${w.change_signals_count} behavior change(s)`} style={{ width: '6px', height: '6px', borderRadius: '50%', background: 'var(--warning)' }} />
                  )}
                  {isBoundary && (
                    <span title="Capture Boundary" style={{ width: '6px', height: '6px', borderRadius: '50%', background: 'var(--text-muted)' }} />
                  )}
                </div>
              </button>
            )
          })}
        </div>

        {/* Epistemic Demarcation Note */}
        <div style={{ marginTop: '10px', display: 'flex', alignItems: 'center', justifyContent: 'space-between', fontSize: '11px', color: 'var(--text-muted)' }}>
          <div>
            <span style={{ color: 'var(--success)', fontWeight: 600 }}>&bull; OBSERVED GROUND TRUTH:</span> Temporal windows 0-{totalWindows - 1} reflect verified PCAP traffic.
          </div>
          <div style={{ fontStyle: 'italic' }}>
            Downstream forecasts remain segregated and are never injected as historical fact.
          </div>
        </div>
      </div>

      {/* Tabs for World State Exploration */}
      <div style={{ display: 'flex', borderBottom: '1px solid var(--border)', background: 'var(--surface-ground)' }}>
        <button
          onClick={() => setActiveTab('SNAPSHOT')}
          style={{
            padding: '10px 18px',
            fontSize: '12px',
            fontWeight: activeTab === 'SNAPSHOT' ? 700 : 500,
            color: activeTab === 'SNAPSHOT' ? 'var(--accent)' : 'var(--text-secondary)',
            borderBottom: activeTab === 'SNAPSHOT' ? '2px solid var(--accent)' : 'none',
            background: 'transparent',
            border: 'none',
            cursor: 'pointer',
            display: 'flex',
            alignItems: 'center',
            gap: '6px',
          }}
        >
          <Layers size={14} /> Snapshot Inspector (Window #{selectedWindowIndex})
        </button>

        <button
          onClick={() => {
            setActiveTab('DIFF')
            if (selectedWindowIndex === 0 && totalWindows > 1) {
              setDiffWindowA(0)
              setDiffWindowB(1)
            } else {
              setDiffWindowA(Math.max(0, selectedWindowIndex - 1))
              setDiffWindowB(selectedWindowIndex)
            }
          }}
          style={{
            padding: '10px 18px',
            fontSize: '12px',
            fontWeight: activeTab === 'DIFF' ? 700 : 500,
            color: activeTab === 'DIFF' ? 'var(--accent)' : 'var(--text-secondary)',
            borderBottom: activeTab === 'DIFF' ? '2px solid var(--accent)' : 'none',
            background: 'transparent',
            border: 'none',
            cursor: 'pointer',
            display: 'flex',
            alignItems: 'center',
            gap: '6px',
          }}
        >
          <TrendingUp size={14} /> What Changed (Temporal Diff)
        </button>

        <button
          onClick={() => setActiveTab('TRAJECTORIES')}
          style={{
            padding: '10px 18px',
            fontSize: '12px',
            fontWeight: activeTab === 'TRAJECTORIES' ? 700 : 500,
            color: activeTab === 'TRAJECTORIES' ? 'var(--accent)' : 'var(--text-secondary)',
            borderBottom: activeTab === 'TRAJECTORIES' ? '2px solid var(--accent)' : 'none',
            background: 'transparent',
            border: 'none',
            cursor: 'pointer',
            display: 'flex',
            alignItems: 'center',
            gap: '6px',
          }}
        >
          <GitCommit size={14} /> Entity Trajectories ({Object.keys(worldState.entity_trajectories || {}).length})
        </button>
      </div>

      {/* Main Tab Content */}
      <div style={{ padding: '16px 20px' }}>
        {/* TAB 1: SNAPSHOT INSPECTOR */}
        {activeTab === 'SNAPSHOT' && (
          <div>
            {currentSnapshot ? (
              <div>
                {/* Snapshot Header Stats */}
                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: '10px', marginBottom: '16px' }}>
                  <div style={{ padding: '10px 12px', background: 'var(--surface-ground)', borderRadius: '6px', border: '1px solid var(--border)' }}>
                    <span style={{ fontSize: '10px', color: 'var(--text-muted)', textTransform: 'uppercase' }}>Active Entities</span>
                    <div style={{ fontSize: '16px', fontWeight: 700, fontFamily: 'var(--mono)', color: 'var(--text-primary)' }}>
                      {Object.keys(currentSnapshot.entities || {}).length}
                    </div>
                  </div>
                  <div style={{ padding: '10px 12px', background: 'var(--surface-ground)', borderRadius: '6px', border: '1px solid var(--border)' }}>
                    <span style={{ fontSize: '10px', color: 'var(--text-muted)', textTransform: 'uppercase' }}>Active Relationships</span>
                    <div style={{ fontSize: '16px', fontWeight: 700, fontFamily: 'var(--mono)', color: 'var(--text-primary)' }}>
                      {Object.keys(currentSnapshot.relationships || {}).length}
                    </div>
                  </div>
                  <div style={{ padding: '10px 12px', background: 'var(--surface-ground)', borderRadius: '6px', border: '1px solid var(--border)' }}>
                    <span style={{ fontSize: '10px', color: 'var(--text-muted)', textTransform: 'uppercase' }}>Behavior Shifts</span>
                    <div style={{ fontSize: '16px', fontWeight: 700, fontFamily: 'var(--mono)', color: (currentSnapshot.behavior_changes?.length || 0) > 0 ? 'var(--warning)' : 'var(--text-primary)' }}>
                      {currentSnapshot.behavior_changes?.length || 0}
                    </div>
                  </div>
                  <div style={{ padding: '10px 12px', background: 'var(--surface-ground)', borderRadius: '6px', border: '1px solid var(--border)' }}>
                    <span style={{ fontSize: '10px', color: 'var(--text-muted)', textTransform: 'uppercase' }}>Capture Boundary</span>
                    <div style={{ fontSize: '14px', fontWeight: 600, color: currentSnapshot.is_capture_boundary ? 'var(--critical)' : 'var(--text-secondary)' }}>
                      {currentSnapshot.is_capture_boundary ? 'YES (Final Window)' : 'Continuous Window'}
                    </div>
                  </div>
                </div>

                {/* Filter and Table of Entities in this Window */}
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '12px' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flex: 1, maxWidth: '360px' }}>
                    <Search size={14} color="var(--text-muted)" />
                    <input
                      type="text"
                      placeholder="Filter entities in this window..."
                      value={entityFilter}
                      onChange={(e) => setEntityFilter(e.target.value)}
                      style={{
                        width: '100%',
                        padding: '6px 10px',
                        fontSize: '12px',
                        borderRadius: '4px',
                        border: '1px solid var(--border)',
                        background: 'var(--surface-ground)',
                        color: 'var(--text-primary)',
                      }}
                    />
                  </div>
                  <span style={{ fontSize: '11px', color: 'var(--text-muted)', fontFamily: 'var(--mono)' }}>
                    Showing {filteredEntities.length} of {Object.keys(currentSnapshot.entities || {}).length} entities
                  </span>
                </div>

                {/* Entities List */}
                <div style={{ overflowX: 'auto', border: '1px solid var(--border)', borderRadius: '6px', marginBottom: '16px' }}>
                  <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '12px' }}>
                    <thead>
                      <tr style={{ background: 'var(--surface-ground)', borderBottom: '1px solid var(--border)', textAlign: 'left' }}>
                        <th style={{ padding: '8px 12px' }}>Entity</th>
                        <th style={{ padding: '8px 12px' }}>Presence Status</th>
                        <th style={{ padding: '8px 12px' }}>Attack State</th>
                        <th style={{ padding: '8px 12px' }}>Fan-Out</th>
                        <th style={{ padding: '8px 12px' }}>Ports</th>
                        <th style={{ padding: '8px 12px' }}>Packets</th>
                        <th style={{ padding: '8px 12px' }}>Rej Ratio</th>
                        <th style={{ padding: '8px 12px', textAlign: 'right' }}>Actions</th>
                      </tr>
                    </thead>
                    <tbody>
                      {filteredEntities.map((ent: EntityTemporalStatePayload) => (
                        <tr key={ent.entity_key} style={{ borderBottom: '1px solid var(--border)' }}>
                          <td style={{ padding: '8px 12px', fontFamily: 'var(--mono)', fontWeight: 600, color: 'var(--text-primary)' }}>
                            {ent.entity_key}
                          </td>
                          <td style={{ padding: '8px 12px' }}>
                            <span
                              style={{
                                fontSize: '10px',
                                fontFamily: 'var(--mono)',
                                padding: '2px 6px',
                                borderRadius: '3px',
                                background:
                                  ent.presence === 'NEWLY_EMERGED'
                                    ? 'rgba(59, 130, 246, 0.15)'
                                    : ent.presence === 'LAST_OBSERVED_AT_CAPTURE_BOUNDARY'
                                    ? 'rgba(239, 68, 68, 0.15)'
                                    : 'rgba(16, 185, 129, 0.15)',
                                color:
                                  ent.presence === 'NEWLY_EMERGED'
                                    ? 'var(--accent)'
                                    : ent.presence === 'LAST_OBSERVED_AT_CAPTURE_BOUNDARY'
                                    ? 'var(--critical)'
                                    : 'var(--success)',
                                fontWeight: 600,
                              }}
                            >
                              {ent.presence}
                            </span>
                          </td>
                          <td style={{ padding: '8px 12px' }}>
                            <span
                              style={{
                                fontSize: '10px',
                                fontFamily: 'var(--mono)',
                                padding: '2px 6px',
                                borderRadius: '3px',
                                background:
                                  ent.attack_state === 'RECONNAISSANCE' || ent.attack_state === 'LATERAL_MOVEMENT'
                                    ? 'rgba(239, 68, 68, 0.15)'
                                    : 'var(--surface-ground)',
                                color:
                                  ent.attack_state === 'RECONNAISSANCE' || ent.attack_state === 'LATERAL_MOVEMENT'
                                    ? 'var(--critical)'
                                    : 'var(--text-secondary)',
                                fontWeight: 600,
                              }}
                            >
                              {ent.attack_state}
                            </span>
                          </td>
                          <td style={{ padding: '8px 12px', fontFamily: 'var(--mono)' }}>{ent.fanout}</td>
                          <td style={{ padding: '8px 12px', fontFamily: 'var(--mono)' }}>{ent.port_diversity}</td>
                          <td style={{ padding: '8px 12px', fontFamily: 'var(--mono)' }}>{ent.packets}</td>
                          <td style={{ padding: '8px 12px', fontFamily: 'var(--mono)' }}>
                            {(ent.failure_ratio * 100).toFixed(0)}%
                          </td>
                          <td style={{ padding: '8px 12px', textAlign: 'right' }}>
                            <div style={{ display: 'inline-flex', gap: '6px' }}>
                              {onSelectEntityForHunt && (
                                <button
                                  onClick={() => onSelectEntityForHunt(ent.entity_key)}
                                  title="Hunt entity in Threat Hunting workspace"
                                  style={{
                                    padding: '3px 8px',
                                    fontSize: '10px',
                                    borderRadius: '3px',
                                    background: 'var(--surface-ground)',
                                    border: '1px solid var(--border)',
                                    color: 'var(--accent)',
                                    cursor: 'pointer',
                                  }}
                                >
                                  Hunt
                                </button>
                              )}
                              {onInspectEntity && (
                                <button
                                  onClick={() => onInspectEntity(ent.entity_key)}
                                  title="View entity investigation dossier"
                                  style={{
                                    padding: '3px 8px',
                                    fontSize: '10px',
                                    borderRadius: '3px',
                                    background: 'var(--surface-ground)',
                                    border: '1px solid var(--border)',
                                    color: 'var(--text-primary)',
                                    cursor: 'pointer',
                                  }}
                                >
                                  Dossier
                                </button>
                              )}
                            </div>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>

                {/* Active Relationships in this window */}
                <div>
                  <div style={{ fontSize: '13px', fontWeight: 600, marginBottom: '8px', color: 'var(--text-primary)' }}>
                    Observed Communication Relationships ({snapshotRelationships.length})
                  </div>
                  {snapshotRelationships.length === 0 ? (
                    <div style={{ fontSize: '11px', color: 'var(--text-muted)', fontStyle: 'italic' }}>
                      No inter-entity communication flows observed in this window.
                    </div>
                  ) : (
                    <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(280px, 1fr))', gap: '8px' }}>
                      {snapshotRelationships.slice(0, 12).map((rel: RelationshipTemporalStatePayload) => (
                        <div
                          key={rel.relationship_id}
                          style={{
                            padding: '8px 10px',
                            background: 'var(--surface-ground)',
                            border: '1px solid var(--border)',
                            borderRadius: '4px',
                            fontSize: '11px',
                          }}
                        >
                          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                            <span style={{ fontFamily: 'var(--mono)', fontWeight: 600, color: 'var(--text-primary)' }}>
                              {rel.src_entity} &rarr; {rel.dst_entity}
                            </span>
                            <span
                              style={{
                                fontSize: '9px',
                                padding: '1px 5px',
                                borderRadius: '3px',
                                background: rel.status === 'NEW' ? 'rgba(59, 130, 246, 0.15)' : 'var(--surface-card)',
                                color: rel.status === 'NEW' ? 'var(--accent)' : 'var(--text-secondary)',
                                fontWeight: 600,
                              }}
                            >
                              {rel.status}
                            </span>
                          </div>
                          <div style={{ display: 'flex', gap: '8px', color: 'var(--text-muted)', marginTop: '4px', fontFamily: 'var(--mono)' }}>
                            <span>Port: {rel.dst_port || 0}</span>
                            <span>{rel.protocol}</span>
                            <span>{rel.packet_count} pkts</span>
                            <span>{rel.connection_count} conns</span>
                          </div>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              </div>
            ) : (
              <div style={{ padding: '24px', textAlign: 'center', color: 'var(--text-muted)' }}>
                No snapshot available for Window #{selectedWindowIndex}
              </div>
            )}
          </div>
        )}

        {/* TAB 2: WHAT CHANGED (DIFF) */}
        {activeTab === 'DIFF' && (
          <div>
            {/* Diff Window Selector */}
            <div
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: '12px',
                padding: '12px 16px',
                background: 'var(--surface-ground)',
                border: '1px solid var(--border)',
                borderRadius: '6px',
                marginBottom: '16px',
              }}
            >
              <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                <span style={{ fontSize: '11px', color: 'var(--text-muted)', fontWeight: 600 }}>Compare Baseline Window:</span>
                <select
                  value={diffWindowA}
                  onChange={(e) => setDiffWindowA(Number(e.target.value))}
                  style={{ padding: '4px 8px', borderRadius: '4px', border: '1px solid var(--border)', background: 'var(--surface-card)', color: 'var(--text-primary)', fontSize: '11px' }}
                >
                  {windows.map((w, i) => (
                    <option key={w.window_id} value={i}>
                      Window #{i}
                    </option>
                  ))}
                </select>
              </div>

              <ArrowRight size={14} color="var(--text-muted)" />

              <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                <span style={{ fontSize: '11px', color: 'var(--text-muted)', fontWeight: 600 }}>Target Window:</span>
                <select
                  value={diffWindowB}
                  onChange={(e) => setDiffWindowB(Number(e.target.value))}
                  style={{ padding: '4px 8px', borderRadius: '4px', border: '1px solid var(--border)', background: 'var(--surface-card)', color: 'var(--text-primary)', fontSize: '11px' }}
                >
                  {windows.map((w, i) => (
                    <option key={w.window_id} value={i}>
                      Window #{i}
                    </option>
                  ))}
                </select>
              </div>

              <span style={{ fontSize: '11px', color: 'var(--text-muted)', marginLeft: 'auto' }}>
                Deterministic delta between W{diffWindowA} &rarr; W{diffWindowB}
              </span>
            </div>

            {/* Diff Summary Cards */}
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: '10px', marginBottom: '16px' }}>
              <div style={{ padding: '10px 12px', background: 'var(--surface-ground)', borderRadius: '6px', border: '1px solid var(--border)' }}>
                <span style={{ fontSize: '10px', color: 'var(--text-muted)', textTransform: 'uppercase' }}>Entities Emerged</span>
                <div style={{ fontSize: '16px', fontWeight: 700, fontFamily: 'var(--mono)', color: 'var(--accent)' }}>
                  +{diff.entities_added.length}
                </div>
              </div>

              <div style={{ padding: '10px 12px', background: 'var(--surface-ground)', borderRadius: '6px', border: '1px solid var(--border)' }}>
                <span style={{ fontSize: '10px', color: 'var(--text-muted)', textTransform: 'uppercase' }}>Not Observed in W{diffWindowB}</span>
                <div style={{ fontSize: '16px', fontWeight: 700, fontFamily: 'var(--mono)', color: 'var(--text-secondary)' }}>
                  {diff.entities_not_observed.length}
                </div>
              </div>

              <div style={{ padding: '10px 12px', background: 'var(--surface-ground)', borderRadius: '6px', border: '1px solid var(--border)' }}>
                <span style={{ fontSize: '10px', color: 'var(--text-muted)', textTransform: 'uppercase' }}>Attack State Shifts</span>
                <div style={{ fontSize: '16px', fontWeight: 700, fontFamily: 'var(--mono)', color: diff.attack_state_transitions.length > 0 ? 'var(--critical)' : 'var(--text-primary)' }}>
                  {diff.attack_state_transitions.length}
                </div>
              </div>

              <div style={{ padding: '10px 12px', background: 'var(--surface-ground)', borderRadius: '6px', border: '1px solid var(--border)' }}>
                <span style={{ fontSize: '10px', color: 'var(--text-muted)', textTransform: 'uppercase' }}>Fanout Surges</span>
                <div style={{ fontSize: '16px', fontWeight: 700, fontFamily: 'var(--mono)', color: diff.fanout_surges.length > 0 ? 'var(--warning)' : 'var(--text-primary)' }}>
                  {diff.fanout_surges.length}
                </div>
              </div>
            </div>

            {/* Attack State Transitions */}
            {diff.attack_state_transitions.length > 0 && (
              <div style={{ marginBottom: '16px', padding: '12px 14px', background: 'rgba(239, 68, 68, 0.08)', borderRadius: '6px', border: '1px solid rgba(239, 68, 68, 0.3)' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '6px', marginBottom: '8px', color: 'var(--critical)', fontWeight: 700, fontSize: '12px' }}>
                  <ShieldAlert size={14} /> Attack State Transitions Detected
                </div>
                {diff.attack_state_transitions.map((tr, idx) => (
                  <div key={idx} style={{ fontSize: '11px', fontFamily: 'var(--mono)', display: 'flex', gap: '8px', alignItems: 'center', marginTop: '4px' }}>
                    <strong style={{ color: 'var(--text-primary)' }}>{tr.entity}</strong>: transitioned from{' '}
                    <span style={{ color: 'var(--text-muted)' }}>{tr.from_state}</span> &rarr;{' '}
                    <span style={{ color: 'var(--critical)', fontWeight: 700 }}>{tr.to_state}</span>
                  </div>
                ))}
              </div>
            )}

            {/* Fanout Surges */}
            {diff.fanout_surges.length > 0 && (
              <div style={{ marginBottom: '16px', padding: '12px 14px', background: 'rgba(234, 179, 8, 0.08)', borderRadius: '6px', border: '1px solid rgba(234, 179, 8, 0.3)' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '6px', marginBottom: '8px', color: 'var(--warning)', fontWeight: 700, fontSize: '12px' }}>
                  <AlertTriangle size={14} /> Sudden Port / Peer Fan-Out Surges
                </div>
                {diff.fanout_surges.map((fs, idx) => (
                  <div key={idx} style={{ fontSize: '11px', fontFamily: 'var(--mono)', display: 'flex', gap: '8px', alignItems: 'center', marginTop: '4px' }}>
                    <strong style={{ color: 'var(--text-primary)' }}>{fs.entity}</strong>: fanout increased from {fs.baseline_fanout} &rarr;{' '}
                    <span style={{ color: 'var(--warning)', fontWeight: 700 }}>{fs.current_fanout} hosts (+{fs.increase})</span>
                  </div>
                ))}
              </div>
            )}

            {/* Entities Added & Not Observed Lists */}
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '14px' }}>
              <div style={{ padding: '12px', background: 'var(--surface-ground)', borderRadius: '6px', border: '1px solid var(--border)' }}>
                <div style={{ fontSize: '12px', fontWeight: 600, color: 'var(--text-primary)', marginBottom: '8px' }}>
                  Newly Observed Entities in W{diffWindowB} ({diff.entities_added.length})
                </div>
                {diff.entities_added.length === 0 ? (
                  <div style={{ fontSize: '11px', color: 'var(--text-muted)', fontStyle: 'italic' }}>None</div>
                ) : (
                  <div style={{ display: 'flex', flexWrap: 'wrap', gap: '6px' }}>
                    {diff.entities_added.map((ip) => (
                      <span key={ip} style={{ fontSize: '11px', fontFamily: 'var(--mono)', padding: '2px 6px', borderRadius: '3px', background: 'var(--surface-card)', border: '1px solid var(--border)' }}>
                        {ip}
                      </span>
                    ))}
                  </div>
                )}
              </div>

              <div style={{ padding: '12px', background: 'var(--surface-ground)', borderRadius: '6px', border: '1px solid var(--border)' }}>
                <div style={{ fontSize: '12px', fontWeight: 600, color: 'var(--text-primary)', marginBottom: '8px' }}>
                  Not Observed in W{diffWindowB} ({diff.entities_not_observed.length})
                </div>
                {diff.entities_not_observed.length === 0 ? (
                  <div style={{ fontSize: '11px', color: 'var(--text-muted)', fontStyle: 'italic' }}>None</div>
                ) : (
                  <div style={{ display: 'flex', flexWrap: 'wrap', gap: '6px' }}>
                    {diff.entities_not_observed.map((ip) => (
                      <span key={ip} style={{ fontSize: '11px', fontFamily: 'var(--mono)', padding: '2px 6px', borderRadius: '3px', background: 'var(--surface-card)', border: '1px solid var(--border)', color: 'var(--text-muted)' }}>
                        {ip}
                      </span>
                    ))}
                  </div>
                )}
              </div>
            </div>
          </div>
        )}

        {/* TAB 3: ENTITY TRAJECTORIES */}
        {activeTab === 'TRAJECTORIES' && (
          <div>
            <div style={{ fontSize: '12px', color: 'var(--text-secondary)', marginBottom: '12px' }}>
              Displays the active temporal presence and window lifespan of observed network entities across the capture duration.
            </div>

            <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
              {Object.entries(worldState.entity_trajectories || {}).map(([ip, activeWins]) => {
                const isLead = ip === '208.111.178.163' || (activeWins && activeWins.length >= totalWindows / 2)
                return (
                  <div
                    key={ip}
                    style={{
                      display: 'flex',
                      alignItems: 'center',
                      padding: '8px 12px',
                      background: 'var(--surface-ground)',
                      borderRadius: '6px',
                      border: isLead ? '1px solid rgba(59, 130, 246, 0.4)' : '1px solid var(--border)',
                    }}
                  >
                    <div style={{ width: '160px', fontFamily: 'var(--mono)', fontSize: '12px', fontWeight: 600, color: 'var(--text-primary)' }}>
                      {ip}
                    </div>

                    {/* Window Activity Heatstrip */}
                    <div style={{ display: 'flex', gap: '4px', flex: 1, margin: '0 16px' }}>
                      {Array.from({ length: totalWindows }).map((_, wIdx) => {
                        const isActive = activeWins.includes(wIdx)
                        return (
                          <div
                            key={wIdx}
                            title={`Window ${wIdx}: ${isActive ? 'ACTIVE' : 'NOT OBSERVED'}`}
                            style={{
                              flex: 1,
                              height: '14px',
                              borderRadius: '2px',
                              background: isActive ? 'var(--accent)' : 'var(--surface-card)',
                              opacity: isActive ? 1 : 0.3,
                            }}
                          />
                        )
                      })}
                    </div>

                    <div style={{ fontSize: '11px', color: 'var(--text-muted)', fontFamily: 'var(--mono)', width: '80px', textAlign: 'right' }}>
                      {activeWins.length}/{totalWindows} wins
                    </div>
                  </div>
                )
              })}
            </div>
          </div>
        )}
      </div>
    </Panel>
  )
}
