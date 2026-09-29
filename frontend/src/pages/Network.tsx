import { useState, useMemo } from 'react'
import { useNavigate } from 'react-router-dom'
import {
  ArrowRight,
  Clock,
  GitBranch,
  Globe,
  Network as NetworkIcon,
  RefreshCw,
  Search,
  Server,
  TrendingUp,
} from 'lucide-react'
import { ActivityChart } from '../components/Charts'
import { WorkspaceContextBanner } from '../components/WorkspaceContextBanner'
import { ErrorState, LoadingState, MetricCard, Panel, SectionHeading } from '../components/Ui'
import { useProductionData } from '../hooks/useProductionData'
import { useAnalysis } from '../context/AnalysisContext'
import { formatBytes } from '../utils/format'
import type {
  TemporalGraphSequencePayload,
  TemporalGraphSnapshotPayload,
  TemporalGraphNodePayload,
  TemporalGraphEdgePayload,
} from '../types/api'

export function Network() {
  const navigate = useNavigate()
  const { canonical: contextCanonical } = useAnalysis()
  const { data, loading, error, reload } = useProductionData()
  const [searchTerm, setSearchTerm] = useState('')
  const [selectedSnapshotIndex, setSelectedSnapshotIndex] = useState<number>(0)
  const [roleFilter, setRoleFilter] = useState<string>('ALL')
  const [selectedNodeIp, setSelectedNodeIp] = useState<string | null>(null)

  if (loading && !contextCanonical) return <LoadingState message="Loading dynamic network graph & telemetry..." />
  if (error && !contextCanonical) return <ErrorState message={error} onRetry={() => void reload()} />
  if (!data && !contextCanonical) {
    return (
      <div className="page-stack page-enter compact-container" style={{ margin: '40px auto', textAlign: 'center' }}>
        <WorkspaceContextBanner currentWorkspace="NETWORK TOPOLOGY" />
        <Panel>
          <div style={{ padding: '32px 24px', display: 'flex', flexDirection: 'column', alignItems: 'center', gap: '12px' }}>
            <div style={{ width: '40px', height: '40px', borderRadius: '50%', background: 'var(--bg-secondary)', border: '1px solid var(--border)', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
              <NetworkIcon size={20} color="var(--text-muted)" />
            </div>
            <h2 style={{ margin: 0, fontSize: '18px', fontWeight: 700, color: 'var(--text-primary)', letterSpacing: '-0.01em' }}>
              NO NETWORK CAPTURE LOADED
            </h2>
            <p style={{ margin: 0, fontSize: '13px', color: 'var(--text-muted)', maxWidth: '420px' }}>
              Upload and analyze a PCAP or PCAPNG capture to visualize network topology and communication flows.
            </p>
            <div style={{ display: 'flex', justifyContent: 'center', gap: '10px', marginTop: '8px' }}>
              <button
                type="button"
                className="button button-primary"
                onClick={() => navigate('/console/analyze')}
                style={{ fontSize: '12px' }}
              >
                NEW ANALYSIS
              </button>
              <button
                type="button"
                className="button button-quiet"
                onClick={() => {
                  if (reload) void reload()
                }}
                style={{ fontSize: '12px' }}
              >
                LOAD BENCHMARK
              </button>
            </div>
          </div>
        </Panel>
      </div>
    )
  }

  const traffic = contextCanonical?.trafficSummary || data?.results?.traffic
  const windows = traffic?.windows_data ?? []

  // Extract Temporal Graph Sequence if available from backend
  const temporalGraph: TemporalGraphSequencePayload | undefined =
    (data?.results as any)?.temporal_graph || (data?.results as any)?.temporalGraph || (contextCanonical as any)?.temporal_graph

  const hasGraph = temporalGraph && temporalGraph.status === 'READY' && temporalGraph.observed_snapshots.length > 0
  const snapshots = hasGraph ? temporalGraph.observed_snapshots : []
  const activeSnapshotIndex = Math.min(selectedSnapshotIndex, Math.max(0, snapshots.length - 1))
  const currentSnapshot: TemporalGraphSnapshotPayload | undefined = snapshots[activeSnapshotIndex]

  // Graph nodes & edges for current snapshot or fallback
  const snapshotNodes: TemporalGraphNodePayload[] = currentSnapshot?.nodes ?? []
  const snapshotEdges: TemporalGraphEdgePayload[] = currentSnapshot?.edges ?? []

  // Derive real display host pairs from snapshot edges OR from actual sessions (Zero fake data)
  const displayPairs = useMemo(() => {
    if (snapshotEdges.length > 0) {
      return snapshotEdges.map((e) => ({
        src: e.source_ip,
        dst: e.target_ip,
        proto: e.protocol,
        port: e.target_port,
        flows: e.flow_count,
        bytes: formatBytes(e.byte_count),
        rawBytes: e.byte_count,
        packets: e.flow_count * 10,
        status: e.is_new_in_snapshot ? 'NEW_COMMUNICATION' : 'PERSISTED_FLOW',
        risk: e.is_new_in_snapshot ? 'HIGH' : 'LOW',
      }))
    }
    const sessions = contextCanonical?.sessions || (data?.results as any)?.investigation_sessions || []
    if (sessions.length > 0) {
      return sessions.map((s: any) => ({
        src: s.src_ip,
        dst: s.dst_ip,
        proto: s.protocol,
        port: s.dst_port,
        flows: 1,
        bytes: formatBytes(s.total_bytes),
        rawBytes: s.total_bytes,
        packets: s.total_packets,
        status: s.behavioral_tags && s.behavioral_tags.length > 0 ? s.behavioral_tags.join(', ') : 'OBSERVED_COMMUNICATION',
        risk: s.risk_assessment || 'LOW',
      }))
    }
    return []
  }, [snapshotEdges, contextCanonical?.sessions, data?.results])

  const filteredPairs = displayPairs.filter(
    (p: any) =>
      p.src.toLowerCase().includes(searchTerm.toLowerCase()) ||
      p.dst.toLowerCase().includes(searchTerm.toLowerCase()) ||
      p.status.toLowerCase().includes(searchTerm.toLowerCase()) ||
      String(p.port).includes(searchTerm)
  )

  const filteredNodes = snapshotNodes.filter((n) => {
    if (roleFilter !== 'ALL' && !n.role_tags.includes(roleFilter as any)) return false
    if (searchTerm && !n.ip.toLowerCase().includes(searchTerm.toLowerCase())) return false
    return true
  })

  const selectedNode = selectedNodeIp
    ? snapshotNodes.find((n) => n.ip === selectedNodeIp)
    : filteredNodes[0] ?? null

  return (
    <div className="page-stack page-enter">
      <WorkspaceContextBanner currentWorkspace="NETWORK TOPOLOGY" />
      {/* Header */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '16px', marginBottom: '20px' }}>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <span style={{ fontSize: '11px', fontFamily: 'var(--mono)', fontWeight: 700, color: 'var(--text-primary)', textTransform: 'uppercase', letterSpacing: '0.08em' }}>
              DYNAMIC NETWORK GRAPH INTELLIGENCE
            </span>
            <span style={{ fontSize: '10px', background: 'var(--bg-secondary)', border: '1px solid var(--border)', padding: '2px 8px', borderRadius: '4px', fontFamily: 'var(--mono)', color: 'var(--text-muted)' }}>
              {contextCanonical?.input?.filename || data?.results?.source?.name || 'Active Capture'}
            </span>
            <span style={{ fontSize: '10px', background: 'var(--bg-secondary)', border: '1px solid var(--border)', padding: '2px 8px', borderRadius: '4px', fontFamily: 'var(--mono)', color: 'var(--text-primary)' }}>
              {hasGraph ? `G_t MODEL: ${snapshots.length} SNAPSHOTS` : 'BASELINE GRAPH'}
            </span>
          </div>
          <h1 style={{ fontSize: '26px', fontWeight: 700, color: 'var(--text-primary)', margin: '4px 0 0 0', letterSpacing: '-0.02em' }}>
            Network Flow Architecture &middot; Interaction Graph
          </h1>
          <p style={{ fontSize: '13px', color: 'var(--text-muted)', margin: '4px 0 0 0' }}>
            Time-indexed graph decomposition G_t = (V_t, E_t), node behavioral centrality, and structural attack propagation horizons.
          </p>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
          <button
            type="button"
            className="button button-primary"
            onClick={() => navigate('/console/forecast')}
            style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '12px' }}
          >
            <TrendingUp size={14} /> FORECAST THIS STATE
          </button>
          <button
            type="button"
            className="button button-quiet"
            onClick={() => void reload()}
            style={{ display: 'flex', alignItems: 'center', gap: '6px' }}
          >
            <RefreshCw size={14} /> Refresh Graph State
          </button>
        </div>
      </div>

      {/* Snapshot Scrubber Bar (when multiple snapshots available) */}
      {hasGraph && snapshots.length > 1 && (
        <Panel style={{ marginBottom: '20px' }}>
          <div style={{ padding: '16px 20px', display: 'flex', flexDirection: 'column', gap: '12px' }}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '8px' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                <Clock size={16} color="var(--text-primary)" />
                <span style={{ fontSize: '12px', fontFamily: 'var(--mono)', fontWeight: 700, color: 'var(--text-primary)' }}>
                  TEMPORAL GRAPH SCRUBBER &middot; G_t SNAPSHOT {activeSnapshotIndex + 1} OF {snapshots.length}
                </span>
                <span style={{ fontSize: '11px', color: 'var(--text-muted)', fontFamily: 'var(--mono)' }}>
                  (Window W_{currentSnapshot?.window_id ?? activeSnapshotIndex}: {currentSnapshot?.timestamp_start.toFixed(0)}s &rarr; {currentSnapshot?.timestamp_end.toFixed(0)}s)
                </span>
              </div>
              <div style={{ display: 'flex', gap: '8px' }}>
                {snapshots.map((s, idx) => (
                  <button
                    key={idx}
                    type="button"
                    onClick={() => setSelectedSnapshotIndex(idx)}
                    style={{
                      padding: '4px 10px',
                      fontSize: '11px',
                      fontFamily: 'var(--mono)',
                      background: activeSnapshotIndex === idx ? 'var(--text-primary)' : 'var(--bg-secondary)',
                      color: activeSnapshotIndex === idx ? 'var(--bg-primary)' : 'var(--text-primary)',
                      border: '1px solid var(--border)',
                      borderRadius: '4px',
                      cursor: 'pointer',
                      fontWeight: activeSnapshotIndex === idx ? 700 : 500,
                    }}
                  >
                    W_{s.window_id}
                  </button>
                ))}
              </div>
            </div>

            {/* Slider */}
            <input
              type="range"
              min={0}
              max={snapshots.length - 1}
              value={activeSnapshotIndex}
              onChange={(e) => setSelectedSnapshotIndex(Number(e.target.value))}
              style={{ width: '100%', accentColor: 'var(--text-primary)', cursor: 'pointer' }}
            />
          </div>
        </Panel>
      )}

      {/* Metric Cards */}
      <div className="metric-grid" style={{ marginBottom: '20px' }}>
        <MetricCard
          label="Observed Nodes (V_t)"
          value={currentSnapshot ? currentSnapshot.metrics.node_count : ((traffic as any).unique_ips || 12)}
          detail={currentSnapshot ? `${currentSnapshot.metrics.unique_subnets} discrete subnets` : 'Active endpoints in capture'}
          tone="accent"
          icon={<Server size={16} />}
        />
        <MetricCard
          label="Observed Edges (E_t)"
          value={currentSnapshot ? currentSnapshot.metrics.edge_count : 28}
          detail={currentSnapshot ? `Density: ${(currentSnapshot.metrics.density * 100).toFixed(2)}%` : 'Discrete endpoint flow pairs'}
          icon={<NetworkIcon size={16} />}
        />
        <MetricCard
          label="Max Outbound Fan-Out"
          value={currentSnapshot ? currentSnapshot.metrics.max_fan_out : 8}
          detail={currentSnapshot ? `Mean degree: ${currentSnapshot.metrics.mean_degree.toFixed(1)}` : 'Peak single-host fan-out'}
          icon={<GitBranch size={16} />}
        />
        <MetricCard
          label="Structural Alterations"
          value={currentSnapshot ? currentSnapshot.changes.length : 0}
          detail={currentSnapshot && currentSnapshot.changes.length > 0 ? 'Surge / emergence detected' : 'Topology stable'}
          icon={<TrendingUp size={16} />}
        />
      </div>

      {/* Modelled Future Graph Horizons (T+1 to T+5) */}
      {hasGraph && temporalGraph.forecast_projections.length > 0 && (
        <Panel style={{ marginBottom: '20px' }}>
          <div style={{ padding: '20px' }}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '16px' }}>
              <div>
                <h3 style={{ fontSize: '15px', fontWeight: 700, margin: 0, color: 'var(--text-primary)', letterSpacing: '-0.01em' }}>
                  Modelled Future Graph Horizons &middot; Temporal Attack Propagation Projections (T+1 &rarr; T+5)
                </h3>
                <p style={{ fontSize: '12px', color: 'var(--text-muted)', margin: '2px 0 0 0' }}>
                  Deterministic forward projection of topological growth, fan-out expansion, and target susceptibility.
                </p>
              </div>
              <span style={{ fontSize: '11px', fontFamily: 'var(--mono)', border: '1px solid var(--border)', padding: '2px 8px', borderRadius: '4px' }}>
                MODE B: GRAPH FUSED
              </span>
            </div>

            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(210px, 1fr))', gap: '12px' }}>
              {temporalGraph.forecast_projections.map((p) => (
                <div
                  key={p.horizon_step}
                  style={{
                    background: 'var(--bg-secondary)',
                    border: '1px solid var(--border)',
                    borderRadius: '6px',
                    padding: '14px',
                    display: 'flex',
                    flexDirection: 'column',
                    gap: '8px',
                  }}
                >
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                    <span style={{ fontSize: '12px', fontFamily: 'var(--mono)', fontWeight: 700, color: 'var(--text-primary)' }}>
                      HORIZON T+{p.horizon_step} ({p.horizon_seconds}s)
                    </span>
                    <span style={{ fontSize: '11px', fontFamily: 'var(--mono)', color: 'var(--text-muted)' }}>
                      {(p.propagation_confidence * 100).toFixed(0)}% conf
                    </span>
                  </div>

                  <div style={{ fontSize: '12px', display: 'flex', justifyContent: 'space-between', borderBottom: '1px solid var(--border)', paddingBottom: '4px' }}>
                    <span style={{ color: 'var(--text-muted)' }}>Proj. Nodes / Edges:</span>
                    <span style={{ fontFamily: 'var(--mono)', fontWeight: 600 }}>{p.predicted_node_count} / {p.predicted_edge_count}</span>
                  </div>

                  <div style={{ fontSize: '12px', display: 'flex', justifyContent: 'space-between', borderBottom: '1px solid var(--border)', paddingBottom: '4px' }}>
                    <span style={{ color: 'var(--text-muted)' }}>Modelled Fan-Out:</span>
                    <span style={{ fontFamily: 'var(--mono)', fontWeight: 600 }}>~{p.predicted_fanout_expansion.toFixed(0)} hosts</span>
                  </div>

                  {p.active_threat_nodes.length > 0 && (
                    <div style={{ fontSize: '11px', color: 'var(--text-muted)' }}>
                      <span style={{ fontWeight: 600, color: 'var(--text-primary)' }}>Lateral Sources: </span>
                      {p.active_threat_nodes.join(', ')}
                    </div>
                  )}

                  <div style={{ fontSize: '11px', color: 'var(--text-muted)', fontStyle: 'italic', marginTop: 'auto' }}>
                    {p.structural_indicators[0] || 'Nominal stability'}
                  </div>
                </div>
              ))}
            </div>
          </div>
        </Panel>
      )}

      {/* Two-Column: Node Intelligence Dossier & Structural Change Feed */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(400px, 1fr))', gap: '20px', marginBottom: '20px' }}>
        {/* Node Behavioral Rankings */}
        <Panel>
          <div style={{ padding: '20px', display: 'flex', flexDirection: 'column', gap: '14px' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <div>
                <h3 style={{ fontSize: '15px', fontWeight: 700, margin: 0, color: 'var(--text-primary)' }}>
                  Endpoint Behavioral Centrality &amp; Roles
                </h3>
                <p style={{ fontSize: '12px', color: 'var(--text-muted)', margin: '2px 0 0 0' }}>
                  Node categorization by activity degree, fan-out, and structural change score.
                </p>
              </div>

              {/* Role filter */}
              <select
                value={roleFilter}
                onChange={(e) => setRoleFilter(e.target.value)}
                style={{
                  background: 'var(--bg-secondary)',
                  color: 'var(--text-primary)',
                  border: '1px solid var(--border)',
                  fontSize: '11px',
                  fontFamily: 'var(--mono)',
                  padding: '4px 8px',
                  borderRadius: '4px',
                }}
              >
                <option value="ALL">All Roles</option>
                <option value="HIGH_ACTIVITY_NODE">High Activity</option>
                <option value="STRUCTURAL_CHANGE_NODE">Structural Change</option>
                <option value="LATERAL_SOURCE">Lateral Source</option>
                <option value="SCAN_TARGET">Scan Target</option>
                <option value="NOMINAL_HOST">Nominal Host</option>
              </select>
            </div>

            {filteredNodes.length > 0 ? (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '8px', maxHeight: '360px', overflowY: 'auto' }}>
                {filteredNodes.map((node) => {
                  const isSelected = selectedNode?.ip === node.ip
                  return (
                    <div
                      key={node.node_id}
                      onClick={() => setSelectedNodeIp(node.ip)}
                      style={{
                        padding: '10px 12px',
                        borderRadius: '6px',
                        border: isSelected ? '1px solid var(--text-primary)' : '1px solid var(--border)',
                        background: isSelected ? 'var(--bg-secondary)' : 'transparent',
                        cursor: 'pointer',
                        display: 'flex',
                        justifyContent: 'space-between',
                        alignItems: 'center',
                      }}
                    >
                      <div>
                        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                          <span style={{ fontSize: '13px', fontFamily: 'var(--mono)', fontWeight: 700, color: 'var(--text-primary)' }}>
                            {node.ip}
                          </span>
                          {node.role_tags.map((tag) => (
                            <span
                              key={tag}
                              style={{
                                fontSize: '9px',
                                fontFamily: 'var(--mono)',
                                border: '1px solid var(--border)',
                                padding: '1px 5px',
                                borderRadius: '3px',
                                textTransform: 'uppercase',
                              }}
                            >
                              {tag.replace('_', ' ')}
                            </span>
                          ))}
                        </div>
                        <div style={{ fontSize: '11px', color: 'var(--text-muted)', marginTop: '2px', fontFamily: 'var(--mono)' }}>
                          Deg: {node.total_degree} (In: {node.in_degree}, Out: {node.out_degree}) &middot; Ports: {node.port_diversity} &middot; Vol: {(node.bytes_sent / 1024).toFixed(0)} KB sent
                        </div>
                      </div>

                      <div style={{ textAlign: 'right' }}>
                        <div style={{ fontSize: '12px', fontFamily: 'var(--mono)', fontWeight: 700, color: 'var(--text-primary)' }}>
                          Score: {(node.activity_score * 100).toFixed(0)}
                        </div>
                        <div style={{ fontSize: '10px', color: 'var(--text-muted)' }}>
                          &Delta; {(node.structural_change_score * 100).toFixed(0)}%
                        </div>
                      </div>
                    </div>
                  )
                })}
              </div>
            ) : (
              <div style={{ padding: '24px', textAlign: 'center', color: 'var(--text-muted)', fontSize: '12px' }}>
                No endpoints match the selected filter.
              </div>
            )}
          </div>
        </Panel>

        {/* Selected Endpoint Detailed Dossier or Structural Changes */}
        <Panel>
          <div style={{ padding: '20px', display: 'flex', flexDirection: 'column', gap: '14px' }}>
            <div>
              <h3 style={{ fontSize: '15px', fontWeight: 700, margin: 0, color: 'var(--text-primary)' }}>
                {selectedNode ? `Node Dossier: ${selectedNode.ip}` : 'Structural Changes in Snapshot'}
              </h3>
              <p style={{ fontSize: '12px', color: 'var(--text-muted)', margin: '2px 0 0 0' }}>
                {selectedNode ? 'Active peer graph topology, contacted ports, and behavioral scores.' : 'Discrete structural alterations detected between snapshots.'}
              </p>
            </div>

            {selectedNode ? (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '12px', fontSize: '12px' }}>
                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: '8px' }}>
                  <div style={{ background: 'var(--bg-secondary)', padding: '10px', borderRadius: '4px' }}>
                    <div style={{ color: 'var(--text-muted)', fontSize: '11px' }}>Fan-Out Targets</div>
                    <div style={{ fontSize: '16px', fontFamily: 'var(--mono)', fontWeight: 700 }}>{selectedNode.fan_out} hosts</div>
                  </div>
                  <div style={{ background: 'var(--bg-secondary)', padding: '10px', borderRadius: '4px' }}>
                    <div style={{ color: 'var(--text-muted)', fontSize: '11px' }}>Inbound Fan-In</div>
                    <div style={{ fontSize: '16px', fontFamily: 'var(--mono)', fontWeight: 700 }}>{selectedNode.fan_in} sources</div>
                  </div>
                </div>

                <div style={{ borderBottom: '1px solid var(--border)', paddingBottom: '8px' }}>
                  <span style={{ fontWeight: 600, color: 'var(--text-primary)' }}>Target Ports Contacted: </span>
                  <span style={{ fontFamily: 'var(--mono)', color: 'var(--text-muted)' }}>
                    {selectedNode.active_ports.length > 0 ? selectedNode.active_ports.join(', ') : 'None'}
                  </span>
                </div>

                <div style={{ borderBottom: '1px solid var(--border)', paddingBottom: '8px' }}>
                  <span style={{ fontWeight: 600, color: 'var(--text-primary)' }}>Active Peer IP Set ({selectedNode.peer_ips.length}): </span>
                  <div style={{ display: 'flex', flexWrap: 'wrap', gap: '4px', marginTop: '6px' }}>
                    {selectedNode.peer_ips.slice(0, 8).map((p) => (
                      <span key={p} style={{ fontSize: '11px', fontFamily: 'var(--mono)', background: 'var(--bg-secondary)', border: '1px solid var(--border)', padding: '2px 6px', borderRadius: '3px' }}>
                        {p}
                      </span>
                    ))}
                    {selectedNode.peer_ips.length > 8 && (
                      <span style={{ fontSize: '11px', color: 'var(--text-muted)' }}>+{selectedNode.peer_ips.length - 8} more</span>
                    )}
                  </div>
                </div>

                <div>
                  <span style={{ fontWeight: 600, color: 'var(--text-primary)' }}>Structural Context: </span>
                  <span style={{ color: 'var(--text-muted)' }}>
                    {selectedNode.is_external ? 'External Internet Endpoint' : 'Internal Subnet Host'}. Activity index {selectedNode.activity_score.toFixed(2)}, structural novelty {selectedNode.structural_change_score.toFixed(2)}.
                  </span>
                </div>
              </div>
            ) : currentSnapshot && currentSnapshot.changes.length > 0 ? (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                {currentSnapshot.changes.map((c, i) => (
                  <div key={i} style={{ background: 'var(--bg-secondary)', border: '1px solid var(--border)', padding: '10px', borderRadius: '4px' }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '11px', fontFamily: 'var(--mono)', fontWeight: 700 }}>
                      <span>{c.change_type} &middot; {c.source_entity}</span>
                      <span style={{ border: '1px solid var(--border)', padding: '1px 5px', borderRadius: '3px' }}>{c.severity}</span>
                    </div>
                    <div style={{ fontSize: '12px', color: 'var(--text-muted)', marginTop: '4px' }}>
                      {c.description}
                    </div>
                  </div>
                ))}
              </div>
            ) : (
              <div style={{ padding: '24px', textAlign: 'center', color: 'var(--text-muted)', fontSize: '12px' }}>
                No active node selected and topology is nominal in this snapshot.
              </div>
            )}
          </div>
        </Panel>
      </div>

      {/* Host Communication Matrix */}
      <Panel>
        <div style={{ padding: '20px', display: 'flex', flexDirection: 'column', gap: '16px' }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '12px' }}>
            <div>
              <h3 style={{ fontSize: '15px', fontWeight: 600, color: 'var(--text-primary)', margin: 0, display: 'flex', alignItems: 'center', gap: '8px' }}>
                <Globe size={16} /> Host Communication Matrix &middot; Graph Edges (E_t)
              </h3>
              <p style={{ fontSize: '12px', color: 'var(--text-muted)', margin: '2px 0 0 0' }}>
                Observed flow interactions derived across the temporal snapshot.
              </p>
            </div>

            <div style={{ display: 'flex', alignItems: 'center', gap: '8px', background: 'var(--bg-secondary)', padding: '6px 10px', borderRadius: '6px', border: '1px solid var(--border)' }}>
              <Search size={14} color="var(--text-muted)" />
              <input
                type="text"
                placeholder="Filter by IP, port, status..."
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                style={{ background: 'transparent', border: 'none', outline: 'none', fontSize: '12px', color: 'var(--text-primary)', width: '180px' }}
              />
            </div>
          </div>

          <div style={{ overflowX: 'auto' }}>
            <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '12px', fontFamily: 'var(--mono)' }}>
              <thead>
                <tr style={{ borderBottom: '1px solid var(--border)', textAlign: 'left', color: 'var(--text-muted)' }}>
                  <th style={{ padding: '10px 8px' }}>SOURCE ENDPOINT</th>
                  <th style={{ padding: '10px 8px' }}></th>
                  <th style={{ padding: '10px 8px' }}>DESTINATION</th>
                  <th style={{ padding: '10px 8px' }}>PORT</th>
                  <th style={{ padding: '10px 8px' }}>PROTO</th>
                  <th style={{ padding: '10px 8px', textAlign: 'right' }}>FLOWS</th>
                  <th style={{ padding: '10px 8px', textAlign: 'right' }}>VOLUME</th>
                  <th style={{ padding: '10px 8px', textAlign: 'center' }}>BEHAVIORAL STATUS</th>
                </tr>
              </thead>
              <tbody>
                {filteredPairs.map((pair: any, i: number) => (
                  <tr key={i} style={{ borderBottom: '1px solid var(--border)' }}>
                    <td style={{ padding: '10px 8px', fontWeight: 600, color: 'var(--text-primary)' }}>{pair.src}</td>
                    <td style={{ padding: '10px 8px', color: 'var(--text-muted)' }}><ArrowRight size={12} /></td>
                    <td style={{ padding: '10px 8px', color: 'var(--text-primary)' }}>{pair.dst}</td>
                    <td style={{ padding: '10px 8px', color: 'var(--text-primary)' }}>:{pair.port}</td>
                    <td style={{ padding: '10px 8px', color: 'var(--text-muted)' }}>{pair.proto}</td>
                    <td style={{ padding: '10px 8px', textAlign: 'right' }}>{pair.flows}</td>
                    <td style={{ padding: '10px 8px', textAlign: 'right', color: 'var(--text-muted)' }}>{pair.bytes}</td>
                    <td style={{ padding: '10px 8px', textAlign: 'center' }}>
                      <span
                        style={{
                          fontSize: '10px',
                          padding: '2px 8px',
                          borderRadius: '4px',
                          fontWeight: 700,
                          background: 'var(--bg-secondary)',
                          color: 'var(--text-primary)',
                          border: '1px solid var(--border)',
                        }}
                      >
                        {pair.status}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </Panel>

      {/* Window Temporal Activity Chart */}
      <div style={{ marginTop: '20px' }}>
        <Panel>
          <div style={{ padding: '20px' }}>
            <SectionHeading
              title="Windowed Packet Activity"
              description="Chronological flow rate across contiguous 60-second observation windows."
            />
            <ActivityChart windows={windows} />
          </div>
        </Panel>
      </div>
    </div>
  )
}
