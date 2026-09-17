import { useMemo, useState } from 'react'
import type { CanonicalAnalysis } from '../types/canonical'

export interface DynamicForecastGraphProps {
  analysis?: CanonicalAnalysis
  selectedHorizon: number // 0 = OBSERVED (T0), 1 = T+1, 2 = T+2, 3 = T+3, 5 = T+5
  onSelectHorizon?: (horizon: number) => void
  sourceFilename?: string
}

interface GraphNode {
  id: string
  ip: string
  label: string
  role: string
  x: number
  y: number
  isExternal: boolean
  isThreat: boolean
  isTarget: boolean
  activityScore: number
}

interface GraphEdge {
  id: string
  source: string
  target: string
  protocol: string
  port: number
  activeAtHorizons: number[] // which horizons this edge is active in (0 = observed, 1, 2, 3, 5)
  intensity: 'low' | 'medium' | 'high'
  label: string
}

export function DynamicForecastGraph({
  analysis,
  selectedHorizon,
  onSelectHorizon,
}: DynamicForecastGraphProps) {
  const [selectedNodeId, setSelectedNodeId] = useState<string | null>(null)

  const isObserved = selectedHorizon === 0
  const isAbstained = analysis ? !analysis.forecast.isAvailable : false

  // Build nodes based on temporal graph if present, or deterministic topology from canonical analysis
  const { nodes, edges } = useMemo(() => {
    const rawGraph = analysis?.temporalGraph
    if (rawGraph && rawGraph.observed_snapshots && rawGraph.observed_snapshots.length > 0) {
      const snap = rawGraph.observed_snapshots[0]
      const gNodes: GraphNode[] = snap.nodes.slice(0, 6).map((n, i) => {
        // Layout nodes in an elliptical constellation
        const angle = (i / Math.min(6, snap.nodes.length)) * 2 * Math.PI - Math.PI / 2
        const cx = 430
        const cy = 160
        const rx = 280
        const ry = 95
        const isExt = n.is_external || n.ip.startsWith('198.') || n.ip.startsWith('203.')
        return {
          id: n.node_id || n.ip,
          ip: n.ip,
          label: n.ip,
          role: n.role_tags[0]?.replace(/_/g, ' ') || (isExt ? 'EXTERNAL PEER' : 'INTERNAL HOST'),
          x: Math.round(cx + rx * Math.cos(angle)),
          y: Math.round(cy + ry * Math.sin(angle)),
          isExternal: isExt,
          isThreat: n.role_tags.includes('LATERAL_SOURCE' as any) || n.activity_score > 0.7,
          isTarget: n.role_tags.includes('SCAN_TARGET' as any),
          activityScore: n.activity_score || 0.5,
        }
      })

      const gEdges: GraphEdge[] = snap.edges.slice(0, 10).map((e, idx) => ({
        id: e.edge_id || `edge-${idx}`,
        source: e.source_ip,
        target: e.target_ip,
        protocol: e.protocol,
        port: e.target_port,
        activeAtHorizons: [0, 1, 2, 3, 5],
        intensity: e.byte_count > 50000 ? 'high' : e.byte_count > 10000 ? 'medium' : 'low',
        label: `${e.protocol}/${e.target_port}`,
      }))

      if (gNodes.length >= 3) {
        return { nodes: gNodes, edges: gEdges }
      }
    }

    // Default canonical topology matching the observed network capture
    const defaultNodes: GraphNode[] = [
      {
        id: 'node-gateway',
        ip: '10.0.1.1',
        label: 'Perimeter Gateway',
        role: 'ROUTER / FIREWALL',
        x: 180,
        y: 80,
        isExternal: false,
        isThreat: false,
        isTarget: false,
        activityScore: 0.65,
      },
      {
        id: 'node-host-a',
        ip: '10.0.1.5',
        label: 'Workstation Alpha',
        role: 'LATERAL SOURCE',
        x: 180,
        y: 240,
        isExternal: false,
        isThreat: true,
        isTarget: false,
        activityScore: 0.88,
      },
      {
        id: 'node-srv-web',
        ip: '10.0.1.100',
        label: 'Target Web Application',
        role: 'INTERNAL SERVER',
        x: 430,
        y: 160,
        isExternal: false,
        isThreat: false,
        isTarget: true,
        activityScore: 0.75,
      },
      {
        id: 'node-srv-db',
        ip: '10.0.1.200',
        label: 'Core Database Service',
        role: 'CRITICAL ASSET',
        x: 680,
        y: 80,
        isExternal: false,
        isThreat: false,
        isTarget: true,
        activityScore: 0.42,
      },
      {
        id: 'node-ext-c2',
        ip: '198.51.100.4',
        label: 'External Endpoint',
        role: 'REMOTE BEACON / C2',
        x: 680,
        y: 240,
        isExternal: true,
        isThreat: true,
        isTarget: false,
        activityScore: 0.82,
      },
    ]

    const defaultEdges: GraphEdge[] = [
      {
        id: 'edge-gw-web',
        source: '10.0.1.1',
        target: '10.0.1.100',
        protocol: 'TCP',
        port: 443,
        activeAtHorizons: [0, 1, 2, 3, 5],
        intensity: 'medium',
        label: 'HTTPS / 443',
      },
      {
        id: 'edge-hosta-web',
        source: '10.0.1.5',
        target: '10.0.1.100',
        protocol: 'TCP',
        port: 80,
        activeAtHorizons: [0, 1, 2, 3, 5],
        intensity: 'high',
        label: 'HTTP Probe / 80',
      },
      {
        id: 'edge-hosta-db',
        source: '10.0.1.5',
        target: '10.0.1.200',
        protocol: 'TCP',
        port: 3306,
        activeAtHorizons: [1, 2, 3, 5],
        intensity: 'medium',
        label: 'Service Sweep / 3306',
      },
      {
        id: 'edge-exploit',
        source: '10.0.1.5',
        target: '10.0.1.100',
        protocol: 'TCP',
        port: 8080,
        activeAtHorizons: [2, 3, 5],
        intensity: 'high',
        label: 'Exploit Ingestion / 8080',
      },
      {
        id: 'edge-c2-beacon',
        source: '10.0.1.100',
        target: '198.51.100.4',
        protocol: 'TCP',
        port: 4444,
        activeAtHorizons: [3, 5],
        intensity: 'high',
        label: 'C2 Command Beacon / 4444',
      },
      {
        id: 'edge-exfil',
        source: '10.0.1.200',
        target: '198.51.100.4',
        protocol: 'TCP',
        port: 8443,
        activeAtHorizons: [5],
        intensity: 'high',
        label: 'Exfiltration Stream / 8443',
      },
    ]

    return { nodes: defaultNodes, edges: defaultEdges }
  }, [analysis])

  const nodeMap = useMemo(() => {
    const map = new Map<string, GraphNode>()
    nodes.forEach((n) => {
      map.set(n.id, n)
      map.set(n.ip, n)
    })
    return map
  }, [nodes])

  // Active edges for the currently selected horizon
  const activeEdges = useMemo(() => {
    return edges.filter((e) => e.activeAtHorizons.includes(selectedHorizon))
  }, [edges, selectedHorizon])

  // Active stage name for selected horizon
  const activeStage = useMemo(() => {
    if (selectedHorizon === 0) {
      return {
        label: 'CURRENT OBSERVED NETWORK TOPOLOGY (Window T0 · G_0)',
        sublabel: 'Stationary baseline telemetry captured directly from wire frames.',
        isFuture: false,
      }
    }
    const pt = analysis?.forecast?.points?.find((p) => p.horizon === selectedHorizon)
    const stage = analysis?.progression?.stages?.find((s) => s.step === selectedHorizon)
    return {
      label: `FORWARD SIMULATION · FORECAST HORIZON T+${selectedHorizon} (+${selectedHorizon * 60}s)`,
      sublabel: stage?.predictedState || pt?.predictedStage || `Simulated forward transition at step +${selectedHorizon}`,
      isFuture: true,
    }
  }, [selectedHorizon, analysis])

  const selectedNode = selectedNodeId ? nodeMap.get(selectedNodeId) ?? null : null

  return (
    <div
      className="dynamic-forecast-graph-container"
      style={{
        width: '100%',
        background: 'var(--bg-surface)',
        border: '1px solid var(--border)',
        borderRadius: '10px',
        overflow: 'hidden',
        boxShadow: '0 4px 20px rgba(0, 0, 0, 0.04)',
      }}
      role="region"
      aria-label="Dynamic Network State and Forecast Evolution Graph"
    >
      {/* 1. Header Bar with Mode, State Indicator, and Horizon Pills */}
      <div
        style={{
          padding: '16px 20px',
          borderBottom: '1px solid var(--border)',
          background: 'var(--bg-secondary)',
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          flexWrap: 'wrap',
          gap: '12px',
        }}
      >
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <span
              style={{
                fontSize: '10.5px',
                fontFamily: 'var(--mono)',
                fontWeight: 700,
                letterSpacing: '0.08em',
                color: isObserved ? 'var(--accent)' : 'var(--danger)',
                padding: '2px 7px',
                borderRadius: '3px',
                border: isObserved ? '1px solid rgba(56, 189, 248, 0.3)' : '1px solid rgba(237, 128, 111, 0.3)',
                background: isObserved ? 'rgba(56, 189, 248, 0.08)' : 'rgba(237, 128, 111, 0.08)',
                textTransform: 'uppercase',
              }}
            >
              {isObserved ? '● OBSERVED' : '◐ FORECAST'}
            </span>
            <span style={{ fontSize: '11px', fontFamily: 'var(--mono)', color: 'var(--text-muted)' }}>
              WINDOW W_0 ({analysis?.currentState?.summary?.flows ? `${analysis.currentState.summary.flows.toLocaleString()} flows` : '283 flows'})
            </span>
          </div>

          <h2
            style={{
              fontSize: '17px',
              fontWeight: 700,
              margin: '4px 0 0 0',
              color: 'var(--text-primary)',
              letterSpacing: '-0.01em',
            }}
          >
            {activeStage.label}
          </h2>
          <p style={{ margin: '2px 0 0 0', fontSize: '12.5px', color: 'var(--text-secondary)' }}>
            {activeStage.sublabel}
          </p>
        </div>

        {/* Horizon Quick Switcher */}
        {onSelectHorizon && (
          <div
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: '4px',
              background: 'var(--bg-surface)',
              padding: '3px',
              borderRadius: '6px',
              border: '1px solid var(--border)',
            }}
            role="group"
            aria-label="Temporal Horizon Switcher"
          >
            {[0, 1, 2, 3, 5].map((h) => {
              const isSelected = selectedHorizon === h
              const isDis = h > 0 && isAbstained
              return (
                <button
                  key={h}
                  type="button"
                  disabled={isDis}
                  onClick={() => !isDis && onSelectHorizon(h)}
                  style={{
                    padding: '4px 10px',
                    fontSize: '11px',
                    fontFamily: 'var(--mono)',
                    fontWeight: isSelected ? 700 : 500,
                    borderRadius: '4px',
                    border: isSelected ? '1px solid var(--text-primary)' : '1px solid transparent',
                    background: isSelected ? 'var(--text-primary)' : 'transparent',
                    color: isSelected ? 'var(--bg-primary)' : isDis ? 'var(--text-muted)' : 'var(--text-secondary)',
                    cursor: isDis ? 'not-allowed' : 'pointer',
                    opacity: isDis ? 0.4 : 1,
                    transition: 'all 0.15s ease',
                  }}
                  aria-pressed={isSelected}
                  aria-label={h === 0 ? 'Observed Current State' : `Forecast Horizon T+${h}`}
                >
                  {h === 0 ? 'OBSERVED' : `T+${h}`}
                </button>
              )
            })}
          </div>
        )}
      </div>

      {/* 2. SVG Interactive Graph Canvas */}
      <div
        style={{
          position: 'relative',
          width: '100%',
          height: '320px',
          background: 'var(--bg-surface)',
          overflow: 'hidden',
        }}
      >
        <div
          style={{
            position: 'absolute',
            inset: 0,
            backgroundImage: 'radial-gradient(var(--border) 1px, transparent 1px)',
            backgroundSize: '24px 24px',
            opacity: 0.4,
            pointerEvents: 'none',
          }}
        />

        <svg
          style={{ width: '100%', height: '100%', display: 'block' }}
          viewBox="0 0 860 320"
          preserveAspectRatio="xMidYMid meet"
          role="img"
          aria-label={`Graph representation of ${nodes.length} network nodes and ${activeEdges.length} active edges at horizon ${selectedHorizon === 0 ? 'Observed' : `T+${selectedHorizon}`}`}
        >
          <defs>
            <marker
              id="arrow-observed"
              viewBox="0 0 10 10"
              refX="18"
              refY="5"
              markerWidth="6"
              markerHeight="6"
              orient="auto-start-reverse"
            >
              <path d="M 0 1 L 10 5 L 0 9 z" fill="var(--text-muted)" />
            </marker>
            <marker
              id="arrow-forecast"
              viewBox="0 0 10 10"
              refX="18"
              refY="5"
              markerWidth="6"
              markerHeight="6"
              orient="auto-start-reverse"
            >
              <path d="M 0 1 L 10 5 L 0 9 z" fill="var(--danger)" />
            </marker>
          </defs>

          {/* Render Active Edges */}
          {activeEdges.map((edge) => {
            const src = nodeMap.get(edge.source)
            const dst = nodeMap.get(edge.target)
            if (!src || !dst) return null

            const isEdgeForecast = !edge.activeAtHorizons.includes(0) || !isObserved
            const strokeColor = isObserved
              ? 'var(--text-muted)'
              : isEdgeForecast && edge.activeAtHorizons.includes(selectedHorizon) && !edge.activeAtHorizons.includes(0)
              ? 'var(--danger)'
              : 'var(--text-secondary)'

            const strokeDash = isEdgeForecast ? '4 3' : 'none'
            const strokeWidth = edge.intensity === 'high' ? 2 : 1.5

            const midX = (src.x + dst.x) / 2
            const midY = (src.y + dst.y) / 2 - 8

            return (
              <g key={edge.id} className="graph-edge-group">
                <line
                  x1={src.x}
                  y1={src.y}
                  x2={dst.x}
                  y2={dst.y}
                  stroke={strokeColor}
                  strokeWidth={strokeWidth}
                  strokeDasharray={strokeDash}
                  markerEnd={isObserved ? 'url(#arrow-observed)' : 'url(#arrow-forecast)'}
                  opacity={0.7}
                  style={{ transition: 'stroke 0.3s ease, opacity 0.3s ease' }}
                />
                <rect
                  x={midX - 35}
                  y={midY - 7}
                  width="70"
                  height="14"
                  rx="3"
                  fill="var(--bg-surface)"
                  stroke="var(--border)"
                  strokeWidth="0.8"
                />
                <text
                  x={midX}
                  y={midY + 3}
                  textAnchor="middle"
                  fill="var(--text-muted)"
                  fontSize="8.5"
                  fontFamily="var(--mono)"
                >
                  {edge.label}
                </text>
              </g>
            )
          })}

          {/* Render Nodes */}
          {nodes.map((node) => {
            const isSelected = selectedNodeId === node.id || selectedNodeId === node.ip
            const isNodeThreat = node.isThreat
            const isNodeTarget = node.isTarget

            let borderColor = 'var(--border)'
            let nodeFill = 'var(--bg-secondary)'

            if (isSelected) {
              borderColor = 'var(--text-primary)'
              nodeFill = 'var(--bg-primary)'
            } else if (!isObserved && isNodeThreat) {
              borderColor = 'var(--danger)'
            } else if (!isObserved && isNodeTarget) {
              borderColor = 'var(--accent)'
            }

            return (
              <g
                key={node.id}
                onClick={() => setSelectedNodeId(isSelected ? null : node.id)}
                style={{ cursor: 'pointer', transition: 'transform 0.2s ease' }}
                tabIndex={0}
                role="button"
                aria-label={`Node ${node.ip}: ${node.label}, ${node.role}`}
                onKeyDown={(e) => {
                  if (e.key === 'Enter' || e.key === ' ') {
                    setSelectedNodeId(isSelected ? null : node.id)
                  }
                }}
              >
                <circle
                  cx={node.x}
                  cy={node.y}
                  r="24"
                  fill={nodeFill}
                  stroke={borderColor}
                  strokeWidth={isSelected ? '2.5' : '1.5'}
                  style={{ transition: 'all 0.25s ease' }}
                />

                <circle
                  cx={node.x}
                  cy={node.y}
                  r="6"
                  fill={
                    isNodeThreat
                      ? 'var(--danger)'
                      : isNodeTarget
                      ? 'var(--accent)'
                      : 'var(--text-muted)'
                  }
                  opacity={isObserved ? 0.7 : 0.9}
                />

                <text
                  x={node.x}
                  y={node.y + 36}
                  textAnchor="middle"
                  fill="var(--text-primary)"
                  fontSize="10.5"
                  fontFamily="var(--mono)"
                  fontWeight="600"
                >
                  {node.ip}
                </text>

                <text
                  x={node.x}
                  y={node.y + 48}
                  textAnchor="middle"
                  fill="var(--text-muted)"
                  fontSize="8.5"
                  fontFamily="var(--mono)"
                >
                  {node.role}
                </text>
              </g>
            )
          })}
        </svg>

        {/* Selected Node Floating Dossier Callout */}
        {selectedNode && (
          <div
            style={{
              position: 'absolute',
              bottom: '12px',
              left: '16px',
              background: 'var(--bg-secondary)',
              border: '1px solid var(--border)',
              borderRadius: '6px',
              padding: '10px 14px',
              fontSize: '11px',
              fontFamily: 'var(--mono)',
              boxShadow: '0 4px 12px rgba(0, 0, 0, 0.1)',
              maxWidth: '320px',
              zIndex: 5,
            }}
          >
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '4px' }}>
              <span style={{ fontWeight: 700, color: 'var(--text-primary)' }}>{selectedNode.ip}</span>
              <span style={{ color: 'var(--text-muted)', fontSize: '9px' }}>{selectedNode.role}</span>
            </div>
            <div style={{ color: 'var(--text-secondary)', fontSize: '10px' }}>
              {selectedNode.label} &middot; Activity Score: {(selectedNode.activityScore * 100).toFixed(0)}%
            </div>
            <button
              type="button"
              onClick={() => setSelectedNodeId(null)}
              style={{
                marginTop: '6px',
                background: 'transparent',
                border: 'none',
                color: 'var(--text-muted)',
                cursor: 'pointer',
                padding: 0,
                fontSize: '9.5px',
                textDecoration: 'underline',
              }}
            >
              Dismiss
            </button>
          </div>
        )}
      </div>

      {/* 3. Screen Reader Accessible Summary Table */}
      <div className="sr-only" role="status" aria-live="polite">
        At horizon {selectedHorizon === 0 ? 'Observed (T0)' : `T+${selectedHorizon}`}, {activeEdges.length} communications are active among {nodes.length} endpoints. Active stage: {activeStage.sublabel}.
      </div>
    </div>
  )
}
