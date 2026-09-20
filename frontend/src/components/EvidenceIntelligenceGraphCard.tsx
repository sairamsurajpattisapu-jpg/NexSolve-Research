import { useState } from 'react'
import { GitFork, Network, ShieldCheck, ChevronDown, ChevronUp, Link as LinkIcon } from 'lucide-react'
import type { EvidenceGraphPayload } from '../types/api'
import { Panel } from './Ui'

interface EvidenceIntelligenceGraphCardProps {
  graph?: EvidenceGraphPayload | null
}

export function EvidenceIntelligenceGraphCard({ graph }: EvidenceIntelligenceGraphCardProps) {
  const [expanded, setExpanded] = useState(false)
  const [subView, setSubView] = useState<'CHAINS' | 'ENTITIES'>('CHAINS')
  const [selectedEntity, setSelectedEntity] = useState<string | null>(null)

  if (!graph || !graph.statistics) {
    return null
  }

  const { statistics, chains } = graph
  const totalNodes = statistics.total_nodes || 0
  const totalEdges = statistics.total_edges || 0
  const totalChains = statistics.total_chains || 0
  const observedNodes = statistics.observed_node_count || 0
  const forecastNodes = statistics.forecast_node_count || 0

  return (
    <Panel style={{ padding: '16px 20px', border: '1px solid var(--border)' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '12px' }}>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <span className="eyebrow" style={{ color: 'var(--accent)', margin: 0 }}>
              Evidence Intelligence Graph
            </span>
            <span
              style={{
                fontSize: '10px',
                fontFamily: 'var(--mono)',
                background: 'rgba(255, 255, 255, 0.06)',
                border: '1px solid var(--border)',
                padding: '1px 6px',
                borderRadius: '3px',
                color: 'var(--text-muted)',
              }}
            >
              DETERMINISTIC ONTOLOGY
            </span>
          </div>
          <h3 style={{ margin: '4px 0 0 0', fontSize: '15px', fontWeight: 600, color: 'var(--text-primary)' }}>
            Cross-Modal Entity & Evidence Correlation Graph
          </h3>
        </div>

        <button
          onClick={() => setExpanded(!expanded)}
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: '6px',
            background: 'transparent',
            border: '1px solid var(--border)',
            borderRadius: '4px',
            color: 'var(--text-muted)',
            fontSize: '11px',
            padding: '4px 10px',
            cursor: 'pointer',
          }}
        >
          <span>{expanded ? 'Collapse Graph' : 'Inspect Chains & Entities'}</span>
          {expanded ? <ChevronUp size={14} /> : <ChevronDown size={14} />}
        </button>
      </div>

      {/* Primary Graph Metrics Strip */}
      <div
        style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(140px, 1fr))',
          gap: '10px',
          marginTop: '14px',
        }}
      >
        <div style={{ background: 'var(--bg-secondary)', padding: '10px 12px', borderRadius: '4px', border: '1px solid var(--border)' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '11px', color: 'var(--text-muted)' }}>
            <Network size={13} color="var(--accent)" />
            <span>Entities & Nodes</span>
          </div>
          <div style={{ fontSize: '18px', fontWeight: 700, fontFamily: 'var(--mono)', marginTop: '2px' }}>
            {totalNodes}
          </div>
          <div style={{ fontSize: '10px', color: 'var(--text-muted)', marginTop: '1px' }}>
            {observedNodes} obs &middot; {forecastNodes} fc
          </div>
        </div>

        <div style={{ background: 'var(--bg-secondary)', padding: '10px 12px', borderRadius: '4px', border: '1px solid var(--border)' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '11px', color: 'var(--text-muted)' }}>
            <LinkIcon size={13} color="var(--teal)" />
            <span>Semantic Edges</span>
          </div>
          <div style={{ fontSize: '18px', fontWeight: 700, fontFamily: 'var(--mono)', marginTop: '2px' }}>
            {totalEdges}
          </div>
          <div style={{ fontSize: '10px', color: 'var(--text-muted)', marginTop: '1px' }}>
            Explicit relationships
          </div>
        </div>

        <div style={{ background: 'var(--bg-secondary)', padding: '10px 12px', borderRadius: '4px', border: '1px solid var(--border)' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '11px', color: 'var(--warning)' }}>
            <GitFork size={13} color="var(--warning)" />
            <span>Evidence Chains</span>
          </div>
          <div style={{ fontSize: '18px', fontWeight: 700, fontFamily: 'var(--mono)', marginTop: '2px' }}>
            {totalChains}
          </div>
          <div style={{ fontSize: '10px', color: 'var(--text-muted)', marginTop: '1px' }}>
            Deterministic paths
          </div>
        </div>

        <div style={{ background: 'var(--bg-secondary)', padding: '10px 12px', borderRadius: '4px', border: '1px solid var(--border)' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '11px', color: 'var(--text-muted)' }}>
            <ShieldCheck size={13} color="var(--success)" />
            <span>Inference Mode</span>
          </div>
          <div style={{ fontSize: '13px', fontWeight: 700, fontFamily: 'var(--mono)', marginTop: '4px', color: 'var(--success)' }}>
            Zero Score Averaging
          </div>
          <div style={{ fontSize: '10px', color: 'var(--text-muted)', marginTop: '1px' }}>
            Ground-truth isolated
          </div>
        </div>
      </div>

      {/* Expanded Chains & Diagnostics */}
      {expanded && (
        <div style={{ marginTop: '16px', borderTop: '1px solid var(--border)', paddingTop: '14px' }}>
          {/* Sub-view switcher: Evidence Chains vs Entity Dossiers */}
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '12px', flexWrap: 'wrap', gap: '8px' }}>
            <div style={{ display: 'flex', gap: '8px' }}>
              <button
                onClick={() => setSubView('CHAINS')}
                style={{
                  background: subView === 'CHAINS' ? 'var(--accent)' : 'transparent',
                  color: subView === 'CHAINS' ? '#fff' : 'var(--text-muted)',
                  border: '1px solid var(--border)',
                  borderRadius: '4px',
                  padding: '4px 10px',
                  fontSize: '11px',
                  cursor: 'pointer',
                  fontWeight: 600,
                }}
              >
                Evidence Chains ({chains.length})
              </button>
              {graph.dossiers && Object.keys(graph.dossiers).length > 0 && (
                <button
                  onClick={() => setSubView('ENTITIES')}
                  style={{
                    background: subView === 'ENTITIES' ? 'var(--accent)' : 'transparent',
                    color: subView === 'ENTITIES' ? '#fff' : 'var(--text-muted)',
                    border: '1px solid var(--border)',
                    borderRadius: '4px',
                    padding: '4px 10px',
                    fontSize: '11px',
                    cursor: 'pointer',
                    fontWeight: 600,
                  }}
                >
                  Entity Attack Dossiers ({Object.keys(graph.dossiers).length})
                </button>
              )}
            </div>

            {subView === 'ENTITIES' && graph.dossiers && (
              <div style={{ display: 'flex', gap: '4px', flexWrap: 'wrap' }}>
                {Object.keys(graph.dossiers).map((ip) => (
                  <button
                    key={ip}
                    onClick={() => setSelectedEntity(ip)}
                    style={{
                      background: (selectedEntity || Object.keys(graph.dossiers || {})[0]) === ip ? 'rgba(59, 130, 246, 0.2)' : 'var(--bg-secondary)',
                      color: (selectedEntity || Object.keys(graph.dossiers || {})[0]) === ip ? 'var(--accent)' : 'var(--text-muted)',
                      border: `1px solid ${(selectedEntity || Object.keys(graph.dossiers || {})[0]) === ip ? 'var(--accent)' : 'var(--border)'}`,
                      borderRadius: '4px',
                      padding: '2px 8px',
                      fontFamily: 'var(--mono)',
                      fontSize: '10px',
                      cursor: 'pointer',
                    }}
                  >
                    {ip}
                  </button>
                ))}
              </div>
            )}
          </div>

          {subView === 'ENTITIES' && graph.dossiers ? (
            (() => {
              const activeKey = selectedEntity || Object.keys(graph.dossiers)[0]
              const dossier = graph.dossiers[activeKey]
              if (!dossier) return null
              return (
                <div style={{ background: 'var(--bg-secondary)', border: '1px solid var(--border)', borderRadius: '6px', padding: '14px' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '10px' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                      <span style={{ fontSize: '13px', fontWeight: 700, fontFamily: 'var(--mono)', color: 'var(--text-primary)' }}>
                        IP: {dossier.entity_key}
                      </span>
                      <span style={{ fontSize: '10px', background: 'rgba(59, 130, 246, 0.15)', color: 'var(--accent)', padding: '2px 6px', borderRadius: '3px', fontFamily: 'var(--mono)' }}>
                        {dossier.total_associated_nodes} Connected Nodes
                      </span>
                    </div>
                  </div>

                  <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '10px', marginBottom: '12px' }}>
                    <div style={{ padding: '8px 10px', background: 'var(--surface-subtle)', borderRadius: '4px', border: '1px solid var(--border-subtle)' }}>
                      <div style={{ fontSize: '10px', color: 'var(--text-muted)', textTransform: 'uppercase' }}>Targeted Ports</div>
                      <div style={{ fontSize: '12px', fontFamily: 'var(--mono)', color: 'var(--text-primary)', marginTop: '2px' }}>
                        {dossier.targeted_ports.length > 0 ? dossier.targeted_ports.join(', ') : 'None'}
                      </div>
                    </div>
                    <div style={{ padding: '8px 10px', background: 'var(--surface-subtle)', borderRadius: '4px', border: '1px solid var(--border-subtle)' }}>
                      <div style={{ fontSize: '10px', color: 'var(--text-muted)', textTransform: 'uppercase' }}>Outbound Peers ({dossier.outbound_peers.length})</div>
                      <div style={{ fontSize: '11px', fontFamily: 'var(--mono)', color: 'var(--text-primary)', marginTop: '2px' }}>
                        {dossier.outbound_peers.slice(0, 5).join(', ') || 'None'}
                      </div>
                    </div>
                    <div style={{ padding: '8px 10px', background: 'var(--surface-subtle)', borderRadius: '4px', border: '1px solid var(--border-subtle)' }}>
                      <div style={{ fontSize: '10px', color: 'var(--text-muted)', textTransform: 'uppercase' }}>Inbound Peers ({dossier.inbound_peers.length})</div>
                      <div style={{ fontSize: '11px', fontFamily: 'var(--mono)', color: 'var(--text-primary)', marginTop: '2px' }}>
                        {dossier.inbound_peers.slice(0, 5).join(', ') || 'None'}
                      </div>
                    </div>
                  </div>

                  {/* Connected Attack States */}
                  {dossier.attack_states.length > 0 && (
                    <div style={{ marginBottom: '8px' }}>
                      <div style={{ fontSize: '10px', color: 'var(--text-muted)', textTransform: 'uppercase', marginBottom: '4px' }}>Observed Kinematic States</div>
                      <div style={{ display: 'flex', gap: '6px', flexWrap: 'wrap' }}>
                        {dossier.attack_states.map((st, idx) => (
                          <span key={idx} style={{ fontSize: '10px', background: 'rgba(234, 179, 8, 0.15)', color: 'var(--warning)', padding: '2px 6px', borderRadius: '4px', fontFamily: 'var(--mono)' }}>
                            {st.label}
                          </span>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* Findings */}
                  {dossier.findings.length > 0 && (
                    <div>
                      <div style={{ fontSize: '10px', color: 'var(--text-muted)', textTransform: 'uppercase', marginBottom: '4px' }}>Associated Findings ({dossier.findings.length})</div>
                      <div style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
                        {dossier.findings.map((f, idx) => (
                          <div key={idx} style={{ fontSize: '11px', color: 'var(--text-secondary)', padding: '4px 8px', background: 'var(--surface-subtle)', borderRadius: '4px' }}>
                            {f.label}
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              )
            })()
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
              {chains.length === 0 ? (
                <div style={{ fontSize: '11px', color: 'var(--text-muted)', fontStyle: 'italic' }}>
                  No active evidence chains generated for current window.
                </div>
              ) : (
                chains.map((chain) => {
                  const isObserved = chain.scope === 'OBSERVED'
                  return (
                    <div
                      key={chain.chain_id}
                      style={{
                        background: 'var(--bg-secondary)',
                        border: '1px solid var(--border)',
                        borderRadius: '4px',
                        padding: '10px 12px',
                      }}
                    >
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '8px' }}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                          <span
                            style={{
                              fontSize: '9px',
                              fontFamily: 'var(--mono)',
                              fontWeight: 700,
                              padding: '1px 6px',
                              borderRadius: '3px',
                              background: isObserved ? 'rgba(34, 197, 94, 0.15)' : 'rgba(168, 85, 247, 0.15)',
                              color: isObserved ? 'var(--success)' : '#c084fc',
                              border: `1px solid ${isObserved ? 'var(--success)' : '#c084fc'}`,
                            }}
                          >
                            {chain.scope}
                          </span>
                          <strong style={{ fontSize: '12px', color: 'var(--text-primary)' }}>
                            {chain.title}
                          </strong>
                        </div>
                        {chain.mitre_technique_id && (
                          <span
                            style={{
                              fontSize: '10px',
                              fontFamily: 'var(--mono)',
                              background: 'rgba(239, 68, 68, 0.15)',
                              color: 'var(--danger)',
                              border: '1px solid var(--danger)',
                              padding: '1px 6px',
                              borderRadius: '3px',
                            }}
                          >
                            MITRE {chain.mitre_technique_id}
                          </span>
                        )}
                      </div>
                      <p style={{ margin: '6px 0 0 0', fontSize: '11px', color: 'var(--text-muted)', lineHeight: '1.4' }}>
                        {chain.explanation}
                      </p>
                      <div style={{ marginTop: '6px', fontSize: '10px', fontFamily: 'var(--mono)', color: 'var(--muted)' }}>
                        Nodes ({chain.node_ids.length}): {chain.node_ids.join(' -> ')}
                      </div>
                    </div>
                  )
                })
              )}
            </div>
          )}
        </div>
      )}
    </Panel>
  )
}

