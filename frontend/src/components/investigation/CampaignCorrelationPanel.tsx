import { useState } from 'react'
import type {
  CampaignClusterPayload,
  IncidentCorrelationPayload,
  IncidentFingerprintPayload,
} from '../../types/api'
import { Panel } from '../Ui'
import {
  Layers,
  Network,
  Share2,
  Activity,
  Split,
} from 'lucide-react'

interface CampaignCorrelationPanelProps {
  fingerprint?: IncidentFingerprintPayload | null
  correlations?: IncidentCorrelationPayload[] | null
  clusters?: CampaignClusterPayload[] | null
}

export function CampaignCorrelationPanel({
  fingerprint,
  correlations,
  clusters,
}: CampaignCorrelationPanelProps) {
  const clusterList = clusters || []
  const correlationList = correlations || []
  const [activeTab, setActiveTab] = useState<'OVERVIEW' | 'CLUSTERS' | 'CORRELATIONS' | 'FINGERPRINT'>('OVERVIEW')

  if (!fingerprint && clusterList.length === 0 && correlationList.length === 0) {
    return null
  }

  const getRelationshipBadge = (rel: string) => {
    switch (rel) {
      case 'RELATED_CAMPAIGN':
        return (
          <span style={{ fontSize: '11px', background: 'rgba(239, 68, 68, 0.15)', color: 'var(--critical)', padding: '2px 8px', borderRadius: '4px', fontWeight: 700, fontFamily: 'var(--mono)' }}>
            RELATED CAMPAIGN
          </span>
        )
      case 'POSSIBLY_RELATED':
        return (
          <span style={{ fontSize: '11px', background: 'rgba(234, 179, 8, 0.15)', color: 'var(--warning)', padding: '2px 8px', borderRadius: '4px', fontWeight: 700, fontFamily: 'var(--mono)' }}>
            POSSIBLY RELATED
          </span>
        )
      case 'INSUFFICIENT_EVIDENCE':
        return (
          <span style={{ fontSize: '11px', background: 'var(--surface-ground)', color: 'var(--text-muted)', padding: '2px 8px', borderRadius: '4px', fontWeight: 600, fontFamily: 'var(--mono)' }}>
            INSUFFICIENT EVIDENCE
          </span>
        )
      default:
        return (
          <span style={{ fontSize: '11px', background: 'var(--surface-ground)', color: 'var(--text-secondary)', padding: '2px 8px', borderRadius: '4px', fontWeight: 600, fontFamily: 'var(--mono)' }}>
            UNRELATED
          </span>
        )
    }
  }

  const getEvolutionBadge = (evo: string) => {
    return (
      <span style={{ fontSize: '10px', background: 'rgba(59, 130, 246, 0.15)', color: 'var(--accent)', padding: '2px 6px', borderRadius: '4px', fontFamily: 'var(--mono)', fontWeight: 600 }}>
        {evo.replace(/_/g, ' ')}
      </span>
    )
  }

  return (
    <Panel className="campaign-correlation-panel" style={{ padding: '20px 24px', marginBottom: '24px' }}>
      {/* Header */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: '12px', marginBottom: '16px' }}>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '6px' }}>
            <span className="eyebrow" style={{ color: 'var(--accent)', margin: 0 }}>CROSS-INCIDENT CORRELATION</span>
            <span style={{ fontSize: '10px', background: 'rgba(59, 130, 246, 0.15)', color: 'var(--accent)', padding: '2px 8px', borderRadius: '4px', fontFamily: 'var(--mono)', fontWeight: 600 }}>
              CAMPAIGN INTELLIGENCE
            </span>
            {clusterList.length > 0 && (
              <span style={{ fontSize: '11px', background: 'rgba(239, 68, 68, 0.2)', color: 'var(--critical)', padding: '2px 8px', borderRadius: '4px', fontWeight: 700 }}>
                {clusterList.length} CAMPAIGN CLUSTER(S)
              </span>
            )}
          </div>
          <h3 style={{ margin: '0 0 6px 0', fontSize: '20px', fontWeight: 700, color: 'var(--text-primary)' }}>
            Cross-Capture Threat Correlation & Attribution Analysis
          </h3>
          <div style={{ fontSize: '12px', color: 'var(--text-secondary)' }}>
            Evaluates multi-incident behavioral and structural recurrences across independent network capture sessions.
          </div>
        </div>

        {/* Safety Attribution Callout */}
        <div style={{ background: 'var(--surface-ground)', border: '1px solid var(--border-subtle)', borderRadius: '6px', padding: '10px 14px', maxWidth: '340px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '6px', marginBottom: '2px' }}>
            <Share2 size={14} style={{ color: 'var(--accent)' }} />
            <span style={{ fontSize: '10px', fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.05em', color: 'var(--accent)' }}>
              Attribution Governance
            </span>
          </div>
          <div style={{ fontSize: '11px', color: 'var(--text-secondary)', lineHeight: 1.3 }}>
            Correlations reflect <strong>behavioral & infrastructure similarity</strong>. NexSolve strictly avoids asserting single-actor attribution without verifiable identity evidence.
          </div>
        </div>
      </div>

      {/* Tabs Strip */}
      <div style={{ display: 'flex', gap: '6px', borderBottom: '1px solid var(--border-subtle)', paddingBottom: '8px', marginBottom: '16px', overflowX: 'auto' }}>
        <button
          onClick={() => setActiveTab('OVERVIEW')}
          style={{
            background: activeTab === 'OVERVIEW' ? 'var(--accent)' : 'transparent',
            color: activeTab === 'OVERVIEW' ? '#fff' : 'var(--text-secondary)',
            border: 'none',
            borderRadius: '4px',
            padding: '6px 12px',
            fontSize: '12px',
            fontWeight: 600,
            cursor: 'pointer',
            display: 'flex',
            alignItems: 'center',
            gap: '6px',
          }}
        >
          <Layers size={14} /> Campaign Summary
        </button>
        <button
          onClick={() => setActiveTab('CLUSTERS')}
          style={{
            background: activeTab === 'CLUSTERS' ? 'var(--accent)' : 'transparent',
            color: activeTab === 'CLUSTERS' ? '#fff' : 'var(--text-secondary)',
            border: 'none',
            borderRadius: '4px',
            padding: '6px 12px',
            fontSize: '12px',
            fontWeight: 600,
            cursor: 'pointer',
            display: 'flex',
            alignItems: 'center',
            gap: '6px',
          }}
        >
          <Network size={14} /> Campaign Clusters ({clusterList.length})
        </button>
        <button
          onClick={() => setActiveTab('CORRELATIONS')}
          style={{
            background: activeTab === 'CORRELATIONS' ? 'var(--accent)' : 'transparent',
            color: activeTab === 'CORRELATIONS' ? '#fff' : 'var(--text-secondary)',
            border: 'none',
            borderRadius: '4px',
            padding: '6px 12px',
            fontSize: '12px',
            fontWeight: 600,
            cursor: 'pointer',
            display: 'flex',
            alignItems: 'center',
            gap: '6px',
          }}
        >
          <Split size={14} /> Pairwise Correlations ({correlationList.length})
        </button>
        <button
          onClick={() => setActiveTab('FINGERPRINT')}
          style={{
            background: activeTab === 'FINGERPRINT' ? 'var(--accent)' : 'transparent',
            color: activeTab === 'FINGERPRINT' ? '#fff' : 'var(--text-secondary)',
            border: 'none',
            borderRadius: '4px',
            padding: '6px 12px',
            fontSize: '12px',
            fontWeight: 600,
            cursor: 'pointer',
            display: 'flex',
            alignItems: 'center',
            gap: '6px',
          }}
        >
          <Activity size={14} /> Incident Fingerprint
        </button>
      </div>

      {/* Tab: Overview */}
      {activeTab === 'OVERVIEW' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
          {clusterList.length > 0 ? (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
              {clusterList.map((cl) => (
                <div key={cl.cluster_id} style={{ padding: '16px', background: 'var(--surface-subtle)', border: '1px solid var(--border-subtle)', borderRadius: '6px' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                      <span style={{ fontSize: '14px', fontWeight: 700, color: 'var(--text-primary)' }}>
                        {cl.label}
                      </span>
                      {getEvolutionBadge(cl.evolution)}
                    </div>
                    <span style={{ fontSize: '11px', fontFamily: 'var(--mono)', color: 'var(--accent)' }}>
                      {cl.member_incidents.length} member incident(s)
                    </span>
                  </div>
                  <div style={{ fontSize: '13px', color: 'var(--text-secondary)', marginBottom: '10px', lineHeight: 1.45 }}>
                    {cl.campaign_assessment}
                  </div>
                  <div style={{ background: 'rgba(59, 130, 246, 0.05)', borderLeft: '3px solid var(--accent)', padding: '8px 12px', borderRadius: '0 4px 4px 0' }}>
                    <div style={{ fontSize: '11px', color: 'var(--text-muted)', marginBottom: '2px' }}>Recommended Analyst Action:</div>
                    <div style={{ fontSize: '12px', color: 'var(--text-primary)', fontWeight: 600 }}>{cl.analyst_action}</div>
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <div style={{ padding: '20px', background: 'var(--surface-subtle)', borderRadius: '6px', textAlign: 'center' }}>
              <div style={{ fontSize: '13px', fontWeight: 600, color: 'var(--text-primary)', marginBottom: '4px' }}>
                Single Incident Session Analyzed
              </div>
              <div style={{ fontSize: '12px', color: 'var(--text-secondary)', maxWidth: '540px', margin: '0 auto' }}>
                This capture sequence represents an isolated incident session. When additional network captures or historical incidents are ingested, NexSolve will automatically evaluate multi-dimensional cross-capture campaign clusters.
              </div>
            </div>
          )}
        </div>
      )}

      {/* Tab: Clusters */}
      {activeTab === 'CLUSTERS' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
          {clusterList.length > 0 ? (
            clusterList.map((cl) => (
              <div key={cl.cluster_id} style={{ padding: '16px', background: 'var(--surface-subtle)', border: '1px solid var(--border-subtle)', borderRadius: '6px' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
                  <span style={{ fontSize: '14px', fontWeight: 700, color: 'var(--text-primary)' }}>{cl.label}</span>
                  <span style={{ fontSize: '11px', fontFamily: 'var(--mono)', color: 'var(--text-muted)' }}>ID: {cl.cluster_id}</span>
                </div>
                {cl.shared_characteristics.length > 0 && (
                  <div style={{ marginBottom: '8px' }}>
                    <span style={{ fontSize: '11px', fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.05em', color: 'var(--text-muted)' }}>Shared Attributes:</span>
                    <ul style={{ margin: '4px 0 0 0', paddingLeft: '18px', fontSize: '12px', color: 'var(--text-secondary)' }}>
                      {cl.shared_characteristics.map((c, idx) => (
                        <li key={idx}>{c}</li>
                      ))}
                    </ul>
                  </div>
                )}
                {cl.timeline.length > 0 && (
                  <div style={{ marginTop: '10px' }}>
                    <span style={{ fontSize: '11px', fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.05em', color: 'var(--text-muted)' }}>Campaign Timeline:</span>
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '6px', marginTop: '6px' }}>
                      {cl.timeline.map((te, idx) => (
                        <div key={idx} style={{ display: 'flex', alignItems: 'center', gap: '10px', fontSize: '12px', background: 'var(--surface-ground)', padding: '6px 10px', borderRadius: '4px' }}>
                          <span style={{ fontFamily: 'var(--mono)', color: 'var(--accent)', minWidth: '90px' }}>W{te.window_range[0]} – W{te.window_range[1]}</span>
                          <span style={{ color: 'var(--text-primary)', flex: 1 }}>{te.summary}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            ))
          ) : (
            <div style={{ padding: '16px', background: 'var(--surface-subtle)', borderRadius: '6px', color: 'var(--text-secondary)', fontSize: '13px' }}>
              No multi-incident campaign clusters currently formed.
            </div>
          )}
        </div>
      )}

      {/* Tab: Correlations */}
      {activeTab === 'CORRELATIONS' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
          {correlationList.length > 0 ? (
            correlationList.map((corr) => (
              <div key={corr.correlation_id} style={{ padding: '14px', background: 'var(--surface-subtle)', border: '1px solid var(--border-subtle)', borderRadius: '6px' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '6px' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                    <span style={{ fontSize: '13px', fontWeight: 700, fontFamily: 'var(--mono)', color: 'var(--text-primary)' }}>
                      {corr.incident_a} ↔ {corr.incident_b}
                    </span>
                    {getRelationshipBadge(corr.relationship)}
                  </div>
                  {getEvolutionBadge(corr.evolution)}
                </div>
                <div style={{ fontSize: '12px', color: 'var(--text-secondary)', marginBottom: '8px', lineHeight: 1.4 }}>
                  {corr.explanation}
                </div>
                {corr.supporting_signals.length > 0 && (
                  <div style={{ display: 'flex', flexWrap: 'wrap', gap: '6px' }}>
                    {corr.supporting_signals.map((sig, idx) => (
                      <span key={idx} style={{ fontSize: '10px', background: 'rgba(34, 197, 94, 0.1)', color: 'var(--success)', padding: '2px 6px', borderRadius: '3px' }}>
                        {sig}
                      </span>
                    ))}
                  </div>
                )}
              </div>
            ))
          ) : (
            <div style={{ padding: '16px', background: 'var(--surface-subtle)', borderRadius: '6px', color: 'var(--text-secondary)', fontSize: '13px' }}>
              No pairwise cross-capture correlations available for this single capture session.
            </div>
          )}
        </div>
      )}

      {/* Tab: Fingerprint */}
      {activeTab === 'FINGERPRINT' && fingerprint && (
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: '14px' }}>
          <div style={{ padding: '12px 14px', background: 'var(--surface-subtle)', border: '1px solid var(--border-subtle)', borderRadius: '6px' }}>
            <div style={{ fontSize: '11px', fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.05em', color: 'var(--text-muted)', marginBottom: '6px' }}>
              Actor & Target Topology
            </div>
            <div style={{ fontSize: '12px', color: 'var(--text-secondary)', display: 'flex', flexDirection: 'column', gap: '4px' }}>
              <div>Actors ({fingerprint.actor_entities.length}): <strong style={{ color: 'var(--text-primary)', fontFamily: 'var(--mono)' }}>{fingerprint.actor_entities.join(', ') || 'None'}</strong></div>
              <div>Targets ({fingerprint.target_entities.length}): <strong style={{ color: 'var(--text-primary)', fontFamily: 'var(--mono)' }}>{fingerprint.target_entities.slice(0, 5).join(', ')}{fingerprint.target_entities.length > 5 ? '...' : ''}</strong></div>
              <div>Fan-out Ratio: <strong style={{ color: 'var(--text-primary)' }}>{fingerprint.fan_out_ratio.toFixed(2)}</strong></div>
            </div>
          </div>

          <div style={{ padding: '12px 14px', background: 'var(--surface-subtle)', border: '1px solid var(--border-subtle)', borderRadius: '6px' }}>
            <div style={{ fontSize: '11px', fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.05em', color: 'var(--text-muted)', marginBottom: '6px' }}>
              Port & Service Signature
            </div>
            <div style={{ fontSize: '12px', color: 'var(--text-secondary)', display: 'flex', flexDirection: 'column', gap: '4px' }}>
              <div>Targeted Ports: <strong style={{ color: 'var(--text-primary)', fontFamily: 'var(--mono)' }}>{fingerprint.targeted_ports.slice(0, 8).join(', ')}{fingerprint.targeted_ports.length > 8 ? '...' : ''}</strong></div>
              <div>Handshake Failure Ratio: <strong style={{ color: 'var(--text-primary)' }}>{(fingerprint.failure_ratio * 100).toFixed(1)}%</strong></div>
              <div>Dominant Category: <strong style={{ color: 'var(--accent)' }}>{fingerprint.dominant_category}</strong></div>
            </div>
          </div>
        </div>
      )}
    </Panel>
  )
}
