import { useState } from 'react'
import type {
  InvestigationContextPayload,
  ThreatRiskBreakdownPayload,
  PrioritizedThreatPayload,
  IncidentInvestigationPayload,
  MitigationRecommendationPayload,
} from '../../types/api'
import { Panel } from '../Ui'
import {
  ShieldAlert,
  Clock,
  Network,
  Scale,
  Activity,
  AlertTriangle,
  ChevronRight,
  ShieldCheck,
  FolderGit2,
} from 'lucide-react'

interface InvestigationWorkspaceProps {
  investigations?: Record<string, InvestigationContextPayload> | null
  prioritizedThreats?: PrioritizedThreatPayload[] | null
  riskBreakdowns?: Record<string, ThreatRiskBreakdownPayload> | null
  incidentInvestigations?: IncidentInvestigationPayload[] | null
  mitigationRecommendations?: MitigationRecommendationPayload[] | null
}

export function InvestigationWorkspace({
  investigations,
  prioritizedThreats,
  riskBreakdowns,
  incidentInvestigations,
  mitigationRecommendations,
}: InvestigationWorkspaceProps) {
  const invMap = investigations || {}
  const threatList = prioritizedThreats || []
  const availableEntities = Object.keys(invMap)

  const defaultEntity = threatList.length > 0 && invMap[threatList[0].entity]
    ? threatList[0].entity
    : availableEntities[0] || null

  const [selectedEntity, setSelectedEntity] = useState<string | null>(defaultEntity)
  const [activeTab, setActiveTab] = useState<'OVERVIEW' | 'INCIDENTS' | 'TIMELINE' | 'RELATIONSHIPS' | 'CONTRADICTIONS' | 'RISK' | 'MITIGATIONS'>('OVERVIEW')

  if (!availableEntities.length) {
    return null
  }

  const currentEntity = selectedEntity && invMap[selectedEntity] ? selectedEntity : availableEntities[0]
  const currentInv = invMap[currentEntity]
  const currentRisk = riskBreakdowns ? riskBreakdowns[currentEntity] : null

  return (
    <Panel className="investigation-workspace" style={{ padding: '20px 24px' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px', flexWrap: 'wrap', gap: '8px' }}>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <span className="eyebrow" style={{ color: 'var(--accent)', margin: 0 }}>SECURITY INVESTIGATION WORKBENCH</span>
            <span style={{ fontSize: '10px', background: 'var(--accent-muted)', color: 'var(--accent)', padding: '2px 8px', borderRadius: '4px', fontFamily: 'var(--mono)' }}>
              END-TO-END DOSSIER
            </span>
          </div>
          <h3 style={{ margin: '4px 0 0 0', fontSize: '18px', fontWeight: 700, color: 'var(--text-primary)' }}>
            Investigating Target: <span style={{ fontFamily: 'var(--mono)', color: 'var(--accent)' }}>{currentEntity}</span>
          </h3>

        </div>

        {/* Entity Selector Pills */}
        <div style={{ display: 'flex', gap: '6px', flexWrap: 'wrap' }}>
          {availableEntities.slice(0, 6).map((ent) => {
            const isSelected = ent === currentEntity
            return (
              <button
                key={ent}
                onClick={() => setSelectedEntity(ent)}
                style={{
                  background: isSelected ? 'var(--accent)' : 'var(--bg-card)',
                  color: isSelected ? '#fff' : 'var(--text-secondary)',
                  border: isSelected ? '1px solid var(--accent)' : '1px solid var(--border)',
                  borderRadius: '4px',
                  padding: '4px 10px',
                  fontFamily: 'var(--mono)',
                  fontSize: '11px',
                  cursor: 'pointer',
                  fontWeight: isSelected ? 700 : 500,
                  transition: 'all 0.15s ease',
                }}
              >
                {ent}
              </button>
            )
          })}
        </div>
      </div>

      {/* Tabs */}
      <div style={{ display: 'flex', gap: '8px', borderBottom: '1px solid var(--border)', paddingBottom: '8px', marginBottom: '16px' }}>
        {[
          { id: 'OVERVIEW', label: 'Dossier Overview', icon: Activity },
          { id: 'INCIDENTS', label: `Incidents (${incidentInvestigations?.length || 0})`, icon: FolderGit2 },
          { id: 'TIMELINE', label: `Timeline (${currentInv?.timeline?.length || 0})`, icon: Clock },
          { id: 'RELATIONSHIPS', label: `Relationships (${currentInv?.relationships?.length || 0})`, icon: Network },
          { id: 'CONTRADICTIONS', label: `Counter-Evidence (${currentInv?.contradictions?.length || 0})`, icon: Scale },
          { id: 'RISK', label: 'Risk Breakdown', icon: ShieldAlert },
          { id: 'MITIGATIONS', label: `Response Actions (${mitigationRecommendations?.length || 0})`, icon: ShieldCheck },
        ].map((tab) => {

          const Icon = tab.icon
          const isActive = activeTab === tab.id
          return (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id as any)}
              style={{
                background: isActive ? 'var(--accent-muted)' : 'transparent',
                color: isActive ? 'var(--accent)' : 'var(--text-muted)',
                border: 'none',
                borderBottom: isActive ? '2px solid var(--accent)' : '2px solid transparent',
                borderRadius: '4px 4px 0 0',
                padding: '6px 12px',
                fontSize: '12px',
                fontWeight: 600,
                cursor: 'pointer',
                display: 'flex',
                alignItems: 'center',
                gap: '6px',
                fontFamily: 'var(--font-sans)',
              }}
            >
              <Icon size={14} />
              {tab.label}
            </button>
          )
        })}
      </div>

      {/* TAB CONTENT: OVERVIEW */}
      {activeTab === 'OVERVIEW' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
          {/* Key Subject Summary Strip */}
          <div
            style={{
              display: 'grid',
              gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))',
              gap: '12px',
            }}
          >
            <div style={{ padding: '12px', background: 'var(--bg-card)', borderRadius: '6px', border: '1px solid var(--border)' }}>
              <span style={{ fontSize: '10px', color: 'var(--text-muted)', textTransform: 'uppercase', fontFamily: 'var(--mono)' }}>Priority Level</span>
              <div style={{ fontSize: '16px', fontWeight: 700, color: 'var(--danger)', fontFamily: 'var(--mono)', marginTop: '2px' }}>
                {currentInv?.subject?.current_priority || 'EVALUATING'}
              </div>
            </div>
            <div style={{ padding: '12px', background: 'var(--bg-card)', borderRadius: '6px', border: '1px solid var(--border)' }}>
              <span style={{ fontSize: '10px', color: 'var(--text-muted)', textTransform: 'uppercase', fontFamily: 'var(--mono)' }}>Inferred Attack State</span>
              <div style={{ fontSize: '15px', fontWeight: 700, color: 'var(--accent)', fontFamily: 'var(--mono)', marginTop: '2px' }}>
                {currentInv?.subject?.inferred_attack_state || 'UNKNOWN'}
              </div>
            </div>
            <div style={{ padding: '12px', background: 'var(--bg-card)', borderRadius: '6px', border: '1px solid var(--border)' }}>
              <span style={{ fontSize: '10px', color: 'var(--text-muted)', textTransform: 'uppercase', fontFamily: 'var(--mono)' }}>Behavioral Roles</span>
              <div style={{ fontSize: '12px', fontWeight: 600, color: 'var(--text-primary)', marginTop: '4px' }}>
                {currentInv?.subject?.primary_roles?.join(', ') || 'None'}
              </div>
            </div>
            <div style={{ padding: '12px', background: 'var(--bg-card)', borderRadius: '6px', border: '1px solid var(--border)' }}>
              <span style={{ fontSize: '10px', color: 'var(--text-muted)', textTransform: 'uppercase', fontFamily: 'var(--mono)' }}>Observation Horizon</span>
              <div style={{ fontSize: '13px', fontWeight: 600, color: 'var(--text-secondary)', marginTop: '2px', fontFamily: 'var(--mono)' }}>
                {currentInv?.subject?.active_windows?.length || 0} active window(s)
              </div>
            </div>
          </div>

          {/* Action Callout */}
          <div
            style={{
              padding: '14px 16px',
              background: 'rgba(239, 68, 68, 0.08)',
              borderLeft: '4px solid var(--danger)',
              borderRadius: '4px',
            }}
          >
            <strong style={{ fontSize: '12px', color: 'var(--danger)', display: 'block', marginBottom: '2px', fontFamily: 'var(--mono)' }}>
              RECOMMENDED INVESTIGATIVE ACTION:
            </strong>
            <p style={{ margin: 0, fontSize: '13px', color: 'var(--text-primary)' }}>
              {currentInv?.recommended_action}
            </p>
          </div>

          {/* Summary & Key Findings */}
          <div>
            <h4 style={{ margin: '0 0 8px 0', fontSize: '13px', color: 'var(--text-secondary)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
              Investigative Findings ({currentInv?.findings?.length || 0})
            </h4>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
              {currentInv?.findings?.map((f, idx) => (
                <div
                  key={f.finding_id || idx}
                  style={{
                    padding: '10px 14px',
                    background: 'var(--bg-card)',
                    border: '1px solid var(--border)',
                    borderRadius: '6px',
                    display: 'flex',
                    justifyContent: 'space-between',
                    alignItems: 'center',
                  }}
                >
                  <div>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                      <span style={{ fontWeight: 600, fontSize: '13px', color: 'var(--text-primary)' }}>{f.title}</span>
                      <span style={{ fontSize: '10px', padding: '1px 6px', borderRadius: '3px', background: 'var(--accent-muted)', color: 'var(--accent)', fontFamily: 'var(--mono)' }}>
                        Window {f.window_index}
                      </span>
                    </div>
                    <p style={{ margin: '3px 0 0 0', fontSize: '12px', color: 'var(--text-secondary)' }}>{f.description}</p>
                  </div>
                  <span
                    style={{
                      fontSize: '11px',
                      fontWeight: 700,
                      fontFamily: 'var(--mono)',
                      color: f.severity === 'HIGH' || f.severity === 'CRITICAL' ? 'var(--danger)' : 'var(--warning)',
                    }}
                  >
                    {f.severity}
                  </span>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* TAB CONTENT: TIMELINE */}
      {activeTab === 'TIMELINE' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
          <div style={{ fontSize: '12px', color: 'var(--text-muted)', marginBottom: '4px' }}>
            Strict chronological sequence separating verified <span style={{ color: 'var(--accent)', fontWeight: 600 }}>OBSERVED</span> telemetry from predictive <span style={{ color: 'var(--warning)', fontWeight: 600 }}>FORECAST</span> horizons.
          </div>
          {currentInv?.timeline?.map((ev, idx) => {
            const isForecast = ev.observed_or_forecast === 'FORECAST'
            return (
              <div
                key={ev.event_id || idx}
                style={{
                  display: 'flex',
                  gap: '12px',
                  padding: '10px 14px',
                  background: isForecast ? 'rgba(234, 179, 8, 0.05)' : 'var(--bg-card)',
                  borderLeft: isForecast ? '3px solid var(--warning)' : '3px solid var(--accent)',
                  borderRadius: '4px',
                  borderTop: '1px solid var(--border)',
                  borderRight: '1px solid var(--border)',
                  borderBottom: '1px solid var(--border)',
                }}
              >
                <div style={{ minWidth: '70px', fontFamily: 'var(--mono)', fontSize: '11px', color: 'var(--text-muted)' }}>
                  w_{ev.window_index}
                  <div style={{ fontSize: '9px', opacity: 0.8 }}>{ev.timestamp.toFixed(0)}s</div>
                </div>
                <div style={{ flex: 1 }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                    <span style={{ fontWeight: 600, fontSize: '13px', color: 'var(--text-primary)' }}>{ev.headline}</span>
                    <span
                      style={{
                        fontSize: '9px',
                        fontWeight: 700,
                        fontFamily: 'var(--mono)',
                        padding: '1px 6px',
                        borderRadius: '3px',
                        background: isForecast ? 'rgba(234, 179, 8, 0.2)' : 'var(--accent-muted)',
                        color: isForecast ? 'var(--warning)' : 'var(--accent)',
                      }}
                    >
                      {ev.observed_or_forecast}
                    </span>
                    <span style={{ fontSize: '10px', color: 'var(--text-muted)', fontFamily: 'var(--mono)' }}>{ev.source_modality}</span>
                  </div>
                  <p style={{ margin: '4px 0 0 0', fontSize: '12px', color: 'var(--text-secondary)' }}>{ev.details}</p>
                </div>
              </div>
            )
          })}
        </div>
      )}

      {/* TAB CONTENT: RELATIONSHIPS */}
      {activeTab === 'RELATIONSHIPS' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
          <div style={{ fontSize: '12px', color: 'var(--text-muted)', marginBottom: '4px' }}>
            Multi-dimensional relationship edges discovered through session interaction, port sweep targeting, or campaign participation.
          </div>
          {currentInv?.relationships?.length === 0 && (
            <div style={{ fontSize: '12px', color: 'var(--text-muted)', fontStyle: 'italic' }}>No cross-entity relationships identified.</div>
          )}
          {currentInv?.relationships?.map((rel, idx) => (
            <div
              key={rel.relationship_id || idx}
              style={{
                padding: '12px 14px',
                background: 'var(--bg-card)',
                borderRadius: '6px',
                border: '1px solid var(--border)',
                display: 'flex',
                justifyContent: 'space-between',
                alignItems: 'center',
                flexWrap: 'wrap',
                gap: '8px',
              }}
            >
              <div>
                <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                  <span style={{ fontFamily: 'var(--mono)', fontWeight: 700, fontSize: '13px', color: 'var(--accent)' }}>
                    {rel.source_entity}
                  </span>
                  <ChevronRight size={14} color="var(--text-muted)" />
                  <span style={{ fontFamily: 'var(--mono)', fontWeight: 700, fontSize: '13px', color: 'var(--text-primary)' }}>
                    {rel.target_entity}
                  </span>
                  <span style={{ fontSize: '10px', padding: '2px 8px', borderRadius: '4px', background: 'var(--accent-muted)', color: 'var(--accent)', fontFamily: 'var(--mono)', fontWeight: 700 }}>
                    {rel.relationship_type}
                  </span>
                </div>
                <div style={{ margin: '4px 0 0 0', fontSize: '12px', color: 'var(--text-secondary)' }}>
                  {rel.supporting_reasons?.join('; ')}
                </div>
              </div>
              <span style={{ fontSize: '10px', fontFamily: 'var(--mono)', color: 'var(--text-muted)', background: 'var(--bg-surface)', padding: '2px 6px', borderRadius: '3px' }}>
                {rel.observed_status}
              </span>
            </div>
          ))}
        </div>
      )}

      {/* TAB CONTENT: CONTRADICTIONS */}
      {activeTab === 'CONTRADICTIONS' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
          <div style={{ fontSize: '12px', color: 'var(--text-muted)', marginBottom: '4px' }}>
            Deterministic counter-evidence and mitigating factors that weaken or bound aggressive attack interpretations.
          </div>
          {currentInv?.contradictions?.length === 0 && (
            <div style={{ padding: '12px', background: 'var(--bg-card)', borderRadius: '6px', border: '1px solid var(--border)', fontSize: '12px', color: 'var(--text-muted)' }}>
              No explicit contradictions detected against the current threat assessment.
            </div>
          )}
          {currentInv?.contradictions?.map((c, idx) => (
            <div
              key={idx}
              style={{
                padding: '12px 14px',
                background: 'rgba(59, 130, 246, 0.05)',
                borderLeft: '4px solid var(--accent)',
                borderRadius: '4px',
                borderTop: '1px solid var(--border)',
                borderRight: '1px solid var(--border)',
                borderBottom: '1px solid var(--border)',
              }}
            >
              <div style={{ display: 'flex', alignItems: 'center', gap: '6px', marginBottom: '2px' }}>
                <AlertTriangle size={14} color="var(--accent)" />
                <span style={{ fontSize: '11px', fontWeight: 700, color: 'var(--accent)', fontFamily: 'var(--mono)' }}>COUNTER-EVIDENCE / MITIGATION</span>
              </div>
              <p style={{ margin: 0, fontSize: '12px', color: 'var(--text-primary)' }}>{c}</p>
            </div>
          ))}

          {currentInv?.mitigating_factors?.map((m, idx) => (
            <div
              key={`mit_${idx}`}
              style={{
                padding: '10px 14px',
                background: 'rgba(16, 185, 129, 0.05)',
                borderLeft: '4px solid var(--success)',
                borderRadius: '4px',
                fontSize: '12px',
                color: 'var(--text-primary)',
              }}
            >
              <strong style={{ color: 'var(--success)', display: 'block', fontSize: '11px', fontFamily: 'var(--mono)' }}>MITIGATING FACTOR:</strong>
              {m}
            </div>
          ))}

        </div>
      )}

      {/* TAB CONTENT: RISK BREAKDOWN */}
      {activeTab === 'RISK' && currentRisk && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
          <div style={{ fontSize: '12px', color: 'var(--text-muted)' }}>
            Additive explainable risk score calculation. Zero score averaging or arbitrary AI confidence weights.
          </div>

          <div
            style={{
              display: 'grid',
              gridTemplateColumns: 'repeat(auto-fit, minmax(160px, 1fr))',
              gap: '12px',
            }}
          >
            <div style={{ padding: '12px', background: 'var(--bg-card)', borderRadius: '6px', border: '1px solid var(--border)' }}>
              <span style={{ fontSize: '10px', color: 'var(--text-muted)', fontFamily: 'var(--mono)' }}>Attack State</span>
              <div style={{ fontSize: '18px', fontWeight: 700, fontFamily: 'var(--mono)', color: 'var(--text-primary)' }}>
                +{currentRisk.attack_state_contribution}
              </div>
            </div>
            <div style={{ padding: '12px', background: 'var(--bg-card)', borderRadius: '6px', border: '1px solid var(--border)' }}>
              <span style={{ fontSize: '10px', color: 'var(--text-muted)', fontFamily: 'var(--mono)' }}>Kinematic Escalation</span>
              <div style={{ fontSize: '18px', fontWeight: 700, fontFamily: 'var(--mono)', color: 'var(--text-primary)' }}>
                +{currentRisk.kinematic_escalation_contribution}
              </div>
            </div>
            <div style={{ padding: '12px', background: 'var(--bg-card)', borderRadius: '6px', border: '1px solid var(--border)' }}>
              <span style={{ fontSize: '10px', color: 'var(--text-muted)', fontFamily: 'var(--mono)' }}>Target Breadth</span>
              <div style={{ fontSize: '18px', fontWeight: 700, fontFamily: 'var(--mono)', color: 'var(--text-primary)' }}>
                +{currentRisk.target_breadth_contribution}
              </div>
            </div>
            <div style={{ padding: '12px', background: 'var(--bg-card)', borderRadius: '6px', border: '1px solid var(--border)' }}>
              <span style={{ fontSize: '10px', color: 'var(--text-muted)', fontFamily: 'var(--mono)' }}>Campaign Factor</span>
              <div style={{ fontSize: '18px', fontWeight: 700, fontFamily: 'var(--mono)', color: 'var(--text-primary)' }}>
                +{currentRisk.campaign_contribution}
              </div>
            </div>
            <div style={{ padding: '12px', background: 'var(--bg-card)', borderRadius: '6px', border: '1px solid var(--border)' }}>
              <span style={{ fontSize: '10px', color: 'var(--text-muted)', fontFamily: 'var(--mono)' }}>Mitigation Discount</span>
              <div style={{ fontSize: '18px', fontWeight: 700, fontFamily: 'var(--mono)', color: 'var(--success)' }}>
                -{currentRisk.mitigation_discount}
              </div>
            </div>
            <div style={{ padding: '12px', background: 'var(--accent-muted)', borderRadius: '6px', border: '1px solid var(--accent)' }}>
              <span style={{ fontSize: '10px', color: 'var(--accent)', fontFamily: 'var(--mono)', fontWeight: 700 }}>FINAL RISK SCORE</span>
              <div style={{ fontSize: '20px', fontWeight: 700, fontFamily: 'var(--mono)', color: 'var(--accent)' }}>
                {currentRisk.final_score}
              </div>
            </div>
          </div>

          <div>
            <h4 style={{ margin: '0 0 6px 0', fontSize: '12px', color: 'var(--text-secondary)', textTransform: 'uppercase' }}>Active Drivers</h4>
            <ul style={{ margin: 0, paddingLeft: '20px', fontSize: '12px', color: 'var(--text-primary)' }}>
              {currentRisk.drivers?.map((d, i) => (
                <li key={i}>{d}</li>
              ))}
            </ul>
          </div>
        </div>
      )}

      {/* TAB CONTENT: INCIDENTS */}
      {activeTab === 'INCIDENTS' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
          <div style={{ fontSize: '12px', color: 'var(--text-muted)' }}>
            Aggregated security incidents synthesizing correlated entities, campaigns, attack states, and response playbooks.
          </div>
          {(!incidentInvestigations || incidentInvestigations.length === 0) && (
            <div style={{ padding: '14px', background: 'var(--bg-card)', borderRadius: '6px', border: '1px solid var(--border)', fontSize: '12px', color: 'var(--text-muted)' }}>
              No aggregated security incidents currently identified.
            </div>
          )}
          {incidentInvestigations?.map((inc) => (
            <div
              key={inc.incident_id}
              style={{
                padding: '16px',
                background: 'var(--bg-card)',
                borderRadius: '6px',
                border: '1px solid var(--border)',
                borderLeft: inc.severity === 'CRITICAL' ? '4px solid var(--danger)' : inc.severity === 'HIGH' ? '4px solid var(--warning)' : '4px solid var(--accent)',
              }}
            >
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: '8px' }}>
                <div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                    <span style={{ fontSize: '14px', fontWeight: 700, color: 'var(--text-primary)' }}>{inc.headline}</span>
                    <span style={{ fontSize: '10px', fontFamily: 'var(--mono)', padding: '2px 6px', borderRadius: '3px', background: 'var(--accent-muted)', color: 'var(--accent)' }}>
                      {inc.incident_id}
                    </span>
                  </div>
                  <p style={{ margin: '4px 0 0 0', fontSize: '12px', color: 'var(--text-secondary)' }}>{inc.summary}</p>
                </div>
                <span
                  style={{
                    fontSize: '11px',
                    fontFamily: 'var(--mono)',
                    fontWeight: 700,
                    padding: '3px 8px',
                    borderRadius: '4px',
                    background: inc.severity === 'CRITICAL' ? 'rgba(239, 68, 68, 0.15)' : 'rgba(234, 179, 8, 0.15)',
                    color: inc.severity === 'CRITICAL' ? 'var(--danger)' : 'var(--warning)',
                  }}
                >
                  {inc.severity}
                </span>
              </div>

              <div style={{ display: 'flex', flexWrap: 'wrap', gap: '12px', marginTop: '12px', paddingTop: '10px', borderTop: '1px solid var(--border)', fontSize: '11px', fontFamily: 'var(--mono)' }}>
                <span>Primary Entity: <strong>{inc.primary_entities.join(', ')}</strong></span>
                <span>Targets: <strong>{inc.target_entities.length} host(s)</strong></span>
                <span>Targeted Ports: <strong>{inc.targeted_ports.slice(0, 6).join(', ') || 'N/A'}</strong></span>
                <span>Duration: <strong>{inc.duration_seconds}s</strong></span>
                {inc.observed_mitre_techniques.length > 0 && (
                  <span>MITRE: <strong>{inc.observed_mitre_techniques.join(', ')}</strong></span>
                )}
              </div>

              {inc.recommended_actions.length > 0 && (
                <div style={{ marginTop: '10px', padding: '10px', background: 'rgba(239, 68, 68, 0.05)', borderRadius: '4px' }}>
                  <span style={{ fontSize: '11px', fontWeight: 700, color: 'var(--danger)', display: 'block', marginBottom: '4px' }}>
                    RECOMMENDED ACTIONS:
                  </span>
                  {inc.recommended_actions.map((act) => (
                    <div key={act.recommendation_id} style={{ fontSize: '12px', color: 'var(--text-primary)', marginBottom: '4px' }}>
                      • <strong>{act.title}</strong>: {act.operational_guidance}
                    </div>
                  ))}
                </div>
              )}
            </div>
          ))}
        </div>
      )}

      {/* TAB CONTENT: MITIGATIONS */}
      {activeTab === 'MITIGATIONS' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
          <div style={{ fontSize: '12px', color: 'var(--text-muted)' }}>
            Deterministic response guidance and investigative playbooks. Explains why each recommendation was generated without pretending automated execution.
          </div>
          {(!mitigationRecommendations || mitigationRecommendations.length === 0) && (
            <div style={{ padding: '14px', background: 'var(--bg-card)', borderRadius: '6px', border: '1px solid var(--border)', fontSize: '12px', color: 'var(--text-muted)' }}>
              No active response recommendations required for current baseline.
            </div>
          )}
          {mitigationRecommendations?.map((rec) => (
            <div
              key={rec.recommendation_id}
              style={{
                padding: '14px 16px',
                background: 'var(--bg-card)',
                borderRadius: '6px',
                border: '1px solid var(--border)',
                borderLeft: rec.urgency === 'CRITICAL' ? '4px solid var(--danger)' : rec.urgency === 'HIGH' ? '4px solid var(--warning)' : '4px solid var(--accent)',
              }}
            >
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                  <span style={{ fontWeight: 700, fontSize: '13px', color: 'var(--text-primary)' }}>{rec.title}</span>
                  <span style={{ fontSize: '10px', fontFamily: 'var(--mono)', padding: '2px 6px', borderRadius: '3px', background: 'var(--accent-muted)', color: 'var(--accent)' }}>
                    Target: {rec.target_entity}
                  </span>
                </div>
                <span
                  style={{
                    fontSize: '10px',
                    fontFamily: 'var(--mono)',
                    fontWeight: 700,
                    padding: '2px 6px',
                    borderRadius: '3px',
                    color: rec.urgency === 'CRITICAL' ? 'var(--danger)' : rec.urgency === 'HIGH' ? 'var(--warning)' : 'var(--accent)',
                  }}
                >
                  {rec.urgency}
                </span>
              </div>
              <div style={{ margin: '6px 0 0 0', fontSize: '12px', color: 'var(--text-secondary)' }}>
                <strong>Trigger Reason:</strong> {rec.reason}
              </div>
              <div style={{ marginTop: '6px', padding: '8px 10px', background: 'var(--bg-surface)', borderRadius: '4px', fontSize: '12px', color: 'var(--text-primary)' }}>
                <strong>Analyst Guidance:</strong> {rec.operational_guidance}
              </div>
            </div>
          ))}
        </div>
      )}
    </Panel>
  )
}
