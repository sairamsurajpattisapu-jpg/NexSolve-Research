import { Panel } from './Ui'
import type { AttackCampaignPayload } from '../types/api'
import { Layers, Crosshair, Calendar } from 'lucide-react'

interface CampaignInvestigationPanelProps {
  campaigns?: AttackCampaignPayload[] | null
}

export const CampaignInvestigationPanel = ({ campaigns }: CampaignInvestigationPanelProps) => {
  if (!campaigns || campaigns.length === 0) {
    return null
  }

  return (
    <Panel
      className="campaign-investigation-panel"
      style={{
        display: 'flex',
        flexDirection: 'column',
        gap: '12px',
        padding: '16px',
        border: '1px solid var(--border)',
        borderRadius: '8px',
        background: 'var(--bg-panel)',
      }}
    >
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
          <Layers size={18} color="var(--accent)" />
          <span style={{ fontWeight: 700, fontSize: '14px', letterSpacing: '0.04em', textTransform: 'uppercase' }}>
            Correlated Attack Campaigns
          </span>
          <span
            style={{
              fontSize: '11px',
              fontFamily: 'var(--mono)',
              padding: '2px 8px',
              borderRadius: '4px',
              border: '1px solid var(--border)',
              color: 'var(--text-muted)',
            }}
          >
            {campaigns.length} Active Campaigns
          </span>
        </div>
      </div>

      <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
        {campaigns.map((c) => (
          <div
            key={c.campaign_id}
            style={{
              display: 'flex',
              flexDirection: 'column',
              gap: '8px',
              padding: '12px 14px',
              background: 'var(--bg-subtle)',
              borderRadius: '6px',
              border: '1px solid var(--border)',
            }}
          >
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                <span style={{ fontWeight: 700, fontSize: '13px' }}>{c.title}</span>
                <span style={{ fontFamily: 'var(--mono)', fontSize: '11px', color: 'var(--text-muted)' }}>
                  ({c.campaign_id})
                </span>
              </div>
              <span
                style={{
                  fontSize: '10px',
                  fontFamily: 'var(--mono)',
                  fontWeight: 700,
                  padding: '2px 8px',
                  borderRadius: '4px',
                  background: c.severity === 'CRITICAL' ? 'rgba(239, 68, 68, 0.15)' : 'rgba(245, 158, 11, 0.15)',
                  color: c.severity === 'CRITICAL' ? 'var(--danger)' : 'var(--warning)',
                  border: c.severity === 'CRITICAL' ? '1px solid var(--danger)' : '1px solid var(--warning)',
                }}
              >
                {c.severity}
              </span>
            </div>

            <p style={{ margin: 0, fontSize: '12px', color: 'var(--text-secondary)', lineHeight: 1.4 }}>
              {c.explanation}
            </p>

            <div style={{ display: 'flex', flexWrap: 'wrap', gap: '8px', alignItems: 'center', fontSize: '11px', color: 'var(--text-muted)' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '4px' }}>
                <Calendar size={12} />
                <span style={{ fontFamily: 'var(--mono)' }}>
                  Windows {c.start_window}..{c.end_window} ({c.duration_seconds}s)
                </span>
              </div>
              <span>•</span>
              <div style={{ display: 'flex', alignItems: 'center', gap: '4px' }}>
                <Crosshair size={12} />
                <span>{c.target_entities.length} Target Host(s)</span>
              </div>
              <span>•</span>
              <span>{c.constituent_episodes.length} Episodes</span>
              <div style={{ display: 'flex', gap: '4px', marginLeft: 'auto' }}>
                {c.correlation_reasons.map((r) => (
                  <span
                    key={r}
                    style={{
                      fontSize: '9px',
                      fontFamily: 'var(--mono)',
                      padding: '1px 5px',
                      borderRadius: '3px',
                      border: '1px solid var(--border)',
                      color: 'var(--text-muted)',
                    }}
                  >
                    {r}
                  </span>
                ))}
              </div>
            </div>
          </div>
        ))}
      </div>
    </Panel>
  )
}
