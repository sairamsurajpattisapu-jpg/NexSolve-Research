import { useState } from 'react'
import { Panel } from './Ui'
import type { EntityBehaviorProfilePayload } from '../types/api'
import { User } from 'lucide-react'

interface EntityBehaviorProfileCardProps {
  profiles?: Record<string, EntityBehaviorProfilePayload> | null
}

export const EntityBehaviorProfileCard = ({ profiles }: EntityBehaviorProfileCardProps) => {
  const [selectedEntity, setSelectedEntity] = useState<string | null>(null)

  if (!profiles || Object.keys(profiles).length === 0) {
    return null
  }

  const entities = Object.keys(profiles)
  const activeEntityKey = selectedEntity && profiles[selectedEntity] ? selectedEntity : entities[0]
  const prof = profiles[activeEntityKey]

  return (
    <Panel
      className="entity-profile-card"
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
          <User size={18} color="var(--accent)" />
          <span style={{ fontWeight: 700, fontSize: '14px', letterSpacing: '0.04em', textTransform: 'uppercase' }}>
            Entity Behavioral Profiles
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
            {entities.length} Profiled Entities
          </span>
        </div>

        {entities.length > 1 && (
          <div style={{ display: 'flex', gap: '6px', flexWrap: 'wrap', maxWidth: '50%' }}>
            {entities.slice(0, 5).map((e) => (
              <button
                key={e}
                onClick={() => setSelectedEntity(e)}
                style={{
                  padding: '3px 8px',
                  fontSize: '11px',
                  fontFamily: 'var(--mono)',
                  borderRadius: '4px',
                  border: e === activeEntityKey ? '1px solid var(--accent)' : '1px solid var(--border)',
                  background: e === activeEntityKey ? 'var(--accent-glow)' : 'transparent',
                  color: e === activeEntityKey ? 'var(--accent)' : 'var(--text-muted)',
                  cursor: 'pointer',
                }}
              >
                {e}
              </button>
            ))}
          </div>
        )}
      </div>

      {prof && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '8px' }}>
            <div>
              <span style={{ fontWeight: 700, fontFamily: 'var(--mono)', fontSize: '14px' }}>{prof.entity}</span>
              <p style={{ margin: '2px 0 0 0', fontSize: '12px', color: 'var(--text-muted)' }}>{prof.role_summary}</p>
            </div>
            <div style={{ display: 'flex', gap: '6px', flexWrap: 'wrap' }}>
              {prof.roles.map((r) => (
                <span
                  key={r}
                  style={{
                    fontSize: '10px',
                    fontFamily: 'var(--mono)',
                    fontWeight: 700,
                    padding: '2px 6px',
                    borderRadius: '4px',
                    background: 'var(--accent-muted)',
                    color: 'var(--accent)',
                    border: '1px solid var(--accent)',
                  }}
                >
                  {r}
                </span>
              ))}
            </div>
          </div>

          <div
            style={{
              display: 'grid',
              gridTemplateColumns: 'repeat(auto-fit, minmax(130px, 1fr))',
              gap: '8px',
              padding: '10px',
              background: 'var(--bg-subtle)',
              borderRadius: '6px',
            }}
          >
            <div>
              <span style={{ fontSize: '10px', color: 'var(--text-muted)', fontFamily: 'var(--mono)', textTransform: 'uppercase' }}>
                Peers
              </span>
              <div style={{ fontWeight: 600, fontSize: '13px', fontFamily: 'var(--mono)' }}>{prof.peer_count}</div>
            </div>
            <div>
              <span style={{ fontSize: '10px', color: 'var(--text-muted)', fontFamily: 'var(--mono)', textTransform: 'uppercase' }}>
                Target Ports
              </span>
              <div style={{ fontWeight: 600, fontSize: '13px', fontFamily: 'var(--mono)' }}>{prof.targeted_ports_count}</div>
            </div>
            <div>
              <span style={{ fontSize: '10px', color: 'var(--text-muted)', fontFamily: 'var(--mono)', textTransform: 'uppercase' }}>
                Conn Attempts
              </span>
              <div style={{ fontWeight: 600, fontSize: '13px', fontFamily: 'var(--mono)' }}>{prof.connection_attempts}</div>
            </div>
            <div>
              <span style={{ fontSize: '10px', color: 'var(--text-muted)', fontFamily: 'var(--mono)', textTransform: 'uppercase' }}>
                Failure Ratio
              </span>
              <div style={{ fontWeight: 600, fontSize: '13px', fontFamily: 'var(--mono)', color: prof.failure_ratio > 0.5 ? 'var(--danger)' : 'inherit' }}>
                {(prof.failure_ratio * 100).toFixed(1)}%
              </div>
            </div>
            <div>
              <span style={{ fontSize: '10px', color: 'var(--text-muted)', fontFamily: 'var(--mono)', textTransform: 'uppercase' }}>
                Active Windows
              </span>
              <div style={{ fontWeight: 600, fontSize: '13px', fontFamily: 'var(--mono)' }}>{prof.active_windows_count}</div>
            </div>
          </div>
        </div>
      )}
    </Panel>
  )
}
