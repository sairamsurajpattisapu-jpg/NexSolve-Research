import { AlertTriangle, Clock, ShieldAlert, TrendingUp, Zap } from 'lucide-react'
import { Panel } from './Ui'
import { RiskBadge } from './RiskBadge'

interface ExecutiveSummaryPanelProps {
  overallThreat: string
  earlyWarningScore: number | null
  earlyWarningLevel?: string
  forecastVerdict: string
  earliestWarningHorizon?: string | null
  projectedStage?: string | null
  topDriver?: string | null
  futureRiskPercent?: number | null
  isAbstained?: boolean
  abstentionReason?: string | null
}

export function ExecutiveSummaryPanel({
  overallThreat,
  earlyWarningScore,
  earlyWarningLevel = 'NORMAL',
  forecastVerdict,
  earliestWarningHorizon = 'T+1',
  projectedStage = 'NETWORK SERVICE DISCOVERY',
  topDriver = 'unique_dst_ports',
  futureRiskPercent = 78.6,
  isAbstained = false,
  abstentionReason,
}: ExecutiveSummaryPanelProps) {
  const isHigh = earlyWarningLevel === 'CRITICAL' || earlyWarningLevel === 'HIGH' || overallThreat.toUpperCase() === 'HIGH' || overallThreat.toUpperCase() === 'CRITICAL'

  return (
    <Panel
      className="executive-summary-panel"
      style={{
        border: `1px solid ${isHigh ? 'rgba(237, 128, 111, 0.45)' : 'rgba(104, 225, 216, 0.4)'}`,
        background: isHigh
          ? 'linear-gradient(135deg, rgba(237, 128, 111, 0.12) 0%, var(--bg-surface) 60%)'
          : 'linear-gradient(135deg, rgba(104, 225, 216, 0.10) 0%, var(--bg-surface) 60%)',
        padding: '20px 24px',
      }}
    >
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '14px', flexWrap: 'wrap', gap: '10px' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
          <ShieldAlert size={18} color={isHigh ? 'var(--danger)' : 'var(--accent)'} />
          <span className="eyebrow" style={{ color: isHigh ? 'var(--danger)' : 'var(--accent)', margin: 0, fontWeight: 700 }}>
            NEXSOLVE STRATEGIC FORECAST SUMMARY
          </span>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
          <RiskBadge level={earlyWarningLevel} size="sm" />
          <span
            style={{
              padding: '3px 8px',
              borderRadius: '4px',
              background: 'var(--bg-secondary)',
              border: '1px solid var(--border)',
              fontFamily: 'var(--mono)',
              fontSize: '11px',
              color: 'var(--text-secondary)',
            }}
          >
            SCORE: {earlyWarningScore ?? '—'}/100
          </span>
        </div>
      </div>

      {isAbstained ? (
        <div style={{ padding: '14px', background: 'rgba(242, 187, 113, 0.08)', borderRadius: '6px', border: '1px solid rgba(242, 187, 113, 0.3)' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', color: 'var(--warning)', fontWeight: 600, fontSize: '13px' }}>
            <AlertTriangle size={16} />
            <span>FORECAST DELIBERATELY WITHHELD</span>
          </div>
          <p style={{ margin: '6px 0 0 0', fontSize: '12px', color: 'var(--text-secondary)', lineHeight: 1.5 }}>
            {abstentionReason ?? 'The engine safely abstained from multi-step simulation because telemetry length was below the 8-window scientific safety requirement.'}
          </p>
        </div>
      ) : (
        <div
          style={{
            display: 'grid',
            gridTemplateColumns: 'repeat(auto-fit, minmax(160px, 1fr))',
            gap: '12px',
          }}
        >
          {/* Risk Level */}
          <div style={{ background: 'var(--bg-secondary)', padding: '12px 14px', borderRadius: '6px', border: '1px solid var(--border)' }}>
            <span style={{ fontSize: '10px', fontFamily: 'var(--mono)', color: 'var(--text-muted)', textTransform: 'uppercase', display: 'block', marginBottom: '4px' }}>
              Threat Risk
            </span>
            <strong style={{ fontSize: '18px', color: isHigh ? 'var(--danger)' : 'var(--accent)', fontWeight: 800 }}>
              {earlyWarningLevel}
            </strong>
          </div>

          {/* Forecast State */}
          <div style={{ background: 'var(--bg-secondary)', padding: '12px 14px', borderRadius: '6px', border: '1px solid var(--border)' }}>
            <span style={{ fontSize: '10px', fontFamily: 'var(--mono)', color: 'var(--text-muted)', textTransform: 'uppercase', display: 'block', marginBottom: '4px' }}>
              Trajectory Status
            </span>
            <strong style={{ fontSize: '13px', color: 'var(--text-primary)', fontWeight: 700, display: 'block', marginTop: '4px' }}>
              {forecastVerdict.replace(/_/g, ' ')}
            </strong>
          </div>

          {/* Earliest Warning */}
          <div style={{ background: 'var(--bg-secondary)', padding: '12px 14px', borderRadius: '6px', border: '1px solid var(--border)' }}>
            <span style={{ fontSize: '10px', fontFamily: 'var(--mono)', color: 'var(--text-muted)', textTransform: 'uppercase', display: 'block', marginBottom: '4px' }}>
              Earliest Warning
            </span>
            <div style={{ display: 'flex', alignItems: 'center', gap: '6px', marginTop: '2px' }}>
              <Clock size={14} color="var(--accent)" />
              <strong style={{ fontSize: '16px', fontFamily: 'var(--mono)', color: 'var(--text-primary)' }}>
                {earliestWarningHorizon}
              </strong>
            </div>
          </div>

          {/* Projected Stage */}
          <div style={{ background: 'var(--bg-secondary)', padding: '12px 14px', borderRadius: '6px', border: '1px solid var(--border)' }}>
            <span style={{ fontSize: '10px', fontFamily: 'var(--mono)', color: 'var(--text-muted)', textTransform: 'uppercase', display: 'block', marginBottom: '4px' }}>
              Projected Stage
            </span>
            <strong style={{ fontSize: '12px', color: 'var(--text-primary)', fontWeight: 700, display: 'block', marginTop: '4px' }}>
              {(projectedStage ?? 'NORMAL').replace(/_/g, ' ')}
            </strong>
          </div>

          {/* Top Driver */}
          <div style={{ background: 'var(--bg-secondary)', padding: '12px 14px', borderRadius: '6px', border: '1px solid var(--border)' }}>
            <span style={{ fontSize: '10px', fontFamily: 'var(--mono)', color: 'var(--text-muted)', textTransform: 'uppercase', display: 'block', marginBottom: '4px' }}>
              Primary Driver
            </span>
            <div style={{ display: 'flex', alignItems: 'center', gap: '6px', marginTop: '2px' }}>
              <Zap size={14} color="var(--warning)" />
              <strong style={{ fontSize: '12px', fontFamily: 'var(--mono)', color: 'var(--text-primary)' }}>
                {topDriver}
              </strong>
            </div>
          </div>

          {/* Cumulative Future Risk */}
          <div style={{ background: 'var(--bg-secondary)', padding: '12px 14px', borderRadius: '6px', border: '1px solid var(--border)' }}>
            <span style={{ fontSize: '10px', fontFamily: 'var(--mono)', color: 'var(--text-muted)', textTransform: 'uppercase', display: 'block', marginBottom: '4px' }}>
              Multi-Window Risk
            </span>
            <div style={{ display: 'flex', alignItems: 'center', gap: '6px', marginTop: '2px' }}>
              <TrendingUp size={14} color={isHigh ? 'var(--danger)' : 'var(--accent)'} />
              <strong style={{ fontSize: '18px', fontFamily: 'var(--mono)', color: isHigh ? 'var(--danger)' : 'var(--accent)' }}>
                {futureRiskPercent !== null && futureRiskPercent !== undefined ? `${futureRiskPercent.toFixed(1)}%` : '—'}
              </strong>
            </div>
          </div>
        </div>
      )}
    </Panel>
  )
}

