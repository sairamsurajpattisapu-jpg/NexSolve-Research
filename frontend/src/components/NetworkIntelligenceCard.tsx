import { useState } from 'react'
import { Activity, Radio, Shield, Waves, ChevronDown, ChevronUp } from 'lucide-react'
import { Panel } from './Ui'

interface NetworkIntelligenceProps {
  sessionState?: Record<string, any> | null
  periodicity?: Record<string, any> | null
  flowStatistics?: Record<string, any> | null
  signatureEvidence?: Record<string, any> | null
}

export function NetworkIntelligenceCard({
  sessionState,
  periodicity,
  flowStatistics,
  signatureEvidence,
}: NetworkIntelligenceProps) {
  const [expanded, setExpanded] = useState(false)

  // Zeek session numbers
  const totalSessions = Number(sessionState?.total_tcp_sessions ?? 0)
  const establishedSessions = Number(sessionState?.established_sessions ?? 0)
  const failedRatio = Number(sessionState?.failed_connection_ratio ?? 0)
  const establishmentRatio = Number(sessionState?.establishment_ratio ?? 0)

  // RITA periodicity numbers
  const totalGroups = Number(periodicity?.total_groups_evaluated ?? 0)
  const periodicGroups = Number(periodicity?.periodic_groups ?? 0) + Number(periodicity?.highly_periodic_groups ?? 0)
  const irregularGroups = Number(periodicity?.irregular_groups ?? 0)
  const insufficientGroups = Number(periodicity?.insufficient_groups ?? 0)

  // NFStream flow numbers
  const totalFlows = Number(flowStatistics?.total_flows ?? 0)
  const singlePacketRatio = Number(flowStatistics?.single_packet_flow_ratio ?? 0)
  const meanPktRate = Number(flowStatistics?.mean_packet_rate ?? 0)

  // Suricata signature numbers
  const alertCount = Number(signatureEvidence?.alert_count ?? 0)
  const sigStatus = String(signatureEvidence?.status ?? 'NO_SURICATA_EVIDENCE_AVAILABLE')

  return (
    <Panel style={{ padding: '16px 20px', border: '1px solid var(--border)' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '12px' }}>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <span className="eyebrow" style={{ color: 'var(--accent)', margin: 0 }}>
              Multi-Modal Network Intelligence
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
              OBSERVED ONLY
            </span>
          </div>
          <h3 style={{ margin: '4px 0 0 0', fontSize: '16px', fontWeight: 700, color: 'var(--text-primary)' }}>
            Protocol, Behavioral & Flow Telemetry
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
            color: 'var(--text-primary)',
            padding: '5px 10px',
            borderRadius: '4px',
            fontSize: '12px',
            cursor: 'pointer',
          }}
          aria-expanded={expanded}
        >
          {expanded ? 'Collapse Details' : 'View Modality Breakdown'}
          {expanded ? <ChevronUp size={14} /> : <ChevronDown size={14} />}
        </button>
      </div>

      {/* 4 Multi-Modal Summary Tiles */}
      <div
        style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(210px, 1fr))',
          gap: '12px',
          marginTop: '16px',
        }}
      >
        {/* 1. Zeek Protocol State */}
        <div style={{ padding: '12px', borderRadius: '6px', background: 'rgba(255, 255, 255, 0.02)', border: '1px solid var(--border)' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '6px', marginBottom: '6px' }}>
            <Activity size={15} color="var(--accent)" />
            <strong style={{ fontSize: '12px', textTransform: 'uppercase', fontFamily: 'var(--mono)', color: 'var(--text-muted)' }}>
              TCP Session State (Zeek)
            </strong>
          </div>
          <div style={{ fontSize: '15px', fontWeight: 700, fontFamily: 'var(--mono)' }}>
            {totalSessions > 0 ? `${totalSessions} Sessions` : '0 Sessions'}
          </div>
          <div style={{ fontSize: '11px', color: 'var(--text-muted)', marginTop: '4px' }}>
            {totalSessions > 0
              ? `${(establishmentRatio * 100).toFixed(1)}% est · ${(failedRatio * 100).toFixed(1)}% failed`
              : 'No TCP traffic observed'}
          </div>
        </div>

        {/* 2. RITA Behavioral Periodicity */}
        <div style={{ padding: '12px', borderRadius: '6px', background: 'rgba(255, 255, 255, 0.02)', border: '1px solid var(--border)' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '6px', marginBottom: '6px' }}>
            <Radio size={15} color="var(--accent)" />
            <strong style={{ fontSize: '12px', textTransform: 'uppercase', fontFamily: 'var(--mono)', color: 'var(--text-muted)' }}>
              Periodicity (RITA)
            </strong>
          </div>
          <div style={{ fontSize: '15px', fontWeight: 700, fontFamily: 'var(--mono)' }}>
            {totalGroups > 0 ? `${totalGroups} Pairs Evaluated` : '0 Pairs'}
          </div>
          <div style={{ fontSize: '11px', color: 'var(--text-muted)', marginTop: '4px' }}>
            {periodicGroups > 0
              ? `${periodicGroups} periodic group(s) observed`
              : 'No periodic metronomic activity'}
          </div>
        </div>

        {/* 3. NFStream Flow Intelligence */}
        <div style={{ padding: '12px', borderRadius: '6px', background: 'rgba(255, 255, 255, 0.02)', border: '1px solid var(--border)' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '6px', marginBottom: '6px' }}>
            <Waves size={15} color="var(--accent)" />
            <strong style={{ fontSize: '12px', textTransform: 'uppercase', fontFamily: 'var(--mono)', color: 'var(--text-muted)' }}>
              Flow Dynamics (NFStream)
            </strong>
          </div>
          <div style={{ fontSize: '15px', fontWeight: 700, fontFamily: 'var(--mono)' }}>
            {totalFlows.toLocaleString()} Flows
          </div>
          <div style={{ fontSize: '11px', color: 'var(--text-muted)', marginTop: '4px' }}>
            {(singlePacketRatio * 100).toFixed(1)}% single-pkt · {meanPktRate.toFixed(1)} pkts/s avg
          </div>
        </div>

        {/* 4. Suricata Signature Layer */}
        <div style={{ padding: '12px', borderRadius: '6px', background: 'rgba(255, 255, 255, 0.02)', border: '1px solid var(--border)' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '6px', marginBottom: '6px' }}>
            <Shield size={15} color={alertCount > 0 ? 'var(--danger)' : 'var(--text-muted)'} />
            <strong style={{ fontSize: '12px', textTransform: 'uppercase', fontFamily: 'var(--mono)', color: 'var(--text-muted)' }}>
              Signatures (Suricata)
            </strong>
          </div>
          <div style={{ fontSize: '15px', fontWeight: 700, fontFamily: 'var(--mono)' }}>
            {alertCount > 0 ? `${alertCount} Alerts` : '0 Alerts'}
          </div>
          <div style={{ fontSize: '11px', color: 'var(--text-muted)', marginTop: '4px' }}>
            {sigStatus === 'AVAILABLE' ? 'EVE telemetry active' : 'No external EVE telemetry'}
          </div>
        </div>
      </div>

      {/* Expanded Breakdown Drawer */}
      {expanded && (
        <div
          style={{
            marginTop: '16px',
            paddingTop: '14px',
            borderTop: '1px solid var(--border)',
            display: 'grid',
            gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))',
            gap: '14px',
            fontSize: '12px',
          }}
        >
          {/* Zeek detailed metrics */}
          <div style={{ background: 'rgba(0,0,0,0.15)', padding: '12px', borderRadius: '4px' }}>
            <strong style={{ color: 'var(--text-primary)', display: 'block', marginBottom: '8px' }}>
              TCP Lifecycle & Boundaries
            </strong>
            <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '4px' }}>
              <span style={{ color: 'var(--text-muted)' }}>Established (S1/SF):</span>
              <span style={{ fontFamily: 'var(--mono)' }}>{establishedSessions}</span>
            </div>
            <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '4px' }}>
              <span style={{ color: 'var(--text-muted)' }}>Closed cleanly (SF):</span>
              <span style={{ fontFamily: 'var(--mono)' }}>{Number(sessionState?.closed_sessions ?? 0)}</span>
            </div>
            <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '4px' }}>
              <span style={{ color: 'var(--text-muted)' }}>Reset (RSTO/RSTR):</span>
              <span style={{ fontFamily: 'var(--mono)' }}>{Number(sessionState?.reset_sessions ?? 0)}</span>
            </div>
            <div style={{ display: 'flex', justifyContent: 'space-between' }}>
              <span style={{ color: 'var(--text-muted)' }}>Incomplete (OTH / Midstream):</span>
              <span style={{ fontFamily: 'var(--mono)' }}>{Number(sessionState?.incomplete_sessions ?? 0)}</span>
            </div>
          </div>

          {/* RITA detailed metrics */}
          <div style={{ background: 'rgba(0,0,0,0.15)', padding: '12px', borderRadius: '4px' }}>
            <strong style={{ color: 'var(--text-primary)', display: 'block', marginBottom: '8px' }}>
              Interval Dispersion & Regularity
            </strong>
            <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '4px' }}>
              <span style={{ color: 'var(--text-muted)' }}>Periodic / Highly Periodic:</span>
              <span style={{ fontFamily: 'var(--mono)' }}>{periodicGroups}</span>
            </div>
            <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '4px' }}>
              <span style={{ color: 'var(--text-muted)' }}>Irregular dispersion:</span>
              <span style={{ fontFamily: 'var(--mono)' }}>{irregularGroups}</span>
            </div>
            <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '4px' }}>
              <span style={{ color: 'var(--text-muted)' }}>Insufficient observations (&lt;4 conns):</span>
              <span style={{ fontFamily: 'var(--mono)' }}>{insufficientGroups}</span>
            </div>
            <div style={{ display: 'flex', justifyContent: 'space-between' }}>
              <span style={{ color: 'var(--text-muted)' }}>Methodology:</span>
              <span style={{ fontFamily: 'var(--mono)', fontSize: '11px' }}>Bowley Skew + MAD</span>
            </div>
          </div>
        </div>
      )}
    </Panel>
  )
}
