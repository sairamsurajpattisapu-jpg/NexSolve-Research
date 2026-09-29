import { useState, useMemo } from 'react'
import { Link } from 'react-router-dom'
import {
  Activity,
  ArrowUpDown,
  Boxes,
  FileUp,
  Network,
  RefreshCw,
  Search,
  SlidersHorizontal,
  Zap,
} from 'lucide-react'
import { ActivityChart, ProtocolBars } from '../components/Charts'
import { ErrorState, LoadingState, MetricCard, Panel, SectionHeading } from '../components/Ui'
import { formatBytes, formatNumber, formatPercent } from '../utils/format'
import { useProductionData } from '../hooks/useProductionData'
import { useAnalysis } from '../context/AnalysisContext'

type SortField = 'packets' | 'bytes' | 'duration' | 'risk'

export function Traffic() {
  const { data, loading, error, reload } = useProductionData()
  const { canonical: contextCanonical } = useAnalysis()

  const [searchQuery, setSearchQuery] = useState('')
  const [protocolFilter, setProtocolFilter] = useState<'ALL' | 'TCP' | 'UDP' | 'ICMP'>('ALL')
  const [riskFilter, setRiskFilter] = useState<'ALL' | 'SUSPICIOUS' | 'HIGH' | 'MEDIUM' | 'LOW'>('ALL')
  const [selectedWindowFilter, setSelectedWindowFilter] = useState<string>('ALL')
  const [sortField, setSortField] = useState<SortField>('packets')
  const [sortAsc, setSortAsc] = useState<boolean>(false)
  const [page, setPage] = useState<number>(1)
  const pageSize = 25

  if (loading && !contextCanonical && !data) return <LoadingState message="Loading traffic telemetry" />
  if (error && !contextCanonical && !data) return <ErrorState message={error} onRetry={() => void reload()} />

  const traffic = contextCanonical?.trafficSummary || data?.results?.traffic
  const rawSessions = contextCanonical?.sessions || (data?.results as any)?.investigation_sessions || []

  if (!traffic) {
    return (
      <div className="page-stack page-enter">
        <SectionHeading
          eyebrow="Network Telemetry"
          title="Traffic Analytics & Temporal Dynamics"
          description="Passive wire telemetry reconstructed across discrete 60-second tumbling observation windows."
        />
        <Panel className="compact-container" style={{ padding: '48px 32px', textAlign: 'center', margin: '24px auto' }}>
          <div style={{ maxWidth: '440px', margin: '0 auto' }}>
            <h3 style={{ fontSize: '16px', fontWeight: 600, color: 'var(--text-primary)', marginBottom: '8px' }}>
              No telemetry available
            </h3>
            <p style={{ fontSize: '13px', color: 'var(--text-secondary)', marginBottom: '20px', lineHeight: 1.5 }}>
              No telemetry available. Analyze a PCAP to populate traffic telemetry.
            </p>
            <Link to="/console/analyze" className="button button-primary" style={{ display: 'inline-flex', gap: '6px' }}>
              <FileUp size={14} /> Analyze PCAP
            </Link>
          </div>
        </Panel>
      </div>
    )
  }

  const windows = traffic.windows_data ?? []
  const retransmissionRate = traffic.packets ? traffic.retransmissions / traffic.packets : 0

  // Filter & sort flow investigation records
  const filteredSessions = useMemo(() => {
    let list = [...rawSessions]

    // Search
    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase().trim()
      list = list.filter(
        (s) =>
          s.src_ip.toLowerCase().includes(q) ||
          s.dst_ip.toLowerCase().includes(q) ||
          String(s.src_port).includes(q) ||
          String(s.dst_port).includes(q) ||
          s.protocol.toLowerCase().includes(q) ||
          (s.behavioral_tags && s.behavioral_tags.some((t: string) => t.toLowerCase().includes(q)))
      )
    }

    // Protocol filter
    if (protocolFilter !== 'ALL') {
      list = list.filter((s) => s.protocol.toUpperCase() === protocolFilter)
    }

    // Risk / Suspicious filter
    if (riskFilter === 'SUSPICIOUS') {
      list = list.filter(
        (s) =>
          (s.behavioral_tags && s.behavioral_tags.length > 0) ||
          s.risk_assessment === 'HIGH' ||
          s.risk_assessment === 'CRITICAL' ||
          s.risk_assessment === 'MEDIUM'
      )
    } else if (riskFilter !== 'ALL') {
      list = list.filter((s) => (s.risk_assessment || 'LOW').toUpperCase() === riskFilter)
    }

    // Window filter
    if (selectedWindowFilter !== 'ALL') {
      list = list.filter((s) => String(s.temporal_window_id || '') === selectedWindowFilter)
    }

    // Sort
    list.sort((a, b) => {
      let diff = 0
      if (sortField === 'packets') {
        diff = (b.total_packets || 0) - (a.total_packets || 0)
      } else if (sortField === 'bytes') {
        diff = (b.total_bytes || 0) - (a.total_bytes || 0)
      } else if (sortField === 'duration') {
        diff = (b.duration_seconds || 0) - (a.duration_seconds || 0)
      } else if (sortField === 'risk') {
        const score = (r?: string) => (r === 'HIGH' ? 3 : r === 'MEDIUM' ? 2 : 1)
        diff = score(b.risk_assessment) - score(a.risk_assessment)
      }
      return sortAsc ? -diff : diff
    })

    return list
  }, [rawSessions, searchQuery, protocolFilter, riskFilter, selectedWindowFilter, sortField, sortAsc])

  const totalPages = Math.max(1, Math.ceil(filteredSessions.length / pageSize))
  const paginatedSessions = filteredSessions.slice((page - 1) * pageSize, page * pageSize)

  return (
    <div className="page-stack page-enter">
      <SectionHeading
        eyebrow="Network Telemetry"
        title="Traffic Analytics & Temporal Dynamics"
        description={`Passive wire telemetry reconstructed across ${traffic.windows || 1} discrete 60-second observation windows.`}
        action={
          <div style={{ display: 'flex', gap: '8px' }}>
            <Link to="/console/network" className="button button-quiet" style={{ fontSize: '12px', gap: '6px' }}>
              <Network size={13} /> Network Topology
            </Link>
            <button className="button button-quiet" onClick={() => void reload()} style={{ fontSize: '12px', gap: '6px' }}>
              <RefreshCw size={13} /> Refresh
            </button>
          </div>
        }
      />

      {/* 1. OVERVIEW: Key Telemetry Metric Cards */}
      <div className="metric-grid" style={{ marginBottom: '20px' }}>
        <MetricCard
          label="Total Packets"
          value={formatNumber(traffic.packets)}
          detail="Ingested wire frames"
          tone="accent"
          icon={<Network size={16} />}
        />
        <MetricCard
          label="TCP Packets"
          value={formatNumber(traffic.tcp)}
          detail={formatPercent(traffic.tcp / Math.max(traffic.packets, 1))}
          icon={<Activity size={16} />}
        />
        <MetricCard
          label="UDP Packets"
          value={formatNumber(traffic.udp)}
          detail={formatPercent(traffic.udp / Math.max(traffic.packets, 1))}
          icon={<Boxes size={16} />}
        />
        <MetricCard
          label="Retransmission Rate"
          value={formatPercent(retransmissionRate)}
          detail={`${formatNumber(traffic.retransmissions)} packets`}
          tone={retransmissionRate > 0.05 ? 'warning' : 'accent'}
          icon={<Zap size={16} />}
        />
      </div>

      {/* 2. TEMPORAL BEHAVIOR: Window Activity Chart */}
      {windows.length > 0 && (
        <Panel style={{ marginBottom: '20px', padding: '20px 24px' }}>
          <SectionHeading
            title="Temporal Behavior (60s Windows)"
            description="Packet density dynamics across sequential 60-second observation windows. Preserves temporal ordering."
          />
          <div style={{ marginTop: '12px' }}>
            <ActivityChart windows={windows} />
          </div>
        </Panel>
      )}

      {/* 3. FLOWS & PROTOCOLS: Grouped Technical Distribution */}
      <div className="content-grid" style={{ marginBottom: '24px' }}>
        {/* Protocol Distribution */}
        <Panel style={{ padding: '20px 24px' }}>
          <SectionHeading
            title="Protocol Distribution"
            description="Normalized frame breakdown across observed layer-4 transport protocols."
          />
          <div style={{ marginTop: '12px' }}>
            <ProtocolBars protocols={traffic.protocol_counts || { TCP: traffic.tcp, UDP: traffic.udp }} />
          </div>
        </Panel>

        {/* 5-Tuple Flows & Indicators */}
        <Panel style={{ padding: '20px 24px' }}>
          <SectionHeading
            title="Flow Characteristics"
            description="5-tuple conversation moments and wire fragmentation indicators."
          />
          <div className="detail-list" style={{ marginTop: '12px' }}>
            <div>
              <span>Reconstructed 5-tuple flows</span>
              <strong style={{ fontFamily: 'var(--font-sans)', fontVariantNumeric: 'tabular-nums' }}>{formatNumber(traffic.flows ?? 0)}</strong>
            </div>
            <div>
              <span>Analysis windows</span>
              <strong style={{ fontFamily: 'var(--font-sans)', fontVariantNumeric: 'tabular-nums' }}>{formatNumber(traffic.windows || 1)} windows</strong>
            </div>
            <div>
              <span>Peak window density</span>
              <strong style={{ fontFamily: 'var(--font-sans)', fontVariantNumeric: 'tabular-nums' }}>
                {windows.length > 0 ? formatNumber(Math.max(...windows.map((item) => item.packet_count), 0)) : '—'} packets
              </strong>
            </div>
            <div>
              <span>Fragmented packets</span>
              <strong style={{ fontFamily: 'var(--font-sans)', fontVariantNumeric: 'tabular-nums' }}>{formatNumber(traffic.retransmissions || 0)}</strong>
            </div>
            <div>
              <span>Capture Data Source</span>
              <strong style={{ fontFamily: 'var(--font-sans)' }}>{contextCanonical?.input.filename || data?.results?.source?.name || 'Passive Wire Ingestion'}</strong>
            </div>
          </div>
        </Panel>
      </div>

      {/* 4. DEEP FLOW INVESTIGATION WORKSPACE */}
      <Panel style={{ padding: '20px 24px' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px', flexWrap: 'wrap', gap: '12px' }}>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
              <SlidersHorizontal size={15} color="var(--text-primary)" />
              <span style={{ fontSize: '11px', fontFamily: 'var(--mono)', fontWeight: 700, color: 'var(--text-primary)', textTransform: 'uppercase', letterSpacing: '0.06em' }}>
                DEEP FLOW INVESTIGATION TABLE
              </span>
            </div>
            <h3 style={{ margin: '4px 0 0 0', fontSize: '16px', color: 'var(--text-primary)' }}>
              Reconstructed 5-Tuple Transport Sessions ({filteredSessions.length} matching)
            </h3>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap' }}>
            {/* Search Input */}
            <div style={{ display: 'flex', alignItems: 'center', gap: '6px', background: 'var(--bg-secondary)', border: '1px solid var(--border)', borderRadius: '6px', padding: '4px 10px' }}>
              <Search size={13} color="var(--text-muted)" />
              <input
                type="text"
                value={searchQuery}
                onChange={(e) => {
                  setSearchQuery(e.target.value)
                  setPage(1)
                }}
                placeholder="Search IP, Port, Tag..."
                style={{ background: 'transparent', border: 'none', color: 'var(--text-primary)', fontSize: '12px', outline: 'none', width: '160px' }}
              />
            </div>

            {/* Protocol Filter */}
            <select
              value={protocolFilter}
              onChange={(e) => {
                setProtocolFilter(e.target.value as any)
                setPage(1)
              }}
              style={{ background: 'var(--bg-secondary)', border: '1px solid var(--border)', borderRadius: '6px', padding: '5px 8px', fontSize: '12px', color: 'var(--text-primary)', outline: 'none' }}
            >
              <option value="ALL">All Protocols</option>
              <option value="TCP">TCP</option>
              <option value="UDP">UDP</option>
              <option value="ICMP">ICMP</option>
            </select>

            {/* Risk / Suspicious Filter */}
            <select
              value={riskFilter}
              onChange={(e) => {
                setRiskFilter(e.target.value as any)
                setPage(1)
              }}
              style={{ background: 'var(--bg-secondary)', border: '1px solid var(--border)', borderRadius: '6px', padding: '5px 8px', fontSize: '12px', color: 'var(--text-primary)', outline: 'none' }}
            >
              <option value="ALL">All Risks</option>
              <option value="SUSPICIOUS">Suspicious Only</option>
              <option value="HIGH">High Risk</option>
              <option value="MEDIUM">Medium Risk</option>
              <option value="LOW">Low Risk</option>
            </select>

            {/* Window Filter */}
            {windows.length > 0 && (
              <select
                value={selectedWindowFilter}
                onChange={(e) => {
                  setSelectedWindowFilter(e.target.value)
                  setPage(1)
                }}
                style={{ background: 'var(--bg-secondary)', border: '1px solid var(--border)', borderRadius: '6px', padding: '5px 8px', fontSize: '12px', color: 'var(--text-primary)', outline: 'none' }}
              >
                <option value="ALL">All Windows</option>
                {windows.map((w, idx) => (
                  <option key={idx} value={String(w.window_id ?? idx + 1)}>
                    Window {idx + 1}
                  </option>
                ))}
              </select>
            )}

            {/* Sort Toggle */}
            <button
              type="button"
              className="button button-quiet"
              onClick={() => setSortAsc(!sortAsc)}
              title="Toggle sort order"
              style={{ fontSize: '11px', height: '30px', padding: '0 8px' }}
            >
              <ArrowUpDown size={12} /> {sortAsc ? 'Asc' : 'Desc'}
            </button>
          </div>
        </div>

        {/* Table of Actual Flows */}
        {filteredSessions.length > 0 ? (
          <div style={{ overflowX: 'auto', border: '1px solid var(--border)', borderRadius: '6px' }}>
            <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '12px', fontFamily: 'var(--font-sans)' }}>
              <thead>
                <tr style={{ background: 'var(--bg-secondary)', borderBottom: '1px solid var(--border)', textAlign: 'left', color: 'var(--text-muted)', fontFamily: 'var(--mono)', fontSize: '10.5px' }}>
                  <th style={{ padding: '10px 12px' }}>SOURCE IP : PORT</th>
                  <th style={{ padding: '10px 12px' }}>&rarr;</th>
                  <th style={{ padding: '10px 12px' }}>DESTINATION IP : PORT</th>
                  <th style={{ padding: '10px 12px' }}>PROTO</th>
                  <th
                    style={{ padding: '10px 12px', cursor: 'pointer', textAlign: 'right' }}
                    onClick={() => {
                      setSortField('packets')
                      setSortAsc(!sortAsc)
                    }}
                  >
                    PACKETS {sortField === 'packets' ? (sortAsc ? '▲' : '▼') : ''}
                  </th>
                  <th
                    style={{ padding: '10px 12px', cursor: 'pointer', textAlign: 'right' }}
                    onClick={() => {
                      setSortField('bytes')
                      setSortAsc(!sortAsc)
                    }}
                  >
                    BYTES {sortField === 'bytes' ? (sortAsc ? '▲' : '▼') : ''}
                  </th>
                  <th
                    style={{ padding: '10px 12px', cursor: 'pointer', textAlign: 'right' }}
                    onClick={() => {
                      setSortField('duration')
                      setSortAsc(!sortAsc)
                    }}
                  >
                    DURATION {sortField === 'duration' ? (sortAsc ? '▲' : '▼') : ''}
                  </th>
                  <th style={{ padding: '10px 12px' }}>BEHAVIORAL TAGS &amp; RISK</th>
                </tr>
              </thead>
              <tbody>
                {paginatedSessions.map((session, idx) => {
                  const isSuspicious =
                    (session.behavioral_tags && session.behavioral_tags.length > 0) ||
                    session.risk_assessment === 'HIGH' ||
                    session.risk_assessment === 'CRITICAL'

                  return (
                    <tr
                      key={session.session_id || idx}
                      style={{
                        borderBottom: '1px solid var(--border)',
                        background: isSuspicious ? 'rgba(255, 255, 255, 0.03)' : 'transparent',
                        transition: 'background 0.1s',
                      }}
                    >
                      <td style={{ padding: '9px 12px', fontFamily: 'var(--mono)', color: 'var(--text-primary)', whiteSpace: 'nowrap' }}>
                        {session.src_ip}
                        <span style={{ color: 'var(--text-muted)' }}>:{session.src_port}</span>
                      </td>
                      <td style={{ padding: '9px 4px', color: 'var(--text-muted)' }}>&rarr;</td>
                      <td style={{ padding: '9px 12px', fontFamily: 'var(--mono)', color: 'var(--text-primary)', whiteSpace: 'nowrap' }}>
                        {session.dst_ip}
                        <span style={{ color: 'var(--text-muted)' }}>:{session.dst_port}</span>
                      </td>
                      <td style={{ padding: '9px 12px' }}>
                        <span
                          style={{
                            fontFamily: 'var(--mono)',
                            fontSize: '10.5px',
                            padding: '2px 6px',
                            borderRadius: '3px',
                            background: 'var(--bg-secondary)',
                            border: '1px solid var(--border)',
                            color: 'var(--text-primary)',
                          }}
                        >
                          {session.protocol}
                        </span>
                      </td>
                      <td style={{ padding: '9px 12px', textAlign: 'right', fontVariantNumeric: 'tabular-nums', fontFamily: 'var(--mono)' }}>
                        {(session.total_packets || 0).toLocaleString()}
                      </td>
                      <td style={{ padding: '9px 12px', textAlign: 'right', fontVariantNumeric: 'tabular-nums', fontFamily: 'var(--mono)' }}>
                        {formatBytes(session.total_bytes)}
                      </td>
                      <td style={{ padding: '9px 12px', textAlign: 'right', fontVariantNumeric: 'tabular-nums', fontFamily: 'var(--mono)' }}>
                        {(session.duration_seconds ?? 0).toFixed(2)}s
                      </td>
                      <td style={{ padding: '9px 12px' }}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: '6px', flexWrap: 'wrap' }}>
                          <span
                            style={{
                              fontSize: '10px',
                              fontFamily: 'var(--mono)',
                              fontWeight: 700,
                              padding: '2px 6px',
                              borderRadius: '3px',
                              background: isSuspicious ? 'var(--text-primary)' : 'var(--bg-secondary)',
                              color: isSuspicious ? 'var(--bg-primary)' : 'var(--text-muted)',
                              border: '1px solid var(--border)',
                            }}
                          >
                            {session.risk_assessment || 'LOW'}
                          </span>
                          {session.behavioral_tags &&
                            session.behavioral_tags.map((tag: string, tIdx: number) => (
                              <span
                                key={tIdx}
                                style={{
                                  fontSize: '10px',
                                  fontFamily: 'var(--mono)',
                                  padding: '1px 5px',
                                  borderRadius: '3px',
                                  border: '1px solid var(--border)',
                                  color: 'var(--text-secondary)',
                                  background: 'var(--bg-secondary)',
                                }}
                              >
                                {tag}
                              </span>
                            ))}
                        </div>
                      </td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </div>
        ) : (
          <div style={{ padding: '32px 20px', textAlign: 'center', background: 'var(--bg-secondary)', borderRadius: '6px', border: '1px dashed var(--border)' }}>
            <p style={{ margin: 0, fontSize: '13px', color: 'var(--text-muted)' }}>
              {rawSessions.length === 0
                ? 'No individual session records were materialized for this capture. Wire frame and window metrics are displayed above.'
                : 'No flow sessions match the specified search or filter criteria.'}
            </p>
          </div>
        )}

        {/* Pagination Bar */}
        {totalPages > 1 && (
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginTop: '14px', fontSize: '12px', color: 'var(--text-muted)' }}>
            <div>
              Showing {Math.min(filteredSessions.length, (page - 1) * pageSize + 1)}&ndash;
              {Math.min(filteredSessions.length, page * pageSize)} of {filteredSessions.length} flows
            </div>
            <div style={{ display: 'flex', gap: '6px' }}>
              <button
                type="button"
                className="button button-quiet"
                disabled={page <= 1}
                onClick={() => setPage((p) => Math.max(1, p - 1))}
                style={{ fontSize: '11px', height: '28px', padding: '0 10px' }}
              >
                Previous
              </button>
              <span style={{ display: 'flex', alignItems: 'center', padding: '0 8px', fontFamily: 'var(--mono)', color: 'var(--text-primary)' }}>
                {page} / {totalPages}
              </span>
              <button
                type="button"
                className="button button-quiet"
                disabled={page >= totalPages}
                onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
                style={{ fontSize: '11px', height: '28px', padding: '0 10px' }}
              >
                Next
              </button>
            </div>
          </div>
        )}
      </Panel>
    </div>
  )
}

export default Traffic
