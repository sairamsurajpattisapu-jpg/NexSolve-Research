export function formatNumber(value: number) {
  return Number.isFinite(value) ? new Intl.NumberFormat('en-US').format(value) : 'Unavailable'
}

export function formatPercent(value: number) {
  return Number.isFinite(value) ? `${(value * 100).toFixed(1)}%` : 'Unavailable'
}

export function formatTimestamp(value: string | number) {
  const date = typeof value === 'number' ? new Date(value * 1000) : new Date(value)
  return Number.isNaN(date.getTime()) ? 'Unknown time' : date.toLocaleString([], { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' })
}

export function formatBytes(bytes: number) {
  if (!Number.isFinite(bytes) || bytes <= 0) return '0 B'
  const k = 1024
  const sizes = ['B', 'KB', 'MB', 'GB']
  const i = Math.floor(Math.log(bytes) / Math.log(k))
  return `${parseFloat((bytes / Math.pow(k, i)).toFixed(2))} ${sizes[i]}`
}

const ACRONYM_MAP: Record<string, string> = {
  tcp: 'TCP',
  udp: 'UDP',
  icmp: 'ICMP',
  dns: 'DNS',
  http: 'HTTP',
  https: 'HTTPS',
  tls: 'TLS',
  ssh: 'SSH',
  soc: 'SOC',
  mitre: 'MITRE',
  c2: 'C2',
  rtt: 'RTT',
  pcap: 'PCAP',
  pcapng: 'PCAPNG',
  sha256: 'SHA-256',
  auroc: 'AUROC',
  ip: 'IP',
  ips: 'IPs',
  iat: 'IAT',
  ttl: 'TTL',
  sttl: 'Source TTL',
  dttl: 'Destination TTL',
  syn: 'SYN',
  ack: 'ACK',
  fin: 'FIN',
  rst: 'RST',
  psh: 'PSH',
  urg: 'URG',
  swin: 'Source Window',
  dwin: 'Destination Window',
  dst: 'Destination',
  src: 'Source',
  id: 'ID',
  utc: 'UTC',
  dos: 'DoS',
  ddos: 'DDoS',
}

const EXACT_LABEL_MAP: Record<string, string> = {
  unique_dst_ports: 'Unique Destination Ports',
  unique_src_ports: 'Unique Source Ports',
  total_src_bytes: 'Total Source Bytes',
  total_dst_bytes: 'Total Destination Bytes',
  total_packets: 'Total Packets',
  packet_count: 'Packet Count',
  mean_duration: 'Mean Session Duration',
  mean_iat: 'Mean Inter-Arrival Time',
  std_iat: 'IAT Standard Deviation',
  max_iat: 'Maximum IAT',
  mean_sttl: 'Mean Source TTL',
  mean_dttl: 'Mean Destination TTL',
  mean_ttl: 'Mean Packet TTL',
  mean_swin: 'Mean Client TCP Window',
  mean_dwin: 'Mean Server TCP Window',
  mean_tcp_window: 'Mean TCP Window',
  mean_tcp_rtt: 'Mean TCP RTT',
  proto_tcp_count: 'TCP Packet Count',
  proto_udp_count: 'UDP Flow Share',
  proto_other_count: 'Non-Standard Protocol Flows',
  tcp_syn_count: 'TCP SYN Flag Count',
  tcp_ack_count: 'TCP ACK Flag Count',
  tcp_fin_count: 'TCP FIN Flag Count',
  tcp_rst_count: 'TCP RST Flag Count',
  tcp_psh_count: 'TCP PSH Flag Count',
  tcp_urg_count: 'TCP URG Flag Count',
  delta_flow_count: 'Flow Initiation Surge Rate',
  delta_total_bytes: 'Bandwidth Volume Acceleration',
  delta_total_packets: 'Packet Transmission Velocity Delta',
  delta_ports: 'Port Space Expansion Delta',
  delta_iat: 'Inter-Arrival Timing Delta',
  rolling_total_bytes: 'Rolling Byte Volume',
  insufficient_history: 'Insufficient History',
  flow_duration: 'Flow Duration',
  src_bytes: 'Source Bytes',
  dst_bytes: 'Destination Bytes',
  tcp_flags: 'TCP Flags',
  network_state: 'Network State',
  attack_stage: 'Attack Stage',
  risk_score: 'Risk Score',
  job_id: 'Job ID',
  window_count: 'Window Count',
  syn_count: 'SYN Count',
  state_persistence: 'State Persistence',
  downstream_progression: 'Downstream Progression',
  network_service_discovery: 'Network Service Discovery',
  attack_trajectory: 'Attack Progression',
  attack_trajectory_detected: 'Attack Progression Detected',
  stable_equilibrium: 'Stable Baseline',
  benign_observation: 'Benign Observation',
  exploit_public_facing_application: 'Exploit Public-Facing Application',
  network_denial_of_service: 'Network Denial of Service',
}

export function formatDisplayLabel(raw: string | null | undefined): string {
  if (!raw) return ''
  const trimmed = String(raw).trim()
  const lower = trimmed.toLowerCase()

  if (EXACT_LABEL_MAP[lower]) {
    return EXACT_LABEL_MAP[lower]
  }

  // Split on underscores or dashes
  const parts = trimmed.split(/[_-]+/)
  const formattedParts = parts.map((part) => {
    const partLower = part.toLowerCase()
    if (ACRONYM_MAP[partLower]) {
      return ACRONYM_MAP[partLower]
    }
    // Capitalize first letter, preserve rest or lowercase
    return part.charAt(0).toUpperCase() + part.slice(1).toLowerCase()
  })

  return formattedParts.join(' ')
}

