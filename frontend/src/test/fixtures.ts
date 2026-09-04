import type { AnalysisData } from '../types/api'

export const fixture: AnalysisData = {
  status: { analysis_id: 'production-cic-ids2017', status: 'completed', windows: 2 },
  health: { service_status: 'ok', model_loaded: true, model_version: 'research prototype', feature_count: 46, sequence_length: 8, K: 5, packet_features_available: false },
  results: {
    analysis_id: 'production-cic-ids2017',
    status: 'completed',
    validation: {
      status: 'VALID', rows: 2, columns: ['packet_count'], dtypes: { packet_count: 'int64' }, missing_columns: [], null_counts: { packet_count: 0 }, null_ratios: { packet_count: 0 }, constant_columns: [], numeric_ranges: {}, protocol_counts: { TCP: 12 },
      window: { unit: 'UTC epoch seconds', seconds: 60, start_min: 0, start_max: 60, ordered: true },
      model_compatibility: { flow_features_available: false, packet_features_available: true, labels_available: false, forecast_model_ready: false, reason: 'packet-only' },
    },
    traffic: { status: 'completed', windows: 2, packets: 12, tcp: 12, udp: 0, icmp: 0, retransmissions: 1, fragmented_packets: 0, protocol_counts: { TCP: 12 }, windows_data: [
      { window_start: 0, window_end: 60, packet_count: 8, tcp_count: 8, udp_count: 0, icmp_count: 0, tcp_retransmission_count: 1, tcp_retransmission_rate: .1, port_scan_score: .2, fragment_count: 0, fragment_ratio: 0, packet_size_mean: 100, payload_mean: 20, protocol_counts: { TCP: 8 } },
      { window_start: 60, window_end: 120, packet_count: 4, tcp_count: 4, udp_count: 0, icmp_count: 0, tcp_retransmission_count: 0, tcp_retransmission_rate: 0, port_scan_score: .8, fragment_count: 0, fragment_ratio: 0, packet_size_mean: 100, payload_mean: 20, protocol_counts: { TCP: 4 } },
    ] },
    detection: {
      status: 'completed', detection_mode: 'traffic_heuristics', model_prediction_available: false, windows_analyzed: 2, detected_events: 1, risk_score: 70, average_window_risk: 45, threat_level: 'high', risk_method: 'test method',
      findings: [{ finding_id: 'window-2', window_id: 1, timestamp: '2026-01-01T00:01:00Z', prediction: 'suspicious_traffic', attack_category: 'network_reconnaissance', severity: 'high', confidence: null, risk_score: 70, evidence: [{ type: 'port_scan_indicator', value: .8, message: 'Traffic-derived port-scan score is at least 0.50.' }], recommendation: 'Review the source and destination context.' }],
    },
  },
  report: {
    report_id: 'production-cic-ids2017', status: 'completed', metadata: { name: 'CIC-IDS2017 packet windows', kind: 'production_parquet' }, validation: {} as AnalysisData['results']['validation'], traffic: {} as AnalysisData['results']['traffic'], detection: {} as AnalysisData['results']['detection'],
  },
}
