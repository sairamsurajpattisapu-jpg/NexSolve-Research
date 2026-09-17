import { useState } from 'react'
import { Link } from 'react-router-dom'
import { ArrowRight, ChevronDown, HelpCircle } from 'lucide-react'

interface FaqItem {
  id: string
  category: string
  question: string
  answer: string
}

const FAQ_ITEMS: FaqItem[] = [
  {
    id: 'what-is-nexsolve',
    category: 'Product Overview',
    question: 'What is NexSolve?',
    answer:
      'NexSolve is a standalone cybersecurity platform designed for AI-based network attack forecasting. Rather than solely detecting attacks after payloads execute or security breaches occur, NexSolve reconstructs continuous network-state behavior over discrete 60-second temporal windows, simulates prospective dynamics using an autoregressive World Model, and forecasts attack progression across forward lookahead horizons (T+1 through T+5) alongside verifiable feature evidence.',
  },
  {
    id: 'network-data-support',
    category: 'Data Ingestion',
    question: 'What network data can NexSolve analyze?',
    answer:
      'NexSolve analyzes raw packet streams, libpcap captures (.pcap), next-generation packet captures (.pcapng), and pre-aggregated 60-second window CSV telemetry adhering strictly to the canonical 45-feature schema. Ingestion is passive and non-intrusive, requiring no host agents, payload decryption, or active network probing.',
  },
  {
    id: 'pcap-analysis',
    category: 'Data Ingestion',
    question: 'Does NexSolve analyze PCAP files?',
    answer:
      'Yes. NexSolve natively ingests microsecond-precision .pcap and .pcapng files up to 250 MB per capture. It parses packet headers, reconstructs bidirectional 5-tuple communication flows, measures inter-arrival times and packet size distributions, and segments the wire telemetry into ordered 60-second temporal windows.',
  },
  {
    id: 'post-upload-pipeline',
    category: 'Pipeline Workflow',
    question: 'What happens after I upload a PCAP?',
    answer:
      'Once uploaded, the capture passes through an 8-stage pipeline: (1) Ingest & byte validation, (2) Header normalization, (3) Bidirectional flow reconstruction, (4) 45-feature continuous state representation, (5) Graph topology & centrality analysis, (6) Autoregressive World Model rollout simulation, (7) Multi-horizon attack forecasting, and (8) Counterfactual feature attribution and MITRE behavioral interpretation.',
  },
  {
    id: 'attack-forecasting-meaning',
    category: 'Forecasting Science',
    question: 'What does attack forecasting mean?',
    answer:
      'Attack forecasting is the prospective projection of network risk and adversarial lifecycle progression into the future before volumetric impacts manifest. Unlike traditional signature or anomaly alerts that trigger reactively upon seeing malicious bytes, NexSolve projects how the network state S_t will evolve over prospective intervals T+1, T+2, T+3, and T+5 (+60s to +300s into the future).',
  },
  {
    id: 'forecast-horizons',
    category: 'Forecasting Science',
    question: 'How far into the future can NexSolve forecast?',
    answer:
      'NexSolve forecasts across 5 forward discrete horizons: T+1 (+60 seconds), T+2 (+120 seconds), T+3 (+180 seconds), and T+5 (+300 seconds). As lookahead horizon deepens, epistemic uncertainty naturally widens, which NexSolve explicitly communicates through confidence decay indicators.',
  },
  {
    id: 'attack-probability',
    category: 'Forecasting Science',
    question: 'What is attack probability?',
    answer:
      'Point attack probability p_h represents the model’s predicted conditional likelihood that an active attack state will be present during a specific discrete forward window T+h, conditioned on the historical sequence context S_{t-7..t} and simulated state S_{t+h}. Probabilities represent raw model activations and are explicitly flagged when uncalibrated.',
  },
  {
    id: 'cumulative-risk',
    category: 'Forecasting Science',
    question: 'What is cumulative risk?',
    answer:
      'Cumulative risk Risk(K) quantifies the compounding likelihood that an attack manifests at least once across the entire forward lookahead window up to horizon K. It is calculated mathematically as Risk(K) = 1 - ∏_{h=1}^K (1 - p_h), assuming conditional independence across steps. This gives security analysts a single metric for overall near-term threat exposure.',
  },
  {
    id: 'forecast-explanation',
    category: 'Explainability & Evidence',
    question: 'How does NexSolve explain a forecast?',
    answer:
      'NexSolve explains predictions using counterfactual perturbation sensitivity analysis rather than synthetic SHAP approximations. It evaluates the mathematical partial derivatives ∂p/∂x_i by perturbing canonical features (such as inter-arrival time variance, SYN/ACK ratios, and byte rate derivatives) to isolate the exact wire telemetry drivers responsible for elevating the risk curve.',
  },
  {
    id: 'attack-progression',
    category: 'Attack Progression',
    question: 'What is attack progression?',
    answer:
      'Attack progression is the chronological trajectory of an adversary across sequential lifecycle phases: Reconnaissance → Probe Scan → Weaponization & Delivery → Exploitation → Lateral Movement → Exfiltration / Impact. NexSolve maps detected historical behavior to predicted prospective phases, giving defenders advance notice of impending kill-chain escalation.',
  },
  {
    id: 'replace-ids',
    category: 'Security Architecture',
    question: 'Does NexSolve replace an IDS?',
    answer:
      'No. NexSolve does not replace signature-based intrusion detection systems (such as Snort or Suricata) or next-gen firewalls. Instead, it operates as a complementary temporal predictive layer. While an IDS matches known patterns in current packets, NexSolve analyzes macro-level state transitions and projects prospective trajectories.',
  },
  {
    id: 'replace-firewall',
    category: 'Security Architecture',
    question: 'Does NexSolve replace a firewall?',
    answer:
      'No. NexSolve is a passive analytical and forecasting engine. It does not perform active inline packet dropping, TCP RST injection, or firewall rule reconfiguration. It provides security operations centers (SOC) with advance intelligence to inform deliberate mitigation actions.',
  },
  {
    id: 'guaranteed-attacks',
    category: 'Forecasting Science',
    question: 'Does NexSolve guarantee an attack will happen?',
    answer:
      'No. Forecasting is probabilistic simulation, not deterministic certainty. A high attack probability indicates that current traffic kinematics closely mirror historical transition paths leading to compromise. Network conditions can alter if defenders intervene or if adversary objectives change.',
  },
  {
    id: 'forecast-uncertainty',
    category: 'Forecasting Science',
    question: 'How should forecast uncertainty be interpreted?',
    answer:
      'Forecast uncertainty reflects model confidence decay over time. As the horizon expands from T+1 to T+5, the prediction interval widens. Analysts should treat T+1 and T+2 predictions with high operational urgency for immediate verification, while T+5 projections provide strategic trajectory awareness.',
  },
  {
    id: 'unsupported-traffic',
    category: 'Data Ingestion',
    question: 'Can NexSolve analyze unsupported traffic?',
    answer:
      'NexSolve requires standardized IPv4/IPv6 packet structures with identifiable TCP, UDP, or ICMP transport layers. Non-IP frames (such as pure Layer 2 protocols) or fragmented frames missing header boundaries are safely quarantined during the Ingest stage.',
  },
  {
    id: 'unsupported-telemetry',
    category: 'Data Ingestion',
    question: 'How is unsupported telemetry handled?',
    answer:
      'When telemetry lacks required 60-second boundary consistency or historical depth (< 8 temporal windows), NexSolve enforces calibrated abstention. The system explicitly withholds predictions rather than generating hallucinated or misleading forecasts.',
  },
  {
    id: 'feature-fabrication',
    category: 'Scientific Integrity',
    question: 'Does NexSolve fabricate unavailable features?',
    answer:
      'Never. NexSolve operates under a strict Zero-Fabrication Contract. Metrics that cannot be genuinely observed from passive packet taps—most notably mean_tcp_rtt—are permanently excluded from the 45-feature schema rather than zero-filled, imputed, or synthetically approximated.',
  },
  {
    id: 'mitre-mapping-representation',
    category: 'Explainability & Evidence',
    question: 'What does the MITRE ATT&CK mapping represent?',
    answer:
      'MITRE ATT&CK classifications in NexSolve represent contextual behavioral interpretations, not direct payload signature proofs. They correlate observed state patterns (e.g., high outbound port fan-out) with established tactics (e.g., T1046 Network Service Discovery) to aid human analyst comprehension.',
  },
  {
    id: 'report-generation',
    category: 'Reporting & Export',
    question: 'Can I generate a report?',
    answer:
      'Yes. NexSolve provides an integrated Reports suite. Users can inspect comprehensive executive and forensic reports, download the complete audit trail as structured JSON with cryptographic provenance hashes, or export clean print/PDF versions for incident documentation.',
  },
  {
    id: 'system-limitations',
    category: 'Scientific Integrity',
    question: 'What are the limitations?',
    answer:
      'Key limitations include: (1) Minimum lookback requirement: requires at least 8 continuous 60-second windows (8 minutes) for calibrated sequence modeling; (2) Passive visibility: cannot inspect encrypted payload contents; (3) Epistemic decay: forecast uncertainty compounds past T+3; and (4) Out-of-distribution inputs: novel attack mechanisms exhibiting zero historical baseline similarity will trigger lower confidence scores or abstention.',
  },
]

export function Faq() {
  const [openIds, setOpenIds] = useState<Set<string>>(new Set(['what-is-nexsolve', 'attack-forecasting-meaning', 'feature-fabrication']))
  const [activeCategory, setActiveCategory] = useState<string>('ALL')

  const toggleItem = (id: string) => {
    setOpenIds((prev) => {
      const next = new Set(prev)
      if (next.has(id)) {
        next.delete(id)
      } else {
        next.add(id)
      }
      return next
    })
  }

  const categories = ['ALL', ...Array.from(new Set(FAQ_ITEMS.map((item) => item.category)))]

  const filteredItems = activeCategory === 'ALL'
    ? FAQ_ITEMS
    : FAQ_ITEMS.filter((item) => item.category === activeCategory)

  return (
    <div className="page-stack page-enter" style={{ maxWidth: '980px', margin: '0 auto', width: '100%', padding: '32px 16px' }}>
      {/* Header */}
      <section style={{ textAlign: 'center', marginBottom: '36px' }}>
        <div style={{ display: 'inline-flex', alignItems: 'center', gap: '8px', padding: '4px 12px', borderRadius: '4px', background: 'var(--bg-secondary)', border: '1px solid var(--border)', fontSize: '11px', fontFamily: 'var(--mono)', color: 'var(--text-primary)', textTransform: 'uppercase', letterSpacing: '0.08em', marginBottom: '14px' }}>
          <HelpCircle size={13} />
          FREQUENTLY ASKED QUESTIONS
        </div>
        <h1 style={{ fontSize: '32px', fontWeight: 700, margin: '0 0 10px 0', color: 'var(--text-primary)', letterSpacing: '-0.02em' }}>
          Technical & Operational FAQ
        </h1>
        <p style={{ fontSize: '15px', color: 'var(--text-secondary)', maxWidth: '640px', margin: '0 auto', lineHeight: 1.6 }}>
          Comprehensive answers regarding data ingestion, 45-feature canonical contracts, World Model forecasting, counterfactual explanations, and operational boundaries.
        </p>
      </section>

      {/* Category Filter Pills */}
      <div style={{ display: 'flex', flexWrap: 'wrap', gap: '8px', justifyContent: 'center', marginBottom: '28px' }}>
        {categories.map((cat) => (
          <button
            key={cat}
            type="button"
            onClick={() => setActiveCategory(cat)}
            className={`button ${activeCategory === cat ? 'button-primary' : 'button-quiet'}`}
            style={{ fontSize: '12px', height: '30px', padding: '0 12px' }}
          >
            {cat}
          </button>
        ))}
      </div>

      {/* Accordion List */}
      <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
        {filteredItems.map((item) => {
          const isOpen = openIds.has(item.id)
          return (
            <div
              key={item.id}
              style={{
                background: 'var(--bg-surface)',
                border: '1px solid var(--border)',
                borderRadius: '8px',
                overflow: 'hidden',
                transition: 'border-color 0.15s ease',
              }}
            >
              <button
                type="button"
                onClick={() => toggleItem(item.id)}
                aria-expanded={isOpen}
                aria-controls={`faq-answer-${item.id}`}
                id={`faq-btn-${item.id}`}
                style={{
                  width: '100%',
                  padding: '16px 20px',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'space-between',
                  background: 'none',
                  border: 'none',
                  cursor: 'pointer',
                  textAlign: 'left',
                  color: 'var(--text-primary)',
                  fontSize: '15px',
                  fontWeight: 600,
                  gap: '12px',
                }}
              >
                <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                  <span style={{ fontSize: '10px', fontFamily: 'var(--mono)', color: 'var(--text-muted)', textTransform: 'uppercase', padding: '2px 6px', background: 'var(--bg-secondary)', borderRadius: '3px', border: '1px solid var(--border)' }}>
                    {item.category}
                  </span>
                  <span>{item.question}</span>
                </div>
                <ChevronDown
                  size={16}
                  style={{
                    color: 'var(--text-muted)',
                    transform: isOpen ? 'rotate(180deg)' : 'rotate(0deg)',
                    transition: 'transform 0.2s ease',
                    flexShrink: 0,
                  }}
                />
              </button>

              {isOpen && (
                <div
                  id={`faq-answer-${item.id}`}
                  role="region"
                  aria-labelledby={`faq-btn-${item.id}`}
                  style={{
                    padding: '0 20px 18px 20px',
                    fontSize: '13.5px',
                    lineHeight: 1.65,
                    color: 'var(--text-secondary)',
                    borderTop: '1px solid var(--border)',
                    paddingTop: '14px',
                  }}
                >
                  {item.answer}
                </div>
              )}
            </div>
          )
        })}
      </div>

      {/* Bottom Help Banner */}
      <div style={{ marginTop: '36px', padding: '24px', background: 'var(--bg-secondary)', border: '1px solid var(--border)', borderRadius: '8px', textAlign: 'center' }}>
        <h3 style={{ margin: '0 0 6px 0', fontSize: '16px', fontWeight: 600, color: 'var(--text-primary)' }}>
          Have more questions or need technical integration guidance?
        </h3>
        <p style={{ margin: '0 0 16px 0', fontSize: '13px', color: 'var(--text-muted)' }}>
          Review the formal mathematical specification or inspect the live analysis workflow.
        </p>
        <div style={{ display: 'flex', gap: '10px', justifyContent: 'center', flexWrap: 'wrap' }}>
          <Link to="/workflow" className="button button-quiet" style={{ fontSize: '12px' }}>
            How It Works
          </Link>
          <Link to="/research" className="button button-quiet" style={{ fontSize: '12px' }}>
            Research Specification
          </Link>
          <Link to="/console/analyze" className="button button-primary" style={{ fontSize: '12px', gap: '6px' }}>
            <span>START</span> <ArrowRight size={13} />
          </Link>
        </div>
      </div>
    </div>
  )
}
