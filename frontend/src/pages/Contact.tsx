import { Link } from 'react-router-dom'
import { ArrowRight, FileText, Mail, MessageSquare, ShieldCheck } from 'lucide-react'
import { Panel, SectionHeading } from '../components/Ui'

export function Contact() {
  return (
    <div className="page-stack page-enter contact-container" style={{ padding: '32px 0' }}>
      <div style={{ maxWidth: '920px', margin: '0 auto', width: '100%' }}>
        {/* Header */}
      <section style={{ textAlign: 'center', marginBottom: '36px' }}>
        <div style={{ display: 'inline-flex', alignItems: 'center', gap: '8px', padding: '4px 12px', borderRadius: '4px', background: 'var(--bg-secondary)', border: '1px solid var(--border)', fontSize: '11px', fontFamily: 'var(--mono)', color: 'var(--text-primary)', textTransform: 'uppercase', letterSpacing: '0.08em', marginBottom: '14px' }}>
          <MessageSquare size={13} />
          CONTACT & TECHNICAL SUPPORT
        </div>
        <h1 style={{ fontSize: '32px', fontWeight: 700, margin: '0 0 10px 0', color: 'var(--text-primary)', letterSpacing: '-0.02em' }}>
          Operational Support & Security Inquiries
        </h1>
        <p style={{ fontSize: '15px', color: 'var(--text-secondary)', maxWidth: '640px', margin: '0 auto', lineHeight: 1.6 }}>
          Reach the engineering team regarding deployment integration, vulnerability disclosure, PCAP schema validation, and scientific methodology.
        </p>
      </section>

      {/* 3 Inquiry Pillars */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: '16px', marginBottom: '32px' }}>
        <Panel>
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '12px' }}>
            <div style={{ width: '36px', height: '36px', borderRadius: '6px', background: 'var(--bg-secondary)', border: '1px solid var(--border)', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
              <Mail size={18} color="var(--text-primary)" />
            </div>
            <div>
              <h3 style={{ margin: 0, fontSize: '16px', fontWeight: 600, color: 'var(--text-primary)' }}>Technical Inquiries</h3>
              <span style={{ fontSize: '12px', color: 'var(--text-muted)' }}>Architecture & API Integration</span>
            </div>
          </div>
          <p style={{ fontSize: '13px', color: 'var(--text-secondary)', lineHeight: 1.55, margin: '0 0 14px 0' }}>
            For queries regarding the 45-feature continuous state representation, discrete 60-second tumbling windows, or offline air-gapped deployments.
          </p>
          <div style={{ fontSize: '12px', fontFamily: 'var(--mono)', color: 'var(--text-primary)', background: 'var(--bg-secondary)', padding: '8px 12px', borderRadius: '4px', border: '1px solid var(--border)' }}>
            support@nexsolve.internal
          </div>
        </Panel>

        <Panel>
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '12px' }}>
            <div style={{ width: '36px', height: '36px', borderRadius: '6px', background: 'var(--bg-secondary)', border: '1px solid var(--border)', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
              <ShieldCheck size={18} color="var(--text-primary)" />
            </div>
            <div>
              <h3 style={{ margin: 0, fontSize: '16px', fontWeight: 600, color: 'var(--text-primary)' }}>Security Disclosure</h3>
              <span style={{ fontSize: '12px', color: 'var(--text-muted)' }}>Vulnerability Reporting</span>
            </div>
          </div>
          <p style={{ fontSize: '13px', color: 'var(--text-secondary)', lineHeight: 1.55, margin: '0 0 14px 0' }}>
            We practice coordinated vulnerability disclosure. Please encrypt sensitive security disclosures using our published PGP engineering key.
          </p>
          <div style={{ fontSize: '12px', fontFamily: 'var(--mono)', color: 'var(--text-primary)', background: 'var(--bg-secondary)', padding: '8px 12px', borderRadius: '4px', border: '1px solid var(--border)' }}>
            security@nexsolve.internal
          </div>
        </Panel>

        <Panel>
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '12px' }}>
            <div style={{ width: '36px', height: '36px', borderRadius: '6px', background: 'var(--bg-secondary)', border: '1px solid var(--border)', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
              <FileText size={18} color="var(--text-primary)" />
            </div>
            <div>
              <h3 style={{ margin: 0, fontSize: '16px', fontWeight: 600, color: 'var(--text-primary)' }}>Research Collaboration</h3>
              <span style={{ fontSize: '12px', color: 'var(--text-muted)' }}>Academic & Industry Datasets</span>
            </div>
          </div>
          <p style={{ fontSize: '13px', color: 'var(--text-secondary)', lineHeight: 1.55, margin: '0 0 14px 0' }}>
            For research groups evaluating autoregressive temporal network state modeling, benchmark replications, or persistence baseline comparisons.
          </p>
          <div style={{ fontSize: '12px', fontFamily: 'var(--mono)', color: 'var(--text-primary)', background: 'var(--bg-secondary)', padding: '8px 12px', borderRadius: '4px', border: '1px solid var(--border)' }}>
            research@nexsolve.internal
          </div>
        </Panel>
      </div>

      {/* Security Principles Panel */}
      <Panel style={{ marginBottom: '24px' }}>
        <SectionHeading
          eyebrow="Data Handling Policy"
          title="Zero Telemetry & Air-Gapped Privacy Guarantees"
          description="NexSolve is designed to operate in fully air-gapped and self-contained environments."
        />
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(260px, 1fr))', gap: '16px', marginTop: '16px' }}>
          <div>
            <strong style={{ display: 'block', fontSize: '13px', color: 'var(--text-primary)', marginBottom: '4px' }}>
              Local Ingestion Only
            </strong>
            <p style={{ fontSize: '12.5px', color: 'var(--text-secondary)', lineHeight: 1.5, margin: 0 }}>
              Uploaded PCAP bytes and extracted temporal state vectors remain strictly confined to the local container process. No cloud sync, external analytics, or third-party telemetry.
            </p>
          </div>
          <div>
            <strong style={{ display: 'block', fontSize: '13px', color: 'var(--text-primary)', marginBottom: '4px' }}>
              Deterministic Cryptographic Provenance
            </strong>
            <p style={{ fontSize: '12.5px', color: 'var(--text-secondary)', lineHeight: 1.5, margin: 0 }}>
              Every analysis run computes an immutable SHA-256 hash over the raw wire capture to ensure forensic integrity and auditable chain of custody.
            </p>
          </div>
        </div>
      </Panel>

      {/* Action Footer */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '12px', borderTop: '1px solid var(--border)', paddingTop: '20px' }}>
        <div style={{ fontSize: '13px', color: 'var(--text-muted)' }}>
          Ready to test your packet captures against the temporal forecasting engine?
        </div>
        <div style={{ display: 'flex', gap: '10px' }}>
          <Link to="/workflow" className="button button-quiet" style={{ fontSize: '12px' }}>
            View Workflow
          </Link>
          <Link to="/console/analyze" className="button button-primary" style={{ fontSize: '12px', gap: '6px' }}>
            <span>START</span> <ArrowRight size={13} />
          </Link>
        </div>
      </div>
    </div>
  </div>
  )
}
