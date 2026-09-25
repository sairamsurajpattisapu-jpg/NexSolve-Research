import { useState } from 'react'
import { Link } from 'react-router-dom'
import {
  ArrowRight,
  Check,
  CheckCircle2,
  Copy,
  ExternalLink,
  Monitor,
  Shield,
  Terminal,
} from 'lucide-react'

const CLI_COMMANDS = [
  {
    cmd: 'nexsolve',
    label: 'Interactive Shell',
    desc: 'Launch interactive shell menu with native PCAP picker & diagnostics.',
  },
  {
    cmd: 'nexsolve analyze',
    label: 'Native PCAP Picker',
    desc: 'Select a PCAP and start an analysis.',
  },
  {
    cmd: 'nexsolve analyze capture.pcap',
    label: 'Direct Capture',
    desc: 'Analyze a specific capture.',
  },
  {
    cmd: 'nexsolve analyze capture.pcap --open',
    label: 'Analyze & Open',
    desc: 'Analyze the capture and open the investigation console.',
  },
  {
    cmd: 'nexsolve doctor',
    label: 'Diagnostics',
    desc: 'Check local NexSolve installation and dependencies.',
  },
  {
    cmd: 'nexsolve version',
    label: 'Version',
    desc: 'Show platform and CLI versions.',
  },
]

const WORKFLOW_STAGES = [
  {
    num: '01',
    title: 'PCAP',
    category: 'INGESTION',
    desc: 'Microsecond packet stream or file (.pcap, .pcapng) via passive tap.',
  },
  {
    num: '02',
    title: 'TEMPORAL NETWORK STATE',
    category: 'REPRESENTATION',
    desc: '45-dim continuous feature vector S_t across discrete 60s tumbling windows.',
  },
  {
    num: '03',
    title: 'ATTACK PROGRESSION',
    category: 'KINEMATICS',
    desc: '15-stage adversarial progression tracking grounded in transition priors.',
  },
  {
    num: '04',
    title: 'FORECAST',
    category: 'SIMULATION',
    desc: 'Autoregressive rollout across forward horizons (T+1 through T+5).',
  },
  {
    num: '05',
    title: 'EVIDENCE',
    category: 'ATTRIBUTION',
    desc: 'Counterfactual feature drivers, confidence intervals, and calibrated abstention.',
  },
  {
    num: '06',
    title: 'INVESTIGATION',
    category: 'AUDIT & CONSOLE',
    desc: 'Browser forensic console drilldown and 16-section self-contained audit packages.',
  },
]

const INSTALL_STEPS = [
  {
    num: '1',
    title: 'Clone Repository',
    cmd: 'git clone https://github.com/sairamsurajpattisapu-jpg/NexSolve-Research.git',
    note: 'Clones repository containing core engine, CLI, and web console.',
  },
  {
    num: '2',
    title: 'Install CLI in Editable Mode',
    cmd: 'pip install -e cli',
    note: 'Registers the global `nexsolve` command executable from any terminal directory.',
  },
  {
    num: '3',
    title: 'Verify Environment',
    cmd: 'nexsolve doctor',
    note: 'Validates Python 3.10+, Wireshark/TShark, PyShark, and sensor components.',
  },
]

export function CliQuickstartSection() {
  const [copiedCmd, setCopiedCmd] = useState<string | null>(null)

  const handleCopy = (text: string) => {
    void navigator.clipboard.writeText(text)
    setCopiedCmd(text)
    setTimeout(() => {
      setCopiedCmd(null)
    }, 2000)
  }

  return (
    <section className="landing-section cli-showcase-section" id="cli-quickstart">
      {/* Anchor shim for backwards compatibility with #workflow */}
      <div id="workflow" style={{ position: 'relative', top: '-70px' }} />

      {/* 1. SECTION HEADER (RESTRAINED HIERARCHY) */}
      <div className="section-header-block" style={{ textAlign: 'center', marginBottom: '36px' }}>
        <span className="section-eyebrow">CLI</span>
        <h2 className="section-heading-large" style={{ margin: '8px auto 12px auto' }}>
          Run it from the terminal.
          <br />
          Investigate it in the browser.
        </h2>
        <p className="section-desc" style={{ maxWidth: 640, margin: '0 auto' }}>
          Select a capture from the terminal. NexSolve analyzes the traffic.
          Continue the investigation in the browser.
        </p>
      </div>

      {/* 2. DUAL INTERFACE CARDS (TERMINAL VS CONSOLE) */}
      <div className="cli-dual-interface-grid">
        <div className="dual-card cli-side">
          <div className="dual-card-header">
            <div className="dual-icon-box">
              <Terminal size={18} />
            </div>
            <div>
              <span className="dual-tag">FAST &amp; HEADLESS</span>
              <h3 className="dual-title">NexSolve CLI</h3>
            </div>
          </div>
          <p className="dual-desc">
            For running analysis quickly. Select captures via native Windows file dialog, automate CI/CD
            regressions, or run headless audits without typing paths or switching contexts.
          </p>
          <ul className="dual-list">
            <li>
              <CheckCircle2 size={13} className="dual-check" />
              <span>Native Windows file picker (<code>nexsolve analyze</code>)</span>
            </li>
            <li>
              <CheckCircle2 size={13} className="dual-check" />
              <span>Zero-configuration global command executable anywhere</span>
            </li>
            <li>
              <CheckCircle2 size={13} className="dual-check" />
              <span>Automated browser launch with <code>--open</code> flag</span>
            </li>
          </ul>
        </div>

        <div className="dual-card console-side">
          <div className="dual-card-header">
            <div className="dual-icon-box console-icon">
              <Monitor size={18} />
            </div>
            <div>
              <span className="dual-tag">DEEP VISUALIZATION</span>
              <h3 className="dual-title">Web Investigation Console</h3>
            </div>
          </div>
          <p className="dual-desc">
            For investigating results visually. Explore communication graphs, scrub forward across
            T+1..T+5 prediction horizons, inspect counterfactual drivers, and export forensic reports.
          </p>
          <ul className="dual-list">
            <li>
              <CheckCircle2 size={13} className="dual-check" />
              <span>Multi-horizon forward attack rollout simulation (T+1 .. T+5)</span>
            </li>
            <li>
              <CheckCircle2 size={13} className="dual-check" />
              <span>15-stage adversarial progression tracking &amp; kinematics</span>
            </li>
            <li>
              <CheckCircle2 size={13} className="dual-check" />
              <span>Counterfactual feature attribution sensitivity drivers</span>
            </li>
          </ul>
        </div>
      </div>

      {/* 3. TERMINAL MOCKUP & COMPACT COMMAND ROWS */}
      <div className="cli-commands-layout">
        {/* Terminal Simulation */}
        <div className="terminal-showcase-panel">
          <div className="terminal-header">
            <div style={{ display: 'flex', gap: 6 }}>
              <span className="term-dot term-dot-red" />
              <span className="term-dot term-dot-yellow" />
              <span className="term-dot term-dot-green" />
            </div>
            <span className="term-title">terminal &middot; nexsolve analyze</span>
            <span className="term-badge">Illustrative CLI output</span>
          </div>

          <div
            className="terminal-body"
            tabIndex={0}
            aria-label="Illustrative terminal output showing nexsolve analyze"
          >
            <div className="term-command-line">
              <span className="term-prompt">$ </span>
              <span className="term-cmd">nexsolve analyze</span>
            </div>
            <div style={{ margin: '14px 0 10px 0', color: '#ffffff', fontWeight: 700 }}>
              NexSolve
              <br />
              <span style={{ fontSize: 11, color: '#a3a3a3', fontWeight: 400 }}>
                AI Network Attack Forecasting
              </span>
            </div>
            <div style={{ color: '#8a8a8a', fontSize: 11.5, margin: '8px 0 10px 0' }}>
              Select a PCAP...
              <br />
              <span style={{ color: '#d4d4d4' }}>[Native Windows File Picker Opened]</span>
              <br />
              <span style={{ color: '#ffffff' }}>Selected: perimeter_capture.pcap</span>
            </div>
            <div className="term-step-line">Creating analysis job...</div>
            <div className="term-step-line">Reconstructing network state (45-dim schema)...</div>
            <div className="term-step-line">Forecasting attack progression (T+1 &rarr; T+5)...</div>
            <div className="term-step-line">Building evidence &amp; uncertainty attribution...</div>
            <div style={{ color: '#ffffff', fontWeight: 600, margin: '12px 0 6px 0' }}>
              Analysis complete.
            </div>
            <div style={{ color: '#a3a3a3', fontSize: 11.5 }}>
              Opening web investigation console...
            </div>
          </div>

          <div className="terminal-footer">
            <span>Example workflow &middot; Native Windows file picker integration validated</span>
          </div>
        </div>

        {/* Compact Command Rows */}
        <div className="cli-command-cards-container">
          <div className="commands-header">
            <h3 style={{ fontSize: 16, fontWeight: 700, margin: 0, color: '#ffffff' }}>
              Supported CLI Commands
            </h3>
            <span style={{ fontSize: 11, color: '#737373', fontFamily: 'var(--mono)' }}>
              CLICK COPY TO USE
            </span>
          </div>

          <div className="commands-list">
            {CLI_COMMANDS.map((item) => (
              <div key={item.cmd} className="command-row">
                <div className="command-info">
                  <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 3 }}>
                    <code className="command-code">{item.cmd}</code>
                    <span className="command-label-badge">{item.label}</span>
                  </div>
                  <p className="command-desc">{item.desc}</p>
                </div>

                <button
                  type="button"
                  className={`command-copy-button ${copiedCmd === item.cmd ? 'is-copied' : ''}`}
                  onClick={() => handleCopy(item.cmd)}
                  aria-label={`Copy command ${item.cmd}`}
                  title="Copy command to clipboard"
                >
                  {copiedCmd === item.cmd ? (
                    <>
                      <Check size={12} />
                      <span>Copied</span>
                    </>
                  ) : (
                    <>
                      <Copy size={12} />
                      <span>Copy</span>
                    </>
                  )}
                </button>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* 4. PRODUCT WORKFLOW (TECHNICAL HORIZONTAL/VERTICAL ARCHITECTURE FLOW) */}
      <div className="architecture-workflow-container" style={{ marginTop: '56px' }}>
        <div style={{ textAlign: 'center', marginBottom: '28px' }}>
          <span className="section-eyebrow">PRODUCT WORKFLOW</span>
          <h3 className="section-heading-large" style={{ fontSize: 'clamp(20px, 2.5vw, 28px)', margin: '6px 0 8px 0' }}>
            System Architecture Flow
          </h3>
          <p className="section-desc" style={{ maxWidth: 640, margin: '0 auto', fontSize: '14px' }}>
            From raw packet capture to prospective trajectory forecasting and evidence-backed forensic audit.
          </p>
        </div>

        <div className="architecture-flow-strip">
          {WORKFLOW_STAGES.map((stage, idx) => (
            <div key={stage.num} className="arch-flow-node">
              <div className="arch-flow-inner">
                <div className="arch-flow-header">
                  <span className="arch-step-num">{stage.num}</span>
                  <span className="arch-step-category">{stage.category}</span>
                </div>
                <h4 className="arch-step-title">{stage.title}</h4>
                <p className="arch-step-desc">{stage.desc}</p>
              </div>
              {idx < WORKFLOW_STAGES.length - 1 && (
                <div className="arch-flow-divider" aria-hidden="true">
                  <span className="arch-divider-line" />
                  <ArrowRight size={13} className="arch-divider-arrow" />
                </div>
              )}
            </div>
          ))}
        </div>
      </div>

      {/* 5. LOCAL REPOSITORY INSTALLATION */}
      <div className="cli-install-box" style={{ marginTop: '48px' }}>
        <div className="install-box-header">
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 4 }}>
              <span className="install-pill">LOCAL REPOSITORY INSTALLATION</span>
              <span style={{ fontSize: 11, color: '#737373', fontFamily: 'var(--mono)' }}>DEVELOPMENT BUILD</span>
            </div>
            <h3 style={{ fontSize: 18, fontWeight: 700, margin: 0, color: '#ffffff' }}>
              Install the NexSolve CLI
            </h3>
          </div>

          <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
            <Link to="/console" className="button button-quiet" style={{ fontSize: 12, gap: 6 }}>
              <Monitor size={13} /> Open Console
            </Link>
            <a
              href="https://github.com/sairamsurajpattisapu-jpg/NexSolve-Research"
              target="_blank"
              rel="noopener noreferrer"
              className="button button-quiet"
              style={{ fontSize: 12, gap: 6 }}
            >
              <ExternalLink size={13} /> GitHub Repository
            </a>
          </div>
        </div>

        <div className="install-notice-banner">
          <Shield size={14} style={{ color: '#a3a3a3', flexShrink: 0, marginTop: 2 }} />
          <div>
            <strong style={{ color: '#ffffff' }}>PyPI publication status:</strong> NexSolve CLI is currently
            distributed directly via the open-source repository. To use the global command today, clone the
            repository and install in editable mode.
          </div>
        </div>

        <div className="install-steps-grid">
          {INSTALL_STEPS.map((step) => (
            <div key={step.num} className="install-step-card">
              <div className="step-num-badge">STEP {step.num}</div>
              <h4 className="step-title">{step.title}</h4>
              <p className="step-note">{step.note}</p>

              <div className="step-code-row">
                <code className="step-code">{step.cmd}</code>
                <button
                  type="button"
                  className={`step-copy-btn ${copiedCmd === step.cmd ? 'is-copied' : ''}`}
                  onClick={() => handleCopy(step.cmd)}
                  aria-label={`Copy command ${step.cmd}`}
                >
                  {copiedCmd === step.cmd ? <Check size={12} /> : <Copy size={12} />}
                </button>
              </div>
            </div>
          ))}
        </div>
      </div>
    </section>
  )
}

export default CliQuickstartSection
