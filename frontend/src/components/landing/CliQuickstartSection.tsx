import { useState } from 'react'
import { Link } from 'react-router-dom'
import {
  Check,
  CheckCircle2,
  Copy,
  ExternalLink,
  Monitor,
  Terminal,
  Shield,
} from 'lucide-react'

const CLI_COMMANDS = [
  {
    cmd: 'nexsolve',
    label: 'Interactive Launcher',
    desc: 'Interactive terminal menu with native PCAP picker & diagnostic sensor check.',
  },
  {
    cmd: 'nexsolve analyze',
    label: 'Native PCAP Picker',
    desc: 'Opens native Windows file dialog to select & analyze any .pcap or .pcapng.',
  },
  {
    cmd: 'nexsolve analyze capture.pcap',
    label: 'Direct Capture Analysis',
    desc: 'Directly parses and forecasts attack behavior from a specified capture file.',
  },
  {
    cmd: 'nexsolve analyze capture.pcap --open',
    label: 'Analyze & Open Console',
    desc: 'Runs full pipeline and automatically launches the web investigation console.',
  },
  {
    cmd: 'nexsolve doctor',
    label: 'Sensor Diagnostics',
    desc: 'Verifies Python runtime, dependencies, PyShark, and telemetry sensors.',
  },
  {
    cmd: 'nexsolve version',
    label: 'Platform & Metadata',
    desc: 'Displays installed version, platform details, and ML engine metadata.',
  },
]

const WORKFLOW_STEPS = [
  {
    step: '01',
    title: 'TERMINAL',
    subtitle: 'Run CLI Command',
    desc: 'Launch nexsolve or nexsolve analyze from PowerShell or bash.',
  },
  {
    step: '02',
    title: 'PCAP PICKER',
    subtitle: 'Native File Picker',
    desc: 'Native OS dialog opens to select .pcap or .pcapng without typing paths.',
  },
  {
    step: '03',
    title: 'ANALYSIS JOB',
    subtitle: 'Passive Processing',
    desc: 'Background engine extracts wire frames into 60s observation windows.',
  },
  {
    step: '04',
    title: 'TEMPORAL STATE',
    subtitle: '45-Dim State Vector',
    desc: 'Infers continuous feature states S_t capturing flow kinetics & burst dynamics.',
  },
  {
    step: '05',
    title: 'ATTACK PROGRESSION',
    subtitle: '15-Stage Lifecycle',
    desc: 'Maps observable telemetry to chronological kill-chain progression stages.',
  },
  {
    step: '06',
    title: 'T+1 → T+5',
    subtitle: 'Multi-Horizon Rollout',
    desc: 'LSTM neural world model projects +60s to +300s forward attack trajectories.',
  },
  {
    step: '07',
    title: 'WEB CONSOLE',
    subtitle: 'Visual Investigation',
    desc: 'Explore communication graphs, evidence drivers, and forensic reports.',
  },
]

const INSTALL_STEPS = [
  {
    num: '1',
    title: 'Clone Repository',
    cmd: 'git clone https://github.com/sairamsurajpattisapu-jpg/NexSolve-Research.git',
    note: 'Clones the local repository containing core engine, CLI, and web console.',
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

      {/* Section Header */}
      <div style={{ textAlign: 'center', marginBottom: '36px' }}>
        <div className="section-eyebrow-badge">
          <Terminal size={12} />
          <span>CLI-FIRST WORKFLOW & RECONSTRUCTION</span>
        </div>
        <h2 className="section-heading-large" style={{ margin: '12px auto' }}>
          From terminal to investigation.
        </h2>
        <p className="cli-showcase-quote">
          &ldquo;Run it from the terminal. Investigate it in the browser.&rdquo;
        </p>
        <p className="section-desc" style={{ maxWidth: 760, margin: '12px auto 0 auto' }}>
          NexSolve combines high-speed terminal execution with interactive browser forensics. Run native
          packet analysis without leaving your shell, then pivot directly to the web console for
          multi-horizon forward trajectories and counterfactual evidence.
        </p>
      </div>

      {/* 1. Dual Interface Architecture Explanation */}
      <div className="cli-dual-interface-grid">
        <div className="dual-card cli-side">
          <div className="dual-card-header">
            <div className="dual-icon-box">
              <Terminal size={18} />
            </div>
            <div>
              <span className="dual-tag">FAST & HEADLESS EXECUTION</span>
              <h3 className="dual-title">NexSolve CLI</h3>
            </div>
          </div>
          <p className="dual-desc">
            For running analysis quickly. Select captures via native Windows file dialog, automate CI/CD
            regressions, or run headless forensic audits without typing file paths or opening browser tabs.
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
              <span>Direct terminal progress and automated browser launching</span>
            </li>
          </ul>
        </div>

        <div className="dual-card console-side">
          <div className="dual-card-header">
            <div className="dual-icon-box console-icon">
              <Monitor size={18} />
            </div>
            <div>
              <span className="dual-tag" style={{ color: '#38bdf8' }}>DEEP FORENSIC VISUALIZATION</span>
              <h3 className="dual-title">Web Investigation Console</h3>
            </div>
          </div>
          <p className="dual-desc">
            For investigating results visually. Explore the reconstructed communication graph, scrub
            forward across T+1..T+5 prediction horizons, inspect counterfactual drivers, and export forensic reports.
          </p>
          <ul className="dual-list">
            <li>
              <CheckCircle2 size={13} className="dual-check" />
              <span>Multi-horizon forward attack rollout simulation (T+1 .. T+5)</span>
            </li>
            <li>
              <CheckCircle2 size={13} className="dual-check" />
              <span>15-stage adversarial progression tracking & kinematics</span>
            </li>
            <li>
              <CheckCircle2 size={13} className="dual-check" />
              <span>Counterfactual feature attribution sensitivity drivers</span>
            </li>
          </ul>
        </div>
      </div>

      {/* 2. Visual Pipeline Flow */}
      <div className="cli-pipeline-container">
        <div className="cli-pipeline-header">
          <span className="pipeline-header-label">END-TO-END PRODUCT PIPELINE</span>
          <span className="pipeline-header-sub">From raw wire capture to forward horizon intelligence</span>
        </div>

        <div className="cli-flow-strip">
          {WORKFLOW_STEPS.map((ws, idx) => (
            <div key={ws.step} className="cli-flow-node">
              <div className="flow-node-inner">
                <div className="flow-step-tag">{ws.step}</div>
                <div className="flow-node-title">{ws.title}</div>
                <div className="flow-node-sub">{ws.subtitle}</div>
                <p className="flow-node-desc">{ws.desc}</p>
              </div>
              {idx < WORKFLOW_STEPS.length - 1 && (
                <div className="flow-node-arrow" aria-hidden="true">
                  &rarr;
                </div>
              )}
            </div>
          ))}
        </div>
      </div>

      {/* 3. Terminal Mockup & Supported Commands Reference */}
      <div className="cli-commands-layout">
        {/* Terminal Simulation */}
        <div className="terminal-showcase-panel">
          <div className="terminal-header">
            <div style={{ display: 'flex', gap: 6 }}>
              <span className="term-dot term-dot-red" />
              <span className="term-dot term-dot-yellow" />
              <span className="term-dot term-dot-green" />
            </div>
            <span className="term-title">PowerShell &middot; nexsolve analyze</span>
            <span className="term-badge">Illustrative CLI output</span>
          </div>
          <div className="terminal-body" tabIndex={0} aria-label="Illustrative terminal output showing nexsolve analyze">
            <div className="term-command-line">
              <span className="term-prompt">$ </span>
              <span className="term-cmd">nexsolve analyze capture.pcap --open</span>
            </div>
            <div style={{ margin: '14px 0 10px 0', color: '#ffffff', fontWeight: 700 }}>
              NexSolve
              <br />
              <span style={{ fontSize: 11, color: '#a1a1aa', fontWeight: 400 }}>AI Network Attack Forecasting</span>
            </div>
            <div style={{ color: '#71717a', fontSize: 11.5, margin: '8px 0 10px 0' }}>
              Selected capture:
              <br />
              <span style={{ color: '#38bdf8' }}>capture.pcap</span>
            </div>
            <div className="term-step-line">Creating analysis job...</div>
            <div className="term-step-line">Reconstructing network state...</div>
            <div className="term-step-line">Forecasting attack progression...</div>
            <div className="term-step-line">Building evidence...</div>
            <div style={{ color: '#10b981', fontWeight: 600, margin: '12px 0 6px 0' }}>
              Analysis complete.
            </div>
            <div style={{ color: '#e4e4e7', fontSize: 11.5 }}>
              Opening investigation console...
            </div>
          </div>
          <div className="terminal-footer">
            <span>Example workflow &middot; Native Windows file picker integration validated</span>
          </div>
        </div>

        {/* Command Reference Cards */}
        <div className="cli-command-cards-container">
          <div className="commands-header">
            <h3 style={{ fontSize: 17, fontWeight: 700, margin: 0, color: '#ffffff' }}>
              Supported CLI Commands
            </h3>
            <span style={{ fontSize: 11, color: '#71717a', fontFamily: 'var(--mono)' }}>
              CLICK COPY TO USE
            </span>
          </div>

          <div className="commands-list">
            {CLI_COMMANDS.map((item) => (
              <div key={item.cmd} className="command-card">
                <div className="command-info">
                  <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 4 }}>
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

      {/* 4. Concise Truthful Installation Section */}
      <div className="cli-install-box">
        <div className="install-box-header">
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 4 }}>
              <span className="install-pill">LOCAL REPOSITORY INSTALLATION</span>
              <span style={{ fontSize: 11, color: '#a1a1aa', fontFamily: 'var(--mono)' }}>DEVELOPMENT BUILD</span>
            </div>
            <h3 style={{ fontSize: 20, fontWeight: 700, margin: 0, color: '#ffffff' }}>
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
          <Shield size={14} style={{ color: '#38bdf8', flexShrink: 0, marginTop: 2 }} />
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
