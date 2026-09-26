import { useState } from 'react'
import { Link } from 'react-router-dom'
import {
  ArrowRight,
  Check,
  CheckCircle2,
  Copy,
  ExternalLink,
  HelpCircle,
  Monitor,
  Shield,
  Terminal,
} from 'lucide-react'

// Step-by-Step Guide Stages (Section 4)
const STEP_BY_STEP_WORKFLOW = [
  {
    step: '01',
    title: 'Install NexSolve',
    desc: 'Install the NexSolve CLI in editable mode from your local workspace.',
    cmd: 'pip install -e ./cli',
  },
  {
    step: '02',
    title: 'Open Terminal',
    desc: 'Launch PowerShell, Command Prompt, or your preferred terminal shell.',
    cmd: 'nexsolve',
  },
  {
    step: '03',
    title: 'Run Analysis',
    desc: 'Launch interactive PCAP analysis pipeline from the terminal.',
    cmd: 'nexsolve analyze',
  },
  {
    step: '04',
    title: 'Select Capture',
    desc: 'Choose a .pcap or .pcapng file via native picker or direct path argument.',
    cmd: 'nexsolve analyze capture.pcap',
  },
  {
    step: '05',
    title: 'Wait for Analysis',
    desc: 'Engine extracts 45 continuous features across discrete 60s windows.',
    cmd: null,
  },
  {
    step: '06',
    title: 'Open Investigation Console',
    desc: 'Launch browser console automatically to inspect forensic findings.',
    cmd: 'nexsolve analyze capture.pcap --open',
  },
  {
    step: '07',
    title: 'Inspect Forecast & Evidence',
    desc: 'Scrub lookaheads T+1..T+5, review feature drivers, and download reports.',
    cmd: null,
  },
]

// Actual Supported Commands from cli/src/nexsolve/main.py (Section 5)
interface CommandItem {
  cmd: string
  label: string
  desc: string
  category: 'CORE' | 'BENCHMARKING' | 'DATASETS' | 'DIAGNOSTICS & SYSTEM' | 'FORENSIC AUDIT'
  flags?: string
}

const COMMAND_REFERENCE: CommandItem[] = [
  // CORE
  {
    cmd: 'nexsolve',
    label: 'Interactive Shell',
    desc: 'Launch interactive shell menu with native PCAP picker & diagnostics.',
    category: 'CORE',
    flags: '-v, --version',
  },
  {
    cmd: 'nexsolve analyze',
    label: 'Native PCAP Picker',
    desc: 'Select a PCAP via native file dialog and execute the analysis pipeline.',
    category: 'CORE',
    flags: '--open, -o/--report-out, -q/--quiet, --json, --server, --timeout',
  },
  {
    cmd: 'nexsolve analyze capture.pcap',
    label: 'Direct Capture',
    desc: 'Analyze a specific network capture file path directly.',
    category: 'CORE',
    flags: '--open, --json, -o/--report-out, -q/--quiet, --poll-interval',
  },
  {
    cmd: 'nexsolve analyze capture.pcap --open',
    label: 'Analyze & Open',
    desc: 'Analyze capture and automatically open the investigation console in browser.',
    category: 'CORE',
    flags: '--open, -o/--report-out, --server, --web-url',
  },
  {
    cmd: 'nexsolve analyze capture.pcap --quiet',
    label: 'Headless / Quiet Mode',
    desc: 'Suppress banner and intermediate updates; print final forensic summary.',
    category: 'CORE',
    flags: '-q, --quiet, --no-color, --json',
  },

  // BENCHMARKING
  {
    cmd: 'nexsolve benchmark',
    label: 'Standardized Benchmark',
    desc: 'Run standardized input-parity benchmark comparing World Model against baselines.',
    category: 'BENCHMARKING',
    flags: 'dataset, --model, --horizons, --embargo-seconds, -o/--output, --seed, --json',
  },
  {
    cmd: 'nexsolve evaluate',
    label: 'Forecasting Performance',
    desc: 'Evaluate model forecasting accuracy across discrete horizons (T+1 to T+5).',
    category: 'BENCHMARKING',
    flags: 'dataset, --model, --horizons, --embargo-seconds, --holdout-family, --json',
  },

  // DATASETS
  {
    cmd: 'nexsolve evaluate unsw',
    label: 'UNSW Evaluation',
    desc: 'Evaluate prospective forecasting calibration against UNSW-NB15 ground truth.',
    category: 'DATASETS',
    flags: '--horizons "1,2,3,5", --embargo-seconds 60.0, --seed 42',
  },
  {
    cmd: 'nexsolve benchmark unsw',
    label: 'UNSW Benchmark',
    desc: 'Run input-parity comparison between Persistence and Logistic Regression on UNSW.',
    category: 'DATASETS',
    flags: '--model checkpoints/, -o artifacts/unsw_benchmark, --json',
  },
  {
    cmd: 'nexsolve evaluate cic',
    label: 'CIC-IDS2017 Evaluation',
    desc: 'Evaluate multi-horizon forecast accuracy on CIC-IDS2017 intrusion benchmark.',
    category: 'DATASETS',
    flags: '--horizons "1,2,3,5", --json',
  },

  // DIAGNOSTICS & SYSTEM
  {
    cmd: 'nexsolve doctor',
    label: 'System Diagnostics',
    desc: 'Verify Python 3.10+, Wireshark/TShark, PyShark, sensors, and backend connectivity.',
    category: 'DIAGNOSTICS & SYSTEM',
    flags: '--server, --json, --no-color',
  },
  {
    cmd: 'nexsolve version',
    label: 'Version Information',
    desc: 'Show platform, CLI, model checkpoint, and 45-feature schema version details.',
    category: 'DIAGNOSTICS & SYSTEM',
    flags: '--json, --no-color',
  },

  // FORENSIC AUDIT
  {
    cmd: 'nexsolve status <job_id>',
    label: 'Job Status',
    desc: 'Check current processing status and stage of an asynchronous analysis job.',
    category: 'FORENSIC AUDIT',
    flags: 'job_id, --server, --json, -q/--quiet, --verbose',
  },
  {
    cmd: 'nexsolve report <job_id>',
    label: 'Forensic Report',
    desc: 'Retrieve and download standalone printable HTML or JSON forensic report.',
    category: 'FORENSIC AUDIT',
    flags: 'job_id, --format [html|json], -o/--output <path>',
  },
  {
    cmd: 'nexsolve evidence <job_id>',
    label: 'Evidence Inspection',
    desc: 'Inspect cryptographic capture fingerprint, protocol capabilities, and evidence fusion.',
    category: 'FORENSIC AUDIT',
    flags: 'job_id, --entity <ip>, --server, --json',
  },
  {
    cmd: 'nexsolve progression <job_id>',
    label: 'Attack Progression',
    desc: 'Inspect 15-stage canonical attack progression, MITRE techniques, and kinematics.',
    category: 'FORENSIC AUDIT',
    flags: 'job_id, -q/--quiet, --json',
  },
]

// 6 Architecture Workflow Stages (Tested in cliQuickstartSection.test.tsx)
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

// Local Installation Steps
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
  const [selectedCategory, setSelectedCategory] = useState<string>('ALL')

  const handleCopy = (text: string) => {
    void navigator.clipboard.writeText(text)
    setCopiedCmd(text)
    setTimeout(() => {
      setCopiedCmd(null)
    }, 2000)
  }

  const categories = ['ALL', 'CORE', 'BENCHMARKING', 'DATASETS', 'DIAGNOSTICS & SYSTEM', 'FORENSIC AUDIT']

  const filteredCommands =
    selectedCategory === 'ALL'
      ? COMMAND_REFERENCE
      : COMMAND_REFERENCE.filter((c) => c.category === selectedCategory)

  return (
    <section className="landing-section cli-showcase-section" id="cli-quickstart">
      {/* Anchor shim for backwards compatibility with #workflow */}
      <div id="workflow" style={{ position: 'relative', top: '-70px' }} />

      {/* 1. HERO / SECTION HEADER (RESTRAINED HIERARCHY) */}
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
      <div className="cli-dual-interface-grid" style={{ marginBottom: '40px' }}>
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

      {/* 3. STEP-BY-STEP WORKFLOW GUIDE (Section 4 Requirement) */}
      <div className="cli-step-guide-section" style={{ marginBottom: '48px' }}>
        <div style={{ textAlign: 'center', marginBottom: '24px' }}>
          <span className="section-eyebrow">STEP-BY-STEP WORKFLOW</span>
          <h3 style={{ fontSize: 'clamp(19px, 2.4vw, 26px)', fontWeight: 700, margin: '6px 0 8px 0', color: 'var(--ns-text-primary)' }}>
            Analysis in Seven Discrete Steps
          </h3>
          <p style={{ fontSize: '13.5px', color: 'var(--ns-text-secondary)', maxWidth: '620px', margin: '0 auto' }}>
            Follow this operational sequence to install, ingest wire telemetry, and explore prospective trajectories.
          </p>
        </div>

        <div className="cli-steps-grid">
          {STEP_BY_STEP_WORKFLOW.map((item) => (
            <div key={item.step} className="cli-step-card">
              <div className="cli-step-top">
                <span className="cli-step-num">{item.step}</span>
                <h4 className="cli-step-title">{item.title}</h4>
              </div>
              <p className="cli-step-desc">{item.desc}</p>
              {item.cmd ? (
                <div className="cli-step-cmd-box">
                  <code className="cli-step-code">{item.cmd}</code>
                  <button
                    type="button"
                    className={`cli-step-copy-btn ${copiedCmd === item.cmd ? 'is-copied' : ''}`}
                    onClick={() => handleCopy(item.cmd!)}
                    aria-label={`Copy step ${item.step} command: ${item.cmd}`}
                    title="Copy command to clipboard"
                  >
                    {copiedCmd === item.cmd ? <Check size={11} /> : <Copy size={11} />}
                  </button>
                </div>
              ) : (
                <div className="cli-step-cmd-box cli-step-cmd-empty">
                  <span style={{ fontSize: '10.5px', color: 'var(--ns-text-muted)', fontFamily: 'var(--mono)' }}>
                    AUTOMATIC ENGINE PROCESS
                  </span>
                </div>
              )}
            </div>
          ))}
        </div>
      </div>

      {/* 4. TERMINAL SIMULATION & QUICK ACCESS (Preserves illustrative CLI simulation test assertions) */}
      <div className="cli-commands-layout" style={{ marginBottom: '48px' }}>
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

        {/* Quick Core Commands Strip */}
        <div className="cli-command-cards-container">
          <div className="commands-header">
            <h3 style={{ fontSize: 16, fontWeight: 700, margin: 0, color: 'var(--ns-text-primary)' }}>
              Core Commands
            </h3>
            <span style={{ fontSize: 11, color: 'var(--ns-text-tertiary)', fontFamily: 'var(--mono)' }}>
              CLICK COPY TO EXECUTE
            </span>
          </div>

          <div className="commands-list">
            {COMMAND_REFERENCE.slice(0, 6).map((item) => (
              <div key={item.cmd} className="command-row">
                <div className="command-info">
                  <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 3, flexWrap: 'wrap' }}>
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

      {/* 5. COMPLETE COMMAND REFERENCE EXPLORER (Section 5 Requirement) */}
      <div className="cli-command-explorer-section" style={{ marginBottom: '48px' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-end', flexWrap: 'wrap', gap: '16px', marginBottom: '20px', borderBottom: '1px solid var(--ns-border)', paddingBottom: '14px' }}>
          <div>
            <span className="section-eyebrow">COMMAND REFERENCE</span>
            <h3 style={{ fontSize: '20px', fontWeight: 700, color: 'var(--ns-text-primary)', margin: '4px 0 0 0' }}>
              CLI Command Reference
            </h3>
          </div>

          {/* Filter Pills */}
          <div style={{ display: 'flex', gap: '6px', flexWrap: 'wrap' }}>
            {categories.map((cat) => (
              <button
                key={cat}
                type="button"
                className={`command-filter-pill ${selectedCategory === cat ? 'active' : ''}`}
                onClick={() => setSelectedCategory(cat)}
              >
                {cat}
              </button>
            ))}
          </div>
        </div>

        <div className="command-explorer-grid">
          {filteredCommands.map((item) => (
            <div key={item.cmd} className="command-explorer-card">
              <div className="explorer-card-header">
                <span className="explorer-card-cat">{item.category}</span>
                <span className="explorer-card-label">{item.label}</span>
              </div>
              <code className="explorer-card-code">{item.cmd}</code>
              <p className="explorer-card-desc">{item.desc}</p>

              {item.flags && (
                <div className="explorer-card-flags">
                  <span className="flags-label">Flags:</span>
                  <code className="flags-code">{item.flags}</code>
                </div>
              )}

              <div className="explorer-card-footer">
                <button
                  type="button"
                  className={`command-copy-button ${copiedCmd === item.cmd ? 'is-copied' : ''}`}
                  onClick={() => handleCopy(item.cmd)}
                  aria-label={`Copy reference command ${item.cmd}`}
                  style={{ width: '100%', justifyContent: 'center' }}
                >
                  {copiedCmd === item.cmd ? (
                    <>
                      <Check size={12} />
                      <span>Command Copied</span>
                    </>
                  ) : (
                    <>
                      <Copy size={12} />
                      <span>Copy Command</span>
                    </>
                  )}
                </button>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* 6. ARCHITECTURE WORKFLOW (6 Stages - Tested) */}
      <div className="architecture-workflow-container" style={{ marginBottom: '48px' }}>
        <div style={{ textAlign: 'center', marginBottom: '24px' }}>
          <span className="section-eyebrow">PRODUCT WORKFLOW</span>
          <h3 className="section-heading-large" style={{ fontSize: 'clamp(18px, 2.2vw, 24px)', margin: '6px 0 8px 0' }}>
            System Architecture Flow
          </h3>
          <p className="section-desc" style={{ maxWidth: 640, margin: '0 auto', fontSize: '13.5px' }}>
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

      {/* 7. LOCAL REPOSITORY INSTALLATION & TROUBLESHOOTING (Preserves install test assertions) */}
      <div className="cli-install-box" style={{ marginBottom: '48px' }}>
        <div className="install-box-header">
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 4 }}>
              <span className="install-pill">LOCAL REPOSITORY INSTALLATION</span>
              <span style={{ fontSize: 11, color: 'var(--ns-text-tertiary)', fontFamily: 'var(--mono)' }}>DEVELOPMENT BUILD</span>
            </div>
            <h3 style={{ fontSize: 18, fontWeight: 700, margin: 0, color: 'var(--ns-text-primary)' }}>
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
          <Shield size={14} style={{ color: 'var(--ns-text-secondary)', flexShrink: 0, marginTop: 2 }} />
          <div>
            <strong style={{ color: 'var(--ns-text-primary)' }}>PyPI publication status:</strong> NexSolve CLI is currently
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

        {/* Troubleshooting guidance */}
        <div style={{ marginTop: '20px', padding: '16px', background: 'rgba(255, 255, 255, 0.02)', border: '1px solid var(--ns-border)', borderRadius: '6px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '6px' }}>
            <HelpCircle size={14} style={{ color: 'var(--ns-text-tertiary)' }} />
            <strong style={{ fontSize: '12.5px', color: 'var(--ns-text-primary)' }}>Troubleshooting &amp; Diagnostics</strong>
          </div>
          <p style={{ margin: 0, fontSize: '12px', color: 'var(--ns-text-secondary)', lineHeight: 1.5 }}>
            If <code style={{ fontFamily: 'var(--mono)', color: 'var(--ns-text-primary)' }}>nexsolve doctor</code> flags missing dependencies, ensure Wireshark/TShark is in your PATH. For air-gapped deployments, pre-bundle the ML checkpoints in <code style={{ fontFamily: 'var(--mono)', color: 'var(--ns-text-primary)' }}>models/</code>.
          </p>
        </div>
      </div>

      {/* 8. CTA TO CONSOLE */}
      <div style={{ textAlign: 'center', padding: '32px 20px', background: 'var(--ns-surface)', border: '1px solid var(--ns-border)', borderRadius: '12px' }}>
        <h3 style={{ fontSize: '18px', fontWeight: 700, color: 'var(--ns-text-primary)', margin: '0 0 6px 0' }}>
          Ready to inspect forecasts in the browser?
        </h3>
        <p style={{ fontSize: '13px', color: 'var(--ns-text-secondary)', margin: '0 0 16px 0' }}>
          Launch the operational security console to visualize communication topology and timeline projections.
        </p>
        <Link to="/console" className="button button-primary" style={{ padding: '8px 20px', fontSize: '12px', gap: '6px' }}>
          <span>Open Web Console</span> <ArrowRight size={13} />
        </Link>
      </div>
    </section>
  )
}

export default CliQuickstartSection
