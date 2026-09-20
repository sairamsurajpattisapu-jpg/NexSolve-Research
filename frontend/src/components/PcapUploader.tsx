import { useState, type DragEvent } from 'react'
import { AlertCircle, FileUp, Upload } from 'lucide-react'
import { Panel } from './Ui'
import { MAX_PCAP_UPLOAD_LABEL, validatePcapFile } from '../config/constants'

interface PcapUploaderProps {
  onFileSelected: (file: File) => void
  disabled?: boolean
  error?: string | null
}

export function PcapUploader({
  onFileSelected,
  disabled = false,
  error = null,
}: PcapUploaderProps) {
  const [isDragging, setIsDragging] = useState(false)
  const [selectedFile, setSelectedFile] = useState<File | null>(null)
  const [validationError, setValidationError] = useState<string | null>(null)

  const validateAndSelect = (file: File | null) => {
    if (!file) return
    const validation = validatePcapFile(file)
    if (!validation.valid) {
      setValidationError(validation.error ?? `Capture exceeds the maximum allowed upload size of ${MAX_PCAP_UPLOAD_LABEL}.`)
      setSelectedFile(null)
      return
    }
    setValidationError(null)
    setSelectedFile(file)
    onFileSelected(file)
  }

  const handleDrop = (e: DragEvent<HTMLDivElement>) => {
    e.preventDefault()
    setIsDragging(false)
    if (disabled) return
    const file = e.dataTransfer.files?.[0] ?? null
    validateAndSelect(file)
  }

  return (
    <Panel className="pcap-uploader-panel">
      <div
        onDragOver={(e) => {
          e.preventDefault()
          if (!disabled) setIsDragging(true)
        }}
        onDragLeave={() => setIsDragging(false)}
        onDrop={handleDrop}
        style={{
          border: isDragging ? '1.5px dashed var(--accent)' : '1px dashed var(--border)',
          borderRadius: '8px',
          background: isDragging ? 'var(--accent-muted)' : 'var(--bg-secondary)',
          padding: '36px 24px',
          textAlign: 'center',
          display: 'flex',
          flexDirection: 'column',
          alignItems: 'center',
          justifyContent: 'center',
          gap: '14px',
          transition: 'all 0.15s ease',
          cursor: disabled ? 'not-allowed' : 'pointer',
        }}
      >
        <div
          style={{
            width: '54px',
            height: '54px',
            borderRadius: '50%',
            background: 'var(--button-secondary-bg)',
            border: '1px solid var(--border)',
            display: 'grid',
            placeItems: 'center',
            color: 'var(--accent)',
          }}
        >
          <Upload size={24} />
        </div>

        <div style={{ maxWidth: '480px' }}>
          <h3 style={{ fontSize: '18px', fontWeight: 700, margin: '0 0 6px 0', color: 'var(--text-primary)' }}>
            {selectedFile ? selectedFile.name : 'DROP PCAP OR CSV HERE'}
          </h3>
          <p style={{ margin: 0, fontSize: '13px', color: 'var(--text-secondary)', lineHeight: 1.5 }}>
            Drag and drop live network traffic captures to reconstruct transport flows, compile 60s temporal states, and execute continuous temporal attack forecasting.
          </p>
          <span style={{ display: 'block', marginTop: '8px', fontFamily: 'var(--mono)', fontSize: '11px', color: 'var(--text-muted)' }}>
            Accepts PCAP, PCAPNG, or flow-telemetry CSV &middot; Max {MAX_PCAP_UPLOAD_LABEL} &middot; 45-feature schema
          </span>
        </div>

        <div style={{ display: 'flex', gap: '12px', alignItems: 'center', marginTop: '6px' }}>
          <label
            className="button"
            style={{
              cursor: disabled ? 'not-allowed' : 'pointer',
              opacity: disabled ? 0.6 : 1,
            }}
          >
            <FileUp size={14} />
            {selectedFile ? 'Change Capture' : 'Select Network Capture'}
            <input
              type="file"
              accept=".pcap,.pcapng,.csv"
              style={{ display: 'none' }}
              disabled={disabled}
              onChange={(e) => {
                const file = e.target.files?.[0] ?? null
                validateAndSelect(file)
              }}
            />
          </label>
        </div>

        {(validationError || error) && (
          <div
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: '6px',
              color: 'var(--danger)',
              fontSize: '12px',
              marginTop: '4px',
            }}
          >
            <AlertCircle size={14} />
            <span>{validationError ?? error}</span>
          </div>
        )}
      </div>
    </Panel>
  )
}
