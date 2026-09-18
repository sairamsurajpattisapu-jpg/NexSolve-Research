/**
 * Canonical configuration constants for NexSolve capture uploads.
 * Single source of truth across all frontend components.
 */

// 1 GiB = 1024 * 1024 * 1024 bytes = 1,073,741,824 bytes
export const MAX_PCAP_UPLOAD_BYTES = 1024 * 1024 * 1024
export const MAX_PCAP_UPLOAD_LABEL = '1 GiB'
export const MAX_PCAP_UPLOAD_DESCRIPTION = '1 GiB (1,073,741,824 bytes)'
export const CHUNK_SIZE_BYTES = 5 * 1024 * 1024 // 5 MiB per transmission chunk

export const ALLOWED_EXTENSIONS = ['.pcap', '.pcapng'] as const

export function formatFileSize(bytes: number): string {
  if (bytes === 0) return '0 B'
  const k = 1024
  const sizes = ['B', 'KB', 'MB', 'GB', 'TB']
  const i = Math.floor(Math.log(bytes) / Math.log(k))
  return `${parseFloat((bytes / Math.pow(k, i)).toFixed(2))} ${sizes[i]}`
}

export function validatePcapFile(
  file: File | null,
  maxBytes: number = MAX_PCAP_UPLOAD_BYTES
): { valid: boolean; error?: string } {
  if (!file) {
    return { valid: false, error: 'No file selected.' }
  }

  const name = file.name.toLowerCase()
  const isPcap = name.endsWith('.pcap') || name.endsWith('.pcapng')
  const isCsv = name.endsWith('.csv')

  if (!isPcap && !isCsv) {
    return { valid: false, error: 'Choose a .pcap or .pcapng capture.' }
  }

  if (file.size === 0) {
    return { valid: false, error: 'The selected capture file is empty (0 bytes).' }
  }

  // Strict byte comparison against canonical limit
  if (file.size > maxBytes) {
    return {
      valid: false,
      error: `Capture exceeds the maximum allowed upload size of ${MAX_PCAP_UPLOAD_LABEL}.`,
    }
  }

  return { valid: true }
}
