import { describe, it, expect } from 'vitest'
import {
  MAX_PCAP_UPLOAD_BYTES,
  MAX_PCAP_UPLOAD_LABEL,
  CHUNK_SIZE_BYTES,
  validatePcapFile,
  formatFileSize,
} from '../config/constants'

function createMockFile(name: string, size: number): File {
  const file = new File([], name)
  Object.defineProperty(file, 'size', { value: size, configurable: true })
  return file
}

describe('Strict 1 GiB PCAP/PCAPNG Upload Validation & Unit Conversion Suite', () => {
  it('1. Verifies exact canonical constant definitions and byte math', () => {
    expect(MAX_PCAP_UPLOAD_BYTES).toBe(1073741824)
    expect(MAX_PCAP_UPLOAD_BYTES).toBe(1024 * 1024 * 1024)
    expect(MAX_PCAP_UPLOAD_LABEL).toBe('1 GiB')
    expect(CHUNK_SIZE_BYTES).toBe(5 * 1024 * 1024)
  })

  it('2. Accepts 100 MB captures (.pcap and .pcapng)', () => {
    const size100Mb = 100 * 1024 * 1024
    expect(validatePcapFile(createMockFile('traffic.pcap', size100Mb)).valid).toBe(true)
    expect(validatePcapFile(createMockFile('traffic.pcapng', size100Mb)).valid).toBe(true)
  })

  it('3. Accepts 220.34 MB captures (.pcap and .pcapng) — User Reported Bug Fix', () => {
    const size220Mb = Math.round(220.34 * 1024 * 1024)
    expect(size220Mb).toBeLessThan(MAX_PCAP_UPLOAD_BYTES)
    const pcapRes = validatePcapFile(createMockFile('r&d.pcap', size220Mb))
    expect(pcapRes.valid).toBe(true)
    expect(pcapRes.error).toBeUndefined()

    const pcapngRes = validatePcapFile(createMockFile('r&d.pcapng', size220Mb))
    expect(pcapngRes.valid).toBe(true)
    expect(pcapngRes.error).toBeUndefined()
  })

  it('4. Accepts 500 MB captures (.pcap and .pcapng)', () => {
    const size500Mb = 500 * 1024 * 1024
    expect(validatePcapFile(createMockFile('capture_500m.pcap', size500Mb)).valid).toBe(true)
    expect(validatePcapFile(createMockFile('capture_500m.pcapng', size500Mb)).valid).toBe(true)
  })

  it('5. Accepts 999 MB captures (.pcap and .pcapng)', () => {
    const size999Mb = 999 * 1024 * 1024
    expect(validatePcapFile(createMockFile('capture_999m.pcap', size999Mb)).valid).toBe(true)
    expect(validatePcapFile(createMockFile('capture_999m.pcapng', size999Mb)).valid).toBe(true)
  })

  it('6. Accepts exactly 1 GiB (1,073,741,824 bytes) boundary captures', () => {
    const sizeExact1Gb = 1073741824
    const pcap = createMockFile('boundary_exact.pcap', sizeExact1Gb)
    expect(validatePcapFile(pcap).valid).toBe(true)

    const pcapng = createMockFile('boundary_exact.pcapng', sizeExact1Gb)
    expect(validatePcapFile(pcapng).valid).toBe(true)
  })

  it('7. Rejects 1 byte above 1 GiB (1,073,741,825 bytes) with canonical error message', () => {
    const size1ByteOver = 1073741825
    const pcap = createMockFile('boundary_over.pcap', size1ByteOver)
    const resPcap = validatePcapFile(pcap)
    expect(resPcap.valid).toBe(false)
    expect(resPcap.error).toBe('Capture exceeds the maximum allowed upload size of 1 GiB.')

    const pcapng = createMockFile('boundary_over.pcapng', size1ByteOver)
    const resPcapng = validatePcapFile(pcapng)
    expect(resPcapng.valid).toBe(false)
    expect(resPcapng.error).toBe('Capture exceeds the maximum allowed upload size of 1 GiB.')
  })

  it('8. Rejects 2 GB captures (2,147,483,648 bytes)', () => {
    const size2Gb = 2 * 1024 * 1024 * 1024
    expect(validatePcapFile(createMockFile('oversized_2gb.pcap', size2Gb)).valid).toBe(false)
    expect(validatePcapFile(createMockFile('oversized_2gb.pcapng', size2Gb)).valid).toBe(false)
  })

  it('9. Rejects 5 GB captures (5,368,709,120 bytes)', () => {
    const size5Gb = 5 * 1024 * 1024 * 1024
    expect(validatePcapFile(createMockFile('massive_5gb.pcap', size5Gb)).valid).toBe(false)
    expect(validatePcapFile(createMockFile('massive_5gb.pcapng', size5Gb)).valid).toBe(false)
  })

  it('10. Rejects 8.23 GB captures (8,836,856,545 bytes)', () => {
    const size823Gb = Math.round(8.23 * 1024 * 1024 * 1024)
    expect(validatePcapFile(createMockFile('huge_823gb.pcap', size823Gb)).valid).toBe(false)
    expect(validatePcapFile(createMockFile('huge_823gb.pcapng', size823Gb)).valid).toBe(false)
  })

  it('11. Rejects 0-byte captures and invalid file extensions', () => {
    const emptyPcap = createMockFile('empty.pcap', 0)
    expect(validatePcapFile(emptyPcap).error).toBe('The selected capture file is empty (0 bytes).')

    const badExt = createMockFile('capture.txt', 1024)
    expect(validatePcapFile(badExt).error).toBe('Choose a .pcap or .pcapng capture.')

    const exeFile = createMockFile('capture.exe', 1024)
    expect(validatePcapFile(exeFile).error).toBe('Choose a .pcap or .pcapng capture.')
  })

  it('12. Chunking arithmetic guarantees memory safety for 1 GiB files', () => {
    const oneGb = 1073741824
    const totalChunks = Math.ceil(oneGb / CHUNK_SIZE_BYTES)
    expect(totalChunks).toBe(205)

    // Verify last chunk size
    const remainingBytes = oneGb - (totalChunks - 1) * CHUNK_SIZE_BYTES
    expect(remainingBytes).toBeLessThanOrEqual(CHUNK_SIZE_BYTES)
    expect(remainingBytes).toBe(4194304) // 4 MiB for the final chunk

    // For 220.34 MB file
    const size220Mb = Math.round(220.34 * 1024 * 1024)
    const chunks220 = Math.ceil(size220Mb / CHUNK_SIZE_BYTES)
    expect(chunks220).toBe(45)
  })

  it('13. Format utility renders readable units', () => {
    expect(formatFileSize(1073741824)).toBe('1 GB')
    expect(formatFileSize(100 * 1024 * 1024)).toBe('100 MB')
  })
})
