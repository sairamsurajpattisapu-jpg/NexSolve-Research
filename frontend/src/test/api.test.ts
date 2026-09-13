import { afterEach, describe, expect, it, vi } from 'vitest'
import { ApiError, api } from '../services/api'

afterEach(() => vi.restoreAllMocks())

describe('api client', () => {
  it('returns JSON from a successful request', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response(JSON.stringify({ service_status: 'ok' }), { status: 200 }))
    await expect(api.health()).resolves.toEqual({ service_status: 'ok' })
    expect(fetch).toHaveBeenCalledWith(expect.stringMatching(/\/health$/), expect.objectContaining({ headers: { Accept: 'application/json' } }))
  })

  it('surfaces structured API errors', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response(JSON.stringify({ detail: 'analysis not found' }), { status: 404 }))
    await expect(api.status('missing')).rejects.toEqual(new ApiError('analysis not found', 404))
  })

  it('turns network failures into a user-safe message', async () => {
    vi.spyOn(globalThis, 'fetch').mockRejectedValue(new Error('connection refused'))
    await expect(api.traffic()).rejects.toThrow('Backend unavailable')
  })

  it('rejects malformed successful responses safely', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response('not json', { status: 200 }))
    await expect(api.health()).rejects.toThrow('invalid JSON response')
  })

  it('detects HTML responses from misconfigured endpoints', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(
      new Response('<!doctype html><html><body>Error</body></html>', {
        status: 200,
        headers: { 'Content-Type': 'text/html' },
      }),
    )
    await expect(api.health()).rejects.toThrow('API endpoint returned HTML instead of JSON')
  })

  it('handles request timeout gracefully', async () => {
    const abortErr = new DOMException('The operation was aborted due to timeout', 'AbortError')
    vi.spyOn(globalThis, 'fetch').mockRejectedValue(abortErr)
    await expect(api.health()).rejects.toThrow('Backend connection timed out')
  })

  it('supports the production readiness probe', async () => {
    const readyPayload = {
      status: 'ready',
      service: 'nexsolve-backend',
      database: { status: 'healthy', mode: 'database', detail: 'connected' },
    }
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response(JSON.stringify(readyPayload), { status: 200 }))
    await expect(api.ready()).resolves.toEqual(readyPayload)
    expect(fetch).toHaveBeenCalledWith(expect.stringMatching(/\/ready$/), expect.objectContaining({ headers: { Accept: 'application/json' } }))
  })
})
