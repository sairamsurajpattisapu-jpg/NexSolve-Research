import { afterEach, describe, expect, it, vi } from 'vitest'
import { ApiError, api } from '../services/api'

afterEach(() => vi.restoreAllMocks())

describe('api client', () => {
  it('returns JSON from a successful request', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response(JSON.stringify({ service_status: 'ok' }), { status: 200 }))
    await expect(api.health()).resolves.toEqual({ service_status: 'ok' })
    expect(fetch).toHaveBeenCalledWith('/health', expect.objectContaining({ headers: { Accept: 'application/json' } }))
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
})
