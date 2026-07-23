/**
 * Tests for the direct provider probe (agent-less fallback for key validation
 * and model discovery).
 *
 * @vitest-environment node
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { probeProviderDirect, canProbeDirectly } from './directProbe'

function stubFetch(status: number, body: unknown) {
  global.fetch = vi.fn(async () =>
    new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } }),
  ) as typeof fetch
}

beforeEach(() => { /* fresh per test */ })
afterEach(() => vi.restoreAllMocks())

describe('canProbeDirectly', () => {
  test('supports the common key-based providers', () => {
    expect(canProbeDirectly({ providerType: 'openai' })).toBe(true)
    expect(canProbeDirectly({ providerType: 'anthropic' })).toBe(true)
    expect(canProbeDirectly({ providerType: 'openrouter' })).toBe(true)
    expect(canProbeDirectly({ providerType: 'gemini' })).toBe(true)
    expect(canProbeDirectly({ providerType: 'openai_compatible', baseUrl: 'http://localhost:11434/v1' })).toBe(true)
  })
  test('does not support agent-only providers', () => {
    expect(canProbeDirectly({ providerType: 'bedrock' })).toBe(false)
    expect(canProbeDirectly({ providerType: 'openai_compatible' })).toBe(false) // no baseUrl
  })
})

describe('probeProviderDirect — OpenAI', () => {
  test('valid key returns chat models, filtering non-chat', async () => {
    stubFetch(200, { data: [{ id: 'gpt-5' }, { id: 'o3-mini' }, { id: 'text-embedding-3-large' }, { id: 'dall-e-3' }] })
    const r = await probeProviderDirect({ providerType: 'openai', apiKey: 'sk-valid' })
    expect(r.supported).toBe(true)
    expect(r.ok).toBe(true)
    const ids = r.models.map((m) => m.id)
    expect(ids).toContain('gpt-5')
    expect(ids).toContain('o3-mini')
    expect(ids).not.toContain('text-embedding-3-large')
    expect(ids).not.toContain('dall-e-3')
  })

  test('invalid key surfaces the provider error', async () => {
    stubFetch(401, { error: { message: 'Incorrect API key provided' } })
    const r = await probeProviderDirect({ providerType: 'openai', apiKey: 'sk-bad' })
    expect(r.supported).toBe(true)
    expect(r.ok).toBe(false)
    expect(r.error).toContain('Incorrect API key')
  })

  test('missing key is rejected before any network call', async () => {
    const spy = vi.fn()
    global.fetch = spy as unknown as typeof fetch
    const r = await probeProviderDirect({ providerType: 'openai', apiKey: '' })
    expect(r.ok).toBe(false)
    expect(spy).not.toHaveBeenCalled()
  })
})

describe('probeProviderDirect — OpenAI-compatible (local)', () => {
  test('lists models from the base URL', async () => {
    stubFetch(200, { data: [{ id: 'llama3.1' }, { id: 'qwen2.5' }] })
    const r = await probeProviderDirect({ providerType: 'openai_compatible', baseUrl: 'http://localhost:11434/v1', apiKey: '' })
    expect(r.ok).toBe(true)
    expect(r.models.map((m) => m.id)).toEqual(['llama3.1', 'qwen2.5'])
  })
})

describe('probeProviderDirect — unsupported', () => {
  test('bedrock is not directly probeable', async () => {
    const r = await probeProviderDirect({ providerType: 'bedrock', apiKey: 'x' })
    expect(r.supported).toBe(false)
    expect(r.ok).toBe(false)
  })
})
