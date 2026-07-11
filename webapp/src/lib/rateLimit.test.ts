import { describe, test, expect, beforeEach, vi } from 'vitest'
import { consumeRateLimit, tierForPath, RATE_LIMIT_TIERS, _resetRateLimitState } from './rateLimit'

describe('rateLimit - consumeRateLimit', () => {
  beforeEach(() => {
    _resetRateLimitState()
    vi.useRealTimers()
  })

  test('allows requests up to the limit', () => {
    const tier = { limit: 3, windowMs: 60_000 }
    for (let i = 0; i < 3; i++) {
      const result = consumeRateLimit('key-a', tier)
      expect(result.allowed).toBe(true)
    }
  })

  test('rejects the request once the limit is exceeded', () => {
    const tier = { limit: 3, windowMs: 60_000 }
    for (let i = 0; i < 3; i++) consumeRateLimit('key-b', tier)
    const result = consumeRateLimit('key-b', tier)
    expect(result.allowed).toBe(false)
    expect(result.remaining).toBe(0)
  })

  test('different keys have independent buckets', () => {
    const tier = { limit: 1, windowMs: 60_000 }
    expect(consumeRateLimit('key-c1', tier).allowed).toBe(true)
    expect(consumeRateLimit('key-c1', tier).allowed).toBe(false)
    // A different key is unaffected by key-c1's exhausted bucket
    expect(consumeRateLimit('key-c2', tier).allowed).toBe(true)
  })

  test('refills tokens over time', () => {
    vi.useFakeTimers()
    const now = Date.now()
    vi.setSystemTime(now)

    const tier = { limit: 2, windowMs: 1000 } // 2 tokens/sec refill rate
    expect(consumeRateLimit('key-d', tier).allowed).toBe(true)
    expect(consumeRateLimit('key-d', tier).allowed).toBe(true)
    expect(consumeRateLimit('key-d', tier).allowed).toBe(false) // exhausted

    // Advance halfway through the window — should refill ~1 token
    vi.setSystemTime(now + 500)
    expect(consumeRateLimit('key-d', tier).allowed).toBe(true)
    expect(consumeRateLimit('key-d', tier).allowed).toBe(false)

    vi.useRealTimers()
  })

  test('resetAt reflects a future time when blocked', () => {
    const tier = { limit: 1, windowMs: 10_000 }
    consumeRateLimit('key-e', tier)
    const blocked = consumeRateLimit('key-e', tier)
    expect(blocked.allowed).toBe(false)
    expect(blocked.resetAt).toBeGreaterThan(Date.now())
  })

  test('never refills beyond the tier limit (no unbounded accumulation)', () => {
    vi.useFakeTimers()
    const now = Date.now()
    vi.setSystemTime(now)

    const tier = { limit: 2, windowMs: 1000 }
    consumeRateLimit('key-f', tier) // 1 token left

    // Advance far beyond the window — bucket should cap at `limit`, not grow unbounded
    vi.setSystemTime(now + 1_000_000)
    const results = [consumeRateLimit('key-f', tier), consumeRateLimit('key-f', tier), consumeRateLimit('key-f', tier)]
    expect(results[0].allowed).toBe(true)
    expect(results[1].allowed).toBe(true)
    expect(results[2].allowed).toBe(false) // capped at 2, third request in the same instant is rejected

    vi.useRealTimers()
  })
})

describe('rateLimit - tierForPath', () => {
  test('routes login paths to the strict auth tier', () => {
    expect(tierForPath('/api/auth/login')).toEqual(RATE_LIMIT_TIERS.auth)
    expect(tierForPath('/api/auth/login-2fa')).toEqual(RATE_LIMIT_TIERS.auth)
  })

  test('routes everything else to the default tier', () => {
    expect(tierForPath('/api/projects')).toEqual(RATE_LIMIT_TIERS.default)
    expect(tierForPath('/graph')).toEqual(RATE_LIMIT_TIERS.default)
    expect(tierForPath('/api/auth/logout')).toEqual(RATE_LIMIT_TIERS.default)
  })

  test('the auth tier is stricter than the default tier', () => {
    expect(RATE_LIMIT_TIERS.auth.limit).toBeLessThan(RATE_LIMIT_TIERS.default.limit)
  })
})
