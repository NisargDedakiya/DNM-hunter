/**
 * Unit tests for Next.js auth middleware.
 *
 * Run: npx vitest run src/middleware.test.ts
 *
 * @vitest-environment node
 */

import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { NextRequest, NextResponse } from 'next/server'

// Mock environment
vi.stubEnv('AUTH_SECRET', 'b'.repeat(64))
vi.stubEnv('INTERNAL_API_KEY', 'internal-secret-abc')

import { middleware } from './middleware'
import { SignJWT } from 'jose'
import { _resetRateLimitState } from './lib/rateLimit'

const originalFetch = global.fetch

beforeEach(() => {
  _resetRateLimitState()
})

afterEach(() => {
  global.fetch = originalFetch
})

/* ------------------------------------------------------------------ */
/*  Helpers                                                            */
/* ------------------------------------------------------------------ */

async function createTestToken(userId: string, role: string): Promise<string> {
  const secret = new TextEncoder().encode('b'.repeat(64))
  return new SignJWT({ sub: userId, role })
    .setProtectedHeader({ alg: 'HS256' })
    .setIssuedAt()
    .setExpirationTime('1h')
    .sign(secret)
}

function makeRequest(
  path: string,
  options: { cookie?: string; headers?: Record<string, string> } = {}
): NextRequest {
  const url = `http://localhost:3000${path}`
  const headers = new Headers(options.headers || {})
  if (options.cookie) {
    headers.set('cookie', `nisarghunter-auth=${options.cookie}`)
  }
  return new NextRequest(url, { headers })
}

/* ------------------------------------------------------------------ */
/*  Public paths                                                       */
/* ------------------------------------------------------------------ */

describe('middleware - public paths', () => {
  test.each([
    '/login',
    '/api/auth/login',
    '/api/auth/logout',
    '/api/health',
    '/api/subscription/webhook', // billing-provider callback, secured by signature
  ])('allows %s without auth', async (path) => {
    const req = makeRequest(path)
    const res = await middleware(req)
    // NextResponse.next() returns a response with no redirect
    expect(res.status).not.toBe(401)
    expect(res.headers.get('location')).toBeNull()
  })
})

/* ------------------------------------------------------------------ */
/*  Tunnel-config sync allowlist (security boundary)                   */
/* ------------------------------------------------------------------ */

describe('middleware - tunnel-config sync allowlist', () => {
  test('allows POST /api/global/tunnel-config/sync without auth (public trigger)', async () => {
    const req = makeRequest('/api/global/tunnel-config/sync')
    const res = await middleware(req)
    expect(res.status).not.toBe(401)
    expect(res.headers.get('location')).toBeNull()
  })

  test('does NOT expose the secret-returning GET /api/global/tunnel-config', async () => {
    // The parent path returns unmasked tunnel credentials and must stay gated.
    // Allowlisting the /sync subpath must not leak it.
    const req = makeRequest('/api/global/tunnel-config')
    const res = await middleware(req)
    expect(res.status).toBe(401)
  })

  test('does NOT allowlist sibling paths sharing the prefix', async () => {
    const req = makeRequest('/api/global/tunnel-config/sync-evil')
    const res = await middleware(req)
    expect(res.status).toBe(401)
  })
})

/* ------------------------------------------------------------------ */
/*  Static assets                                                      */
/* ------------------------------------------------------------------ */

describe('middleware - static assets', () => {
  test.each([
    '/_next/static/chunk.js',
    '/_next/image?url=test',
    '/favicon.ico',
    '/favicon.png',
    '/logo.png',
    '/js_logo.png',
  ])('allows %s without auth', async (path) => {
    const req = makeRequest(path)
    const res = await middleware(req)
    expect(res.status).not.toBe(401)
    expect(res.headers.get('location')).toBeNull()
  })
})

/* ------------------------------------------------------------------ */
/*  Internal requests                                                  */
/* ------------------------------------------------------------------ */

describe('middleware - internal requests', () => {
  test('allows request with valid X-Internal-Key', async () => {
    const req = makeRequest('/api/users', {
      headers: { 'x-internal-key': 'internal-secret-abc' },
    })
    const res = await middleware(req)
    expect(res.status).not.toBe(401)
    expect(res.headers.get('location')).toBeNull()
  })

  test('rejects request with wrong X-Internal-Key', async () => {
    const req = makeRequest('/api/users', {
      headers: { 'x-internal-key': 'wrong-key' },
    })
    const res = await middleware(req)
    // Should redirect or return 401
    const isRedirect = res.headers.get('location')?.includes('/login')
    const is401 = res.status === 401
    expect(isRedirect || is401).toBe(true)
  })
})

/* ------------------------------------------------------------------ */
/*  Unauthenticated requests                                           */
/* ------------------------------------------------------------------ */

describe('middleware - unauthenticated', () => {
  test('redirects page request to /login', async () => {
    const req = makeRequest('/graph')
    const res = await middleware(req)
    expect(res.headers.get('location')).toContain('/login')
  })

  test('returns 401 for API request', async () => {
    const req = makeRequest('/api/projects')
    const res = await middleware(req)
    expect(res.status).toBe(401)
  })
})

/* ------------------------------------------------------------------ */
/*  Bearer API tokens (Phase 12)                                       */
/* ------------------------------------------------------------------ */

describe('middleware - Bearer API tokens', () => {
  const originalFetch = global.fetch

  beforeEach(() => {
    global.fetch = originalFetch
  })

  test('allows a request with a valid Bearer token (delegated verification succeeds)', async () => {
    global.fetch = vi.fn(async () => new Response(
      JSON.stringify({ userId: 'user-42', role: 'standard' }),
      { status: 200 }
    )) as unknown as typeof fetch

    const req = makeRequest('/api/projects', { headers: { authorization: 'Bearer nh_validtoken' } })
    const res = await middleware(req)
    expect(res.status).not.toBe(401)
    expect(res.headers.get('location')).toBeNull()
    expect(global.fetch).toHaveBeenCalledWith(
      expect.stringContaining('/api/auth/verify-api-token'),
      expect.objectContaining({ method: 'POST' })
    )
  })

  test('rejects a request when the token verification route reports invalid', async () => {
    global.fetch = vi.fn(async () => new Response(
      JSON.stringify({ error: 'Invalid token' }),
      { status: 401 }
    )) as unknown as typeof fetch

    const req = makeRequest('/api/projects', { headers: { authorization: 'Bearer nh_revoked' } })
    const res = await middleware(req)
    expect(res.status).toBe(401)
  })

  test('rejects an empty Bearer value without calling the verification route', async () => {
    global.fetch = vi.fn() as unknown as typeof fetch
    const req = makeRequest('/api/projects', { headers: { authorization: 'Bearer ' } })
    const res = await middleware(req)
    expect(res.status).toBe(401)
    expect(global.fetch).not.toHaveBeenCalled()
  })

  test('rejects Bearer auth entirely when INTERNAL_API_KEY is unset (no fetch attempted)', async () => {
    vi.stubEnv('INTERNAL_API_KEY', '')
    global.fetch = vi.fn() as unknown as typeof fetch

    const req = makeRequest('/api/projects', { headers: { authorization: 'Bearer nh_anything' } })
    const res = await middleware(req)
    expect(res.status).toBe(401)
    expect(global.fetch).not.toHaveBeenCalled()

    vi.stubEnv('INTERNAL_API_KEY', 'internal-secret-abc')
  })

  test('a request with BOTH a Bearer header and a valid cookie is authenticated via Bearer (checked first)', async () => {
    global.fetch = vi.fn(async () => new Response(
      JSON.stringify({ userId: 'bearer-user', role: 'admin' }),
      { status: 200 }
    )) as unknown as typeof fetch

    const token = await createTestToken('cookie-user', 'standard')
    const req = makeRequest('/api/projects', { cookie: token, headers: { authorization: 'Bearer nh_valid' } })
    const res = await middleware(req)
    expect(res.status).not.toBe(401)
    expect(global.fetch).toHaveBeenCalledTimes(1)
  })
})

/* ------------------------------------------------------------------ */
/*  Authenticated requests                                             */
/* ------------------------------------------------------------------ */

describe('middleware - authenticated', () => {
  test('allows request with valid JWT cookie', async () => {
    const token = await createTestToken('user-1', 'admin')
    const req = makeRequest('/graph', { cookie: token })
    const res = await middleware(req)
    expect(res.status).not.toBe(401)
    expect(res.headers.get('location')).toBeNull()
  })

  test('injects x-user-id and x-user-role headers', async () => {
    const token = await createTestToken('user-xyz', 'standard')
    const req = makeRequest('/api/projects', { cookie: token })
    const res = await middleware(req)

    // The middleware calls NextResponse.next() with modified request headers
    // We can verify no redirect/401
    expect(res.status).not.toBe(401)
    expect(res.headers.get('location')).toBeNull()
  })

  test('rejects expired token for page request', async () => {
    // Create an already-expired token
    const secret = new TextEncoder().encode('b'.repeat(64))
    const token = await new SignJWT({ sub: 'user-1', role: 'admin' })
      .setProtectedHeader({ alg: 'HS256' })
      .setIssuedAt(Math.floor(Date.now() / 1000) - 3600)
      .setExpirationTime(Math.floor(Date.now() / 1000) - 1800)
      .sign(secret)

    const req = makeRequest('/graph', { cookie: token })
    const res = await middleware(req)
    expect(res.headers.get('location')).toContain('/login')
  })

  test('returns 401 for expired token on API request', async () => {
    const secret = new TextEncoder().encode('b'.repeat(64))
    const token = await new SignJWT({ sub: 'user-1', role: 'admin' })
      .setProtectedHeader({ alg: 'HS256' })
      .setIssuedAt(Math.floor(Date.now() / 1000) - 3600)
      .setExpirationTime(Math.floor(Date.now() / 1000) - 1800)
      .sign(secret)

    const req = makeRequest('/api/projects', { cookie: token })
    const res = await middleware(req)
    expect(res.status).toBe(401)
  })
})

/* ------------------------------------------------------------------ */
/*  Rate limiting                                                      */
/* ------------------------------------------------------------------ */

describe('middleware - rate limiting', () => {
  test('allows requests under the auth-tier limit, then 429s with Retry-After', async () => {
    const ip = '203.0.113.10'
    // RATE_LIMIT_AUTH_MAX defaults to 10 when unset
    for (let i = 0; i < 10; i++) {
      const req = makeRequest('/api/auth/login', { headers: { 'x-forwarded-for': ip } })
      const res = await middleware(req)
      expect(res.status).not.toBe(429)
    }
    const blockedReq = makeRequest('/api/auth/login', { headers: { 'x-forwarded-for': ip } })
    const blockedRes = await middleware(blockedReq)
    expect(blockedRes.status).toBe(429)
    expect(blockedRes.headers.get('Retry-After')).toBeTruthy()
    const body = await blockedRes.json()
    expect(body.error).toMatch(/too many requests/i)
  })

  test('different IPs get independent auth-tier budgets', async () => {
    const ipA = '203.0.113.20'
    const ipB = '203.0.113.21'
    for (let i = 0; i < 10; i++) {
      await middleware(makeRequest('/api/auth/login', { headers: { 'x-forwarded-for': ipA } }))
    }
    // ipA is now exhausted
    const exhaustedRes = await middleware(makeRequest('/api/auth/login', { headers: { 'x-forwarded-for': ipA } }))
    expect(exhaustedRes.status).toBe(429)

    // ipB is untouched
    const freshRes = await middleware(makeRequest('/api/auth/login', { headers: { 'x-forwarded-for': ipB } }))
    expect(freshRes.status).not.toBe(429)
  })

  test('the default tier has a much higher budget than the auth tier', async () => {
    const ip = '203.0.113.30'
    // 10 requests to a non-auth path should never trip the default (300/60s) limit
    for (let i = 0; i < 10; i++) {
      const req = makeRequest('/api/projects', { headers: { 'x-forwarded-for': ip } })
      const res = await middleware(req)
      expect(res.status).not.toBe(429)
    }
  })

  test('rate limiting is bypassed for internal service-to-service calls', async () => {
    const ip = '203.0.113.40'
    // Exhaust the auth-tier budget for this IP first
    for (let i = 0; i < 10; i++) {
      await middleware(makeRequest('/api/auth/login', { headers: { 'x-forwarded-for': ip } }))
    }
    // A request presenting the valid internal key from the same IP still gets through
    const req = makeRequest('/api/auth/login', {
      headers: { 'x-forwarded-for': ip, 'x-internal-key': 'internal-secret-abc' },
    })
    const res = await middleware(req)
    expect(res.status).not.toBe(429)
  })

  test('static assets are never rate limited', async () => {
    const ip = '203.0.113.50'
    for (let i = 0; i < 15; i++) {
      const res = await middleware(makeRequest('/_next/static/chunk.js', { headers: { 'x-forwarded-for': ip } }))
      expect(res.status).not.toBe(429)
    }
  })
})

/* ------------------------------------------------------------------ */
/*  RBAC — central route-permission enforcement (Phase 16)             */
/* ------------------------------------------------------------------ */

describe('middleware - RBAC route permissions', () => {
  test('blocks a standard-role cookie session from /api/audit-log with 403', async () => {
    const token = await createTestToken('user-standard', 'standard')
    const req = makeRequest('/api/audit-log', { cookie: token })
    const res = await middleware(req)
    expect(res.status).toBe(403)
  })

  test('allows an admin-role cookie session through /api/audit-log', async () => {
    const token = await createTestToken('user-admin', 'admin')
    const req = makeRequest('/api/audit-log', { cookie: token })
    const res = await middleware(req)
    expect(res.status).not.toBe(403)
    expect(res.status).not.toBe(401)
  })

  test('blocks an operator-role session from /api/audit-log (users.manage/audit_log.view are admin-only)', async () => {
    const token = await createTestToken('user-operator', 'operator')
    const req = makeRequest('/api/audit-log', { cookie: token })
    const res = await middleware(req)
    expect(res.status).toBe(403)
  })

  test('redirects a non-admin page request to /settings/users away, instead of a 403 JSON body', async () => {
    const token = await createTestToken('user-standard', 'standard')
    const req = makeRequest('/settings/users', { cookie: token })
    const res = await middleware(req)
    expect(res.status).not.toBe(403) // page routes redirect, not JSON 403
    expect(res.headers.get('location')).toContain('/graph')
  })

  test('allows an admin page request to /settings/users through', async () => {
    const token = await createTestToken('user-admin', 'admin')
    const req = makeRequest('/settings/users', { cookie: token })
    const res = await middleware(req)
    expect(res.headers.get('location')).toBeNull()
  })

  test('a Bearer API token for a standard-role user is also blocked from /api/audit-log', async () => {
    global.fetch = vi.fn(async () => new Response(
      JSON.stringify({ userId: 'user-42', role: 'standard' }),
      { status: 200 }
    )) as unknown as typeof fetch

    const req = makeRequest('/api/audit-log', { headers: { authorization: 'Bearer nh_validtoken' } })
    const res = await middleware(req)
    expect(res.status).toBe(403)
  })

  test('an unrecognized role string is denied a permission-gated route (fail closed)', async () => {
    const token = await createTestToken('user-weird', 'superuser')
    const req = makeRequest('/api/audit-log', { cookie: token })
    const res = await middleware(req)
    expect(res.status).toBe(403)
  })

  test('routes with no listed permission requirement are unaffected by RBAC', async () => {
    const token = await createTestToken('user-standard', 'standard')
    const req = makeRequest('/api/projects', { cookie: token })
    const res = await middleware(req)
    expect(res.status).not.toBe(403)
  })
})

/* ------------------------------------------------------------------ */
/*  Request-ID correlation (Phase 16)                                  */
/* ------------------------------------------------------------------ */

describe('middleware - request-id correlation', () => {
  test('every response carries an x-request-id header, even a 401', async () => {
    const res = await middleware(makeRequest('/api/projects'))
    expect(res.status).toBe(401)
    expect(res.headers.get('x-request-id')).toBeTruthy()
  })

  test('an incoming x-request-id is echoed back unchanged', async () => {
    const res = await middleware(makeRequest('/api/health', { headers: { 'x-request-id': 'trace-abc-123' } }))
    expect(res.headers.get('x-request-id')).toBe('trace-abc-123')
  })

  test('no incoming header: a fresh id is generated', async () => {
    const res = await middleware(makeRequest('/api/health'))
    const id = res.headers.get('x-request-id')
    expect(id).toBeTruthy()
    expect(id).toMatch(/^[0-9a-f-]{36}$/) // crypto.randomUUID() shape
  })

  test('two requests without a header get different generated ids', async () => {
    const res1 = await middleware(makeRequest('/api/health'))
    const res2 = await middleware(makeRequest('/api/health'))
    expect(res1.headers.get('x-request-id')).not.toBe(res2.headers.get('x-request-id'))
  })

  test('a 429 rate-limited response still carries an x-request-id', async () => {
    const ip = '203.0.113.60'
    for (let i = 0; i < 10; i++) {
      await middleware(makeRequest('/api/auth/login', { headers: { 'x-forwarded-for': ip } }))
    }
    const res = await middleware(makeRequest('/api/auth/login', { headers: { 'x-forwarded-for': ip } }))
    expect(res.status).toBe(429)
    expect(res.headers.get('x-request-id')).toBeTruthy()
  })

  test('a login-page redirect still carries an x-request-id', async () => {
    const res = await middleware(makeRequest('/graph'))
    expect(res.headers.get('location')).toContain('/login')
    expect(res.headers.get('x-request-id')).toBeTruthy()
  })
})
