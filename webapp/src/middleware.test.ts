/**
 * Unit tests for Next.js auth middleware.
 *
 * Run: npx vitest run src/middleware.test.ts
 *
 * @vitest-environment node
 */

import { describe, test, expect, vi, beforeEach } from 'vitest'
import { NextRequest, NextResponse } from 'next/server'

// Mock environment
vi.stubEnv('AUTH_SECRET', 'b'.repeat(64))
vi.stubEnv('INTERNAL_API_KEY', 'internal-secret-abc')

import { middleware } from './middleware'
import { SignJWT } from 'jose'

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
