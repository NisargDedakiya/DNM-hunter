import { NextRequest, NextResponse } from 'next/server'
import { jwtVerify } from 'jose'
import { consumeRateLimit, tierForPath } from '@/lib/rateLimit'
import { hasPermission, requiredPermissionForPath } from '@/lib/rbac'

const AUTH_COOKIE_NAME = 'nisarghunter-auth'

const PUBLIC_PATHS = ['/login', '/api/auth/login', '/api/auth/login-2fa', '/api/auth/logout', '/api/health', '/api/version/check', '/api/global/tunnel-config/sync']

function getSecret() {
  const secret = process.env.AUTH_SECRET
  if (!secret || secret === 'changeme') return null
  return new TextEncoder().encode(secret)
}

async function verifyJwt(token: string): Promise<{ sub: string; role: string } | null> {
  try {
    const secret = getSecret()
    if (!secret) return null
    const { payload } = await jwtVerify(token, secret)
    if (!payload.sub || !payload.role) return null
    return { sub: payload.sub, role: payload.role as string }
  } catch {
    return null
  }
}

// API tokens (Phase 12) are bearer credentials for programmatic access,
// hashed at rest -- resolving one requires a Postgres lookup, which Edge
// middleware can't do directly. Delegate to a Node-runtime route handler,
// authenticating that internal call the same way service-to-service calls
// already are (X-Internal-Key) so the route only ever answers middleware.
async function verifyApiToken(origin: string, rawToken: string): Promise<{ sub: string; role: string } | null> {
  const internalKey = process.env.INTERNAL_API_KEY
  if (!internalKey || internalKey === 'changeme') return null
  try {
    const resp = await fetch(`${origin}/api/auth/verify-api-token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Internal-Key': internalKey },
      body: JSON.stringify({ token: rawToken }),
    })
    if (!resp.ok) return null
    const data = await resp.json()
    if (!data.userId || !data.role) return null
    return { sub: data.userId, role: data.role }
  } catch {
    return null
  }
}

function clientIp(request: NextRequest): string {
  const forwardedFor = request.headers.get('x-forwarded-for')
  if (forwardedFor) return forwardedFor.split(',')[0].trim()
  const realIp = request.headers.get('x-real-ip')
  if (realIp) return realIp.trim()
  return 'unknown'
}

function rateLimitedResponse(resetAt: number): NextResponse {
  const retryAfterSeconds = Math.max(1, Math.ceil((resetAt - Date.now()) / 1000))
  const response = NextResponse.json({ error: 'Too many requests. Please slow down.' }, { status: 429 })
  response.headers.set('Retry-After', String(retryAfterSeconds))
  return response
}

/**
 * Central RBAC gate (see lib/rbac.ts ROUTE_PERMISSIONS) for routes whose
 * access rule is a plain role/permission check with no per-resource
 * ownership nuance. Returns a 403/redirect response if denied, or null to
 * let the request proceed. Routes needing "admin OR the record's owner"
 * logic aren't listed there and keep handling that in the route handler,
 * since middleware has no access to which resource is being requested.
 */
function enforceRoutePermission(request: NextRequest, role: string): NextResponse | null {
  const { pathname } = request.nextUrl
  const required = requiredPermissionForPath(pathname)
  if (!required) return null
  if (hasPermission(role, required)) return null

  if (pathname.startsWith('/api/')) {
    return NextResponse.json({ error: 'Forbidden' }, { status: 403 })
  }
  return NextResponse.redirect(new URL('/graph', request.url))
}

export async function middleware(request: NextRequest) {
  const { pathname } = request.nextUrl

  // Allow static assets and Next.js internals — never rate limited or authed
  if (
    pathname.startsWith('/_next') ||
    pathname.startsWith('/favicon') ||
    pathname === '/logo.png' ||
    pathname === '/js_logo.png'
  ) {
    return NextResponse.next()
  }

  // Internal service-to-service calls (Docker network) — trusted infra, not
  // an attacker-controlled surface, so exempt from rate limiting too.
  const internalKey = request.headers.get('x-internal-key')
  const expectedKey = process.env.INTERNAL_API_KEY
  if (internalKey && expectedKey && expectedKey !== 'changeme' && internalKey === expectedKey) {
    return NextResponse.next()
  }

  // Rate limit everything else by client IP, before auth resolution — this
  // is what actually protects /api/auth/login from credential brute-forcing
  // (it's a public path and would otherwise skip every other check below).
  const rateLimit = consumeRateLimit(`ip:${clientIp(request)}`, tierForPath(pathname))
  if (!rateLimit.allowed) {
    return rateLimitedResponse(rateLimit.resetAt)
  }

  // Allow public paths
  if (PUBLIC_PATHS.some(p => pathname === p || pathname.startsWith(p + '/'))) {
    return NextResponse.next()
  }

  // Bearer API token (Phase 12) — programmatic access, checked before the
  // cookie so a script that only sends Authorization doesn't need a session.
  const authHeader = request.headers.get('authorization')
  if (authHeader?.startsWith('Bearer ')) {
    const rawToken = authHeader.slice('Bearer '.length).trim()
    const apiPayload = rawToken ? await verifyApiToken(request.nextUrl.origin, rawToken) : null
    if (apiPayload) {
      const denied = enforceRoutePermission(request, apiPayload.role)
      if (denied) return denied
      const requestHeaders = new Headers(request.headers)
      requestHeaders.set('x-user-id', apiPayload.sub)
      requestHeaders.set('x-user-role', apiPayload.role)
      return NextResponse.next({ request: { headers: requestHeaders } })
    }
    return NextResponse.json({ error: 'Unauthorized' }, { status: 401 })
  }

  // Check JWT cookie
  const token = request.cookies.get(AUTH_COOKIE_NAME)?.value
  if (!token) {
    if (pathname.startsWith('/api/')) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 })
    }
    return NextResponse.redirect(new URL('/login', request.url))
  }

  const payload = await verifyJwt(token)
  if (!payload) {
    // Invalid/expired token
    if (pathname.startsWith('/api/')) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 })
    }
    const response = NextResponse.redirect(new URL('/login', request.url))
    response.cookies.delete(AUTH_COOKIE_NAME)
    return response
  }

  const denied = enforceRoutePermission(request, payload.role)
  if (denied) return denied

  // Inject user info into request headers for downstream API routes
  const requestHeaders = new Headers(request.headers)
  requestHeaders.set('x-user-id', payload.sub)
  requestHeaders.set('x-user-role', payload.role)

  return NextResponse.next({ request: { headers: requestHeaders } })
}

export const config = {
  matcher: ['/((?!_next/static|_next/image|favicon.ico|favicon.png|logo.png|js_logo.png).*)'],
}
