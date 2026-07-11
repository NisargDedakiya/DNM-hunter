import { NextRequest, NextResponse } from 'next/server'
import { jwtVerify } from 'jose'

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

export async function middleware(request: NextRequest) {
  const { pathname } = request.nextUrl

  // Allow public paths
  if (PUBLIC_PATHS.some(p => pathname === p || pathname.startsWith(p + '/'))) {
    return NextResponse.next()
  }

  // Allow static assets and Next.js internals
  if (
    pathname.startsWith('/_next') ||
    pathname.startsWith('/favicon') ||
    pathname === '/logo.png' ||
    pathname === '/js_logo.png'
  ) {
    return NextResponse.next()
  }

  // Internal service-to-service calls (Docker network)
  const internalKey = request.headers.get('x-internal-key')
  const expectedKey = process.env.INTERNAL_API_KEY
  if (internalKey && expectedKey && expectedKey !== 'changeme' && internalKey === expectedKey) {
    return NextResponse.next()
  }

  // Bearer API token (Phase 12) — programmatic access, checked before the
  // cookie so a script that only sends Authorization doesn't need a session.
  const authHeader = request.headers.get('authorization')
  if (authHeader?.startsWith('Bearer ')) {
    const rawToken = authHeader.slice('Bearer '.length).trim()
    const apiPayload = rawToken ? await verifyApiToken(request.nextUrl.origin, rawToken) : null
    if (apiPayload) {
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

  // Inject user info into request headers for downstream API routes
  const requestHeaders = new Headers(request.headers)
  requestHeaders.set('x-user-id', payload.sub)
  requestHeaders.set('x-user-role', payload.role)

  return NextResponse.next({ request: { headers: requestHeaders } })
}

export const config = {
  matcher: ['/((?!_next/static|_next/image|favicon.ico|favicon.png|logo.png|js_logo.png).*)'],
}
