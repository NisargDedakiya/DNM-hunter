import { NextRequest, NextResponse } from 'next/server'
import prisma from '@/lib/prisma'
import { decryptSecret } from '@/lib/credentialVault'

interface RouteParams {
  params: Promise<{ id: string }>
}

const MAX_BODY_PREVIEW = 20_000
const REQUEST_TIMEOUT_MS = 20_000

interface ReplayRequestBody {
  method: string
  url: string
  headers?: Record<string, string>
  body?: string
  credentialId?: string
}

// POST /api/programs/[id]/replay — re-issue a request as a stored identity.
//
// This is the cross-account/IDOR testing primitive: capture a request (from
// the browser devtools, Katana output, or hand-written), pick a stored
// AuthCredential, and the server swaps in that identity's cookies/JWT/
// headers/OAuth token before sending. Run it twice with two different
// credentialIds against the same request to diff the responses -- that diff
// IS the IDOR/BOLA check.
//
// Deliberately server-side (not a browser fetch) so cross-origin/CORS never
// gets in the way, and so the decrypted credential never reaches the client.
export async function POST(request: NextRequest, { params }: RouteParams) {
  try {
    const { id: programId } = await params
    const payload = (await request.json()) as ReplayRequestBody
    const { method, url, headers = {}, body, credentialId } = payload

    if (!method || !url) {
      return NextResponse.json({ error: 'method and url are required' }, { status: 400 })
    }

    let parsedUrl: URL
    try {
      parsedUrl = new URL(url)
    } catch {
      return NextResponse.json({ error: 'url is not a valid absolute URL' }, { status: 400 })
    }
    if (!['http:', 'https:'].includes(parsedUrl.protocol)) {
      return NextResponse.json({ error: 'url must be http or https' }, { status: 400 })
    }

    const outboundHeaders: Record<string, string> = { ...headers }

    if (credentialId) {
      const credential = await prisma.authCredential.findFirst({ where: { id: credentialId, programId } })
      if (!credential) {
        return NextResponse.json({ error: 'Credential not found for this program' }, { status: 404 })
      }
      if (credential.cookiesEncrypted) {
        outboundHeaders['Cookie'] = decryptSecret(credential.cookiesEncrypted)
      }
      if (credential.jwtEncrypted) {
        outboundHeaders['Authorization'] = `Bearer ${decryptSecret(credential.jwtEncrypted)}`
      }
      if (credential.oauthTokenEncrypted) {
        outboundHeaders['Authorization'] = `Bearer ${decryptSecret(credential.oauthTokenEncrypted)}`
      }
      if (credential.headersEncrypted) {
        try {
          const extraHeaders = JSON.parse(decryptSecret(credential.headersEncrypted)) as Record<string, string>
          Object.assign(outboundHeaders, extraHeaders)
        } catch {
          // Malformed stored headers shouldn't block the replay — the
          // cookie/JWT/OAuth injection above still applies.
        }
      }
    }

    const controller = new AbortController()
    const timer = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS)
    const startedAt = Date.now()

    try {
      const upstreamMethod = method.toUpperCase()
      const hasBody = body !== undefined && !['GET', 'HEAD'].includes(upstreamMethod)
      const response = await fetch(parsedUrl, {
        method: upstreamMethod,
        headers: outboundHeaders,
        body: hasBody ? body : undefined,
        redirect: 'manual',
        signal: controller.signal,
      })

      const responseHeaders: Record<string, string> = {}
      response.headers.forEach((value, key) => { responseHeaders[key] = value })

      const rawBody = await response.text()
      const truncated = rawBody.length > MAX_BODY_PREVIEW
      const bodyPreview = truncated ? rawBody.slice(0, MAX_BODY_PREVIEW) : rawBody

      return NextResponse.json({
        request: {
          method: upstreamMethod,
          url: parsedUrl.toString(),
          headers: outboundHeaders,
          identityUsed: credentialId ? true : false,
        },
        response: {
          status: response.status,
          statusText: response.statusText,
          headers: responseHeaders,
          body: bodyPreview,
          bodyTruncated: truncated,
          bodyLength: rawBody.length,
        },
        timingMs: Date.now() - startedAt,
      })
    } finally {
      clearTimeout(timer)
    }
  } catch (error) {
    if (error instanceof Error && error.name === 'AbortError') {
      return NextResponse.json({ error: `Request timed out after ${REQUEST_TIMEOUT_MS}ms` }, { status: 504 })
    }
    console.error('Replay request failed:', error)
    return NextResponse.json(
      { error: error instanceof Error ? error.message : 'Replay request failed' },
      { status: 502 }
    )
  }
}
