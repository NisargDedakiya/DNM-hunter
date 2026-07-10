import { NextRequest, NextResponse } from 'next/server'
import prisma from '@/lib/prisma'
import { encryptSecret } from '@/lib/credentialVault'

const AUTH_TYPES = ['cookie', 'jwt', 'header', 'oauth', 'saml', 'mfa']

interface RouteParams {
  params: Promise<{ id: string }>
}

function maskCredential(cred: {
  id: string; label: string; role: string; authType: string; notes: string
  cookiesEncrypted: string; jwtEncrypted: string; headersEncrypted: string; oauthTokenEncrypted: string
  createdAt: Date; updatedAt: Date
}) {
  // List/detail views never return decrypted secrets — only a masked
  // preview so the UI can show "cookie is set" without exposing it.
  // Full plaintext is only ever returned from the Replay endpoint, and
  // only server-side for the outbound request it builds.
  return {
    id: cred.id,
    label: cred.label,
    role: cred.role,
    authType: cred.authType,
    notes: cred.notes,
    hasCookies: !!cred.cookiesEncrypted,
    hasJwt: !!cred.jwtEncrypted,
    hasHeaders: !!cred.headersEncrypted,
    hasOauthToken: !!cred.oauthTokenEncrypted,
    createdAt: cred.createdAt,
    updatedAt: cred.updatedAt,
  }
}

// GET /api/programs/[id]/credentials — list stored identities (masked)
export async function GET(_request: NextRequest, { params }: RouteParams) {
  try {
    const { id: programId } = await params
    const credentials = await prisma.authCredential.findMany({
      where: { programId },
      orderBy: { createdAt: 'desc' },
    })
    return NextResponse.json(credentials.map(maskCredential))
  } catch (error) {
    console.error('Failed to fetch credentials:', error)
    return NextResponse.json({ error: 'Failed to fetch credentials' }, { status: 500 })
  }
}

// POST /api/programs/[id]/credentials — add a stored identity
export async function POST(request: NextRequest, { params }: RouteParams) {
  try {
    const { id: programId } = await params
    const body = await request.json()
    const { label, role, authType, cookies, jwt, headers, oauthToken, notes } = body

    if (!label) {
      return NextResponse.json({ error: 'label is required' }, { status: 400 })
    }
    if (authType && !AUTH_TYPES.includes(authType)) {
      return NextResponse.json({ error: `authType must be one of: ${AUTH_TYPES.join(', ')}` }, { status: 400 })
    }

    const credential = await prisma.authCredential.create({
      data: {
        programId,
        label,
        role: role || '',
        authType: authType || 'cookie',
        cookiesEncrypted: cookies ? encryptSecret(cookies) : '',
        jwtEncrypted: jwt ? encryptSecret(jwt) : '',
        headersEncrypted: headers ? encryptSecret(JSON.stringify(headers)) : '',
        oauthTokenEncrypted: oauthToken ? encryptSecret(oauthToken) : '',
        notes: notes || '',
      },
    })

    return NextResponse.json(maskCredential(credential), { status: 201 })
  } catch (error) {
    console.error('Failed to create credential:', error)
    return NextResponse.json({ error: 'Failed to create credential' }, { status: 500 })
  }
}
