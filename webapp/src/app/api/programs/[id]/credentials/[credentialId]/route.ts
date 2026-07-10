import { NextRequest, NextResponse } from 'next/server'
import prisma from '@/lib/prisma'
import { encryptSecret } from '@/lib/credentialVault'

interface RouteParams {
  params: Promise<{ id: string; credentialId: string }>
}

// PATCH /api/programs/[id]/credentials/[credentialId] — update a stored identity
export async function PATCH(request: NextRequest, { params }: RouteParams) {
  try {
    const { credentialId } = await params
    const body = await request.json()
    const { label, role, authType, cookies, jwt, headers, oauthToken, notes } = body

    const credential = await prisma.authCredential.update({
      where: { id: credentialId },
      data: {
        ...(label !== undefined && { label }),
        ...(role !== undefined && { role }),
        ...(authType !== undefined && { authType }),
        ...(cookies !== undefined && { cookiesEncrypted: cookies ? encryptSecret(cookies) : '' }),
        ...(jwt !== undefined && { jwtEncrypted: jwt ? encryptSecret(jwt) : '' }),
        ...(headers !== undefined && { headersEncrypted: headers ? encryptSecret(JSON.stringify(headers)) : '' }),
        ...(oauthToken !== undefined && { oauthTokenEncrypted: oauthToken ? encryptSecret(oauthToken) : '' }),
        ...(notes !== undefined && { notes }),
      },
    })

    return NextResponse.json({ id: credential.id, label: credential.label, updatedAt: credential.updatedAt })
  } catch (error) {
    console.error('Failed to update credential:', error)
    return NextResponse.json({ error: 'Failed to update credential' }, { status: 500 })
  }
}

// DELETE /api/programs/[id]/credentials/[credentialId] — remove a stored identity
export async function DELETE(_request: NextRequest, { params }: RouteParams) {
  try {
    const { credentialId } = await params
    await prisma.authCredential.delete({ where: { id: credentialId } })
    return NextResponse.json({ success: true })
  } catch (error) {
    console.error('Failed to delete credential:', error)
    return NextResponse.json({ error: 'Failed to delete credential' }, { status: 500 })
  }
}
