import { NextRequest, NextResponse } from 'next/server'
import prisma from '@/lib/prisma'
import { ASSET_TYPES } from '../route'

interface RouteParams {
  params: Promise<{ id: string; assetId: string }>
}

// PATCH /api/programs/[id]/assets/[assetId] - Update a scope entry
export async function PATCH(request: NextRequest, { params }: RouteParams) {
  try {
    const { assetId } = await params
    const body = await request.json()
    const { type, value, inScope, notes } = body

    if (type !== undefined && !ASSET_TYPES.includes(type)) {
      return NextResponse.json({ error: `type must be one of: ${ASSET_TYPES.join(', ')}` }, { status: 400 })
    }

    const asset = await prisma.asset.update({
      where: { id: assetId },
      data: {
        ...(type !== undefined && { type }),
        ...(value !== undefined && { value }),
        ...(inScope !== undefined && { inScope }),
        ...(notes !== undefined && { notes }),
      },
    })

    return NextResponse.json(asset)
  } catch (error) {
    console.error('Failed to update asset:', error)
    return NextResponse.json({ error: 'Failed to update asset' }, { status: 500 })
  }
}

// DELETE /api/programs/[id]/assets/[assetId] - Remove a scope entry
export async function DELETE(_request: NextRequest, { params }: RouteParams) {
  try {
    const { assetId } = await params
    await prisma.asset.delete({ where: { id: assetId } })
    return NextResponse.json({ success: true })
  } catch (error) {
    console.error('Failed to delete asset:', error)
    return NextResponse.json({ error: 'Failed to delete asset' }, { status: 500 })
  }
}
