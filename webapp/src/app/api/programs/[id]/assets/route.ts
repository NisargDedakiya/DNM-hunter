import { NextRequest, NextResponse } from 'next/server'
import prisma from '@/lib/prisma'

export const ASSET_TYPES = [
  'domain', 'subdomain', 'cidr', 'api', 'mobile_android', 'mobile_ios',
  'github', 'cloud', 'graphql',
] as const

interface RouteParams {
  params: Promise<{ id: string }>
}

// GET /api/programs/[id]/assets - List assets in a program's scope
export async function GET(_request: NextRequest, { params }: RouteParams) {
  try {
    const { id } = await params
    const assets = await prisma.asset.findMany({
      where: { programId: id },
      orderBy: { createdAt: 'desc' },
    })
    return NextResponse.json(assets)
  } catch (error) {
    console.error('Failed to fetch assets:', error)
    return NextResponse.json({ error: 'Failed to fetch assets' }, { status: 500 })
  }
}

// POST /api/programs/[id]/assets - Add a scope entry to a program
export async function POST(request: NextRequest, { params }: RouteParams) {
  try {
    const { id } = await params
    const body = await request.json()
    const { type, value } = body

    if (!type || !value) {
      return NextResponse.json({ error: 'type and value are required' }, { status: 400 })
    }
    if (!ASSET_TYPES.includes(type)) {
      return NextResponse.json({ error: `type must be one of: ${ASSET_TYPES.join(', ')}` }, { status: 400 })
    }

    const asset = await prisma.asset.create({
      data: {
        programId: id,
        type,
        value,
        inScope: body.inScope ?? true,
        notes: body.notes || '',
      },
    })

    return NextResponse.json(asset, { status: 201 })
  } catch (error) {
    console.error('Failed to create asset:', error)
    return NextResponse.json({ error: 'Failed to create asset' }, { status: 500 })
  }
}
