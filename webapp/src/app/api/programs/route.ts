import { NextRequest, NextResponse } from 'next/server'
import prisma from '@/lib/prisma'

const PLATFORMS = ['hackerone', 'bugcrowd', 'intigriti', 'yeswehack', 'manual']

// GET /api/programs?userId=... - List programs for a user
export async function GET(request: NextRequest) {
  try {
    const { searchParams } = new URL(request.url)
    const userId = searchParams.get('userId')
    if (!userId) {
      return NextResponse.json({ error: 'userId is required' }, { status: 400 })
    }

    const programs = await prisma.program.findMany({
      where: { userId },
      orderBy: { updatedAt: 'desc' },
      include: {
        _count: { select: { assets: true, projects: true, remediations: true } },
      },
    })

    return NextResponse.json(programs)
  } catch (error) {
    console.error('Failed to fetch programs:', error)
    return NextResponse.json({ error: 'Failed to fetch programs' }, { status: 500 })
  }
}

// POST /api/programs - Create a new program
export async function POST(request: NextRequest) {
  try {
    const body = await request.json()
    const { userId, name, platform } = body

    if (!userId || !name) {
      return NextResponse.json({ error: 'userId and name are required' }, { status: 400 })
    }
    if (platform && !PLATFORMS.includes(platform)) {
      return NextResponse.json({ error: `platform must be one of: ${PLATFORMS.join(', ')}` }, { status: 400 })
    }

    const program = await prisma.program.create({
      data: {
        userId,
        name,
        platform: platform || 'manual',
        platformHandle: body.platformHandle || '',
        platformUrl: body.platformUrl || '',
        status: body.status || 'active',
        scopeSummary: body.scopeSummary || '',
        outOfScope: body.outOfScope || '',
        rateLimits: body.rateLimits || '',
        credentialNotes: body.credentialNotes || '',
        notes: body.notes || '',
        rewardMin: body.rewardMin ?? null,
        rewardMax: body.rewardMax ?? null,
        rewardCurrency: body.rewardCurrency || 'USD',
        startDate: body.startDate ? new Date(body.startDate) : null,
        deadline: body.deadline ? new Date(body.deadline) : null,
      },
    })

    return NextResponse.json(program, { status: 201 })
  } catch (error) {
    console.error('Failed to create program:', error)
    return NextResponse.json({ error: 'Failed to create program' }, { status: 500 })
  }
}
