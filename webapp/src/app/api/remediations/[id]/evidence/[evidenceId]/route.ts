import { NextRequest, NextResponse } from 'next/server'
import prisma from '@/lib/prisma'
import { readFileSync, existsSync, unlinkSync } from 'fs'

interface RouteParams {
  params: Promise<{ id: string; evidenceId: string }>
}

/** GET /api/remediations/{id}/evidence/{evidenceId} — serve the screenshot
 *  bytes (type=screenshot) or the note JSON (type=note). */
export async function GET(_request: NextRequest, { params }: RouteParams) {
  try {
    const { id, evidenceId } = await params
    const evidence = await prisma.evidence.findFirst({ where: { id: evidenceId, remediationId: id } })
    if (!evidence) {
      return NextResponse.json({ error: 'Evidence not found' }, { status: 404 })
    }

    if (evidence.type === 'screenshot') {
      if (!evidence.filePath || !existsSync(evidence.filePath)) {
        return NextResponse.json({ error: 'Evidence file missing on disk' }, { status: 404 })
      }
      const buffer = readFileSync(evidence.filePath)
      return new NextResponse(new Uint8Array(buffer), {
        headers: {
          'Content-Type': 'image/png',
          'Content-Length': String(buffer.length),
          'Cache-Control': 'private, max-age=3600',
        },
      })
    }

    return NextResponse.json({
      id: evidence.id, type: evidence.type, label: evidence.label,
      textContent: evidence.textContent, source: evidence.source, capturedAt: evidence.capturedAt,
    })
  } catch (error) {
    console.error('Fetch evidence failed:', error)
    return NextResponse.json({ error: 'Failed to fetch evidence' }, { status: 500 })
  }
}

/** DELETE /api/remediations/{id}/evidence/{evidenceId} */
export async function DELETE(_request: NextRequest, { params }: RouteParams) {
  try {
    const { id, evidenceId } = await params
    const evidence = await prisma.evidence.findFirst({ where: { id: evidenceId, remediationId: id } })
    if (!evidence) {
      return NextResponse.json({ error: 'Evidence not found' }, { status: 404 })
    }
    if (evidence.filePath && existsSync(evidence.filePath)) {
      unlinkSync(evidence.filePath)
    }
    await prisma.evidence.delete({ where: { id: evidenceId } })
    return NextResponse.json({ success: true })
  } catch (error) {
    console.error('Delete evidence failed:', error)
    return NextResponse.json({ error: 'Failed to delete evidence' }, { status: 500 })
  }
}
