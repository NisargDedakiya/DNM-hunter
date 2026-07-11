import { NextRequest, NextResponse } from 'next/server'
import prisma from '@/lib/prisma'
import { writeFileSync, mkdirSync, existsSync } from 'fs'
import path from 'path'

const EVIDENCE_OUTPUT_PATH = process.env.EVIDENCE_OUTPUT_PATH || '/data/evidence'
const MAX_IMAGE_BYTES = 8 * 1024 * 1024 // 8MB — generous for a full-page PNG screenshot

interface RouteParams {
  params: Promise<{ id: string }>
}

/** GET /api/remediations/{id}/evidence — list evidence metadata (no file bytes) */
export async function GET(_request: NextRequest, { params }: RouteParams) {
  try {
    const { id } = await params
    const evidence = await prisma.evidence.findMany({
      where: { remediationId: id },
      orderBy: { capturedAt: 'desc' },
      select: {
        id: true, type: true, label: true, fileSize: true,
        textContent: true, source: true, capturedAt: true,
      },
    })
    return NextResponse.json(evidence)
  } catch (error) {
    console.error('List evidence failed:', error)
    return NextResponse.json({ error: 'Failed to list evidence' }, { status: 500 })
  }
}

/**
 * POST /api/remediations/{id}/evidence — attach evidence to a finding.
 *
 * Two shapes, selected by `type`:
 *   { type: "screenshot", label?, imageBase64, source? }  — decodes and
 *     stores a PNG on disk (EVIDENCE_OUTPUT_PATH), keeps only the path in DB.
 *   { type: "note", label?, textContent, source? }        — stores text only,
 *     no file on disk.
 *
 * `source` defaults to "manual" (operator-attached via the UI); the agent's
 * Playwright screenshot tool passes "agent" when auto-capturing evidence.
 */
export async function POST(request: NextRequest, { params }: RouteParams) {
  try {
    const { id } = await params
    const remediation = await prisma.remediation.findUnique({ where: { id }, select: { id: true } })
    if (!remediation) {
      return NextResponse.json({ error: 'Remediation not found' }, { status: 404 })
    }

    const body = await request.json()
    const { type, label, imageBase64, textContent, source } = body as {
      type?: string
      label?: string
      imageBase64?: string
      textContent?: string
      source?: string
    }

    if (type === 'screenshot') {
      if (!imageBase64 || typeof imageBase64 !== 'string') {
        return NextResponse.json({ error: 'imageBase64 is required for type=screenshot' }, { status: 400 })
      }
      const base64Data = imageBase64.replace(/^data:image\/\w+;base64,/, '')
      const buffer = Buffer.from(base64Data, 'base64')
      if (buffer.length === 0) {
        return NextResponse.json({ error: 'imageBase64 decoded to an empty buffer' }, { status: 400 })
      }
      if (buffer.length > MAX_IMAGE_BYTES) {
        return NextResponse.json({ error: `Image exceeds ${MAX_IMAGE_BYTES} byte limit` }, { status: 413 })
      }

      if (!existsSync(EVIDENCE_OUTPUT_PATH)) {
        mkdirSync(EVIDENCE_OUTPUT_PATH, { recursive: true })
      }
      const filename = `evidence_${id}_${Date.now()}.png`
      const filePath = path.join(EVIDENCE_OUTPUT_PATH, filename)
      writeFileSync(filePath, buffer)

      const created = await prisma.evidence.create({
        data: {
          remediationId: id,
          type: 'screenshot',
          label: label || '',
          filePath,
          fileSize: buffer.length,
          source: source === 'agent' ? 'agent' : 'manual',
        },
        select: { id: true, type: true, label: true, fileSize: true, source: true, capturedAt: true },
      })
      return NextResponse.json(created, { status: 201 })
    }

    if (type === 'note') {
      if (!textContent || typeof textContent !== 'string') {
        return NextResponse.json({ error: 'textContent is required for type=note' }, { status: 400 })
      }
      const created = await prisma.evidence.create({
        data: {
          remediationId: id,
          type: 'note',
          label: label || '',
          textContent,
          source: source === 'agent' ? 'agent' : 'manual',
        },
        select: { id: true, type: true, label: true, textContent: true, source: true, capturedAt: true },
      })
      return NextResponse.json(created, { status: 201 })
    }

    return NextResponse.json({ error: "type must be 'screenshot' or 'note'" }, { status: 400 })
  } catch (error) {
    console.error('Attach evidence failed:', error)
    return NextResponse.json({ error: 'Failed to attach evidence' }, { status: 500 })
  }
}
