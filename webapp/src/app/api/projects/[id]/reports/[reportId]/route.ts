import { NextRequest, NextResponse } from 'next/server'
import prisma from '@/lib/prisma'
import { existsSync, readFileSync, unlinkSync } from 'fs'

interface RouteParams {
  params: Promise<{ id: string; reportId: string }>
}

const CONTENT_TYPE_BY_FORMAT: Record<string, string> = {
  html: 'text/html; charset=utf-8',
  pdf: 'application/pdf',
  docx: 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
}

/** GET /api/projects/{id}/reports/{reportId} — Download report (HTML/PDF/DOCX) */
export async function GET(_request: NextRequest, { params }: RouteParams) {
  try {
    const { id, reportId } = await params

    const report = await prisma.report.findFirst({
      where: { id: reportId, projectId: id },
    })
    if (!report) {
      return NextResponse.json({ error: 'Report not found' }, { status: 404 })
    }

    if (!existsSync(report.filePath)) {
      return NextResponse.json({ error: 'Report file not found on disk' }, { status: 404 })
    }

    const fileBuffer = readFileSync(report.filePath)
    const contentType = CONTENT_TYPE_BY_FORMAT[report.format] || 'application/octet-stream'
    // Binary formats (PDF/DOCX) download as attachments; HTML stays inline
    // so the existing "open in new tab" behavior keeps working.
    const disposition = report.format === 'html' ? 'inline' : 'attachment'

    return new Response(fileBuffer, {
      headers: {
        'Content-Type': contentType,
        'Content-Disposition': `${disposition}; filename="${report.filename}"`,
        'Content-Length': String(fileBuffer.length),
        'Cache-Control': 'no-cache',
      },
    })
  } catch (error) {
    console.error('Download report failed:', error)
    return NextResponse.json(
      { error: error instanceof Error ? error.message : 'Download failed' },
      { status: 500 }
    )
  }
}

/** DELETE /api/projects/{id}/reports/{reportId} — Delete report (file + DB) */
export async function DELETE(_request: NextRequest, { params }: RouteParams) {
  try {
    const { id, reportId } = await params

    const report = await prisma.report.findFirst({
      where: { id: reportId, projectId: id },
    })
    if (!report) {
      return NextResponse.json({ error: 'Report not found' }, { status: 404 })
    }

    // Delete file from disk
    if (existsSync(report.filePath)) {
      unlinkSync(report.filePath)
    }

    // Delete DB row
    await prisma.report.delete({ where: { id: reportId } })

    return new Response(null, { status: 204 })
  } catch (error) {
    console.error('Delete report failed:', error)
    return NextResponse.json(
      { error: error instanceof Error ? error.message : 'Delete failed' },
      { status: 500 }
    )
  }
}
