import { NextRequest, NextResponse } from 'next/server'
import { toSarif, toMarkdown, toHtml } from '@/lib/scan/report'
import { sampleMeta, SAMPLE_FINDINGS } from '@/lib/scan/sample'

const CONTENT_TYPE: Record<string, string> = {
  md: 'text/markdown; charset=utf-8',
  html: 'text/html; charset=utf-8',
  sarif: 'application/json; charset=utf-8',
}

// GET /api/scan/sample/report?format=md|html|sarif — public sample deliverable,
// so prospects (and reviewers) can see the actual report quality, unauthenticated.
export async function GET(request: NextRequest) {
  const format = (new URL(request.url).searchParams.get('format') || 'html').toLowerCase()
  const fmt = format === 'markdown' ? 'md' : format
  if (!(fmt in CONTENT_TYPE)) {
    return NextResponse.json({ error: 'Unsupported format' }, { status: 400 })
  }
  const meta = sampleMeta()
  const body = fmt === 'sarif' ? JSON.stringify(toSarif(meta, SAMPLE_FINDINGS), null, 2)
    : fmt === 'md' ? toMarkdown(meta, SAMPLE_FINDINGS)
      : toHtml(meta, SAMPLE_FINDINGS)
  return new NextResponse(body, {
    status: 200,
    headers: {
      'Content-Type': CONTENT_TYPE[fmt],
      'Content-Disposition': `inline; filename="nisarghunter-sample-report.${fmt}"`,
      'Cache-Control': 'public, max-age=3600',
    },
  })
}
