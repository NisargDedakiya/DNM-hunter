import { NextRequest, NextResponse } from 'next/server'

const AGENT_API_URL = process.env.AGENT_API_URL || 'http://localhost:8090'

interface RouteParams {
  params: Promise<{ source: string; id: string[] }>
}

// The agent's /skills/{id} endpoint returns the raw file (frontmatter
// included) — it's designed to feed the agent's own context injection,
// where the frontmatter is harmless. Strip it here since the Academy
// already surfaces name/description in its own header.
function stripFrontmatter(text: string): string {
  const match = /^---\s*\n[\s\S]*?\n---\s*\n/.exec(text)
  return match ? text.slice(match[0].length).trimStart() : text
}

// GET /api/learning-center/[source]/[...id] — full markdown content for a
// single skill doc. source is 'skills' or 'community'; id is the slug
// (skills ids can contain slashes, e.g. "vulnerabilities/ssrf").
export async function GET(request: NextRequest, { params }: RouteParams) {
  const { source, id } = await params
  if (source !== 'skills' && source !== 'community') {
    return NextResponse.json({ error: 'Unknown source' }, { status: 400 })
  }

  const skillId = id.map(encodeURIComponent).join('/')
  const upstreamPath = source === 'skills' ? `/skills/${skillId}` : `/community-skills/${skillId}`

  try {
    const res = await fetch(`${AGENT_API_URL}${upstreamPath}`, { cache: 'no-store' })
    if (!res.ok) {
      return NextResponse.json({ error: 'Not found' }, { status: 404 })
    }
    const data = await res.json()
    return NextResponse.json({
      source,
      id: data.id,
      name: data.name,
      description: data.description || '',
      category: data.category || (source === 'community' ? 'community' : 'general'),
      content: stripFrontmatter(data.content || ''),
    })
  } catch {
    return NextResponse.json({ error: 'Learning Center service unreachable' }, { status: 502 })
  }
}
