import { NextRequest, NextResponse } from 'next/server'

const AGENT_API_URL = process.env.AGENT_API_URL || 'http://localhost:8090'

interface RouteParams {
  params: Promise<{ skillId: string[] }>
}

// GET /api/skills/[...skillId] — proxy to agentic's /skills/{skill_id} for full
// content. Catch-all because skill ids are category-prefixed paths, e.g.
// "vulnerabilities/jwt_attacks".
export async function GET(_request: NextRequest, { params }: RouteParams) {
  try {
    const { skillId } = await params
    const id = skillId.join('/')
    const res = await fetch(`${AGENT_API_URL}/skills/${id}`, {
      method: 'GET',
      headers: { 'Content-Type': 'application/json' },
      cache: 'no-store',
    })

    if (!res.ok) {
      return NextResponse.json({ error: 'Skill not found or agent unavailable' }, { status: res.status === 404 ? 404 : 503 })
    }

    const data = await res.json()
    return NextResponse.json(data)
  } catch {
    return NextResponse.json({ error: 'Agent service unreachable' }, { status: 503 })
  }
}
