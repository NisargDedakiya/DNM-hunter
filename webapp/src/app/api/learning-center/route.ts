import { NextResponse } from 'next/server'

const AGENT_API_URL = process.env.AGENT_API_URL || 'http://localhost:8090'

export interface LearningCenterEntry {
  source: 'skills' | 'community'
  id: string
  name: string
  description: string
  category: string
}

// GET /api/learning-center — merged catalog of agentic/skills/ (protocol,
// technology, cloud, tooling, framework references) and
// agentic/community-skills/ (attack-skill playbooks). Both are proxied from
// the agentic service, which has direct filesystem access to those
// directories; the webapp container does not ship them.
export async function GET() {
  const [skillsRes, communityRes] = await Promise.allSettled([
    fetch(`${AGENT_API_URL}/skills`, { cache: 'no-store' }),
    fetch(`${AGENT_API_URL}/community-skills`, { cache: 'no-store' }),
  ])

  const entries: LearningCenterEntry[] = []

  if (skillsRes.status === 'fulfilled' && skillsRes.value.ok) {
    const data = await skillsRes.value.json()
    for (const s of data.skills ?? []) {
      entries.push({
        source: 'skills',
        id: s.id,
        name: s.name,
        description: s.description || '',
        category: s.category || 'general',
      })
    }
  }

  if (communityRes.status === 'fulfilled' && communityRes.value.ok) {
    const data = await communityRes.value.json()
    for (const s of data.skills ?? []) {
      entries.push({
        source: 'community',
        id: s.id,
        name: s.name,
        description: s.description || '',
        category: 'community',
      })
    }
  }

  entries.sort((a, b) => a.category.localeCompare(b.category) || a.name.localeCompare(b.name))

  return NextResponse.json({ entries, total: entries.length })
}
