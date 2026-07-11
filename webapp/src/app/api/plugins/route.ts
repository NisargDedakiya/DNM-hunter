import { NextResponse } from 'next/server'

const AGENT_API_URL = process.env.AGENT_API_URL || 'http://localhost:8090'

// GET /api/plugins — proxy to agentic's plugin catalog
export async function GET() {
  try {
    const res = await fetch(`${AGENT_API_URL}/plugins`, {
      method: 'GET',
      headers: { 'Content-Type': 'application/json' },
      cache: 'no-store',
    })

    if (!res.ok) {
      return NextResponse.json({ plugins: [], total: 0 }, { status: 200 })
    }

    const data = await res.json()
    return NextResponse.json(data)
  } catch {
    // Agent service unreachable — return empty list so UI degrades gracefully
    return NextResponse.json({ plugins: [], total: 0 }, { status: 200 })
  }
}
