import { NextRequest, NextResponse } from 'next/server'
import prisma from '@/lib/prisma'
import { probeProviderDirect, canProbeDirectly, type ProbeModel } from '@/lib/llm/directProbe'

const AGENT_API_URL = process.env.AGENT_API_URL || 'http://localhost:8090'

interface ProviderRow {
  providerType?: string
  name?: string
  apiKey?: string
  baseUrl?: string
  [k: string]: unknown
}

const PROVIDER_LABEL: Record<string, string> = {
  openai: 'OpenAI',
  anthropic: 'Anthropic',
  openrouter: 'OpenRouter',
  gemini: 'Google Gemini',
  openai_compatible: 'OpenAI-compatible',
}

// Build the same { "Provider (name)": [models] } shape the agent returns, by
// probing each configured provider directly. Used when the agent is unreachable.
async function discoverDirect(providers: ProviderRow[]): Promise<Record<string, ProbeModel[]>> {
  const out: Record<string, ProbeModel[]> = {}
  const results = await Promise.all(
    providers.map(async (p) => {
      if (!canProbeDirectly(p)) return null
      const probe = await probeProviderDirect(p)
      if (!probe.ok || probe.models.length === 0) return null
      const label = PROVIDER_LABEL[(p.providerType || '').toLowerCase()] || p.name || 'Provider'
      return { key: `${label} (${p.name || 'default'})`, models: probe.models }
    }),
  )
  for (const r of results) if (r) out[r.key] = r.models
  return out
}

// POST /api/models { userId? } - Fetch available AI models from all configured providers.
// Body-based (not query-string) so plaintext apiKey values never appear in access logs.
export async function POST(request: NextRequest) {
  const { userId } = await request.json().catch(() => ({ userId: null }))

  let providers: ProviderRow[] = []
  if (userId) {
    providers = (await prisma.userLlmProvider.findMany({ where: { userId } })) as unknown as ProviderRow[]
  }

  // Primary path: the agent aggregates models across every provider type.
  try {
    const res = await fetch(`${AGENT_API_URL}/models`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ providers: providers.length > 0 ? providers : null }),
      cache: 'no-store',
    })
    if (res.ok) {
      return NextResponse.json(await res.json())
    }
    // non-2xx from the agent — fall through to the direct fallback
  } catch {
    // agent unreachable — fall through to the direct fallback
  }

  // Fallback: probe the common key-based providers directly (no agent needed).
  if (providers.length > 0) {
    const direct = await discoverDirect(providers)
    if (Object.keys(direct).length > 0) {
      return NextResponse.json(direct)
    }
  }

  return NextResponse.json(
    { error: 'Could not load models. Start the AI agent service, or check that your provider key is valid.' },
    { status: 503 },
  )
}
