import { NextRequest, NextResponse } from 'next/server'
import prisma from '@/lib/prisma'
import { probeProviderDirect } from '@/lib/llm/directProbe'

interface RouteParams {
  params: Promise<{ id: string; providerId: string }>
}

const AGENT_API_URL = process.env.AGENT_API_URL || 'http://localhost:8090'

// POST /api/users/[id]/llm-providers/[providerId]/test
// Also supports testing unsaved configs by passing full config in body
export async function POST(request: NextRequest, { params }: RouteParams) {
  try {
    const { id, providerId } = await params
    const body = await request.json()

    let config: Record<string, unknown>

    if (providerId === 'unsaved') {
      // Testing an unsaved config — full config in body
      config = body
    } else {
      // Testing a saved config: start from DB (has full secrets), then
      // overlay any fields the operator has edited in the form. Secret
      // fields (apiKey, awsAccessKeyId, awsSecretKey) are returned masked
      // by GET; if the body still carries the mask, keep the DB value.
      // Otherwise the form-edited value wins (so a freshly typed key is
      // actually what gets tested).
      const provider = await prisma.userLlmProvider.findFirst({
        where: { id: providerId, userId: id },
      })
      if (!provider) {
        return NextResponse.json({ error: 'Provider not found' }, { status: 404 })
      }
      const isMasked = (v: unknown) => typeof v === 'string' && v.startsWith('••••')
      const SECRET_FIELDS = new Set(['apiKey', 'awsAccessKeyId', 'awsSecretKey', 'awsBearerToken'])
      config = { ...(provider as unknown as Record<string, unknown>) }
      for (const [key, value] of Object.entries(body)) {
        if (SECRET_FIELDS.has(key) && isMasked(value)) {
          // Keep DB value — user did not retype the secret
          continue
        }
        config[key] = value
      }
    }

    // Proxy to agent test endpoint. The agent is what actually calls the AI
    // provider, so a network failure here means the agent is unreachable — not
    // that the API key is wrong. Translate the cryptic "fetch failed" into an
    // actionable message.
    let agentResp: Response
    try {
      agentResp = await fetch(`${AGENT_API_URL}/llm-provider/test`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(config),
      })
    } catch {
      // Agent unreachable — fall back to validating the key directly against the
      // provider's own API (works for the common key-based / OpenAI-compatible
      // providers without needing the agent service running).
      const probe = await probeProviderDirect(config)
      if (probe.supported) {
        return NextResponse.json(
          probe.ok
            ? { success: true, message: `Key valid — ${probe.models.length} model(s) available (validated directly).` }
            : { success: false, error: probe.error || 'The provider rejected this API key.' },
          { status: probe.ok ? 200 : 400 }
        )
      }
      return NextResponse.json(
        {
          success: false,
          error: `Could not reach the AI agent service at ${AGENT_API_URL}, and this provider type can only be validated by the agent. Start the agent container (check "docker compose ps" / "./nisarghunter.sh status") and try again. This is not a problem with your API key.`,
        },
        { status: 502 }
      )
    }

    const result = await agentResp.json()
    return NextResponse.json(result, { status: agentResp.status })
  } catch (error) {
    console.error('Failed to test LLM provider:', error)
    return NextResponse.json(
      { success: false, error: String(error) },
      { status: 500 }
    )
  }
}
