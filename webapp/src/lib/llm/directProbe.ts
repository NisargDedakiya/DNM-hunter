/**
 * Direct provider probing — a webapp-side fallback for validating LLM provider
 * keys and listing models WITHOUT the agent service.
 *
 * Normally the agent (AGENT_API_URL) does this, but when it is unreachable the
 * key test and model dropdown would be dead. For the common key-based cloud
 * providers (and any OpenAI-compatible endpoint) we can hit the provider's own
 * `/models` API directly from the Next.js server — a valid key returns 200 and
 * the model list; a bad key returns 401. Providers that need special signing
 * (e.g. AWS Bedrock SigV4) are not covered here and still require the agent.
 */

export interface ProbeModel {
  id: string
  name: string
  context_length: number | null
  description: string
}

interface ProviderConfig {
  providerType?: string
  name?: string
  apiKey?: string
  baseUrl?: string
  [k: string]: unknown
}

const TIMEOUT_MS = 15_000

function m(id: string, name?: string, ctx: number | null = null, description = ''): ProbeModel {
  return { id, name: name || id, context_length: ctx, description }
}

async function getJson(
  url: string,
  headers: Record<string, string>,
): Promise<{ ok: boolean; status: number; data?: unknown; error?: string }> {
  const controller = new AbortController()
  const timer = setTimeout(() => controller.abort(), TIMEOUT_MS)
  try {
    const resp = await fetch(url, { headers, signal: controller.signal, cache: 'no-store' })
    if (!resp.ok) {
      let msg = `HTTP ${resp.status}`
      try {
        const j = (await resp.json()) as { error?: { message?: string } | string; message?: string }
        const e = j?.error
        msg = (typeof e === 'object' ? e?.message : e) || j?.message || msg
      } catch { /* non-JSON body */ }
      return { ok: false, status: resp.status, error: msg }
    }
    return { ok: true, status: resp.status, data: await resp.json() }
  } catch (e) {
    return { ok: false, status: 0, error: e instanceof Error ? e.message : String(e) }
  } finally {
    clearTimeout(timer)
  }
}

// --- OpenAI chat/reasoning family filter (mirrors the agent) ---
const OA_EXCLUDE = ['embedding', 'whisper', 'dall-e', 'moderation', 'tts', 'realtime', 'audio', 'image', 'sora', 'davinci', 'babbage', 'curie']
function isOpenAIChatModel(id: string): boolean {
  const chat = id.startsWith('gpt-') || id.startsWith('chatgpt-') || /^o\d/.test(id)
  return chat && !OA_EXCLUDE.some((s) => id.includes(s))
}

/** Whether the fallback can validate this provider type directly. */
export function canProbeDirectly(cfg: ProviderConfig): boolean {
  const t = (cfg.providerType || '').toLowerCase()
  if (['openai', 'anthropic', 'openrouter', 'gemini'].includes(t)) return true
  if (t === 'openai_compatible' && typeof cfg.baseUrl === 'string' && cfg.baseUrl.trim()) return true
  return false
}

/**
 * Probe a provider directly. Returns { ok, error?, models }. `ok` means the key
 * is valid (the provider's model list was reachable with it).
 */
export async function probeProviderDirect(
  cfg: ProviderConfig,
): Promise<{ supported: boolean; ok: boolean; error?: string; models: ProbeModel[] }> {
  const type = (cfg.providerType || '').toLowerCase()
  const key = (cfg.apiKey || '').trim()

  if (!canProbeDirectly(cfg)) return { supported: false, ok: false, models: [] }
  if (type !== 'gemini' && type !== 'openai_compatible' && !key) {
    return { supported: true, ok: false, error: 'API key is required.', models: [] }
  }

  if (type === 'openai') {
    const r = await getJson('https://api.openai.com/v1/models', { Authorization: `Bearer ${key}` })
    if (!r.ok) return { supported: true, ok: false, error: r.error, models: [] }
    const data = ((r.data as { data?: { id: string }[] })?.data ?? [])
      .map((x) => x.id).filter(isOpenAIChatModel).sort().reverse().map((id) => m(id, id, null, 'OpenAI'))
    return { supported: true, ok: true, models: data }
  }

  if (type === 'anthropic') {
    const r = await getJson('https://api.anthropic.com/v1/models?limit=100', {
      'x-api-key': key,
      'anthropic-version': '2023-06-01',
    })
    if (!r.ok) return { supported: true, ok: false, error: r.error, models: [] }
    const data = ((r.data as { data?: { id: string; display_name?: string }[] })?.data ?? [])
      .map((x) => m(x.id, x.display_name || x.id, null, 'Anthropic'))
    return { supported: true, ok: true, models: data }
  }

  if (type === 'openrouter') {
    const r = await getJson('https://openrouter.ai/api/v1/models', { Authorization: `Bearer ${key}` })
    if (!r.ok) return { supported: true, ok: false, error: r.error, models: [] }
    const data = ((r.data as { data?: { id: string; name?: string; context_length?: number }[] })?.data ?? [])
      .map((x) => m(x.id, x.name || x.id, x.context_length ?? null, 'OpenRouter'))
    return { supported: true, ok: true, models: data }
  }

  if (type === 'gemini') {
    const r = await getJson(`https://generativelanguage.googleapis.com/v1beta/models?key=${encodeURIComponent(key)}`, {})
    if (!r.ok) return { supported: true, ok: false, error: r.error, models: [] }
    const data = ((r.data as { models?: { name: string; displayName?: string; supportedGenerationMethods?: string[] }[] })?.models ?? [])
      .filter((x) => (x.supportedGenerationMethods ?? []).includes('generateContent'))
      .map((x) => { const id = x.name.replace(/^models\//, ''); return m(id, x.displayName || id, null, 'Google Gemini') })
    return { supported: true, ok: true, models: data }
  }

  // openai_compatible — Ollama / vLLM / LM Studio / Groq / Together / custom
  const base = (cfg.baseUrl || '').trim().replace(/\/+$/, '')
  const headers: Record<string, string> = {}
  if (key) headers.Authorization = `Bearer ${key}`
  const r = await getJson(`${base}/models`, headers)
  if (!r.ok) return { supported: true, ok: false, error: r.error, models: [] }
  const data = ((r.data as { data?: { id: string }[] })?.data ?? [])
    .map((x) => m(x.id, x.id, null, cfg.name || 'OpenAI-compatible'))
  return { supported: true, ok: true, models: data }
}
