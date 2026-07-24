/**
 * Server-side fetch wrapper for all calls to the recon orchestrator.
 *
 * The orchestrator requires `X-Orchestrator-Key` on every route except `/health`
 * (V1-auth). This helper injects that header so the webapp's server-side API
 * routes are accepted, while a compromised recon container (which does not hold
 * ORCHESTRATOR_API_KEY) cannot drive the orchestration API even though it can
 * reach 127.0.0.1:8010 over host networking.
 *
 * Pass the full URL (callers keep their existing `${RECON_ORCHESTRATOR_URL}/...`
 * templates); only the function name changes from `fetch` to `orchestratorFetch`.
 * Server-side only — never import this into client components.
 */
import { backendUnreachableMessage, isUnreachableError } from '@/lib/serviceErrors'

export async function orchestratorFetch(url: string | URL, init: RequestInit = {}): Promise<Response> {
  try {
    return await fetch(url, {
      ...init,
      headers: {
        ...(init.headers || {}),
        'X-Orchestrator-Key': process.env.ORCHESTRATOR_API_KEY || 'changeme',
      },
    })
  } catch (err) {
    // undici throws TypeError("fetch failed") when the orchestrator container is
    // down/unreachable — replace it with an actionable message so the UI modal
    // tells the user what to check instead of a cryptic "fetch failed".
    if (isUnreachableError(err)) {
      throw new Error(backendUnreachableMessage(
        'recon orchestrator service', 'recon-orchestrator',
        { url: String(url), detail: err instanceof Error ? err.message : String(err) }))
    }
    throw err
  }
}
