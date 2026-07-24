/**
 * Human-readable errors for when a backend service (agent, recon orchestrator)
 * can't be reached. Isomorphic — safe to import from both server routes and
 * client components (no server-only imports here).
 *
 * The AI features (Red Zone recon pipeline, CypherFix triage/codefix) live in
 * separate containers. When one isn't up yet, the raw failure is a cryptic
 * `fetch failed` / `WebSocket connection error`; these builders turn that into a
 * clear, actionable message that points at the launcher's diagnostics.
 */

/** True for the connection-level failures that mean "the service isn't up/reachable". */
export function isUnreachableError(err: unknown): boolean {
  const msg = (err instanceof Error ? err.message : String(err || '')).toLowerCase()
  return (
    msg.includes('fetch failed') ||
    msg.includes('econnrefused') ||
    msg.includes('enotfound') ||
    msg.includes('network') ||
    msg.includes('failed to fetch') ||
    msg.includes('connect')
  )
}

/**
 * @param service  human name, e.g. "AI agent service (port 8090)"
 * @param logsName compose service to tail, e.g. "agent" or "recon-orchestrator"
 * @param extra    optional underlying detail to append in parentheses
 */
export function backendUnreachableMessage(service: string, logsName: string, extra?: string): string {
  const base =
    `The ${service} isn't reachable. It may still be starting after a rebuild, or not running. ` +
    `Check it with "starthunt status" (Windows: .\\starthunt.ps1 status) and view its logs with ` +
    `"starthunt logs ${logsName}". These AI features also need an LLM API key configured in .env.`
  return extra ? `${base} (${extra})` : base
}
