// Recon plan builder (master-plan Phase 3, Priority 2) — webapp-native mirror of
// the canonical Python planner in common/recon_planner.py. Both share the same
// module catalog + technology-aware prioritization rules so the approve-before-
// execute UI and the orchestrator never disagree about what a plan looks like.
//
// Two invariants, matching the Python side:
//   1. Every step references a module that actually exists in MODULE_CATALOG.
//   2. Modules whose techAffinity matches a detected technology are prioritized.

export type ModuleCategory = 'recon' | 'scanner' | 'validator' | 'reporter' | 'export'
export type Priority = 'high' | 'medium' | 'low'

export interface ModuleCatalogEntry {
  name: string
  displayName: string
  category: ModuleCategory
  techAffinity: string[]
}

// The seven built-in modules, kept in lockstep with
// common/adapters/builtin_adapters.py.
export const MODULE_CATALOG: ModuleCatalogEntry[] = [
  { name: 'recon', displayName: 'Attack-Surface Recon', category: 'recon', techAffinity: ['spa', 'graphql', 'rest', 'wordpress'] },
  { name: 'gvm_scan', displayName: 'GVM Vulnerability Scan', category: 'scanner', techAffinity: ['network', 'infrastructure'] },
  { name: 'github_secret_hunt', displayName: 'GitHub Secret Hunt', category: 'scanner', techAffinity: ['github'] },
  { name: 'trufflehog_scan', displayName: 'TruffleHog Secret Scan', category: 'scanner', techAffinity: ['github', 'filesystem'] },
  { name: 'iac_scan', displayName: 'IaC / DevOps Misconfig Scan', category: 'scanner', techAffinity: ['docker', 'kubernetes', 'terraform', 'github-actions'] },
  { name: 'cloud_recon', displayName: 'Cloud Storage Recon', category: 'recon', techAffinity: ['aws', 'gcp', 'azure'] },
  { name: 'ai_attack_surface_scan', displayName: 'AI Attack-Surface (Gauntlet)', category: 'scanner', techAffinity: ['rest', 'graphql', 'spa'] },
]

export interface PlanStep {
  moduleName: string
  displayName: string
  rationale: string
  targetAssets: string[]
  priority: Priority
  estimatedValue: string
}

export interface ReconPlan {
  steps: PlanStep[]
  reasoning: string
}

const PRIORITY_RANK: Record<Priority, number> = { high: 0, medium: 1, low: 2 }

const ESTIMATED_VALUE: Record<ModuleCategory, string> = {
  recon: 'attack-surface expansion (assets, endpoints, params)',
  scanner: 'confirmed vulnerabilities / exposures',
  validator: 'confidence + false-positive filtering',
  reporter: 'reportable output',
  export: 'exported artifacts',
}

export function buildReconPlan(detectedTech: string[], assets: string[]): ReconPlan {
  const detected = detectedTech.map(t => t.trim().toLowerCase()).filter(Boolean)

  const steps: PlanStep[] = MODULE_CATALOG.map(m => {
    const affinity = new Set(m.techAffinity.map(t => t.toLowerCase()))
    const matched = detected.filter(t => affinity.has(t))
    const priority: Priority = matched.length > 0
      ? 'high'
      : m.category === 'recon'
        ? 'medium'
        : detected.length > 0 ? 'low' : 'medium'

    const rationale = matched.length > 0
      ? `Detected ${matched.join(', ')} — ${m.displayName} is tuned for this stack.`
      : m.category === 'recon'
        ? `${m.displayName} broadens the attack surface before targeted scanning.`
        : `${m.displayName} runs once recon surfaces relevant targets.`

    return { moduleName: m.name, displayName: m.displayName, rationale, targetAssets: assets, priority, estimatedValue: ESTIMATED_VALUE[m.category] }
  })

  steps.sort((a, b) => {
    const p = PRIORITY_RANK[a.priority] - PRIORITY_RANK[b.priority]
    if (p !== 0) return p
    const aRecon = catOf(a.moduleName) === 'recon' ? 0 : 1
    const bRecon = catOf(b.moduleName) === 'recon' ? 0 : 1
    if (aRecon !== bRecon) return aRecon - bRecon
    return a.moduleName.localeCompare(b.moduleName)
  })

  const high = steps.filter(s => s.priority === 'high').map(s => s.moduleName)
  const lead = detected.length > 0
    ? `Technology signals (${[...new Set(detected)].sort().join(', ')}) drive prioritization. `
    : 'No technology signals yet — leading with broad recon to build the attack surface. '
  const focus = high.length > 0 ? `Prioritized first: ${high.join(', ')}.` : 'Running recon before targeted scanners.'

  return { steps, reasoning: lead + focus }
}

function catOf(moduleName: string): ModuleCategory | undefined {
  return MODULE_CATALOG.find(m => m.name === moduleName)?.category
}
