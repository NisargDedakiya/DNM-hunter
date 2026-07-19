// Subscription plan catalogue + entitlements — the single source of truth for
// what each tier costs and unlocks. Pure data + pure helpers (no DB, no I/O) so
// it is trivially unit-testable and safe to import on both server and client.

export type PlanId = 'free' | 'pro' | 'team'

// A capability the app can gate on. Keep these coarse and product-meaningful.
export type Feature =
  | 'scan.sast'            // web-app source SAST (code_audit)
  | 'scan.dast'            // live HTTP probe (web_probe)
  | 'scan.iac'             // cloud / IaC misconfig
  | 'scan.llm'             // OWASP LLM Top 10
  | 'scan.smart_contract'  // Solidity
  | 'scan.binary'          // ELF / binary hardening
  | 'scan.deep_binary'     // angr symbolic execution
  | 'scan.github_repo'     // clone + scan a GitHub repo
  | 'scan.scheduled'       // scheduled / recurring scans
  | 'report.markdown'      // Markdown report export
  | 'report.html'          // client-deliverable HTML report
  | 'export.sarif'         // SARIF 2.1.0 export (code scanning)
  | 'api.access'           // programmatic API / CI tokens
  | 'collab.team'          // shared workspaces / seats
  | 'support.priority'     // priority support

// -1 means unlimited (kept JSON-serialisable, unlike Infinity).
export const UNLIMITED = -1

export interface PlanLimits {
  scansPerMonth: number   // metered scan runs per billing period
  seats: number           // members who can share the account's workspaces
  targetsPerScan: number  // targets/assets a single scan may include
}

export interface Plan {
  id: PlanId
  name: string
  tagline: string
  /** USD, per month, billed monthly. 0 = free. */
  priceMonthly: number
  /** USD, per month, when billed yearly (usually discounted). */
  priceYearly: number
  limits: PlanLimits
  features: Feature[]
  /** Marketing bullet points for the pricing card. */
  highlights: string[]
  /** Visually emphasise this plan on the pricing page. */
  featured?: boolean
}

const FREE: Plan = {
  id: 'free',
  name: 'Free',
  tagline: 'For learning and the occasional scan.',
  priceMonthly: 0,
  priceYearly: 0,
  limits: { scansPerMonth: 10, seats: 1, targetsPerScan: 1 },
  features: ['scan.sast', 'scan.dast', 'scan.iac', 'scan.llm', 'report.markdown'],
  highlights: [
    '10 scans / month',
    'SAST, IaC, LLM & live-HTTP scanners',
    'Markdown reports',
    'Community support',
  ],
}

const PRO: Plan = {
  id: 'pro',
  name: 'Pro',
  tagline: 'For the working bug hunter.',
  priceMonthly: 49,
  priceYearly: 39,
  limits: { scansPerMonth: 500, seats: 1, targetsPerScan: 25 },
  features: [
    'scan.sast', 'scan.dast', 'scan.iac', 'scan.llm', 'scan.smart_contract',
    'scan.binary', 'scan.deep_binary', 'scan.github_repo', 'scan.scheduled',
    'report.markdown', 'report.html', 'export.sarif', 'api.access',
  ],
  featured: true,
  highlights: [
    '500 scans / month',
    'Every scanner — incl. smart-contract, binary & deep symbolic',
    'GitHub-repo scanning & scheduled scans',
    'HTML reports + SARIF export',
    'API / CI access',
  ],
}

const TEAM: Plan = {
  id: 'team',
  name: 'Team',
  tagline: 'For pentest teams and agencies.',
  priceMonthly: 199,
  priceYearly: 159,
  limits: { scansPerMonth: UNLIMITED, seats: 10, targetsPerScan: UNLIMITED },
  features: [
    'scan.sast', 'scan.dast', 'scan.iac', 'scan.llm', 'scan.smart_contract',
    'scan.binary', 'scan.deep_binary', 'scan.github_repo', 'scan.scheduled',
    'report.markdown', 'report.html', 'export.sarif', 'api.access',
    'collab.team', 'support.priority',
  ],
  highlights: [
    'Unlimited scans',
    'Up to 10 team seats & shared workspaces',
    'Everything in Pro',
    'Priority support',
  ],
}

export const PLANS: Record<PlanId, Plan> = { free: FREE, pro: PRO, team: TEAM }

// Ordered for display (cheapest → most capable).
export const PLAN_ORDER: PlanId[] = ['free', 'pro', 'team']

export function isPlanId(v: unknown): v is PlanId {
  return v === 'free' || v === 'pro' || v === 'team'
}

export function getPlan(id: string | null | undefined): Plan {
  return isPlanId(id) ? PLANS[id] : FREE
}

export function planRank(id: PlanId): number {
  return PLAN_ORDER.indexOf(id)
}

export function isUnlimited(n: number): boolean {
  return n === UNLIMITED
}

/** Does this plan grant the given feature? */
export function planHasFeature(planId: string | null | undefined, feature: Feature): boolean {
  return getPlan(planId).features.includes(feature)
}

/** Is `a` a strictly higher tier than `b`? (upgrade vs downgrade) */
export function isUpgrade(from: PlanId, to: PlanId): boolean {
  return planRank(to) > planRank(from)
}

export interface PriceInfo {
  amount: number      // per-month price for the chosen cycle
  cycle: 'monthly' | 'yearly'
  billedYearlyTotal: number
}

export function priceFor(planId: PlanId, cycle: 'monthly' | 'yearly'): PriceInfo {
  const p = PLANS[planId]
  const amount = cycle === 'yearly' ? p.priceYearly : p.priceMonthly
  return { amount, cycle, billedYearlyTotal: cycle === 'yearly' ? amount * 12 : 0 }
}
