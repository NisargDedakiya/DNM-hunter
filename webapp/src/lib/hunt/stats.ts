// Bug-hunter pipeline analytics — pure aggregation over submissions so the
// numbers are unit-tested without a database. The API layer feeds real rows in.

export const SUBMISSION_STATUSES = [
  'draft', 'submitted', 'triaged', 'accepted', 'duplicate', 'rejected', 'paid',
] as const
export type SubmissionStatus = (typeof SUBMISSION_STATUSES)[number]

export const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'] as const

export interface SubmissionLike {
  status: string
  severity: string
  bounty?: number | null
}

export interface HunterStats {
  total: number
  byStatus: Record<string, number>
  bySeverity: Record<string, number>
  /** Sum of bounties on paid submissions. */
  totalEarned: number
  /** Sum of bounties on accepted-but-not-yet-paid submissions. */
  pending: number
  paidCount: number
  /** accepted+paid ÷ resolved (accepted+paid+duplicate+rejected), 0–1. */
  acceptanceRate: number
  /** submissions still awaiting a triage decision. */
  openCount: number
}

const isResolved = (s: string) => ['accepted', 'paid', 'duplicate', 'rejected'].includes(s)
const isWin = (s: string) => s === 'accepted' || s === 'paid'
const isOpen = (s: string) => ['draft', 'submitted', 'triaged'].includes(s)

export function computeHunterStats(subs: SubmissionLike[]): HunterStats {
  const byStatus: Record<string, number> = Object.fromEntries(SUBMISSION_STATUSES.map((s) => [s, 0]))
  const bySeverity: Record<string, number> = Object.fromEntries(SEVERITIES.map((s) => [s, 0]))
  let totalEarned = 0
  let pending = 0
  let paidCount = 0
  let resolved = 0
  let wins = 0
  let openCount = 0

  for (const s of subs) {
    const status = String(s.status || 'draft')
    const sev = String(s.severity || 'info')
    byStatus[status] = (byStatus[status] ?? 0) + 1
    bySeverity[sev] = (bySeverity[sev] ?? 0) + 1
    const bounty = typeof s.bounty === 'number' ? s.bounty : 0

    if (status === 'paid') { totalEarned += bounty; paidCount += 1 }
    else if (status === 'accepted') { pending += bounty }
    if (isResolved(status)) { resolved += 1; if (isWin(status)) wins += 1 }
    if (isOpen(status)) openCount += 1
  }

  return {
    total: subs.length,
    byStatus,
    bySeverity,
    totalEarned,
    pending,
    paidCount,
    acceptanceRate: resolved > 0 ? wins / resolved : 0,
    openCount,
  }
}

export function isSubmissionStatus(v: unknown): v is SubmissionStatus {
  return typeof v === 'string' && (SUBMISSION_STATUSES as readonly string[]).includes(v)
}
