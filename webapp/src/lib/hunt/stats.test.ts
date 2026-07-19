import { describe, it, expect } from 'vitest'
import { computeHunterStats, isSubmissionStatus, type SubmissionLike } from './stats'

const subs: SubmissionLike[] = [
  { status: 'paid', severity: 'critical', bounty: 2000 },
  { status: 'paid', severity: 'high', bounty: 500 },
  { status: 'accepted', severity: 'high', bounty: 800 },   // pending payout
  { status: 'duplicate', severity: 'medium', bounty: null },
  { status: 'rejected', severity: 'low' },
  { status: 'submitted', severity: 'medium' },
  { status: 'draft', severity: 'info' },
]

describe('computeHunterStats', () => {
  const s = computeHunterStats(subs)

  it('counts totals and by-status', () => {
    expect(s.total).toBe(7)
    expect(s.byStatus.paid).toBe(2)
    expect(s.byStatus.draft).toBe(1)
  })

  it('sums earned (paid only) and pending (accepted)', () => {
    expect(s.totalEarned).toBe(2500)
    expect(s.pending).toBe(800)
    expect(s.paidCount).toBe(2)
  })

  it('computes acceptance rate over resolved submissions', () => {
    // resolved = paid(2) + accepted(1) + duplicate(1) + rejected(1) = 5
    // wins = paid(2) + accepted(1) = 3  → 0.6
    expect(s.acceptanceRate).toBeCloseTo(0.6, 5)
  })

  it('counts open (awaiting decision) submissions', () => {
    // draft + submitted + triaged = 2 here (draft, submitted)
    expect(s.openCount).toBe(2)
  })

  it('bySeverity tallies', () => {
    expect(s.bySeverity.high).toBe(2)
    expect(s.bySeverity.critical).toBe(1)
  })

  it('empty input yields zeroed stats (no divide-by-zero)', () => {
    const z = computeHunterStats([])
    expect(z.total).toBe(0)
    expect(z.acceptanceRate).toBe(0)
    expect(z.totalEarned).toBe(0)
  })

  it('validates submission status', () => {
    expect(isSubmissionStatus('paid')).toBe(true)
    expect(isSubmissionStatus('nonsense')).toBe(false)
  })
})
