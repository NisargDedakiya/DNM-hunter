import React from 'react'
import { describe, test, expect, afterEach, vi } from 'vitest'
import { render, screen, cleanup } from '@testing-library/react'
import { ReasoningPanel } from './ReasoningPanel'
import type { Remediation } from '@/lib/cypherfix-types'

const mockUseReasoning = vi.fn()
vi.mock('@/hooks/useReasoning', () => ({
  useReasoning: (...args: unknown[]) => mockUseReasoning(...args),
}))

afterEach(cleanup)

function makeRemediation(overrides: Partial<Remediation> = {}): Remediation {
  return {
    id: 'r1', projectId: 'p1', title: 'SQLi in /api/search', description: 'UNION-based SQL injection.',
    severity: 'critical', priority: 0, category: 'sqli', remediationType: 'code_fix',
    affectedAssets: [], cvssScore: 9.8, cveIds: [], cweIds: [], capecIds: [],
    evidence: '', attackChainPath: '', exploitAvailable: true, cisaKev: false,
    solution: '', fixComplexity: 'medium', estimatedFiles: 1,
    targetRepo: '', targetBranch: 'main', fixBranch: '', prUrl: '', prStatus: 'none',
    status: 'pending', agentSessionId: '', agentNotes: '', fileChanges: [],
    confidenceScore: 90, falsePositiveScore: 10, businessImpact: 'Full DB access if exploited.', likelihood: 'high',
    validatorStatus: 'confirmed', sourceFindingIds: [],
    createdAt: '2026-01-01T00:00:00Z', updatedAt: '2026-01-01T00:00:00Z',
    ...overrides,
  } as Remediation
}

describe('ReasoningPanel', () => {
  test('always shows "why this finding" and "why this severity" from the remediation itself', () => {
    mockUseReasoning.mockReturnValue({ available: false, steps: [], isLoading: false })
    render(<ReasoningPanel remediation={makeRemediation()} />)
    expect(screen.getByText('Why this finding?')).toBeTruthy()
    expect(screen.getByText('Why this severity?')).toBeTruthy()
    expect(screen.getByText(/Full DB access if exploited/)).toBeTruthy()
    expect(screen.getByText(/high likelihood/)).toBeTruthy()
  })

  test('loading state shows a loading message, not the fallback', () => {
    mockUseReasoning.mockReturnValue({ available: false, steps: [], isLoading: true })
    render(<ReasoningPanel remediation={makeRemediation()} />)
    expect(screen.getByText(/Loading agent reasoning/)).toBeTruthy()
    expect(screen.queryByText(/wasn.t derived from a live attack-chain session/)).toBeNull()
  })

  test('unavailable (not chain-derived) shows a graceful, non-error fallback', () => {
    mockUseReasoning.mockReturnValue({ available: false, steps: [], isLoading: false })
    render(<ReasoningPanel remediation={makeRemediation()} />)
    expect(screen.getByText(/wasn.t derived from a live attack-chain session/)).toBeTruthy()
  })

  test('renders "why this tool / payload / endpoint" for each returned step', () => {
    mockUseReasoning.mockReturnValue({
      available: true,
      isLoading: false,
      steps: [{
        findingId: 'find-1', findingTitle: 'SQLi confirmed', evidence: 'ev',
        targetIp: '10.0.0.5', targetPort: 443, attackType: 'sqli', payload: "' OR 1=1--",
        toolName: 'sqlmap', toolArgsSummary: '--dbs --batch', thought: 'Testing for SQLi',
        reasoning: 'Parameter looked unsanitized', outputSummary: '3 dbs found', outputAnalysis: 'Confirmed injectable',
      }],
    })
    render(<ReasoningPanel remediation={makeRemediation()} />)

    expect(screen.getByText('Why this tool?')).toBeTruthy()
    expect(screen.getByText('Why this payload?')).toBeTruthy()
    expect(screen.getByText('Why this endpoint?')).toBeTruthy()
    expect(screen.getByText(/sqlmap/)).toBeTruthy()
    expect(screen.getByText(/Parameter looked unsanitized/)).toBeTruthy()
    expect(screen.getByText(/10\.0\.0\.5/)).toBeTruthy()
    expect(screen.getByText(/Confirmed injectable/)).toBeTruthy()
  })

  test('a step missing toolName/payload/target fields omits those Q&A rows without crashing', () => {
    mockUseReasoning.mockReturnValue({
      available: true,
      isLoading: false,
      steps: [{
        findingId: 'find-2', findingTitle: null, evidence: null,
        targetIp: null, targetPort: null, attackType: null, payload: null,
        toolName: null, toolArgsSummary: null, thought: null,
        reasoning: null, outputSummary: null, outputAnalysis: null,
      }],
    })
    expect(() => render(<ReasoningPanel remediation={makeRemediation()} />)).not.toThrow()
    // The step-level rows are absent (nothing to report), but the always-on rows remain.
    expect(screen.queryByText('Why this tool?')).toBeNull()
    expect(screen.queryByText('Why this payload?')).toBeNull()
    expect(screen.queryByText('Why this endpoint?')).toBeNull()
    expect(screen.getByText('Why this finding?')).toBeTruthy()
  })
})
