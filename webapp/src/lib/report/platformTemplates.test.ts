import { describe, test, expect } from 'vitest'
import { formatForPlatform, formatForBugcrowd, PLATFORM_LABELS, type BugBountyPlatform } from './platformTemplates'
import type { Remediation } from '@/lib/cypherfix-types'

function makeRemediation(overrides: Partial<Remediation> = {}): Remediation {
  return {
    id: 'r1', projectId: 'p1', title: 'SQLi in /api/search', description: 'UNION-based SQL injection.',
    severity: 'critical', priority: 0, category: 'sqli', remediationType: 'code_fix',
    affectedAssets: [], cvssScore: 9.8, cveIds: ['CVE-2024-1234'], cweIds: ['CWE-89'], capecIds: [],
    evidence: 'curl ...', attackChainPath: '', exploitAvailable: true, cisaKev: false,
    solution: 'Use parameterized queries.', fixComplexity: 'medium', estimatedFiles: 1,
    targetRepo: '', targetBranch: 'main', fixBranch: '', prUrl: '', prStatus: 'none',
    status: 'pending', agentSessionId: '', agentNotes: '', fileChanges: [],
    confidenceScore: 90, falsePositiveScore: 10, businessImpact: 'Full DB access.', likelihood: 'high',
    validatorStatus: 'confirmed', sourceFindingIds: [],
    createdAt: '2026-01-01T00:00:00Z', updatedAt: '2026-01-01T00:00:00Z',
    ...overrides,
  }
}

const PLATFORMS: BugBountyPlatform[] = ['hackerone', 'bugcrowd', 'intigriti', 'yeswehack']

describe('platformTemplates', () => {
  test('every platform produces distinct, non-empty output for the same finding', () => {
    const rem = makeRemediation()
    const outputs = PLATFORMS.map(p => formatForPlatform(p, rem, { targetName: 'acme.example.com' }))
    for (const out of outputs) expect(out.length).toBeGreaterThan(50)
    expect(new Set(outputs).size).toBe(PLATFORMS.length)
  })

  test('all templates include the finding title, target, and severity', () => {
    const rem = makeRemediation()
    for (const platform of PLATFORMS) {
      const text = formatForPlatform(platform, rem, { targetName: 'acme.example.com' })
      expect(text).toContain('SQLi in /api/search')
      expect(text).toContain('acme.example.com')
      expect(text.toLowerCase()).toContain('critical')
    }
  })

  test('Bugcrowd maps severity to VRT priority tiers', () => {
    const cases: Array<[Remediation['severity'], string]> = [
      ['critical', 'P1'], ['high', 'P2'], ['medium', 'P3'], ['low', 'P4'], ['info', 'P5'],
    ]
    for (const [severity, expectedPriority] of cases) {
      const text = formatForBugcrowd(makeRemediation({ severity }), { targetName: 'x' })
      expect(text).toContain(expectedPriority)
    }
  })

  test('references section includes CVE and CWE links when present', () => {
    const rem = makeRemediation({ cveIds: ['CVE-2024-1234'], cweIds: ['CWE-89'] })
    const text = formatForPlatform('hackerone', rem, { targetName: 'x' })
    expect(text).toContain('CVE-2024-1234')
    expect(text).toContain('cwe.mitre.org/data/definitions/89')
  })

  test('gracefully handles a finding with no CVEs, no assets, no evidence', () => {
    const rem = makeRemediation({ cveIds: [], cweIds: [], affectedAssets: [], evidence: '', attackChainPath: '' })
    for (const platform of PLATFORMS) {
      const text = formatForPlatform(platform, rem, { targetName: 'x' })
      expect(text.length).toBeGreaterThan(0)
      expect(text).not.toContain('undefined')
    }
  })

  test('PLATFORM_LABELS covers every BugBountyPlatform value', () => {
    for (const platform of PLATFORMS) {
      expect(PLATFORM_LABELS[platform]).toBeTruthy()
    }
  })
})
