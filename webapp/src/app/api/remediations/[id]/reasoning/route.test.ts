/**
 * Tests for GET /api/remediations/[id]/reasoning (Phase 16 AI Reasoning panel).
 *
 * Strategy: mock @/lib/prisma for the Remediation lookup, and @/app/api/graph/neo4j
 * (same pattern as redzoneRoutes.test.ts) to capture the Cypher query shape and
 * return deterministic fake ChainStep/ChainFinding records.
 *
 * @vitest-environment node
 */
import { describe, test, expect, vi, beforeEach } from 'vitest'

const mockFindUnique = vi.fn()

vi.mock('@/lib/prisma', () => ({
  default: {
    remediation: {
      findUnique: (...args: unknown[]) => mockFindUnique(...args),
    },
  },
}))

const runCalls: Array<{ cypher: string; params: Record<string, unknown> }> = []
let runReturn: Array<Record<string, unknown>> = []
let shouldThrow: Error | null = null

vi.mock('@/app/api/graph/neo4j', () => ({
  getSession: () => ({
    run: async (cypher: string, params: Record<string, unknown>) => {
      runCalls.push({ cypher, params })
      if (shouldThrow) throw shouldThrow
      const records = runReturn.map(row => ({ get: (key: string) => row[key] }))
      return { records }
    },
    close: async () => {},
  }),
}))

const { GET } = await import('./route')

function makeParams(id: string) {
  return { params: Promise.resolve({ id }) }
}

function getReq() {
  return new Request('http://localhost/api/remediations/r1/reasoning') as never
}

beforeEach(() => {
  mockFindUnique.mockReset()
  runCalls.length = 0
  runReturn = []
  shouldThrow = null
})

describe('GET /api/remediations/[id]/reasoning', () => {
  test('404 when the remediation does not exist', async () => {
    mockFindUnique.mockResolvedValue(null)
    const res = await GET(getReq(), makeParams('missing'))
    expect(res.status).toBe(404)
  })

  test('available: false when sourceFindingIds is empty (the common case)', async () => {
    mockFindUnique.mockResolvedValue({ id: 'r1', sourceFindingIds: [], project: { userId: 'u1' } })
    const res = await GET(getReq(), makeParams('r1'))
    const body = await res.json()
    expect(res.status).toBe(200)
    expect(body.available).toBe(false)
    expect(body.reason).toBe('not_chain_derived')
    expect(body.steps).toEqual([])
    // No Neo4j query should even run when there's nothing to look up.
    expect(runCalls.length).toBe(0)
  })

  test('queries Neo4j scoped by user_id and the sourceFindingIds when present', async () => {
    mockFindUnique.mockResolvedValue({ id: 'r1', sourceFindingIds: ['find-1', 'find-2'], project: { userId: 'u1' } })
    runReturn = [{
      findingId: 'find-1', findingTitle: 'SQLi confirmed', evidence: 'evidence text',
      targetIp: '10.0.0.5', targetPort: 443, attackType: 'sqli', payload: "' OR 1=1--",
      toolName: 'sqlmap', toolArgsSummary: '--dbs --batch', thought: 'Testing for SQLi',
      reasoning: 'Parameter looked unsanitized', outputSummary: '3 databases found', outputAnalysis: 'Confirmed injectable',
    }]
    const res = await GET(getReq(), makeParams('r1'))
    const body = await res.json()

    expect(res.status).toBe(200)
    expect(body.available).toBe(true)
    expect(body.steps).toHaveLength(1)
    expect(body.steps[0].toolName).toBe('sqlmap')
    expect(body.steps[0].payload).toBe("' OR 1=1--")

    expect(runCalls).toHaveLength(1)
    expect(runCalls[0].params.userId).toBe('u1')
    expect(runCalls[0].params.findingIds).toEqual(['find-1', 'find-2'])
    expect(runCalls[0].cypher).toContain('ChainFinding')
    expect(runCalls[0].cypher).toContain('ChainStep')
  })

  test('available: false when sourceFindingIds point at IDs no longer in the graph', async () => {
    mockFindUnique.mockResolvedValue({ id: 'r1', sourceFindingIds: ['gone'], project: { userId: 'u1' } })
    runReturn = []
    const res = await GET(getReq(), makeParams('r1'))
    const body = await res.json()
    expect(body.available).toBe(false)
    expect(body.reason).toBe('source_findings_not_in_graph')
  })

  test('numeric targetPort (Neo4j Int64 shape) is normalized to a plain number', async () => {
    mockFindUnique.mockResolvedValue({ id: 'r1', sourceFindingIds: ['find-1'], project: { userId: 'u1' } })
    runReturn = [{
      findingId: 'find-1', targetPort: { low: 8080, high: 0 },
    }]
    const res = await GET(getReq(), makeParams('r1'))
    const body = await res.json()
    expect(body.steps[0].targetPort).toBe(8080)
  })

  test('500 when the Neo4j query throws', async () => {
    mockFindUnique.mockResolvedValue({ id: 'r1', sourceFindingIds: ['find-1'], project: { userId: 'u1' } })
    shouldThrow = new Error('connection refused')
    const errSpy = vi.spyOn(console, 'error').mockImplementation(() => {})
    const res = await GET(getReq(), makeParams('r1'))
    expect(res.status).toBe(500)
    errSpy.mockRestore()
  })
})
