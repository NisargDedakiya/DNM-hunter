/**
 * Tests for /api/programs/[id]/plan (master-plan Phase 3, Priority 2).
 * @vitest-environment node
 */
import { describe, test, expect, vi, beforeEach } from 'vitest'

const mockFindUnique = vi.fn()

vi.mock('@/lib/prisma', () => ({
  default: { program: { findUnique: (...a: unknown[]) => mockFindUnique(...a) } },
}))

const { GET } = await import('./route')

function req() { return new Request('http://localhost/api/programs/p1/plan') as never }
const params = { params: Promise.resolve({ id: 'p1' }) }

beforeEach(() => mockFindUnique.mockReset())

describe('GET /api/programs/[id]/plan', () => {
  test('404 when the program is missing', async () => {
    mockFindUnique.mockResolvedValue(null)
    const res = await GET(req(), params)
    expect(res.status).toBe(404)
  })

  test('builds a plan from in-scope assets and remembered tech stack', async () => {
    mockFindUnique.mockResolvedValue({
      id: 'p1',
      assets: [{ value: 'acme.com' }],
      memory: { techStack: [{ name: 'terraform' }] },
    })
    const res = await GET(req(), params)
    const body = await res.json()
    expect(res.status).toBe(200)
    expect(body.assetCount).toBe(1)
    expect(body.detectedTech).toContain('terraform')
    // terraform affinity should push iac_scan to high priority
    const iac = body.steps.find((s: { moduleName: string }) => s.moduleName === 'iac_scan')
    expect(iac.priority).toBe('high')
  })

  test('handles a program with no memory (empty tech signals)', async () => {
    mockFindUnique.mockResolvedValue({ id: 'p1', assets: [{ value: 'x.com' }], memory: null })
    const res = await GET(req(), params)
    const body = await res.json()
    expect(body.detectedTech).toEqual([])
    expect(body.steps.length).toBeGreaterThan(0)
  })
})
