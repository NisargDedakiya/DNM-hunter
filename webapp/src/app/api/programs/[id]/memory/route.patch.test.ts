/**
 * Tests for PATCH /api/programs/[id]/memory (master-plan Phase 4 — user-
 * authoritative memory edits). @vitest-environment node
 */
import { describe, test, expect, vi, beforeEach } from 'vitest'

const mockProgramFindUnique = vi.fn()
const mockUpsert = vi.fn()

vi.mock('@/lib/prisma', () => ({
  default: {
    program: { findUnique: (...a: unknown[]) => mockProgramFindUnique(...a) },
    programMemory: { upsert: (...a: unknown[]) => mockUpsert(...a) },
  },
}))

const { PATCH } = await import('./route')

function req(body: unknown) {
  return new Request('http://localhost/api/programs/p1/memory', { method: 'PATCH', body: JSON.stringify(body) }) as never
}
const params = { params: Promise.resolve({ id: 'p1' }) }

beforeEach(() => { mockProgramFindUnique.mockReset(); mockUpsert.mockReset() })

describe('PATCH /api/programs/[id]/memory', () => {
  test('404 when the program is missing', async () => {
    mockProgramFindUnique.mockResolvedValue(null)
    const res = await PATCH(req({ userNotes: 'x' }), params)
    expect(res.status).toBe(404)
  })

  test('400 when no editable field is provided', async () => {
    mockProgramFindUnique.mockResolvedValue({ id: 'p1' })
    const res = await PATCH(req({ techStack: [] }), params)   // not user-editable
    expect(res.status).toBe(400)
    expect(mockUpsert).not.toHaveBeenCalled()
  })

  test('upserts pinned endpoints and notes', async () => {
    mockProgramFindUnique.mockResolvedValue({ id: 'p1' })
    mockUpsert.mockResolvedValue({ id: 'm1' })
    const res = await PATCH(req({
      userNotes: 'reuse admin token',
      interestingEndpoints: [{ endpoint: '/api/v2/export', note: 'IDOR here' }],
    }), params)
    expect(res.status).toBe(200)
    const arg = mockUpsert.mock.calls[0][0]
    expect(arg.update.userNotes).toBe('reuse admin token')
    expect(arg.update.interestingEndpoints).toHaveLength(1)
  })
})
