/**
 * Tests for /api/programs/[id]/submissions (master-plan Phase 1, Priority 10).
 * @vitest-environment node
 */
import { describe, test, expect, vi, beforeEach } from 'vitest'

const mockFindMany = vi.fn()
const mockCreate = vi.fn()
const mockProgramFindUnique = vi.fn()

vi.mock('@/lib/prisma', () => ({
  default: {
    submission: {
      findMany: (...a: unknown[]) => mockFindMany(...a),
      create: (...a: unknown[]) => mockCreate(...a),
    },
    program: { findUnique: (...a: unknown[]) => mockProgramFindUnique(...a) },
  },
}))

const { GET, POST } = await import('./route')

function req(body?: unknown) {
  return new Request('http://localhost/api/programs/p1/submissions', body ? { method: 'POST', body: JSON.stringify(body) } : undefined) as never
}
const params = { params: Promise.resolve({ id: 'p1' }) }

beforeEach(() => {
  mockFindMany.mockReset(); mockCreate.mockReset(); mockProgramFindUnique.mockReset()
})

describe('GET', () => {
  test('lists submissions scoped by programId', async () => {
    mockFindMany.mockResolvedValue([{ id: 's1' }])
    const res = await GET(req(), params)
    expect(res.status).toBe(200)
    expect(mockFindMany).toHaveBeenCalledWith(expect.objectContaining({ where: { programId: 'p1' } }))
  })
})

describe('POST', () => {
  test('400 without a title', async () => {
    const res = await POST(req({ severity: 'high' }), params)
    expect(res.status).toBe(400)
  })

  test('404 when the program does not exist', async () => {
    mockProgramFindUnique.mockResolvedValue(null)
    const res = await POST(req({ title: 'IDOR' }), params)
    expect(res.status).toBe(404)
  })

  test('coerces invalid severity/status to defaults and stamps submittedAt only when not draft', async () => {
    mockProgramFindUnique.mockResolvedValue({ id: 'p1' })
    mockCreate.mockImplementation(({ data }: { data: Record<string, unknown> }) => Promise.resolve({ id: 's2', ...data }))
    const res = await POST(req({ title: 'XSS', severity: 'bogus', status: 'submitted' }), params)
    const body = await res.json()
    expect(res.status).toBe(201)
    expect(body.severity).toBe('medium')       // coerced
    expect(body.status).toBe('submitted')       // valid, kept
    expect(body.submittedAt).not.toBeNull()      // stamped because not draft
  })

  test('draft submissions have a null submittedAt', async () => {
    mockProgramFindUnique.mockResolvedValue({ id: 'p1' })
    mockCreate.mockImplementation(({ data }: { data: Record<string, unknown> }) => Promise.resolve({ id: 's3', ...data }))
    const res = await POST(req({ title: 'Draft finding' }), params)
    const body = await res.json()
    expect(body.status).toBe('draft')
    expect(body.submittedAt).toBeNull()
  })
})
