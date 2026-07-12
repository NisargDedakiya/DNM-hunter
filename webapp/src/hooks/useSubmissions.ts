'use client'

import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'

export interface Submission {
  id: string
  programId: string
  title: string
  severity: 'info' | 'low' | 'medium' | 'high' | 'critical'
  status: 'draft' | 'submitted' | 'triaged' | 'accepted' | 'duplicate' | 'rejected' | 'paid'
  platform: string | null
  bounty: number | null
  notes: string
  reportId: string | null
  submittedAt: string | null
  createdAt: string
  updatedAt: string
}

export const SUBMISSION_STATUSES = [
  { value: 'draft', label: 'Draft' },
  { value: 'submitted', label: 'Submitted' },
  { value: 'triaged', label: 'Triaged' },
  { value: 'accepted', label: 'Accepted' },
  { value: 'duplicate', label: 'Duplicate' },
  { value: 'rejected', label: 'Rejected' },
  { value: 'paid', label: 'Paid' },
] as const

export const SUBMISSION_SEVERITIES = ['info', 'low', 'medium', 'high', 'critical'] as const

async function fetchSubmissions(programId: string): Promise<Submission[]> {
  const res = await fetch(`/api/programs/${programId}/submissions`)
  if (!res.ok) throw new Error('Failed to fetch submissions')
  return res.json()
}

export function useSubmissions(programId: string | null) {
  return useQuery({
    queryKey: ['submissions', programId],
    queryFn: () => fetchSubmissions(programId!),
    enabled: !!programId,
  })
}

export function useCreateSubmission(programId: string | null) {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: async (data: Partial<Submission>) => {
      const res = await fetch(`/api/programs/${programId}/submissions`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(data),
      })
      if (!res.ok) throw new Error((await res.json()).error || 'Failed to create submission')
      return res.json() as Promise<Submission>
    },
    onSuccess: () => qc.invalidateQueries({ queryKey: ['submissions', programId] }),
  })
}

export function useUpdateSubmission(programId: string | null) {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: async ({ id, ...data }: Partial<Submission> & { id: string }) => {
      const res = await fetch(`/api/programs/${programId}/submissions/${id}`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(data),
      })
      if (!res.ok) throw new Error((await res.json()).error || 'Failed to update submission')
      return res.json() as Promise<Submission>
    },
    onSuccess: () => qc.invalidateQueries({ queryKey: ['submissions', programId] }),
  })
}

export function useDeleteSubmission(programId: string | null) {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: async (id: string) => {
      const res = await fetch(`/api/programs/${programId}/submissions/${id}`, { method: 'DELETE' })
      if (!res.ok) throw new Error((await res.json()).error || 'Failed to delete submission')
      return res.json()
    },
    onSuccess: () => qc.invalidateQueries({ queryKey: ['submissions', programId] }),
  })
}
