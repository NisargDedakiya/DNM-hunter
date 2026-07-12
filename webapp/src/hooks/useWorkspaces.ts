'use client'

import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'

export interface Workspace {
  id: string
  name: string
  description: string
  createdAt: string
  updatedAt: string
  _count?: { programs: number }
}

async function fetchWorkspaces(userId: string): Promise<Workspace[]> {
  const res = await fetch(`/api/workspaces?userId=${encodeURIComponent(userId)}`)
  if (!res.ok) throw new Error('Failed to fetch workspaces')
  return res.json()
}

export function useWorkspaces(userId: string | null) {
  return useQuery({
    queryKey: ['workspaces', userId],
    queryFn: () => fetchWorkspaces(userId!),
    enabled: !!userId,
  })
}

export function useCreateWorkspace() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: async (data: { userId: string; name: string; description?: string }) => {
      const res = await fetch('/api/workspaces', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(data),
      })
      if (!res.ok) throw new Error((await res.json()).error || 'Failed to create workspace')
      return res.json() as Promise<Workspace>
    },
    onSuccess: (_data, vars) => {
      qc.invalidateQueries({ queryKey: ['workspaces', vars.userId] })
    },
  })
}

export function useUpdateWorkspace(userId: string | null) {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: async ({ id, ...data }: { id: string; name?: string; description?: string }) => {
      const res = await fetch(`/api/workspaces/${id}`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(data),
      })
      if (!res.ok) throw new Error((await res.json()).error || 'Failed to update workspace')
      return res.json() as Promise<Workspace>
    },
    onSuccess: () => qc.invalidateQueries({ queryKey: ['workspaces', userId] }),
  })
}

export function useDeleteWorkspace(userId: string | null) {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: async (id: string) => {
      const res = await fetch(`/api/workspaces/${id}`, { method: 'DELETE' })
      if (!res.ok) throw new Error((await res.json()).error || 'Failed to delete workspace')
      return res.json()
    },
    onSuccess: () => qc.invalidateQueries({ queryKey: ['workspaces', userId] }),
  })
}
