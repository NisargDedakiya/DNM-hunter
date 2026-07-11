/**
 * useProgramMemory Hook
 *
 * Cross-scan memory (Phase 11) for a bug-bounty Program: tech-surface
 * categories, known paths, confirmed/likely findings from prior scans, and
 * a deterministic rollup summary. Read by the orchestrator at session start
 * (agentic/project_settings.py) and browsable/refreshable here.
 */

import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'

export interface ProgramMemory {
  id: string
  programId: string
  techStack: Array<{ name: string; category: string; confidence: number; source: string }>
  knownPaths: Array<{ path: string; note: string }>
  workingPayloads: Array<{ category: string; summary: string; workedOn: string }>
  priorFindingsSummary: string
  lastComputedFromProjectId: string | null
  createdAt: string
  updatedAt: string
}

const MEMORY_KEY = 'program-memory'

async function fetchMemory(programId: string): Promise<ProgramMemory | null> {
  const res = await fetch(`/api/programs/${programId}/memory`)
  if (!res.ok) throw new Error('Failed to fetch program memory')
  return res.json()
}

async function recomputeMemory(programId: string): Promise<ProgramMemory> {
  const res = await fetch(`/api/programs/${programId}/memory`, { method: 'POST' })
  if (!res.ok) throw new Error('Failed to recompute program memory')
  return res.json()
}

export function useProgramMemory(programId: string | null) {
  const queryClient = useQueryClient()

  const query = useQuery({
    queryKey: [MEMORY_KEY, programId],
    queryFn: () => fetchMemory(programId as string),
    enabled: !!programId,
  })

  const recomputeMutation = useMutation({
    mutationFn: () => recomputeMemory(programId as string),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: [MEMORY_KEY, programId] })
    },
  })

  return {
    memory: query.data ?? null,
    isLoading: query.isLoading,
    recompute: recomputeMutation.mutate,
    isRecomputing: recomputeMutation.isPending,
  }
}
