'use client'

import { useQuery } from '@tanstack/react-query'

export interface Job {
  id: string
  moduleName: string
  programId: string | null
  status: 'queued' | 'running' | 'paused' | 'retrying' | 'completed' | 'cancelled' | 'failed'
  progress: number
  error: string | null
  retries: number
  startedAt: string | null
  finishedAt: string | null
  createdAt: string
  updatedAt: string
}

async function fetchJobs(params: string): Promise<Job[]> {
  const res = await fetch(`/api/jobs${params}`)
  if (!res.ok) throw new Error('Failed to fetch jobs')
  return res.json()
}

// Live projection of the unified scan-lifecycle state machine (master-plan
// Phase 2/5). Polls so the dashboard cockpit reflects queue/run state without a
// websocket dependency; the orchestrator remains the source of truth.
export function useJobs(opts: { programId?: string; active?: boolean } = {}) {
  const qs = new URLSearchParams()
  if (opts.programId) qs.set('programId', opts.programId)
  if (opts.active) qs.set('active', '1')
  const query = qs.toString() ? `?${qs.toString()}` : ''
  return useQuery({
    queryKey: ['jobs', query],
    queryFn: () => fetchJobs(query),
    refetchInterval: 5000,
  })
}
