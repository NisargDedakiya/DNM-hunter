/**
 * useReasoning Hook
 *
 * TanStack Query hook for the AI Reasoning panel (Phase 16) — the agent's
 * tool/payload/endpoint provenance for a finding, when it was derived from
 * a live attack-chain session.
 */

import { useQuery } from '@tanstack/react-query'
import type { ReasoningStep } from '@/app/api/remediations/[id]/reasoning/route'

export type { ReasoningStep }

interface ReasoningResponse {
  available: boolean
  reason?: string
  steps: ReasoningStep[]
}

async function fetchReasoning(remediationId: string): Promise<ReasoningResponse> {
  const res = await fetch(`/api/remediations/${remediationId}/reasoning`)
  if (!res.ok) throw new Error('Failed to fetch reasoning')
  return res.json()
}

export function useReasoning(remediationId: string) {
  const query = useQuery({
    queryKey: ['reasoning', remediationId],
    queryFn: () => fetchReasoning(remediationId),
    enabled: !!remediationId,
  })

  return {
    available: query.data?.available ?? false,
    steps: query.data?.steps ?? [],
    isLoading: query.isLoading,
    isError: query.isError,
  }
}
