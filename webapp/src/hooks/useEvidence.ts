/**
 * useEvidence Hook
 *
 * TanStack Query hook for attaching/listing/deleting evidence (screenshots
 * and text notes) on a Remediation (Phase 09 finding).
 */

import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'

export interface EvidenceItem {
  id: string
  type: 'screenshot' | 'note'
  label: string
  fileSize?: number
  textContent?: string
  source: 'manual' | 'agent'
  capturedAt: string
}

const EVIDENCE_KEY = 'evidence'

async function fetchEvidence(remediationId: string): Promise<EvidenceItem[]> {
  const res = await fetch(`/api/remediations/${remediationId}/evidence`)
  if (!res.ok) throw new Error('Failed to fetch evidence')
  return res.json()
}

async function attachScreenshot(remediationId: string, imageBase64: string, label: string): Promise<EvidenceItem> {
  const res = await fetch(`/api/remediations/${remediationId}/evidence`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ type: 'screenshot', imageBase64, label, source: 'manual' }),
  })
  if (!res.ok) throw new Error((await res.json()).error || 'Failed to attach screenshot')
  return res.json()
}

async function attachNote(remediationId: string, textContent: string, label: string): Promise<EvidenceItem> {
  const res = await fetch(`/api/remediations/${remediationId}/evidence`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ type: 'note', textContent, label, source: 'manual' }),
  })
  if (!res.ok) throw new Error((await res.json()).error || 'Failed to attach note')
  return res.json()
}

async function deleteEvidence(remediationId: string, evidenceId: string): Promise<void> {
  const res = await fetch(`/api/remediations/${remediationId}/evidence/${evidenceId}`, { method: 'DELETE' })
  if (!res.ok) throw new Error('Failed to delete evidence')
}

export function useEvidence(remediationId: string) {
  const queryClient = useQueryClient()

  const query = useQuery({
    queryKey: [EVIDENCE_KEY, remediationId],
    queryFn: () => fetchEvidence(remediationId),
    enabled: !!remediationId,
  })

  const invalidate = () => queryClient.invalidateQueries({ queryKey: [EVIDENCE_KEY, remediationId] })

  const attachScreenshotMutation = useMutation({
    mutationFn: ({ imageBase64, label }: { imageBase64: string; label: string }) =>
      attachScreenshot(remediationId, imageBase64, label),
    onSuccess: invalidate,
  })

  const attachNoteMutation = useMutation({
    mutationFn: ({ textContent, label }: { textContent: string; label: string }) =>
      attachNote(remediationId, textContent, label),
    onSuccess: invalidate,
  })

  const deleteMutation = useMutation({
    mutationFn: (evidenceId: string) => deleteEvidence(remediationId, evidenceId),
    onSuccess: invalidate,
  })

  return {
    evidence: query.data ?? [],
    isLoading: query.isLoading,
    error: query.error,
    attachScreenshot: attachScreenshotMutation.mutate,
    attachNote: attachNoteMutation.mutate,
    deleteEvidence: deleteMutation.mutate,
    isAttaching: attachScreenshotMutation.isPending || attachNoteMutation.isPending,
  }
}
