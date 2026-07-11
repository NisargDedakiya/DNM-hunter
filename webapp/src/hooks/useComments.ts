/**
 * useComments Hook
 *
 * TanStack Query hook for the discussion thread on a finding (Remediation).
 */

import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'

export interface CommentItem {
  id: string
  remediationId: string
  userId: string
  body: string
  createdAt: string
  updatedAt: string
  user: { id: string; name: string; email: string }
}

const COMMENTS_KEY = 'comments'

async function fetchComments(remediationId: string): Promise<CommentItem[]> {
  const res = await fetch(`/api/remediations/${remediationId}/comments`)
  if (!res.ok) throw new Error('Failed to fetch comments')
  return res.json()
}

async function createComment(remediationId: string, userId: string, body: string): Promise<CommentItem> {
  const res = await fetch(`/api/remediations/${remediationId}/comments`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ userId, body }),
  })
  if (!res.ok) throw new Error((await res.json()).error || 'Failed to post comment')
  return res.json()
}

async function deleteComment(remediationId: string, commentId: string): Promise<void> {
  const res = await fetch(`/api/remediations/${remediationId}/comments/${commentId}`, { method: 'DELETE' })
  if (!res.ok) throw new Error('Failed to delete comment')
}

export function useComments(remediationId: string) {
  const queryClient = useQueryClient()

  const query = useQuery({
    queryKey: [COMMENTS_KEY, remediationId],
    queryFn: () => fetchComments(remediationId),
    enabled: !!remediationId,
  })

  const invalidate = () => queryClient.invalidateQueries({ queryKey: [COMMENTS_KEY, remediationId] })

  const addMutation = useMutation({
    mutationFn: ({ userId, body }: { userId: string; body: string }) => createComment(remediationId, userId, body),
    onSuccess: invalidate,
  })

  const deleteMutation = useMutation({
    mutationFn: (commentId: string) => deleteComment(remediationId, commentId),
    onSuccess: invalidate,
  })

  return {
    comments: query.data ?? [],
    isLoading: query.isLoading,
    addComment: addMutation.mutate,
    isAdding: addMutation.isPending,
    deleteComment: deleteMutation.mutate,
  }
}
