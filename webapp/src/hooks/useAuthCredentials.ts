'use client'

import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'

export const AUTH_TYPES = [
  { value: 'cookie', label: 'Cookie' },
  { value: 'jwt', label: 'JWT' },
  { value: 'header', label: 'Custom Header' },
  { value: 'oauth', label: 'OAuth Token' },
  { value: 'saml', label: 'SAML' },
  { value: 'mfa', label: 'MFA' },
] as const

export interface AuthCredentialMasked {
  id: string
  label: string
  role: string
  authType: string
  notes: string
  hasCookies: boolean
  hasJwt: boolean
  hasHeaders: boolean
  hasOauthToken: boolean
  createdAt: string
  updatedAt: string
}

export interface CreateCredentialInput {
  label: string
  role?: string
  authType?: string
  cookies?: string
  jwt?: string
  headers?: Record<string, string>
  oauthToken?: string
  notes?: string
}

async function fetchCredentials(programId: string): Promise<AuthCredentialMasked[]> {
  const res = await fetch(`/api/programs/${programId}/credentials`)
  if (!res.ok) throw new Error('Failed to fetch credentials')
  return res.json()
}

async function createCredential(programId: string, data: CreateCredentialInput): Promise<AuthCredentialMasked> {
  const res = await fetch(`/api/programs/${programId}/credentials`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(data),
  })
  if (!res.ok) throw new Error((await res.json()).error || 'Failed to create credential')
  return res.json()
}

async function deleteCredential(programId: string, credentialId: string): Promise<void> {
  const res = await fetch(`/api/programs/${programId}/credentials/${credentialId}`, { method: 'DELETE' })
  if (!res.ok) throw new Error((await res.json()).error || 'Failed to delete credential')
}

export function useAuthCredentials(programId: string | null) {
  return useQuery({
    queryKey: ['auth-credentials', programId],
    queryFn: () => fetchCredentials(programId as string),
    enabled: !!programId,
  })
}

export function useCreateCredential() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: ({ programId, data }: { programId: string; data: CreateCredentialInput }) => createCredential(programId, data),
    onSuccess: (_cred, { programId }) => queryClient.invalidateQueries({ queryKey: ['auth-credentials', programId] }),
  })
}

export function useDeleteCredential() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: ({ programId, credentialId }: { programId: string; credentialId: string }) => deleteCredential(programId, credentialId),
    onSuccess: (_void, { programId }) => queryClient.invalidateQueries({ queryKey: ['auth-credentials', programId] }),
  })
}

export interface ReplayResult {
  request: { method: string; url: string; headers: Record<string, string>; identityUsed: boolean }
  response: {
    status: number
    statusText: string
    headers: Record<string, string>
    body: string
    bodyTruncated: boolean
    bodyLength: number
  }
  timingMs: number
}

export async function replayRequest(
  programId: string,
  input: { method: string; url: string; headers?: Record<string, string>; body?: string; credentialId?: string }
): Promise<ReplayResult> {
  const res = await fetch(`/api/programs/${programId}/replay`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(input),
  })
  const data = await res.json()
  if (!res.ok) throw new Error(data.error || 'Replay failed')
  return data
}
