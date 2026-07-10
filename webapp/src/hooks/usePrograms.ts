'use client'

import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import type { Program, Asset } from '@prisma/client'

export type ProgramListItem = Program & {
  _count: { assets: number; projects: number; remediations: number }
}

export type ProgramDetail = Program & {
  assets: Asset[]
  projects: { id: string; name: string; targetDomain: string; updatedAt: string }[]
  _count: { remediations: number }
}

export const PLATFORMS = [
  { value: 'hackerone', label: 'HackerOne' },
  { value: 'bugcrowd', label: 'Bugcrowd' },
  { value: 'intigriti', label: 'Intigriti' },
  { value: 'yeswehack', label: 'YesWeHack' },
  { value: 'manual', label: 'Manual' },
] as const

export const ASSET_TYPES = [
  { value: 'domain', label: 'Domain' },
  { value: 'subdomain', label: 'Subdomain' },
  { value: 'cidr', label: 'CIDR' },
  { value: 'api', label: 'API' },
  { value: 'mobile_android', label: 'Android APK' },
  { value: 'mobile_ios', label: 'iOS IPA' },
  { value: 'github', label: 'GitHub' },
  { value: 'cloud', label: 'Cloud' },
  { value: 'graphql', label: 'GraphQL' },
] as const

async function fetchPrograms(userId: string): Promise<ProgramListItem[]> {
  const res = await fetch(`/api/programs?userId=${userId}`)
  if (!res.ok) throw new Error('Failed to fetch programs')
  return res.json()
}

async function fetchProgram(programId: string): Promise<ProgramDetail> {
  const res = await fetch(`/api/programs/${programId}`)
  if (!res.ok) throw new Error('Failed to fetch program')
  return res.json()
}

async function createProgram(data: { userId: string; name: string; [key: string]: unknown }): Promise<Program> {
  const res = await fetch('/api/programs', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(data),
  })
  if (!res.ok) throw new Error((await res.json()).error || 'Failed to create program')
  return res.json()
}

async function updateProgram(programId: string, data: Partial<Program>): Promise<Program> {
  const res = await fetch(`/api/programs/${programId}`, {
    method: 'PATCH',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(data),
  })
  if (!res.ok) throw new Error((await res.json()).error || 'Failed to update program')
  return res.json()
}

async function deleteProgram(programId: string): Promise<void> {
  const res = await fetch(`/api/programs/${programId}`, { method: 'DELETE' })
  if (!res.ok) throw new Error((await res.json()).error || 'Failed to delete program')
}

async function createAsset(programId: string, data: { type: string; value: string; notes?: string }): Promise<Asset> {
  const res = await fetch(`/api/programs/${programId}/assets`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(data),
  })
  if (!res.ok) throw new Error((await res.json()).error || 'Failed to add asset')
  return res.json()
}

async function deleteAsset(programId: string, assetId: string): Promise<void> {
  const res = await fetch(`/api/programs/${programId}/assets/${assetId}`, { method: 'DELETE' })
  if (!res.ok) throw new Error((await res.json()).error || 'Failed to delete asset')
}

export function usePrograms(userId: string | null) {
  return useQuery({
    queryKey: ['programs', userId],
    queryFn: () => fetchPrograms(userId as string),
    enabled: !!userId,
  })
}

export function useProgram(programId: string | null) {
  return useQuery({
    queryKey: ['program', programId],
    queryFn: () => fetchProgram(programId as string),
    enabled: !!programId,
  })
}

export function useCreateProgram() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: createProgram,
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['programs'] }),
  })
}

export function useUpdateProgram() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: ({ programId, data }: { programId: string; data: Partial<Program> }) => updateProgram(programId, data),
    onSuccess: (program) => {
      queryClient.invalidateQueries({ queryKey: ['programs'] })
      queryClient.invalidateQueries({ queryKey: ['program', program.id] })
    },
  })
}

export function useDeleteProgram() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: deleteProgram,
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['programs'] }),
  })
}

export function useCreateAsset() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: ({ programId, data }: { programId: string; data: { type: string; value: string; notes?: string } }) =>
      createAsset(programId, data),
    onSuccess: (_asset, { programId }) => {
      queryClient.invalidateQueries({ queryKey: ['program', programId] })
    },
  })
}

export function useDeleteAsset() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: ({ programId, assetId }: { programId: string; assetId: string }) => deleteAsset(programId, assetId),
    onSuccess: (_void, { programId }) => {
      queryClient.invalidateQueries({ queryKey: ['program', programId] })
    },
  })
}
