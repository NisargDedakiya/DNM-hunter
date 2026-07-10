'use client'

import { useQuery } from '@tanstack/react-query'

export interface AiSummaryTech {
  name: string
  version: string | null
  cveCount: number
}

export interface AiSummaryInterestingEndpoint {
  url: string
  baseUrl: string | null
  category: string
  isForm: boolean
  isGraphql: boolean
}

export interface AiSummary {
  project: { id: string; name: string; targetDomain: string }
  companyOverview: string
  attackSurfaceNarrative: string
  techStack: AiSummaryTech[]
  authentication: { endpointCount: number }
  adminPanels: { count: number }
  apiSummary: { restEndpointCount: number; graphqlEndpointCount: number }
  javascriptFiles: { fileCount: number; secretCount: number }
  attackSurface: {
    subdomains: { total: number; resolved: number }
    exposedServices: { service: string; count: number }[]
  }
  interestingEndpoints: AiSummaryInterestingEndpoint[]
  riskScore: number
  vulnBySeverity: Record<string, number>
  totalVulns: number
  secretsBySeverity: Record<string, number>
  totalSecrets: number
}

async function fetchAiSummary(projectId: string): Promise<AiSummary> {
  const response = await fetch(`/api/projects/${projectId}/ai-summary`)
  if (!response.ok) {
    throw new Error('Failed to fetch AI summary')
  }
  return response.json()
}

export function useAiSummary(projectId: string | null) {
  return useQuery({
    queryKey: ['ai-summary', projectId],
    queryFn: () => fetchAiSummary(projectId as string),
    enabled: !!projectId,
    staleTime: 60_000,
  })
}
