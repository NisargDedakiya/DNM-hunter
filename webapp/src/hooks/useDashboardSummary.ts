'use client'

import { useQuery } from '@tanstack/react-query'

export interface DashboardActivityItem {
  type: 'program' | 'project' | 'finding' | 'report'
  label: string
  at: string
  href: string
}

export interface DashboardReportItem {
  id: string
  title: string
  filename: string
  format: string
  createdAt: string
  projectId: string
  project: { name: string }
}

export interface DashboardSuggestionItem {
  id: string
  title: string
  severity: string
  priority: number
  createdAt: string
  projectId: string
  project: { name: string }
}

export interface DashboardSummary {
  programs: { total: number; active: number }
  targets: { total: number }
  findings: { total: number; highSeverity: number; bySeverity: Record<string, number> }
  reports: { total: number; recent: DashboardReportItem[] }
  suggestions: { recent: DashboardSuggestionItem[] }
  activity: DashboardActivityItem[]
  scans: { running: number; checkedProjects: number; orchestratorReachable: boolean }
  toolHealth: { orchestratorUp: boolean }
  apiUsage: null
}

async function fetchDashboardSummary(userId: string): Promise<DashboardSummary> {
  const response = await fetch(`/api/dashboard/summary?userId=${userId}`)
  if (!response.ok) {
    throw new Error('Failed to fetch dashboard summary')
  }
  return response.json()
}

export function useDashboardSummary(userId: string | null) {
  return useQuery({
    queryKey: ['dashboard-summary', userId],
    queryFn: () => fetchDashboardSummary(userId as string),
    enabled: !!userId,
    staleTime: 30_000,
    refetchInterval: 60_000,
  })
}
