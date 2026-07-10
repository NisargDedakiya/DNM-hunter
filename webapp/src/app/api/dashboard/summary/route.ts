import { NextRequest, NextResponse } from 'next/server'
import prisma from '@/lib/prisma'
import { orchestratorFetch } from '@/lib/orchestrator'

const RECON_ORCHESTRATOR_URL = process.env.RECON_ORCHESTRATOR_URL || 'http://localhost:8010'
const HIGH_SEVERITIES = ['critical', 'high']
// Bound how many recent projects we ping for live scan status — a dashboard
// summary should stay fast even for a user with hundreds of projects.
const MAX_SCAN_STATUS_CHECKS = 15
const SCAN_STATUS_TIMEOUT_MS = 2500

interface ActivityItem {
  type: 'program' | 'project' | 'finding' | 'report'
  label: string
  at: string
  href: string
}

async function fetchWithTimeout(url: string, ms: number): Promise<Response | null> {
  const controller = new AbortController()
  const timer = setTimeout(() => controller.abort(), ms)
  try {
    return await orchestratorFetch(url, { signal: controller.signal, cache: 'no-store' })
  } catch {
    return null
  } finally {
    clearTimeout(timer)
  }
}

// GET /api/dashboard/summary?userId=... — the bug-bounty home dashboard's data source.
export async function GET(request: NextRequest) {
  try {
    const { searchParams } = new URL(request.url)
    const userId = searchParams.get('userId')
    if (!userId) {
      return NextResponse.json({ error: 'userId is required' }, { status: 400 })
    }

    const [
      programTotal,
      programActive,
      targetTotal,
      findingsBySeverity,
      reportTotal,
      recentReports,
      recentSuggestions,
      recentProjects,
      recentPrograms,
      recentFindings,
    ] = await Promise.all([
      prisma.program.count({ where: { userId } }),
      prisma.program.count({ where: { userId, status: 'active' } }),
      prisma.project.count({ where: { userId } }),
      prisma.remediation.groupBy({
        by: ['severity'],
        where: { project: { userId }, validatorStatus: { not: 'ignored' } },
        _count: { _all: true },
      }),
      prisma.report.count({ where: { project: { userId } } }),
      prisma.report.findMany({
        where: { project: { userId } },
        orderBy: { createdAt: 'desc' },
        take: 5,
        select: {
          id: true, title: true, filename: true, format: true, createdAt: true,
          projectId: true, project: { select: { name: true } },
        },
      }),
      prisma.remediation.findMany({
        where: { project: { userId }, status: 'pending' },
        orderBy: { createdAt: 'desc' },
        take: 5,
        select: {
          id: true, title: true, severity: true, priority: true, createdAt: true,
          projectId: true, project: { select: { name: true } },
        },
      }),
      prisma.project.findMany({
        where: { userId },
        orderBy: { updatedAt: 'desc' },
        take: 5,
        select: { id: true, name: true, updatedAt: true },
      }),
      prisma.program.findMany({
        where: { userId },
        orderBy: { updatedAt: 'desc' },
        take: 5,
        select: { id: true, name: true, updatedAt: true },
      }),
      prisma.remediation.findMany({
        where: { project: { userId } },
        orderBy: { createdAt: 'desc' },
        take: 5,
        select: {
          id: true, title: true, severity: true, createdAt: true,
          projectId: true, project: { select: { name: true } },
        },
      }),
    ])

    const severityCounts: Record<string, number> = {}
    for (const row of findingsBySeverity) severityCounts[row.severity] = row._count._all
    const highSeverityCount = HIGH_SEVERITIES.reduce((sum, s) => sum + (severityCounts[s] || 0), 0)

    // Live "running scans" + "tool health" signal — bounded, best-effort, never
    // fabricated. If the orchestrator is unreachable this degrades to 0/unknown
    // exactly like the existing per-project status route does.
    const projectsToCheck = recentProjects.slice(0, MAX_SCAN_STATUS_CHECKS)
    const healthCheck = await fetchWithTimeout(`${RECON_ORCHESTRATOR_URL}/health`, SCAN_STATUS_TIMEOUT_MS)
    const orchestratorUp = !!healthCheck && healthCheck.ok

    let runningScans = 0
    if (orchestratorUp) {
      const statuses = await Promise.allSettled(
        projectsToCheck.map(async p => {
          const res = await fetchWithTimeout(`${RECON_ORCHESTRATOR_URL}/recon/${p.id}/status`, SCAN_STATUS_TIMEOUT_MS)
          if (!res || !res.ok) return 'idle'
          const data = await res.json().catch(() => ({ status: 'idle' }))
          return data.status || 'idle'
        })
      )
      runningScans = statuses.filter(
        s => s.status === 'fulfilled' && s.value !== 'idle' && s.value !== 'completed' && s.value !== 'stopped'
      ).length
    }

    const activity: ActivityItem[] = [
      ...recentPrograms.map(p => ({
        type: 'program' as const, label: `Program "${p.name}" updated`, at: p.updatedAt.toISOString(), href: `/programs/${p.id}`,
      })),
      ...recentProjects.map(p => ({
        type: 'project' as const, label: `Target "${p.name}" updated`, at: p.updatedAt.toISOString(), href: `/projects/${p.id}/settings`,
      })),
      ...recentFindings.map(f => ({
        type: 'finding' as const,
        label: `${f.severity.toUpperCase()} finding "${f.title}" in ${f.project?.name ?? 'a project'}`,
        at: f.createdAt.toISOString(),
        href: `/projects/${f.projectId}/settings`,
      })),
    ]
      .sort((a, b) => new Date(b.at).getTime() - new Date(a.at).getTime())
      .slice(0, 8)

    return NextResponse.json({
      programs: { total: programTotal, active: programActive },
      targets: { total: targetTotal },
      findings: {
        total: Object.values(severityCounts).reduce((a, b) => a + b, 0),
        highSeverity: highSeverityCount,
        bySeverity: severityCounts,
      },
      reports: { total: reportTotal, recent: recentReports },
      suggestions: { recent: recentSuggestions },
      activity,
      scans: {
        running: runningScans,
        checkedProjects: projectsToCheck.length,
        orchestratorReachable: orchestratorUp,
      },
      toolHealth: { orchestratorUp },
      // API usage metering doesn't exist anywhere in the codebase yet (no LLM
      // token/request tracking table) — report that honestly instead of a
      // fabricated number. Real tracking is future work (Phase 12 security).
      apiUsage: null,
    })
  } catch (error) {
    console.error('Failed to build dashboard summary:', error)
    return NextResponse.json({ error: 'Failed to load dashboard summary' }, { status: 500 })
  }
}
