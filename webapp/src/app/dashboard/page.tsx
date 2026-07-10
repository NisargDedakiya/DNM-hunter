'use client'

import Link from 'next/link'
import {
  Target, ShieldAlert, FileText, Sparkles, Radar, Activity,
  CheckCircle2, XCircle, Gauge, ArrowRight,
} from 'lucide-react'
import { useProject } from '@/providers/ProjectProvider'
import { useDashboardSummary } from '@/hooks/useDashboardSummary'
import styles from './page.module.css'

function formatDate(iso: string): string {
  try {
    return new Date(iso).toLocaleString('en-US', {
      month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit',
    })
  } catch {
    return iso
  }
}

function severityClass(severity: string): string {
  switch (severity.toLowerCase()) {
    case 'critical': return styles.sevCritical
    case 'high': return styles.sevHigh
    case 'medium': return styles.sevMedium
    default: return styles.sevLow
  }
}

export default function DashboardPage() {
  const { userId } = useProject()
  const { data, isLoading, isError } = useDashboardSummary(userId)

  return (
    <div className={styles.page}>
      <div className={styles.header}>
        <div>
          <h1 className={styles.title}>Dashboard</h1>
          <p className={styles.subtitle}>Today&apos;s activity across every program and target.</p>
        </div>
      </div>

      {isError && (
        <div className={styles.errorBanner}>Couldn&apos;t load dashboard data. Try refreshing.</div>
      )}

      <div className={styles.statGrid}>
        <div className={styles.statCard}>
          <div className={styles.statIcon}><Radar size={18} /></div>
          <div className={styles.statBody}>
            <span className={styles.statValue}>{isLoading ? '—' : data?.programs.total ?? 0}</span>
            <span className={styles.statLabel}>Programs</span>
            <span className={styles.statHint}>
              {isLoading ? '' : `${data?.programs.active ?? 0} active · manager coming soon`}
            </span>
          </div>
        </div>

        <Link href="/projects" className={styles.statCard}>
          <div className={styles.statIcon}><Target size={18} /></div>
          <div className={styles.statBody}>
            <span className={styles.statValue}>{isLoading ? '—' : data?.targets.total ?? 0}</span>
            <span className={styles.statLabel}>Targets</span>
            <span className={styles.statHint}>tracked recon targets</span>
          </div>
        </Link>

        <div className={styles.statCard}>
          <div className={styles.statIcon}><Activity size={18} /></div>
          <div className={styles.statBody}>
            <span className={styles.statValue}>{isLoading ? '—' : data?.scans.running ?? 0}</span>
            <span className={styles.statLabel}>Running Scans</span>
            <span className={styles.statHint}>
              {isLoading ? '' : data?.scans.orchestratorReachable
                ? `of last ${data.scans.checkedProjects} targets checked`
                : 'orchestrator unreachable'}
            </span>
          </div>
        </div>

        <Link href="/reports" className={styles.statCard}>
          <div className={styles.statIcon}><FileText size={18} /></div>
          <div className={styles.statBody}>
            <span className={styles.statValue}>{isLoading ? '—' : data?.reports.total ?? 0}</span>
            <span className={styles.statLabel}>Completed Reports</span>
            <span className={styles.statHint}>generated to date</span>
          </div>
        </Link>

        <div className={`${styles.statCard} ${styles.statCardAlert}`}>
          <div className={styles.statIcon}><ShieldAlert size={18} /></div>
          <div className={styles.statBody}>
            <span className={styles.statValue}>{isLoading ? '—' : data?.findings.highSeverity ?? 0}</span>
            <span className={styles.statLabel}>High Severity Findings</span>
            <span className={styles.statHint}>{isLoading ? '' : `${data?.findings.total ?? 0} findings total`}</span>
          </div>
        </div>

        <div className={styles.statCard}>
          <div className={styles.statIcon}><Gauge size={18} /></div>
          <div className={styles.statBody}>
            <span className={styles.statValue}>
              {isLoading ? '—' : data?.toolHealth.orchestratorUp
                ? <CheckCircle2 size={20} className={styles.healthOk} />
                : <XCircle size={20} className={styles.healthDown} />}
            </span>
            <span className={styles.statLabel}>Tool Health</span>
            <span className={styles.statHint}>recon orchestrator</span>
          </div>
        </div>
      </div>

      <div className={styles.columns}>
        <section className={styles.panel}>
          <div className={styles.panelHeader}>
            <h2 className={styles.panelTitle}><Sparkles size={15} /> Recent AI Suggestions</h2>
            <Link href="/cypherfix" className={styles.panelLink}>View all <ArrowRight size={12} /></Link>
          </div>
          {(!data?.suggestions.recent.length && !isLoading) && (
            <p className={styles.emptyState}>No pending AI suggestions yet.</p>
          )}
          <ul className={styles.list}>
            {data?.suggestions.recent.map(s => (
              <li key={s.id} className={styles.listItem}>
                <Link href={`/projects/${s.projectId}/settings`} className={styles.listItemLink}>
                  <span className={`${styles.sevBadge} ${severityClass(s.severity)}`}>{s.severity}</span>
                  <span className={styles.listItemTitle}>{s.title}</span>
                  <span className={styles.listItemMeta}>{s.project.name} · {formatDate(s.createdAt)}</span>
                </Link>
              </li>
            ))}
          </ul>
        </section>

        <section className={styles.panel}>
          <div className={styles.panelHeader}>
            <h2 className={styles.panelTitle}><FileText size={15} /> Recent Reports</h2>
            <Link href="/reports" className={styles.panelLink}>View all <ArrowRight size={12} /></Link>
          </div>
          {(!data?.reports.recent.length && !isLoading) && (
            <p className={styles.emptyState}>No reports generated yet.</p>
          )}
          <ul className={styles.list}>
            {data?.reports.recent.map(r => (
              <li key={r.id} className={styles.listItem}>
                <span className={styles.listItemLink}>
                  <span className={styles.formatBadge}>{r.format}</span>
                  <span className={styles.listItemTitle}>{r.title}</span>
                  <span className={styles.listItemMeta}>{r.project.name} · {formatDate(r.createdAt)}</span>
                </span>
              </li>
            ))}
          </ul>
        </section>
      </div>

      <section className={styles.panel}>
        <div className={styles.panelHeader}>
          <h2 className={styles.panelTitle}><Activity size={15} /> Workspace Activity</h2>
        </div>
        {(!data?.activity.length && !isLoading) && (
          <p className={styles.emptyState}>No recent activity.</p>
        )}
        <ul className={styles.activityList}>
          {data?.activity.map((a, i) => (
            <li key={i} className={styles.activityItem}>
              <Link href={a.href} className={styles.activityLink}>
                <span className={styles.activityDot} data-type={a.type} />
                <span>{a.label}</span>
                <span className={styles.activityTime}>{formatDate(a.at)}</span>
              </Link>
            </li>
          ))}
        </ul>
      </section>

      <p className={styles.footNote}>
        API usage metering isn&apos;t tracked yet — that lands with the security/API-token work later in the roadmap.
      </p>
    </div>
  )
}
