'use client'

import { useParams } from 'next/navigation'
import Link from 'next/link'
import {
  ArrowLeft, Building2, Layers, KeyRound, ShieldAlert, FileCode2,
  Radar, Gauge, Network, Sparkles,
} from 'lucide-react'
import { useAiSummary } from '@/hooks/useAiSummary'
import styles from './page.module.css'

function riskClass(score: number): string {
  if (score >= 70) return 'riskCritical'
  if (score >= 40) return 'riskHigh'
  if (score >= 15) return 'riskMedium'
  return 'riskLow'
}

function riskLabel(score: number): string {
  if (score >= 70) return 'Critical'
  if (score >= 40) return 'High'
  if (score >= 15) return 'Medium'
  return 'Low'
}

export default function ProjectAiSummaryPage() {
  const params = useParams()
  const projectId = typeof params.id === 'string' ? params.id : null
  const { data, isLoading, isError } = useAiSummary(projectId)

  return (
    <div className={styles.page}>
      <div className={styles.header}>
        <Link href={projectId ? `/projects/${projectId}/settings` : '/projects'} className={styles.backButton}>
          <ArrowLeft size={14} /> Back to project
        </Link>
        <h1 className={styles.title}><Sparkles size={18} /> AI Recon Summary</h1>
        {data && <p className={styles.subtitle}>{data.project.targetDomain || data.project.name}</p>}
      </div>

      {isLoading && <p className={styles.emptyState}>Analyzing recon data…</p>}
      {isError && <p className={styles.emptyState}>Couldn&apos;t load the summary. Try refreshing.</p>}

      {data && (
        <>
          <section className={styles.riskBanner}>
            <div className={styles.riskScoreBox}>
              <span className={styles.riskScoreValue}>{data.riskScore}</span>
              <span className={`${styles.riskBadge} ${styles[riskClass(data.riskScore)]}`}>
                {riskLabel(data.riskScore)} Risk
              </span>
            </div>
            <div className={styles.riskBreakdown}>
              <span>{data.totalVulns} vulnerabilities</span>
              <span>·</span>
              <span>{data.totalSecrets} secrets exposed</span>
            </div>
          </section>

          <section className={styles.panel}>
            <h2 className={styles.panelTitle}><Building2 size={15} /> Company Overview</h2>
            <p className={styles.narrative}>
              {data.companyOverview || 'AI narrative unavailable — showing raw counts below instead.'}
            </p>
          </section>

          <div className={styles.grid}>
            <section className={styles.card}>
              <h3 className={styles.cardTitle}><Layers size={14} /> Tech Stack</h3>
              {data.techStack.length === 0 && <p className={styles.cardEmpty}>No technologies detected yet.</p>}
              <ul className={styles.tagList}>
                {data.techStack.slice(0, 15).map((t, i) => (
                  <li key={i} className={styles.tag}>
                    {t.name}{t.version ? ` ${t.version}` : ''}
                    {t.cveCount > 0 && <span className={styles.tagCve}>{t.cveCount} CVE</span>}
                  </li>
                ))}
              </ul>
            </section>

            <section className={styles.card}>
              <h3 className={styles.cardTitle}><KeyRound size={14} /> Authentication</h3>
              <p className={styles.cardStat}>{data.authentication.endpointCount}</p>
              <p className={styles.cardCaption}>auth-related endpoints discovered</p>
            </section>

            <section className={styles.card}>
              <h3 className={styles.cardTitle}><ShieldAlert size={14} /> Admin Panels</h3>
              <p className={styles.cardStat}>{data.adminPanels.count}</p>
              <p className={styles.cardCaption}>admin/dashboard/CMS endpoints</p>
            </section>

            <section className={styles.card}>
              <h3 className={styles.cardTitle}><Network size={14} /> API Summary</h3>
              <p className={styles.cardStat}>{data.apiSummary.restEndpointCount}</p>
              <p className={styles.cardCaption}>REST-style endpoints · {data.apiSummary.graphqlEndpointCount} GraphQL</p>
            </section>

            <section className={styles.card}>
              <h3 className={styles.cardTitle}><FileCode2 size={14} /> JavaScript Files</h3>
              <p className={styles.cardStat}>{data.javascriptFiles.fileCount}</p>
              <p className={styles.cardCaption}>{data.javascriptFiles.secretCount} secrets found in JS</p>
            </section>

            <section className={styles.card}>
              <h3 className={styles.cardTitle}><Gauge size={14} /> Attack Surface</h3>
              <p className={styles.cardStat}>{data.attackSurface.subdomains.total}</p>
              <p className={styles.cardCaption}>
                subdomains ({data.attackSurface.subdomains.resolved} resolved) ·{' '}
                {data.attackSurface.exposedServices.length} services exposed
              </p>
            </section>
          </div>

          <section className={styles.panel}>
            <h2 className={styles.panelTitle}><Radar size={15} /> Potential Attack Surface</h2>
            <p className={styles.narrative}>
              {data.attackSurfaceNarrative || 'AI narrative unavailable — see Interesting Endpoints below.'}
            </p>
          </section>

          <section className={styles.panel}>
            <h2 className={styles.panelTitle}>Interesting Endpoints</h2>
            {data.interestingEndpoints.length === 0 && (
              <p className={styles.cardEmpty}>No high-value endpoints (admin/auth/API/forms) discovered yet.</p>
            )}
            <ul className={styles.endpointList}>
              {data.interestingEndpoints.map((e, i) => (
                <li key={i} className={styles.endpointItem}>
                  <span className={styles.endpointCategory}>{e.category}</span>
                  <span className={styles.endpointUrl}>{e.url}</span>
                </li>
              ))}
            </ul>
          </section>
        </>
      )}
    </div>
  )
}
