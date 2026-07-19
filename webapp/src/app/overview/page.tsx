'use client'

import { useCallback, useEffect, useState } from 'react'
import Link from 'next/link'
import { useRouter } from 'next/navigation'
import { Loader2, Radar, Crosshair, Sparkles, FileText, Lock } from 'lucide-react'
import styles from '@/components/overview/Overview.module.css'

interface RecentScan {
  id: string; target: string; scanType: string; status: string; total: number
  maxCvss: number; bySeverity: Record<string, number>; createdAt: string
}
interface Overview {
  userName: string; plan: string; planName: string
  usage: { scansUsed: number; scansLimit: number; scansRemaining: number }
  recentScans: RecentScan[]; scanCount: number; programCount: number
  hunt: { earningsLocked: boolean; totalEarned: number | null; openCount: number; acceptanceRate: number; total: number }
  firstRun: boolean
}

const SEV = ['critical', 'high', 'medium', 'low', 'info']
const topSev = (b: Record<string, number>) => SEV.find((s) => (b?.[s] ?? 0) > 0) ?? 'none'

export default function OverviewPage() {
  const router = useRouter()
  const [data, setData] = useState<Overview | null>(null)
  const [loading, setLoading] = useState(true)

  const load = useCallback(async () => {
    setLoading(true)
    try {
      const r = await fetch('/api/overview', { credentials: 'include' })
      if (r.ok) setData(await r.json())
    } finally { setLoading(false) }
  }, [])
  useEffect(() => { load() }, [load])

  if (loading) return <div className={styles.center}><Loader2 className="spin" /> Loading…</div>
  if (!data) return <div className={styles.center}>Please sign in.</div>

  const u = data.usage
  const limitTxt = u.scansLimit < 0 ? '∞' : u.scansLimit
  const pct = u.scansLimit > 0 ? Math.min(100, (u.scansUsed / u.scansLimit) * 100) : 0
  const money = (n: number | null) => (n === null ? null : `$${n.toLocaleString()}`)

  return (
    <div className={styles.page}>
      <h1 className={styles.hello}>Welcome{data.userName ? `, ${data.userName.split(' ')[0]}` : ''} 👋</h1>
      <p className={styles.sub}>Scan a target, track your bugs, and export a submission-ready report.</p>

      {/* quick actions */}
      <div className={styles.actions}>
        <Link href="/scans" className={`${styles.action} ${styles.actionPrimary}`}>
          <Radar size={20} className={styles.actionIcon} />
          <span><span className={styles.actionTitle}>Run a scan</span><span className={styles.actionDesc}>A live URL or a GitHub repo</span></span>
        </Link>
        <Link href="/hunt" className={styles.action}>
          <Crosshair size={20} className={styles.actionIcon} />
          <span><span className={styles.actionTitle}>Bug Hunter</span><span className={styles.actionDesc}>Pipeline &amp; earnings</span></span>
        </Link>
        <a href="/api/scan/sample/report?format=html" target="_blank" rel="noopener noreferrer" className={styles.action}>
          <FileText size={20} className={styles.actionIcon} />
          <span><span className={styles.actionTitle}>See a sample report</span><span className={styles.actionDesc}>Preview the deliverable</span></span>
        </a>
        <Link href="/pricing" className={styles.action}>
          <Sparkles size={20} className={styles.actionIcon} />
          <span><span className={styles.actionTitle}>Plans &amp; billing</span><span className={styles.actionDesc}>You’re on {data.planName}</span></span>
        </Link>
      </div>

      {/* first-run guidance */}
      {data.firstRun && (
        <div className={styles.welcome}>
          <p className={styles.welcomeTitle}>Get your first result in under a minute</p>
          <ol className={styles.steps}>
            <li className={styles.step}><span className={styles.stepNum}>1</span> <span><Link className={styles.upgrade} href="/scans">Run a scan</Link> on a live URL — no setup needed.</span></li>
            <li className={styles.step}><span className={styles.stepNum}>2</span> <span>Review the findings (severity · CVSS · VRT) and download the report.</span></li>
            <li className={styles.step}><span className={styles.stepNum}>3</span> <span>Add a <Link className={styles.upgrade} href="/programs">program</Link> and “Track” a finding to start your bounty pipeline.</span></li>
          </ol>
        </div>
      )}

      {/* stat cards */}
      <div className={styles.cards}>
        <div className={styles.card}>
          <p className={styles.cardLabel}>Scans this period</p>
          <div className={styles.cardValue}>{u.scansUsed} <span className={styles.cardSmall}>/ {limitTxt}</span></div>
          {u.scansLimit > 0 && <div className={styles.bar}><div className={`${styles.barFill} ${pct >= 80 ? styles.barFillWarn : ''}`} style={{ width: `${pct}%` }} /></div>}
          {u.scansLimit >= 0 && u.scansRemaining === 0 && <div className={styles.cardSmall}><Link className={styles.upgrade} href="/pricing">Upgrade for more →</Link></div>}
        </div>
        <div className={styles.card}>
          <p className={styles.cardLabel}>Total scans</p>
          <div className={styles.cardValue}>{data.scanCount}</div>
          <div className={styles.cardSmall}>{data.programCount} program(s) tracked</div>
        </div>
        <div className={styles.card}>
          <p className={styles.cardLabel}>Open submissions</p>
          <div className={styles.cardValue}>{data.hunt.openCount}</div>
          <div className={styles.cardSmall}>{data.hunt.total} total · {Math.round(data.hunt.acceptanceRate * 100)}% accepted</div>
        </div>
        <div className={styles.card}>
          <p className={styles.cardLabel}>Earned</p>
          {data.hunt.earningsLocked ? (
            <>
              <div className={`${styles.cardValue} ${styles.locked}`}><Lock size={16} /></div>
              <div className={styles.cardSmall}><Link className={styles.upgrade} href="/pricing">Upgrade →</Link></div>
            </>
          ) : (
            <div className={styles.cardValue}>{money(data.hunt.totalEarned)}</div>
          )}
        </div>
      </div>

      {/* recent scans */}
      <div className={styles.panel}>
        <div className={styles.panelHead}>
          <p className={styles.panelTitle}>Recent scans</p>
          {data.recentScans.length > 0 && <Link href="/scans" className={styles.viewAll}>View all →</Link>}
        </div>
        {data.recentScans.length === 0 ? (
          <div className={styles.empty}>No scans yet — <Link className={styles.upgrade} href="/scans">run your first one</Link>.</div>
        ) : (
          <table className={styles.table}>
            <thead><tr><th>Target</th><th>Type</th><th className={styles.num}>Findings</th><th>Top severity</th><th>When</th></tr></thead>
            <tbody>
              {data.recentScans.map((s) => (
                <tr key={s.id}>
                  <td><button className={styles.rowLink} onClick={() => router.push('/scans')}>{s.target}</button></td>
                  <td>{s.scanType}</td>
                  <td className={styles.num}>{s.total}{s.status === 'failed' ? ' (failed)' : ''}</td>
                  <td><span className={`${styles.sev} ${styles['sev' + topSev(s.bySeverity) as keyof typeof styles]}`}>{topSev(s.bySeverity)}</span></td>
                  <td>{new Date(s.createdAt).toLocaleDateString()}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  )
}
