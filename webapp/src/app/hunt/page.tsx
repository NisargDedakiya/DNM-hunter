'use client'

import { useCallback, useEffect, useState } from 'react'
import Link from 'next/link'
import { Loader2, Lock } from 'lucide-react'
import styles from '@/components/hunt/Hunt.module.css'

const STATUSES = ['draft', 'submitted', 'triaged', 'accepted', 'duplicate', 'rejected', 'paid']
const STATUS_COLOR: Record<string, string> = {
  draft: '#5a6270', submitted: '#2b6cb0', triaged: '#7c5cbf', accepted: '#2e8b57',
  duplicate: '#c08a00', rejected: '#b3123b', paid: '#0f9d58',
}

interface Sub {
  id: string; programName: string; title: string; severity: string; status: string
  platform: string | null; bounty: number | null; createdAt: string
}
interface Stats {
  total: number; byStatus: Record<string, number>; totalEarned: number | null
  pending: number | null; paidCount: number; acceptanceRate: number; openCount: number
}
interface HuntData {
  programCount: number; programLimit: number; earningsLocked: boolean
  stats: Stats; submissions: Sub[]
}

export default function HuntPage() {
  const [data, setData] = useState<HuntData | null>(null)
  const [loading, setLoading] = useState(true)

  const load = useCallback(async () => {
    setLoading(true)
    try {
      const r = await fetch('/api/hunt', { credentials: 'include' })
      if (r.ok) setData(await r.json())
    } finally { setLoading(false) }
  }, [])
  useEffect(() => { load() }, [load])

  const patch = async (id: string, body: Record<string, unknown>) => {
    await fetch(`/api/hunt/submissions/${id}`, {
      method: 'PATCH', credentials: 'include',
      headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body),
    })
    load()
  }

  if (loading) return <div className={styles.empty}><Loader2 className="spin" /> Loading your pipeline…</div>
  if (!data) return <div className={styles.empty}>Please sign in.</div>

  const s = data.stats
  const money = (n: number | null) => (n === null ? null : `$${n.toLocaleString()}`)
  const limitTxt = data.programLimit < 0 ? '∞' : data.programLimit
  const total = s.total || 1

  return (
    <div className={styles.page}>
      <h1 className={styles.h1}>Bug Hunter</h1>
      <p className={styles.sub}>Your whole bounty pipeline and earnings across every program, in one place.</p>

      <div className={styles.cards}>
        <div className={styles.card}>
          <p className={styles.cardLabel}>Earned</p>
          {data.earningsLocked ? (
            <>
              <div className={`${styles.cardValue} ${styles.locked}`}><Lock size={18} /></div>
              <div className={styles.cardSmall}><Link className={styles.upgrade} href="/pricing">Upgrade to see earnings →</Link></div>
            </>
          ) : (
            <>
              <div className={styles.cardValue}>{money(s.totalEarned)}</div>
              <div className={styles.cardSmall}>{s.paidCount} paid{s.pending ? ` · ${money(s.pending)} pending` : ''}</div>
            </>
          )}
        </div>
        <div className={styles.card}>
          <p className={styles.cardLabel}>Acceptance rate</p>
          <div className={styles.cardValue}>{Math.round(s.acceptanceRate * 100)}%</div>
          <div className={styles.cardSmall}>of resolved reports</div>
        </div>
        <div className={styles.card}>
          <p className={styles.cardLabel}>Open</p>
          <div className={styles.cardValue}>{s.openCount}</div>
          <div className={styles.cardSmall}>awaiting a decision</div>
        </div>
        <div className={styles.card}>
          <p className={styles.cardLabel}>Total submissions</p>
          <div className={styles.cardValue}>{s.total}</div>
          <div className={styles.cardSmall}>across {data.programCount} program(s)</div>
        </div>
      </div>

      {s.total > 0 && (
        <div className={styles.panel} style={{ marginBottom: 20 }}>
          <p className={styles.panelTitle}>Pipeline</p>
          <div className={styles.statusBar}>
            {STATUSES.filter((st) => s.byStatus[st] > 0).map((st) => (
              <span key={st} className={styles.seg} style={{ width: `${(s.byStatus[st] / total) * 100}%`, background: STATUS_COLOR[st] }} />
            ))}
          </div>
          <div className={styles.legend}>
            {STATUSES.filter((st) => s.byStatus[st] > 0).map((st) => (
              <span key={st} className={styles.legItem}><span className={styles.dot} style={{ background: STATUS_COLOR[st] }} /> {st} ({s.byStatus[st]})</span>
            ))}
          </div>
        </div>
      )}

      <div className={styles.panel}>
        <p className={styles.panelTitle}>Submissions</p>
        {data.submissions.length === 0 ? (
          <div className={styles.empty}>
            No submissions yet. Run a <Link className={styles.upgrade} href="/scans">scan</Link> and “Track as submission”,
            or add one from a <Link className={styles.upgrade} href="/programs">program</Link>.
          </div>
        ) : (
          <table className={styles.table}>
            <thead><tr><th>Title</th><th>Program</th><th>Severity</th><th>Status</th><th className={styles.num}>Bounty</th></tr></thead>
            <tbody>
              {data.submissions.map((sub) => (
                <tr key={sub.id}>
                  <td>{sub.title}</td>
                  <td>{sub.programName}</td>
                  <td><span className={`${styles.sev} ${styles['sev' + sub.severity as keyof typeof styles]}`}>{sub.severity}</span></td>
                  <td>
                    <select className={styles.select} value={sub.status} onChange={(e) => patch(sub.id, { status: e.target.value })}>
                      {STATUSES.map((st) => <option key={st} value={st}>{st}</option>)}
                    </select>
                  </td>
                  <td className={styles.num}>
                    <input
                      className={styles.bountyInput}
                      type="number" min="0" placeholder="$0"
                      defaultValue={sub.bounty ?? ''}
                      onBlur={(e) => { const v = e.target.value; if (v !== String(sub.bounty ?? '')) patch(sub.id, { bounty: Number(v || 0) }) }}
                    />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
        <p className={styles.progLimit}>Tracking {data.programCount} / {limitTxt} programs.
          {data.programLimit >= 0 && data.programCount >= data.programLimit && <> <Link className={styles.upgrade} href="/pricing">Upgrade for more →</Link></>}
        </p>
      </div>
    </div>
  )
}
