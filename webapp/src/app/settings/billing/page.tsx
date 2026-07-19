'use client'

import { useEffect, useState, useCallback } from 'react'
import Link from 'next/link'
import { Loader2, Check } from 'lucide-react'
import type { Entitlements } from '@/lib/subscription/entitlements'
import styles from '@/components/subscription/Billing.module.css'

interface Payload {
  entitlements: Entitlements
  billingMode: 'mock' | 'stripe'
}

const FEATURE_LABELS: Record<string, string> = {
  'scan.sast': 'Source SAST',
  'scan.dast': 'Live HTTP (DAST)',
  'scan.iac': 'Cloud / IaC',
  'scan.llm': 'LLM Top 10',
  'scan.smart_contract': 'Smart contracts',
  'scan.binary': 'Binary hardening',
  'scan.deep_binary': 'Deep symbolic',
  'scan.github_repo': 'GitHub-repo scan',
  'scan.scheduled': 'Scheduled scans',
  'report.markdown': 'Markdown reports',
  'report.html': 'HTML reports',
  'export.sarif': 'SARIF export',
  'api.access': 'API / CI access',
  'collab.team': 'Team seats',
  'support.priority': 'Priority support',
}

function Meter({ label, used, limit }: { label: string; used: number; limit: number }) {
  const unlimited = limit < 0
  const pct = unlimited ? 0 : Math.min(100, Math.round((used / Math.max(1, limit)) * 100))
  const fillClass = pct >= 100 ? styles.barFillFull : pct >= 80 ? styles.barFillWarn : ''
  return (
    <div className={styles.meter}>
      <div className={styles.meterHead}>
        <span>{label}</span>
        <span className={styles.meterVal}>{used}{unlimited ? '' : ` / ${limit}`}{unlimited ? ' (unlimited)' : ''}</span>
      </div>
      {!unlimited && (
        <div className={styles.bar}><div className={`${styles.barFill} ${fillClass}`} style={{ width: `${pct}%` }} /></div>
      )}
    </div>
  )
}

export default function BillingPage() {
  const [data, setData] = useState<Payload | null>(null)
  const [loading, setLoading] = useState(true)
  const [busy, setBusy] = useState(false)
  const [msg, setMsg] = useState('')

  const load = useCallback(async () => {
    setLoading(true)
    try {
      const res = await fetch('/api/subscription', { credentials: 'include' })
      if (res.ok) setData(await res.json())
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    load()
    const params = new URLSearchParams(window.location.search)
    if (params.get('upgraded')) setMsg(`You're now on the ${params.get('upgraded')} plan. 🎉`)
    else if (params.get('downgraded')) setMsg('Your plan was changed to Free.')
  }, [load])

  const cancel = async () => {
    if (!confirm('Cancel your subscription? You keep access until the end of the current period.')) return
    setBusy(true); setMsg('')
    try {
      const res = await fetch('/api/subscription/cancel', { method: 'POST', credentials: 'include' })
      if (res.ok) { setMsg('Subscription set to cancel at period end.'); await load() }
    } finally {
      setBusy(false)
    }
  }

  if (loading) return <div className={styles.center}><Loader2 className="spin" /> Loading billing…</div>
  if (!data) return <div className={styles.center}>Please sign in to manage your subscription.</div>

  const e = data.entitlements
  const isPaid = e.plan !== 'free'
  const periodEnd = e.currentPeriodEnd ? new Date(e.currentPeriodEnd).toLocaleDateString() : null

  return (
    <div className={styles.page}>
      <h1 className={styles.h1}>Billing &amp; plan</h1>

      {msg && <div className={styles.card} style={{ borderColor: 'var(--accent-primary)' }}>{msg}</div>}

      <div className={styles.card}>
        <div className={styles.row}>
          <div>
            <div className={styles.planLine}>
              <span className={styles.planName}>{e.planName}</span>
              <span className={`${styles.pill} ${e.cancelAtPeriodEnd ? styles.pillWarn : ''}`}>
                {e.cancelAtPeriodEnd ? 'Cancels at period end' : e.status}
              </span>
            </div>
            <p className={styles.sub}>
              {isPaid && periodEnd
                ? (e.cancelAtPeriodEnd ? `Access until ${periodEnd}.` : `Renews ${periodEnd}.`)
                : 'The free plan — upgrade any time for more scans and every scanner.'}
              {data.billingMode === 'mock' && ' (evaluation / self-hosted billing mode)'}
            </p>
          </div>
          <div className={styles.actions}>
            <Link href="/pricing" className={`${styles.btn} ${styles.btnPrimary}`}>
              {isPaid ? 'Change plan' : 'Upgrade'}
            </Link>
            {isPaid && !e.cancelAtPeriodEnd && (
              <button className={`${styles.btn} ${styles.btnDanger}`} onClick={cancel} disabled={busy}>
                {busy ? <Loader2 size={15} className="spin" /> : 'Cancel'}
              </button>
            )}
          </div>
        </div>
      </div>

      <div className={styles.card}>
        <p className={styles.usageTitle}>Usage this period</p>
        <Meter label="Scans" used={e.usage.scansUsed} limit={e.usage.scansLimit} />
        <Meter label="Seats" used={e.usage.seatsUsed} limit={e.usage.seatsLimit} />
      </div>

      <div className={styles.card}>
        <p className={styles.usageTitle}>Included in {e.planName}</p>
        <div className={styles.feats}>
          {e.features.map((f) => (
            <span key={f} className={styles.feat}><Check size={13} /> {FEATURE_LABELS[f] ?? f}</span>
          ))}
        </div>
      </div>
    </div>
  )
}
