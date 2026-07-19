'use client'

import { useEffect, useState, useCallback } from 'react'
import { useRouter } from 'next/navigation'
import { Check, Loader2 } from 'lucide-react'
import type { Plan, PlanId } from '@/lib/subscription/plans'
import styles from '@/components/subscription/Pricing.module.css'

type Cycle = 'monthly' | 'yearly'

interface SubscriptionData {
  entitlements: { plan: PlanId; status: string }
  billingMode: 'mock' | 'stripe'
  plans: Plan[]
}

const RANK: Record<PlanId, number> = { free: 0, pro: 1, team: 2 }

export default function PricingPage() {
  const router = useRouter()
  const [data, setData] = useState<SubscriptionData | null>(null)
  const [cycle, setCycle] = useState<Cycle>('monthly')
  const [busy, setBusy] = useState<PlanId | null>(null)
  const [error, setError] = useState('')

  const load = useCallback(async () => {
    try {
      const res = await fetch('/api/subscription', { credentials: 'include' })
      if (res.ok) setData(await res.json())
      else setError('Please sign in to view plans.')
    } catch {
      setError('Failed to load plans.')
    }
  }, [])

  useEffect(() => { load() }, [load])

  const choose = async (plan: PlanId) => {
    setBusy(plan); setError('')
    try {
      const res = await fetch('/api/subscription/checkout', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify({ plan, cycle }),
      })
      const body = await res.json()
      if (!res.ok) { setError(body?.error || 'Checkout failed'); return }
      // mock mode returns an in-app URL; stripe mode returns a hosted URL
      if (body.url?.startsWith('http')) window.location.href = body.url
      else router.push(body.url || '/settings/billing')
    } catch {
      setError('Checkout failed')
    } finally {
      setBusy(null)
    }
  }

  const currentPlan = data?.entitlements.plan ?? 'free'

  return (
    <div className={styles.page}>
      <div className={styles.header}>
        <h1 className={styles.title}>Choose your plan</h1>
        <p className={styles.subtitle}>
          Scan source, cloud, binaries, smart contracts, LLM apps and live targets —
          scored against the Bugcrowd VRT with CVSS, SARIF export, and submission-ready reports.
        </p>
        <div className={styles.cycleToggle} role="tablist" aria-label="Billing cycle">
          <button
            className={`${styles.cycleBtn} ${cycle === 'monthly' ? styles.cycleBtnActive : ''}`}
            onClick={() => setCycle('monthly')} role="tab" aria-selected={cycle === 'monthly'}>
            Monthly
          </button>
          <button
            className={`${styles.cycleBtn} ${cycle === 'yearly' ? styles.cycleBtnActive : ''}`}
            onClick={() => setCycle('yearly')} role="tab" aria-selected={cycle === 'yearly'}>
            Yearly <span className={styles.save}>save ~20%</span>
          </button>
        </div>
      </div>

      {error && <p className={styles.note} style={{ color: 'var(--color-red-500, #dc2626)' }}>{error}</p>}

      <div className={styles.grid}>
        {(data?.plans ?? []).map((plan) => {
          const price = cycle === 'yearly' ? plan.priceYearly : plan.priceMonthly
          const isCurrent = plan.id === currentPlan
          const isDowngrade = RANK[plan.id] < RANK[currentPlan]
          return (
            <div key={plan.id} className={`${styles.card} ${plan.featured ? styles.cardFeatured : ''}`}>
              {plan.featured && <span className={styles.badge}>Most popular</span>}
              <h2 className={styles.planName}>{plan.name}</h2>
              <p className={styles.planTagline}>{plan.tagline}</p>
              <div className={styles.price}>
                <span className={styles.priceAmount}>${price}</span>
                <span className={styles.priceUnit}>{price === 0 ? 'forever' : '/ mo'}</span>
              </div>
              <ul className={styles.features}>
                {plan.highlights.map((h) => (
                  <li key={h} className={styles.feature}>
                    <Check size={16} className={styles.check} /> <span>{h}</span>
                  </li>
                ))}
              </ul>
              {isCurrent ? (
                <div className={styles.current}>Current plan</div>
              ) : (
                <button
                  className={`${styles.cta} ${plan.featured ? styles.ctaPrimary : ''}`}
                  onClick={() => choose(plan.id)}
                  disabled={busy !== null}>
                  {busy === plan.id ? <Loader2 size={16} className="spin" />
                    : isDowngrade ? `Switch to ${plan.name}` : plan.id === 'free' ? 'Get started' : `Upgrade to ${plan.name}`}
                </button>
              )}
            </div>
          )
        })}
      </div>

      <p className={styles.note}>
        {data?.billingMode === 'stripe'
          ? 'Secure checkout via Stripe. Cancel anytime.'
          : 'Self-hosted / evaluation mode — plans activate instantly for testing. Cancel anytime.'}
      </p>
    </div>
  )
}
