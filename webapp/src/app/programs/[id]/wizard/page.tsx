'use client'

import { useState } from 'react'
import { useParams, useRouter } from 'next/navigation'
import Link from 'next/link'
import ReactMarkdown from 'react-markdown'
import remarkGfm from 'remark-gfm'
import {
  ArrowLeft, Compass, KeyRound, Loader2,
  Code2, Scale, Fingerprint, ShieldCheck, Lock, Layers, Repeat, Waypoints,
} from 'lucide-react'
import { useQuery } from '@tanstack/react-query'
import styles from './page.module.css'

interface WizardCategory {
  id: string
  title: string
  blurb: string
  icon: React.ReactNode
  source: 'skills' | 'community-skills'
  skillId: string
}

const CATEGORIES: WizardCategory[] = [
  { id: 'dom-xss', title: 'DOM XSS', blurb: 'Client-side sinks, blind XSS, context-aware payloads.', icon: <Code2 size={18} />, source: 'community-skills', skillId: 'xss_exploitation' },
  { id: 'business-logic', title: 'Business Logic', blurb: 'Workflow bypass, state-machine abuse, price/quantity manipulation.', icon: <Scale size={18} />, source: 'skills', skillId: 'vulnerabilities/business_logic' },
  { id: 'idor', title: 'IDOR / BOLA', blurb: 'Object-reference enumeration, cross-account access checks.', icon: <Fingerprint size={18} />, source: 'community-skills', skillId: 'idor_bola_exploitation' },
  { id: 'jwt', title: 'JWT', blurb: 'Algorithm confusion, key injection, claim tampering.', icon: <ShieldCheck size={18} />, source: 'skills', skillId: 'vulnerabilities/jwt_attacks' },
  { id: 'oauth', title: 'OAuth / OIDC', blurb: 'Redirect URI abuse, PKCE downgrade, token confusion.', icon: <Lock size={18} />, source: 'skills', skillId: 'vulnerabilities/oauth_oidc' },
  { id: 'cache-poisoning', title: 'Cache Poisoning', blurb: 'Unkeyed inputs, cache key confusion, poisoned responses.', icon: <Layers size={18} />, source: 'skills', skillId: 'vulnerabilities/web_cache_poisoning' },
  { id: 'race-conditions', title: 'Race Conditions', blurb: 'Single-packet attacks, TOCTOU windows, idempotency abuse.', icon: <Repeat size={18} />, source: 'skills', skillId: 'vulnerabilities/race_conditions' },
  { id: 'http-smuggling', title: 'HTTP Smuggling', blurb: 'CL.TE/TE.CL/TE.TE desync detection and exploitation.', icon: <Waypoints size={18} />, source: 'skills', skillId: 'vulnerabilities/http_request_smuggling' },
]

async function fetchSkillContent(category: WizardCategory): Promise<{ name: string; content: string }> {
  const url = category.source === 'skills' ? `/api/skills/${category.skillId}` : `/api/community-skills/${category.skillId}`
  const res = await fetch(url)
  const data = await res.json()
  if (!res.ok) throw new Error(data.error || 'Failed to load guide')
  return data
}

export default function ManualHuntWizardPage() {
  const params = useParams()
  const router = useRouter()
  const programId = typeof params.id === 'string' ? params.id : null
  const [selected, setSelected] = useState<WizardCategory | null>(null)

  const { data, isLoading, isError } = useQuery({
    queryKey: ['wizard-skill', selected?.id],
    queryFn: () => fetchSkillContent(selected as WizardCategory),
    enabled: !!selected,
  })

  if (!programId) return null

  return (
    <div className={styles.page}>
      <div className={styles.header}>
        <button className={styles.backButton} onClick={() => router.push(`/programs/${programId}`)}>
          <ArrowLeft size={14} /> Back to program
        </button>
        <Link href={`/programs/${programId}/auth`} className={styles.authLink}>
          <KeyRound size={14} /> Auth Manager
        </Link>
      </div>
      <h1 className={styles.title}><Compass size={18} /> Manual Hunt Wizard</h1>
      <p className={styles.subtitle}>
        Guided methodology for the classes automation can&apos;t reliably confirm on its own. Pick a class, follow
        the steps, use the Auth Manager&apos;s Replay tool for anything that needs a second identity.
      </p>

      <div className={styles.layout}>
        <div className={styles.cardGrid}>
          {CATEGORIES.map(cat => (
            <button
              key={cat.id}
              className={`${styles.card} ${selected?.id === cat.id ? styles.cardActive : ''}`}
              onClick={() => setSelected(cat)}
            >
              <div className={styles.cardIcon}>{cat.icon}</div>
              <div className={styles.cardText}>
                <span className={styles.cardTitle}>{cat.title}</span>
                <span className={styles.cardBlurb}>{cat.blurb}</span>
              </div>
            </button>
          ))}
        </div>

        <div className={styles.reader}>
          {!selected && <p className={styles.emptyState}>Pick a vulnerability class on the left to open its guide.</p>}
          {selected && isLoading && (
            <p className={styles.emptyState}><Loader2 size={14} className={styles.spin} /> Loading guide…</p>
          )}
          {selected && isError && (
            <p className={styles.emptyState}>
              Couldn&apos;t load this guide from the agent service. It may be offline — the guide content lives in
              the agent container, not the webapp.
            </p>
          )}
          {selected && data && (
            <article className={styles.markdown}>
              <ReactMarkdown remarkPlugins={[remarkGfm]}>{data.content}</ReactMarkdown>
            </article>
          )}
        </div>
      </div>
    </div>
  )
}
