'use client'

import { useMemo, useState } from 'react'
import { useParams, useRouter } from 'next/navigation'
import Link from 'next/link'
import ReactMarkdown from 'react-markdown'
import remarkGfm from 'remark-gfm'
import { ArrowLeft, Compass, KeyRound, Loader2 } from 'lucide-react'
import { useQuery } from '@tanstack/react-query'
import { AGENT_ROLE_ICON_BY_ID, roleLabel } from '@/lib/agentRoles'
import styles from './page.module.css'

interface VulnModule {
  id: string
  title: string
  blurb: string
  source: 'builtin' | 'skills' | 'community-skills'
  skill_id: string | null
  automated: boolean
  suggested_role: string
}

async function fetchModules(): Promise<{ modules: VulnModule[] }> {
  const res = await fetch('/api/vuln-modules')
  return res.json()
}

async function fetchSkillContent(mod: VulnModule): Promise<{ name: string; content: string }> {
  const url = mod.source === 'skills' ? `/api/skills/${mod.skill_id}` : `/api/community-skills/${mod.skill_id}`
  const res = await fetch(url)
  const data = await res.json()
  if (!res.ok) throw new Error(data.error || 'Failed to load guide')
  return data
}

export default function ManualHuntWizardPage() {
  const params = useParams()
  const router = useRouter()
  const programId = typeof params.id === 'string' ? params.id : null
  const [selected, setSelected] = useState<VulnModule | null>(null)

  const { data: moduleData, isLoading: modulesLoading } = useQuery({ queryKey: ['vuln-modules'], queryFn: fetchModules })
  const modules = moduleData?.modules ?? []
  const guided = useMemo(() => modules.filter(m => !m.automated), [modules])
  const automatedTitles = useMemo(() => modules.filter(m => m.automated).map(m => m.title), [modules])

  const { data, isLoading, isError } = useQuery({
    queryKey: ['wizard-skill', selected?.id],
    queryFn: () => fetchSkillContent(selected as VulnModule),
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
        {automatedTitles.length > 0 && (
          <> {automatedTitles.length} classes ({automatedTitles.join(', ')}) are fully automated by the AI agent — ask for them directly in chat.</>
        )}
      </p>

      <div className={styles.layout}>
        <div className={styles.cardGrid}>
          {modulesLoading && <p className={styles.emptyState}><Loader2 size={14} className={styles.spin} /> Loading modules…</p>}
          {!modulesLoading && guided.length === 0 && (
            <p className={styles.emptyState}>
              No guides available — the agent service may be offline.
            </p>
          )}
          {guided.map(mod => {
            const RoleIcon = AGENT_ROLE_ICON_BY_ID[mod.suggested_role]
            return (
              <button
                key={mod.id}
                className={`${styles.card} ${selected?.id === mod.id ? styles.cardActive : ''}`}
                onClick={() => setSelected(mod)}
              >
                <div className={styles.cardIcon}>{RoleIcon ? <RoleIcon size={18} /> : null}</div>
                <div className={styles.cardText}>
                  <span className={styles.cardTitle}>{mod.title}</span>
                  <span className={styles.cardBlurb}>{mod.blurb}</span>
                  <span className={styles.cardRole}>{roleLabel(mod.suggested_role)}</span>
                </div>
              </button>
            )
          })}
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
