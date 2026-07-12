'use client'

import { useMemo } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Store, Radar, ScanSearch, ShieldCheck, FileText, PackageOpen, Loader2 } from 'lucide-react'
import styles from './page.module.css'

interface PluginPermission { scope: string; reason: string }

interface Plugin {
  id: string
  name: string
  category: 'recon' | 'scanner' | 'validator' | 'reporter' | 'export'
  kind: 'mcp-server' | 'builtin' | 'webapp-subsystem'
  description: string
  dockerService: string | null
  status: 'core' | 'community'
  tags: string[]
  // Master-plan Phase 6 installable-module fields (optional on legacy manifests).
  version?: string
  author?: string
  requiredTools?: string[]
  permissions?: PluginPermission[]
}

const CATEGORY_META: Record<Plugin['category'], { label: string; icon: React.ReactNode }> = {
  recon: { label: 'Recon', icon: <Radar size={16} /> },
  scanner: { label: 'Scanner', icon: <ScanSearch size={16} /> },
  validator: { label: 'Validator', icon: <ShieldCheck size={16} /> },
  reporter: { label: 'Reporter', icon: <FileText size={16} /> },
  export: { label: 'Export', icon: <PackageOpen size={16} /> },
}

const CATEGORY_ORDER: Plugin['category'][] = ['recon', 'scanner', 'validator', 'reporter', 'export']

interface PluginHealth {
  id: string
  health: 'healthy' | 'active' | 'unreachable' | 'unknown'
  latencyMs: number | null
  detail: string | null
}

const HEALTH_CLASS: Record<PluginHealth['health'], string> = {
  healthy: 'healthHealthy',
  active: 'healthActive',
  unreachable: 'healthUnreachable',
  unknown: 'healthUnknown',
}

async function fetchPlugins(): Promise<{ plugins: Plugin[] }> {
  const res = await fetch('/api/plugins')
  return res.json()
}

async function fetchPluginsHealth(): Promise<{ health: PluginHealth[] }> {
  const res = await fetch('/api/plugins/health')
  return res.json()
}

export default function MarketplacePage() {
  const { data, isLoading } = useQuery({ queryKey: ['plugins'], queryFn: fetchPlugins })
  const plugins = data?.plugins ?? []

  const { data: healthData } = useQuery({
    queryKey: ['plugins-health'],
    queryFn: fetchPluginsHealth,
    staleTime: 30_000,
    refetchInterval: 60_000,
  })
  const healthById = useMemo(() => {
    const map = new Map<string, PluginHealth>()
    for (const h of healthData?.health ?? []) map.set(h.id, h)
    return map
  }, [healthData])

  const byCategory = useMemo(() => {
    const map = new Map<Plugin['category'], Plugin[]>()
    for (const cat of CATEGORY_ORDER) map.set(cat, [])
    for (const p of plugins) {
      if (!map.has(p.category)) map.set(p.category, [])
      map.get(p.category)!.push(p)
    }
    return map
  }, [plugins])

  return (
    <div className={styles.page}>
      <div className={styles.header}>
        <h1 className={styles.title}><Store size={18} /> Marketplace</h1>
        <p className={styles.subtitle}>
          Every recon, scanner, validator, reporter, and export capability this platform ships, in one catalog.
          <strong> Core</strong> capabilities are always available — no install step, they&apos;re already running.
          <strong> Community</strong> capabilities are opt-in imports.
        </p>
      </div>

      {isLoading && (
        <p className={styles.emptyState}><Loader2 size={14} className={styles.spin} /> Loading catalog…</p>
      )}

      {!isLoading && plugins.length === 0 && (
        <p className={styles.emptyState}>
          Catalog unavailable — the agent service may be offline. The capabilities themselves aren&apos;t affected.
        </p>
      )}

      {CATEGORY_ORDER.map(cat => {
        const items = byCategory.get(cat) ?? []
        if (items.length === 0) return null
        return (
          <section key={cat} className={styles.categorySection}>
            <h2 className={styles.categoryTitle}>{CATEGORY_META[cat].icon} {CATEGORY_META[cat].label}</h2>
            <div className={styles.grid}>
              {items.map(p => {
                const health = healthById.get(p.id)
                return (
                  <div key={p.id} className={styles.card}>
                    <div className={styles.cardHeader}>
                      <span className={styles.cardName}>{p.name}</span>
                      <span className={`${styles.statusBadge} ${p.status === 'core' ? styles.statusCore : styles.statusCommunity}`}>
                        {p.status}
                      </span>
                    </div>
                    <p className={styles.cardDescription}>{p.description}</p>
                    <div className={styles.cardMeta}>
                      <span className={styles.kindTag}>{p.kind}</span>
                      {p.tags.map(t => <span key={t} className={styles.tag}>{t}</span>)}
                    </div>
                    {p.permissions && p.permissions.length > 0 && (
                      <div className={styles.permBlock}>
                        <span className={styles.permTitle}>Permissions this plugin requests</span>
                        <ul className={styles.permList}>
                          {p.permissions.map(perm => (
                            <li key={perm.scope} className={styles.permItem} title={perm.reason}>
                              <code className={styles.permScope}>{perm.scope}</code>
                              {perm.reason && <span className={styles.permReason}>{perm.reason}</span>}
                            </li>
                          ))}
                        </ul>
                      </div>
                    )}
                    {health && (
                      <div className={styles.cardMeta} title={health.detail ?? undefined}>
                        <span className={`${styles.healthDot} ${styles[HEALTH_CLASS[health.health]]}`} />
                        <span className={styles.healthLabel}>
                          {health.health}
                          {health.latencyMs != null && ` · ${health.latencyMs}ms`}
                        </span>
                      </div>
                    )}
                  </div>
                )
              })}
            </div>
          </section>
        )
      })}
    </div>
  )
}
