'use client'

import { useMemo, useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { BookOpen, Search, Loader2, X, ExternalLink } from 'lucide-react'
import ReactMarkdown from 'react-markdown'
import remarkGfm from 'remark-gfm'
import { Prism as SyntaxHighlighter } from 'react-syntax-highlighter'
import { vscDarkPlus } from 'react-syntax-highlighter/dist/esm/styles/prism'
import styles from './page.module.css'
import type { LearningCenterEntry, LearningCenterDetail } from './types'

const CATEGORY_LABEL_OVERRIDES: Record<string, string> = {
  community: 'Attack-Skill Playbooks',
  api_security: 'API Security',
  active_directory: 'Active Directory',
  post_exploitation: 'Post-Exploitation',
  general: 'General',
}

function categoryLabel(category: string): string {
  if (CATEGORY_LABEL_OVERRIDES[category]) return CATEGORY_LABEL_OVERRIDES[category]
  return category.split(/[_/]/).map(w => w.charAt(0).toUpperCase() + w.slice(1)).join(' ')
}

async function fetchCatalog(): Promise<{ entries: LearningCenterEntry[] }> {
  const res = await fetch('/api/learning-center')
  return res.json()
}

async function fetchDetail(source: string, id: string): Promise<LearningCenterDetail> {
  const res = await fetch(`/api/learning-center/${source}/${id}`)
  if (!res.ok) throw new Error('Failed to load skill doc')
  return res.json()
}

export default function AcademyPage() {
  const { data, isLoading } = useQuery({ queryKey: ['learning-center'], queryFn: fetchCatalog })
  const entries = useMemo(() => data?.entries ?? [], [data])

  const [search, setSearch] = useState('')
  const [activeCategory, setActiveCategory] = useState<string | null>(null)
  const [selected, setSelected] = useState<LearningCenterEntry | null>(null)

  const categories = useMemo(() => {
    const set = new Set(entries.map(e => e.category))
    return [...set].sort()
  }, [entries])

  const filtered = useMemo(() => {
    const q = search.trim().toLowerCase()
    return entries.filter(e => {
      if (activeCategory && e.category !== activeCategory) return false
      if (!q) return true
      return e.name.toLowerCase().includes(q) || e.description.toLowerCase().includes(q)
    })
  }, [entries, search, activeCategory])

  const grouped = useMemo(() => {
    const map = new Map<string, LearningCenterEntry[]>()
    for (const e of filtered) {
      if (!map.has(e.category)) map.set(e.category, [])
      map.get(e.category)!.push(e)
    }
    return [...map.entries()].sort((a, b) => a[0].localeCompare(b[0]))
  }, [filtered])

  const detailQuery = useQuery({
    queryKey: ['learning-center-detail', selected?.source, selected?.id],
    queryFn: () => fetchDetail(selected!.source, selected!.id),
    enabled: !!selected,
  })

  return (
    <div className={styles.page}>
      <div className={styles.header}>
        <h1 className={styles.title}><BookOpen size={18} /> Academy</h1>
        <p className={styles.subtitle}>
          The methodology references the AI agent pulls into context during attacks (<code>/skill &lt;name&gt;</code>),
          browsable directly — protocol deep-dives, cloud/framework playbooks, and attack-skill workflows,
          in one searchable library.
        </p>
      </div>

      <div className={styles.controls}>
        <div className={styles.searchBox}>
          <Search size={14} className={styles.searchIcon} />
          <input
            type="text"
            placeholder="Search skills…"
            value={search}
            onChange={e => setSearch(e.target.value)}
            className={styles.searchInput}
          />
        </div>
        <div className={styles.categoryChips}>
          <button
            className={`${styles.chip} ${activeCategory === null ? styles.chipActive : ''}`}
            onClick={() => setActiveCategory(null)}
          >
            All ({entries.length})
          </button>
          {categories.map(cat => (
            <button
              key={cat}
              className={`${styles.chip} ${activeCategory === cat ? styles.chipActive : ''}`}
              onClick={() => setActiveCategory(cat === activeCategory ? null : cat)}
            >
              {categoryLabel(cat)} ({entries.filter(e => e.category === cat).length})
            </button>
          ))}
        </div>
      </div>

      <div className={styles.body}>
        <div className={styles.catalog}>
          {isLoading && (
            <p className={styles.emptyState}><Loader2 size={14} className={styles.spin} /> Loading catalog…</p>
          )}
          {!isLoading && entries.length === 0 && (
            <p className={styles.emptyState}>
              Catalog unavailable — the agent service may be offline.
            </p>
          )}
          {!isLoading && entries.length > 0 && filtered.length === 0 && (
            <p className={styles.emptyState}>No skills match &ldquo;{search}&rdquo;.</p>
          )}

          {grouped.map(([cat, items]) => (
            <section key={cat} className={styles.categorySection}>
              <h2 className={styles.categoryTitle}>{categoryLabel(cat)}</h2>
              <div className={styles.grid}>
                {items.map(item => (
                  <button
                    key={`${item.source}:${item.id}`}
                    className={`${styles.card} ${selected?.id === item.id && selected?.source === item.source ? styles.cardSelected : ''}`}
                    onClick={() => setSelected(item)}
                  >
                    <span className={styles.cardName}>{item.name}</span>
                    <p className={styles.cardDescription}>{item.description || 'No description available.'}</p>
                  </button>
                ))}
              </div>
            </section>
          ))}
        </div>

        {selected && (
          <div className={styles.detailPanel}>
            <div className={styles.detailHeader}>
              <div>
                <span className={styles.detailCategory}>{categoryLabel(selected.category)}</span>
                <h3 className={styles.detailTitle}>{selected.name}</h3>
              </div>
              <button className={styles.closeButton} onClick={() => setSelected(null)} aria-label="Close">
                <X size={16} />
              </button>
            </div>

            {detailQuery.isLoading && (
              <p className={styles.emptyState}><Loader2 size={14} className={styles.spin} /> Loading…</p>
            )}
            {detailQuery.isError && (
              <p className={styles.emptyState}>Failed to load this skill doc.</p>
            )}
            {detailQuery.data && (
              <div className={styles.markdown}>
                <ReactMarkdown
                  remarkPlugins={[remarkGfm]}
                  components={{
                    code({ className, children, ...props }: any) {
                      const match = /language-(\w+)/.exec(className || '')
                      const isInline = !className
                      const codeText = String(children).replace(/\n$/, '')
                      if (!isInline && match) {
                        return (
                          <SyntaxHighlighter style={vscDarkPlus as any} language={match[1]} PreTag="div">
                            {codeText}
                          </SyntaxHighlighter>
                        )
                      }
                      return <code className={className} {...props}>{children}</code>
                    },
                    a({ href, children, ...props }: any) {
                      const isExternal = typeof href === 'string' && href.startsWith('http')
                      return (
                        <a href={href} target={isExternal ? '_blank' : undefined} rel={isExternal ? 'noopener noreferrer' : undefined} {...props}>
                          {children}{isExternal && <ExternalLink size={10} style={{ display: 'inline', marginLeft: 2, verticalAlign: 'middle' }} />}
                        </a>
                      )
                    },
                  }}
                >
                  {detailQuery.data.content}
                </ReactMarkdown>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  )
}
