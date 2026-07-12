'use client'

import { useState, useMemo, useEffect } from 'react'
import Link from 'next/link'
import {
  Layers, Plus, Radar, ShieldAlert, ShieldCheck, Target as TargetIcon, Search,
  FileText, Camera, StickyNote, Send, ChevronRight, FolderOpen,
} from 'lucide-react'
import { useProject } from '@/providers/ProjectProvider'
import { useWorkspace } from '@/providers/WorkspaceProvider'
import { useWorkspaces, useCreateWorkspace } from '@/hooks/useWorkspaces'
import { usePrograms, useProgram, useUpdateProgram } from '@/hooks/usePrograms'
import { useToast } from '@/components/ui'
import { SubmissionsSection } from './SubmissionsSection'
import styles from './workspace.module.css'

type SubSection = 'scope' | 'assets' | 'recon' | 'findings' | 'evidence' | 'reports' | 'notes' | 'submissions'

const SUB_SECTIONS: { id: SubSection; label: string; icon: React.ReactNode }[] = [
  { id: 'scope', label: 'Scope', icon: <ShieldCheck size={14} /> },
  { id: 'assets', label: 'Assets', icon: <TargetIcon size={14} /> },
  { id: 'recon', label: 'Recon', icon: <Radar size={14} /> },
  { id: 'findings', label: 'Findings', icon: <Search size={14} /> },
  { id: 'evidence', label: 'Evidence', icon: <Camera size={14} /> },
  { id: 'reports', label: 'Reports', icon: <FileText size={14} /> },
  { id: 'notes', label: 'Notes', icon: <StickyNote size={14} /> },
  { id: 'submissions', label: 'Submissions', icon: <Send size={14} /> },
]

export default function WorkspacePage() {
  const { userId } = useProject()
  const { activeWorkspaceId, activeProgramId, setActiveWorkspaceId, setActiveProgramId } = useWorkspace()
  const { data: workspaces = [] } = useWorkspaces(userId)
  const { data: allPrograms = [] } = usePrograms(userId)
  const createWorkspace = useCreateWorkspace()
  const toast = useToast()

  const [subSection, setSubSection] = useState<SubSection>('scope')
  const [creatingWs, setCreatingWs] = useState(false)
  const [newWsName, setNewWsName] = useState('')

  const programs = useMemo(
    () => allPrograms.filter(p => (activeWorkspaceId ? p.workspaceId === activeWorkspaceId : true)),
    [allPrograms, activeWorkspaceId],
  )

  const handleCreateWorkspace = async () => {
    if (!newWsName.trim() || !userId) return
    try {
      const ws = await createWorkspace.mutateAsync({ userId, name: newWsName.trim() })
      setActiveWorkspaceId(ws.id)
      setNewWsName('')
      setCreatingWs(false)
      toast.success('Workspace created')
    } catch (e) {
      toast.error(e instanceof Error ? e.message : 'Failed to create workspace')
    }
  }

  return (
    <div className={styles.page}>
      {/* ── Left rail: the walkable spine ── */}
      <aside className={styles.rail}>
        <div className={styles.railHeader}>
          <Layers size={16} />
          <span>Workspace</span>
        </div>

        {creatingWs ? (
          <div className={styles.wsCreateRow}>
            <input
              className={styles.input}
              autoFocus
              placeholder="Workspace name"
              value={newWsName}
              onChange={e => setNewWsName(e.target.value)}
              onKeyDown={e => { if (e.key === 'Enter') handleCreateWorkspace(); if (e.key === 'Escape') setCreatingWs(false) }}
            />
            <button className={styles.addBtn} onClick={handleCreateWorkspace} disabled={!newWsName.trim()}><Plus size={14} /></button>
          </div>
        ) : (
          <div className={styles.wsSwitchRow}>
            <select
              className={styles.wsSelect}
              value={activeWorkspaceId ?? ''}
              onChange={e => setActiveWorkspaceId(e.target.value || null)}
            >
              {workspaces.length === 0 && <option value="">No workspaces</option>}
              {workspaces.map(w => (
                <option key={w.id} value={w.id}>{w.name}{w._count ? ` (${w._count.programs})` : ''}</option>
              ))}
            </select>
            <button className={styles.addBtn} title="New workspace" onClick={() => setCreatingWs(true)}><Plus size={14} /></button>
          </div>
        )}

        <div className={styles.railLabel}>Programs</div>
        <ul className={styles.programList}>
          {programs.length === 0 && (
            <li className={styles.emptyRail}>
              No programs here. <Link href="/programs" className={styles.inlineLink}>Create one →</Link>
            </li>
          )}
          {programs.map(p => (
            <li key={p.id}>
              <button
                className={`${styles.programBtn} ${activeProgramId === p.id ? styles.programBtnActive : ''}`}
                onClick={() => { setActiveProgramId(p.id); setSubSection('scope') }}
              >
                <Radar size={13} />
                <span className={styles.programName}>{p.name}</span>
                <ChevronRight size={13} className={styles.chevron} />
              </button>
            </li>
          ))}
        </ul>
      </aside>

      {/* ── Main panel: the active program's sub-section ── */}
      <main className={styles.main}>
        {!activeProgramId ? (
          <div className={styles.placeholder}>
            <FolderOpen size={28} />
            <p>Pick a program from the left to walk its Scope → Assets → Recon → Findings → Evidence → Reports.</p>
          </div>
        ) : (
          <ProgramSpine
            programId={activeProgramId}
            subSection={subSection}
            onSubSection={setSubSection}
          />
        )}
      </main>
    </div>
  )
}

function ProgramSpine({
  programId, subSection, onSubSection,
}: { programId: string; subSection: SubSection; onSubSection: (s: SubSection) => void }) {
  const { data: program, isLoading } = useProgram(programId)
  const updateProgram = useUpdateProgram()
  const toast = useToast()
  const [notes, setNotes] = useState('')

  useEffect(() => { if (program) setNotes(program.notes ?? '') }, [program])

  if (isLoading || !program) return <p className={styles.muted}>Loading program…</p>

  const firstProjectId = program.projects[0]?.id ?? null

  const saveNotes = async () => {
    try {
      await updateProgram.mutateAsync({ programId, data: { notes } })
      toast.success('Notes saved')
    } catch (e) {
      toast.error(e instanceof Error ? e.message : 'Failed to save notes')
    }
  }

  return (
    <div className={styles.spine}>
      <div className={styles.spineHeader}>
        <h2 className={styles.spineTitle}>{program.name}</h2>
        <Link href={`/programs/${program.id}`} className={styles.editLink}>Edit program →</Link>
      </div>

      <nav className={styles.subTabs}>
        {SUB_SECTIONS.map(s => (
          <button
            key={s.id}
            className={`${styles.subTab} ${subSection === s.id ? styles.subTabActive : ''}`}
            onClick={() => onSubSection(s.id)}
          >
            {s.icon}<span>{s.label}</span>
          </button>
        ))}
      </nav>

      <section className={styles.subPanel}>
        {subSection === 'scope' && (
          <div>
            <h3 className={styles.subSectionTitle}>In scope</h3>
            <pre className={styles.scopeText}>{program.scopeSummary || 'No scope summary set.'}</pre>
            <h3 className={styles.subSectionTitle}>Out of scope</h3>
            <pre className={styles.scopeText}>{program.outOfScope || 'Nothing explicitly out of scope.'}</pre>
          </div>
        )}

        {subSection === 'assets' && (
          <div>
            <h3 className={styles.subSectionTitle}>Assets ({program.assets.length})</h3>
            {program.assets.length === 0 && <p className={styles.muted}>No assets in scope yet.</p>}
            <ul className={styles.assetList}>
              {program.assets.map(a => (
                <li key={a.id} className={`${styles.assetItem} ${a.inScope ? '' : styles.assetOut}`}>
                  <span className={styles.assetType}>{a.type}</span>
                  <span className={styles.assetValue}>{a.value}</span>
                  {a.inScope ? (
                    <span className={styles.inScopeTag}><ShieldCheck size={12} /> in scope</span>
                  ) : (
                    <span className={styles.outScopeTag}><ShieldAlert size={12} /> out of scope — recon blocked</span>
                  )}
                </li>
              ))}
            </ul>
            <p className={styles.scopeNote}>
              <ShieldAlert size={12} /> Out-of-scope assets are flagged here and refused by the RoE hard-guardrail
              at recon time; the platform will not launch scans against them.
            </p>
          </div>
        )}

        {subSection === 'recon' && (
          <ContextCards
            title="Recon targets"
            empty="No recon targets linked to this program yet."
            items={program.projects.map(p => ({
              key: p.id,
              label: p.name,
              sub: p.targetDomain,
              href: `/projects/${p.id}/settings`,
              icon: <Radar size={14} />,
            }))}
            cta={{ label: 'New recon target', href: '/projects/new' }}
          />
        )}

        {subSection === 'findings' && (
          <ContextCards
            title="Findings"
            empty="No findings yet — run recon and let the AI validator triage them."
            items={firstProjectId ? [{
              key: 'cypherfix', label: 'Open CypherFix triage',
              sub: `${program._count?.remediations ?? 0} remediation(s) tracked`,
              href: '/cypherfix', icon: <Search size={14} />,
            }] : []}
            cta={{ label: 'Open CypherFix', href: '/cypherfix' }}
          />
        )}

        {subSection === 'evidence' && (
          <ContextCards
            title="Evidence"
            empty="Evidence is captured per finding during triage."
            items={[{
              key: 'graph', label: 'Open Red Zone graph', sub: 'Screenshots & captured requests live on findings',
              href: '/graph', icon: <Camera size={14} /> }]}
          />
        )}

        {subSection === 'reports' && (
          <ContextCards
            title="Reports"
            empty="No reports generated yet."
            items={[{ key: 'reports', label: 'Open Report Center', sub: 'Generate & export program reports', href: '/reports', icon: <FileText size={14} /> }]}
            cta={{ label: 'Report Center', href: '/reports' }}
          />
        )}

        {subSection === 'notes' && (
          <div>
            <h3 className={styles.subSectionTitle}>Program notes</h3>
            <textarea
              className={styles.notesArea}
              rows={12}
              value={notes}
              onChange={e => setNotes(e.target.value)}
              placeholder="Freeform notes for this program — recon leads, credentials location, ideas to revisit…"
            />
            <button className={styles.saveBtn} onClick={saveNotes} disabled={updateProgram.isPending || notes === program.notes}>
              Save notes
            </button>
          </div>
        )}

        {subSection === 'submissions' && <SubmissionsSection programId={program.id} />}
      </section>
    </div>
  )
}

function ContextCards({
  title, empty, items, cta,
}: {
  title: string
  empty: string
  items: { key: string; label: string; sub: string; href: string; icon: React.ReactNode }[]
  cta?: { label: string; href: string }
}) {
  return (
    <div>
      <div className={styles.submitHeaderRow}>
        <h3 className={styles.subSectionTitle}>{title}</h3>
        {cta && <Link href={cta.href} className={styles.editLink}>{cta.label} →</Link>}
      </div>
      {items.length === 0 && <p className={styles.muted}>{empty}</p>}
      <div className={styles.cardGrid}>
        {items.map(it => (
          <Link key={it.key} href={it.href} className={styles.ctxCard}>
            <span className={styles.ctxIcon}>{it.icon}</span>
            <span className={styles.ctxLabel}>{it.label}</span>
            <span className={styles.ctxSub}>{it.sub}</span>
          </Link>
        ))}
      </div>
    </div>
  )
}
