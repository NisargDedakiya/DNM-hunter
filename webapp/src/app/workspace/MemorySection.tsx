'use client'

import { useState, useEffect } from 'react'
import { Brain, Pin, Trash2, RotateCw, Plus } from 'lucide-react'
import { useProgramMemory, type InterestingEndpoint } from '@/hooks/useProgramMemory'
import { useToast } from '@/components/ui'
import styles from './workspace.module.css'

// The Memory sub-section (master-plan Phase 4). Shows what the AI remembers for
// a program: auto-derived tech surface / known paths / working payloads (read-
// only, recomputed from findings) plus user-authoritative pinned endpoints and
// notes the operator can edit. User edits win over auto-written memory and feed
// straight into the agent's context on the next run.
export function MemorySection({ programId }: { programId: string }) {
  const { memory, isLoading, recompute, isRecomputing, editMemory, isEditing } = useProgramMemory(programId)
  const toast = useToast()

  const [notes, setNotes] = useState('')
  const [newEndpoint, setNewEndpoint] = useState('')
  const [newNote, setNewNote] = useState('')

  useEffect(() => { setNotes(memory?.userNotes ?? '') }, [memory?.userNotes])

  if (isLoading) return <p className={styles.muted}>Loading memory…</p>

  const pinned: InterestingEndpoint[] = memory?.interestingEndpoints ?? []

  const saveNotes = async () => {
    try { await editMemory({ userNotes: notes }); toast.success('Memory notes saved') }
    catch (e) { toast.error(e instanceof Error ? e.message : 'Failed to save') }
  }

  const addPin = async () => {
    if (!newEndpoint.trim()) return
    const next = [...pinned, { endpoint: newEndpoint.trim(), note: newNote.trim(), pinnedAt: new Date().toISOString() }]
    try {
      await editMemory({ interestingEndpoints: next })
      setNewEndpoint(''); setNewNote('')
      toast.success('Endpoint pinned')
    } catch (e) { toast.error(e instanceof Error ? e.message : 'Failed to pin') }
  }

  const removePin = async (endpoint: string) => {
    try { await editMemory({ interestingEndpoints: pinned.filter(p => p.endpoint !== endpoint) }); toast.success('Unpinned') }
    catch (e) { toast.error(e instanceof Error ? e.message : 'Failed to unpin') }
  }

  return (
    <div>
      <div className={styles.submitHeaderRow}>
        <h3 className={styles.subSectionTitle}><Brain size={14} /> What the AI remembers</h3>
        <button className={styles.editLink} onClick={() => recompute()} disabled={isRecomputing}>
          <RotateCw size={12} /> Recompute
        </button>
      </div>

      {!memory && <p className={styles.muted}>No memory yet — it builds up as findings are confirmed. You can still pin endpoints and add notes below.</p>}

      {memory && memory.priorFindingsSummary && (
        <p className={styles.planReasoning}>{memory.priorFindingsSummary}</p>
      )}

      {memory && memory.techStack.length > 0 && (
        <div className={styles.techRow}>
          {memory.techStack.slice(0, 12).map(t => <span key={t.name} className={styles.techChip}>{t.name}</span>)}
        </div>
      )}

      {/* ── User-authoritative: pinned endpoints ── */}
      <h4 className={styles.memSubhead}><Pin size={12} /> Pinned endpoints (authoritative)</h4>
      <div className={styles.submitAddRow}>
        <input className={styles.input} placeholder="/api/v2/export" value={newEndpoint} onChange={e => setNewEndpoint(e.target.value)} />
        <input className={styles.inputSmall} placeholder="why interesting" value={newNote} onChange={e => setNewNote(e.target.value)} onKeyDown={e => e.key === 'Enter' && addPin()} />
        <button className={styles.addBtn} onClick={addPin} disabled={!newEndpoint.trim() || isEditing}><Plus size={14} /></button>
      </div>
      {pinned.length === 0 && <p className={styles.muted}>No pinned endpoints yet.</p>}
      <ul className={styles.assetList}>
        {pinned.map(p => (
          <li key={p.endpoint} className={styles.assetItem}>
            <span className={styles.assetValue}><strong>{p.endpoint}</strong>{p.note ? ` — ${p.note}` : ''}</span>
            <button className={styles.iconBtn} onClick={() => removePin(p.endpoint)} aria-label={`Unpin ${p.endpoint}`}><Trash2 size={13} /></button>
          </li>
        ))}
      </ul>

      {/* ── Auto-derived: known paths & working payloads (read-only) ── */}
      {memory && memory.knownPaths.length > 0 && (
        <>
          <h4 className={styles.memSubhead}>Known paths (auto)</h4>
          <ul className={styles.assetList}>
            {memory.knownPaths.slice(0, 15).map(p => (
              <li key={p.path} className={styles.assetItem}><span className={styles.assetValue}>{p.path}</span></li>
            ))}
          </ul>
        </>
      )}

      {/* ── User note ── */}
      <h4 className={styles.memSubhead}>Memory notes (authoritative)</h4>
      <textarea className={styles.notesArea} rows={5} value={notes} onChange={e => setNotes(e.target.value)}
        placeholder="Anything the AI should carry into the next engagement — a payload that worked, an account to reuse…" />
      <button className={styles.saveBtn} onClick={saveNotes} disabled={isEditing || notes === (memory?.userNotes ?? '')}>Save notes</button>
    </div>
  )
}
