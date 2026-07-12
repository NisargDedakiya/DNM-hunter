'use client'

import { useState } from 'react'
import { Plus, Trash2, DollarSign } from 'lucide-react'
import {
  useSubmissions, useCreateSubmission, useUpdateSubmission, useDeleteSubmission,
  SUBMISSION_STATUSES, SUBMISSION_SEVERITIES, type Submission,
} from '@/hooks/useSubmissions'
import { useAlertModal, useToast } from '@/components/ui'
import styles from './workspace.module.css'

const STATUS_CLASS: Record<Submission['status'], string> = {
  draft: styles.pillDraft,
  submitted: styles.pillSubmitted,
  triaged: styles.pillTriaged,
  accepted: styles.pillAccepted,
  duplicate: styles.pillDuplicate,
  rejected: styles.pillRejected,
  paid: styles.pillPaid,
}

export function SubmissionsSection({ programId }: { programId: string }) {
  const { data: submissions = [], isLoading } = useSubmissions(programId)
  const createMut = useCreateSubmission(programId)
  const updateMut = useUpdateSubmission(programId)
  const deleteMut = useDeleteSubmission(programId)
  const { dangerConfirm } = useAlertModal()
  const toast = useToast()

  const [title, setTitle] = useState('')
  const [severity, setSeverity] = useState<Submission['severity']>('medium')

  const totalPaid = submissions
    .filter(s => s.status === 'paid')
    .reduce((sum, s) => sum + (s.bounty ?? 0), 0)

  const handleAdd = async () => {
    if (!title.trim()) return
    try {
      await createMut.mutateAsync({ title: title.trim(), severity })
      setTitle('')
      setSeverity('medium')
      toast.success('Submission added')
    } catch (e) {
      toast.error(e instanceof Error ? e.message : 'Failed to add submission')
    }
  }

  const handleStatus = async (id: string, status: Submission['status']) => {
    try {
      await updateMut.mutateAsync({ id, status })
    } catch (e) {
      toast.error(e instanceof Error ? e.message : 'Failed to update submission')
    }
  }

  const handleBounty = async (id: string, raw: string) => {
    const bounty = raw.trim() === '' ? null : Number(raw)
    if (bounty !== null && Number.isNaN(bounty)) return
    try {
      await updateMut.mutateAsync({ id, bounty })
    } catch (e) {
      toast.error(e instanceof Error ? e.message : 'Failed to update bounty')
    }
  }

  const handleDelete = async (id: string, t: string) => {
    if (await dangerConfirm(`Delete submission "${t}"?`)) {
      await deleteMut.mutateAsync(id)
      toast.success('Submission deleted')
    }
  }

  return (
    <div>
      <div className={styles.submitHeaderRow}>
        <h3 className={styles.subSectionTitle}>Submissions ({submissions.length})</h3>
        {totalPaid > 0 && (
          <span className={styles.bountyTotal}>
            <DollarSign size={13} /> {totalPaid.toLocaleString()} earned
          </span>
        )}
      </div>

      <div className={styles.submitAddRow}>
        <input
          className={styles.input}
          placeholder="Submission title (e.g. IDOR on /api/v2/export)"
          value={title}
          onChange={e => setTitle(e.target.value)}
          onKeyDown={e => e.key === 'Enter' && handleAdd()}
        />
        <select className={styles.inputSmall} value={severity} onChange={e => setSeverity(e.target.value as Submission['severity'])}>
          {SUBMISSION_SEVERITIES.map(s => <option key={s} value={s}>{s}</option>)}
        </select>
        <button className={styles.addBtn} onClick={handleAdd} disabled={!title.trim() || createMut.isPending}>
          <Plus size={14} />
        </button>
      </div>

      {isLoading && <p className={styles.muted}>Loading submissions…</p>}
      {!isLoading && submissions.length === 0 && (
        <p className={styles.muted}>No submissions logged yet. Track a report you sent to the program here.</p>
      )}

      <ul className={styles.submitList}>
        {submissions.map(s => (
          <li key={s.id} className={styles.submitItem}>
            <div className={styles.submitMain}>
              <span className={styles.submitTitle}>{s.title}</span>
              <span className={styles.submitMeta}>{s.severity}</span>
            </div>
            <div className={styles.submitControls}>
              <select
                className={`${styles.statusPill} ${STATUS_CLASS[s.status]}`}
                value={s.status}
                onChange={e => handleStatus(s.id, e.target.value as Submission['status'])}
              >
                {SUBMISSION_STATUSES.map(st => <option key={st.value} value={st.value}>{st.label}</option>)}
              </select>
              <input
                className={styles.bountyInput}
                type="number"
                placeholder="bounty"
                defaultValue={s.bounty ?? ''}
                onBlur={e => handleBounty(s.id, e.target.value)}
              />
              <button className={styles.iconBtn} onClick={() => handleDelete(s.id, s.title)} aria-label={`Delete ${s.title}`}>
                <Trash2 size={13} />
              </button>
            </div>
          </li>
        ))}
      </ul>
    </div>
  )
}
