'use client'

import { useState } from 'react'
import Link from 'next/link'
import { Plus, Radar, Target, Bug, Trash2 } from 'lucide-react'
import { useProject } from '@/providers/ProjectProvider'
import { usePrograms, useCreateProgram, useDeleteProgram, PLATFORMS } from '@/hooks/usePrograms'
import { Modal, useAlertModal, useToast } from '@/components/ui'
import styles from './page.module.css'

function platformLabel(value: string): string {
  return PLATFORMS.find(p => p.value === value)?.label ?? value
}

export default function ProgramsPage() {
  const { userId } = useProject()
  const { data: programs, isLoading } = usePrograms(userId)
  const createMutation = useCreateProgram()
  const deleteMutation = useDeleteProgram()
  const { dangerConfirm } = useAlertModal()
  const toast = useToast()

  const [showNew, setShowNew] = useState(false)
  const [name, setName] = useState('')
  const [platform, setPlatform] = useState('manual')

  const handleCreate = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!userId || !name.trim()) return
    try {
      await createMutation.mutateAsync({ userId, name: name.trim(), platform })
      setShowNew(false)
      setName('')
      setPlatform('manual')
      toast.success('Program created')
    } catch (error) {
      toast.error(error instanceof Error ? error.message : 'Failed to create program')
    }
  }

  const handleDelete = async (e: React.MouseEvent, programId: string, programName: string) => {
    e.preventDefault()
    e.stopPropagation()
    if (await dangerConfirm(`Delete program "${programName}"? Its assets are removed too; linked targets and findings are kept.`)) {
      await deleteMutation.mutateAsync(programId)
      toast.success('Program deleted')
    }
  }

  return (
    <div className={styles.page}>
      <div className={styles.header}>
        <div>
          <h1 className={styles.title}>Programs</h1>
          <p className={styles.subtitle}>Bug-bounty engagements: platform, scope, rate limits, rewards, deadlines.</p>
        </div>
        <button className={styles.newButton} onClick={() => setShowNew(true)} disabled={!userId}>
          <Plus size={14} /> New Program
        </button>
      </div>

      {isLoading && <p className={styles.emptyState}>Loading programs…</p>}
      {!isLoading && (!programs || programs.length === 0) && (
        <p className={styles.emptyState}>No programs yet. Create one to start tracking scope, assets and findings.</p>
      )}

      <div className={styles.grid}>
        {programs?.map(program => (
          <Link key={program.id} href={`/programs/${program.id}`} className={styles.card}>
            <div className={styles.cardHeader}>
              <div className={styles.cardIcon}><Radar size={16} /></div>
              <div className={styles.cardHeaderText}>
                <h2 className={styles.cardTitle}>{program.name}</h2>
                <span className={styles.cardPlatform}>{platformLabel(program.platform)}</span>
              </div>
              <span className={`${styles.statusBadge} ${program.status === 'active' ? styles.statusActive : ''}`}>
                {program.status}
              </span>
            </div>
            <div className={styles.cardStats}>
              <span className={styles.cardStat}><Target size={12} /> {program._count.assets} assets</span>
              <span className={styles.cardStat}><Radar size={12} /> {program._count.projects} targets</span>
              <span className={styles.cardStat}><Bug size={12} /> {program._count.remediations} findings</span>
            </div>
            {(program.rewardMin != null || program.rewardMax != null) && (
              <div className={styles.cardReward}>
                {program.rewardCurrency} {program.rewardMin ?? 0}–{program.rewardMax ?? '?'}
              </div>
            )}
            <button
              className={styles.deleteButton}
              onClick={(e) => handleDelete(e, program.id, program.name)}
              title="Delete program"
              aria-label={`Delete program ${program.name}`}
            >
              <Trash2 size={14} />
            </button>
          </Link>
        ))}
      </div>

      <Modal
        isOpen={showNew}
        onClose={() => setShowNew(false)}
        title="New Program"
        footer={
          <>
            <button className={styles.secondaryButton} onClick={() => setShowNew(false)}>Cancel</button>
            <button className={styles.newButton} onClick={handleCreate} disabled={!name.trim() || createMutation.isPending}>
              Create
            </button>
          </>
        }
      >
        <form className={styles.form} onSubmit={handleCreate}>
          <label className={styles.label}>
            Name
            <input
              className={styles.input}
              value={name}
              onChange={e => setName(e.target.value)}
              placeholder="Acme Corp VDP"
              autoFocus
            />
          </label>
          <label className={styles.label}>
            Platform
            <select className={styles.input} value={platform} onChange={e => setPlatform(e.target.value)}>
              {PLATFORMS.map(p => <option key={p.value} value={p.value}>{p.label}</option>)}
            </select>
          </label>
        </form>
      </Modal>
    </div>
  )
}
