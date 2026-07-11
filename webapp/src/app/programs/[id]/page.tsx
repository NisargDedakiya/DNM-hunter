'use client'

import { useState, useEffect } from 'react'
import { useParams, useRouter } from 'next/navigation'
import Link from 'next/link'
import { ArrowLeft, Plus, Trash2, Target as TargetIcon, KeyRound, Compass } from 'lucide-react'
import { useProgram, useUpdateProgram, useCreateAsset, useDeleteAsset, PLATFORMS, ASSET_TYPES } from '@/hooks/usePrograms'
import { useAlertModal, useToast } from '@/components/ui'
import { ProgramMemoryPanel } from './ProgramMemoryPanel'
import styles from './page.module.css'

function assetTypeLabel(value: string): string {
  return ASSET_TYPES.find(a => a.value === value)?.label ?? value
}

export default function ProgramDetailPage() {
  const params = useParams()
  const router = useRouter()
  const programId = typeof params.id === 'string' ? params.id : null
  const { data: program, isLoading } = useProgram(programId)
  const updateMutation = useUpdateProgram()
  const createAssetMutation = useCreateAsset()
  const deleteAssetMutation = useDeleteAsset()
  const { dangerConfirm } = useAlertModal()
  const toast = useToast()

  const [form, setForm] = useState({
    name: '', platform: 'manual', status: 'active',
    scopeSummary: '', outOfScope: '', rateLimits: '', credentialNotes: '', notes: '',
    rewardMin: '', rewardMax: '', rewardCurrency: 'USD',
  })
  const [newAssetType, setNewAssetType] = useState('domain')
  const [newAssetValue, setNewAssetValue] = useState('')

  useEffect(() => {
    if (!program) return
    setForm({
      name: program.name,
      platform: program.platform,
      status: program.status,
      scopeSummary: program.scopeSummary,
      outOfScope: program.outOfScope,
      rateLimits: program.rateLimits,
      credentialNotes: program.credentialNotes,
      notes: program.notes,
      rewardMin: program.rewardMin != null ? String(program.rewardMin) : '',
      rewardMax: program.rewardMax != null ? String(program.rewardMax) : '',
      rewardCurrency: program.rewardCurrency,
    })
  }, [program])

  if (!programId) return null

  const handleSave = async () => {
    try {
      await updateMutation.mutateAsync({
        programId,
        data: {
          name: form.name,
          platform: form.platform,
          status: form.status,
          scopeSummary: form.scopeSummary,
          outOfScope: form.outOfScope,
          rateLimits: form.rateLimits,
          credentialNotes: form.credentialNotes,
          notes: form.notes,
          rewardMin: form.rewardMin ? parseFloat(form.rewardMin) : null,
          rewardMax: form.rewardMax ? parseFloat(form.rewardMax) : null,
          rewardCurrency: form.rewardCurrency,
        },
      })
      toast.success('Program saved')
    } catch (error) {
      toast.error(error instanceof Error ? error.message : 'Failed to save program')
    }
  }

  const handleAddAsset = async () => {
    if (!newAssetValue.trim()) return
    try {
      await createAssetMutation.mutateAsync({ programId, data: { type: newAssetType, value: newAssetValue.trim() } })
      setNewAssetValue('')
      toast.success('Asset added to scope')
    } catch (error) {
      toast.error(error instanceof Error ? error.message : 'Failed to add asset')
    }
  }

  const handleDeleteAsset = async (assetId: string, value: string) => {
    if (await dangerConfirm(`Remove "${value}" from scope?`)) {
      await deleteAssetMutation.mutateAsync({ programId, assetId })
      toast.success('Asset removed')
    }
  }

  if (isLoading || !program) {
    return <div className={styles.page}><p className={styles.emptyState}>Loading program…</p></div>
  }

  return (
    <div className={styles.page}>
      <div className={styles.header}>
        <button className={styles.backButton} onClick={() => router.push('/programs')}>
          <ArrowLeft size={14} /> Programs
        </button>
        <div className={styles.headerActions}>
          <Link href={`/programs/${programId}/wizard`} className={styles.authManagerLink}>
            <Compass size={14} /> Manual Hunt Wizard
          </Link>
          <Link href={`/programs/${programId}/auth`} className={styles.authManagerLink}>
            <KeyRound size={14} /> Auth Manager
          </Link>
        </div>
      </div>

      <div className={styles.grid}>
        <section className={styles.panel}>
          <h2 className={styles.panelTitle}>Program details</h2>
          <label className={styles.label}>
            Name
            <input className={styles.input} value={form.name} onChange={e => setForm({ ...form, name: e.target.value })} />
          </label>
          <div className={styles.row}>
            <label className={styles.label}>
              Platform
              <select className={styles.input} value={form.platform} onChange={e => setForm({ ...form, platform: e.target.value })}>
                {PLATFORMS.map(p => <option key={p.value} value={p.value}>{p.label}</option>)}
              </select>
            </label>
            <label className={styles.label}>
              Status
              <select className={styles.input} value={form.status} onChange={e => setForm({ ...form, status: e.target.value })}>
                <option value="active">Active</option>
                <option value="paused">Paused</option>
                <option value="completed">Completed</option>
                <option value="archived">Archived</option>
              </select>
            </label>
          </div>
          <div className={styles.row}>
            <label className={styles.label}>
              Reward min ({form.rewardCurrency})
              <input className={styles.input} type="number" value={form.rewardMin} onChange={e => setForm({ ...form, rewardMin: e.target.value })} />
            </label>
            <label className={styles.label}>
              Reward max ({form.rewardCurrency})
              <input className={styles.input} type="number" value={form.rewardMax} onChange={e => setForm({ ...form, rewardMax: e.target.value })} />
            </label>
          </div>
          <label className={styles.label}>
            Scope summary
            <textarea className={styles.textarea} rows={3} value={form.scopeSummary} onChange={e => setForm({ ...form, scopeSummary: e.target.value })} />
          </label>
          <label className={styles.label}>
            Out of scope
            <textarea className={styles.textarea} rows={3} value={form.outOfScope} onChange={e => setForm({ ...form, outOfScope: e.target.value })} />
          </label>
          <label className={styles.label}>
            Rate limits
            <textarea className={styles.textarea} rows={2} value={form.rateLimits} onChange={e => setForm({ ...form, rateLimits: e.target.value })} />
          </label>
          <label className={styles.label}>
            Credential notes
            <textarea className={styles.textarea} rows={2} value={form.credentialNotes} onChange={e => setForm({ ...form, credentialNotes: e.target.value })} placeholder="Test account handles, roles, where creds are stored — full credential vault lands in a later phase" />
          </label>
          <label className={styles.label}>
            Notes
            <textarea className={styles.textarea} rows={3} value={form.notes} onChange={e => setForm({ ...form, notes: e.target.value })} />
          </label>
          <button className={styles.saveButton} onClick={handleSave} disabled={updateMutation.isPending}>
            Save changes
          </button>
        </section>

        <div className={styles.sideCol}>
          <section className={styles.panel}>
            <h2 className={styles.panelTitle}>Scope ({program.assets.length})</h2>
            <div className={styles.assetForm}>
              <select className={styles.inputSmall} value={newAssetType} onChange={e => setNewAssetType(e.target.value)}>
                {ASSET_TYPES.map(t => <option key={t.value} value={t.value}>{t.label}</option>)}
              </select>
              <input
                className={styles.inputSmall}
                value={newAssetValue}
                onChange={e => setNewAssetValue(e.target.value)}
                placeholder="e.g. *.acme.example"
                onKeyDown={e => e.key === 'Enter' && handleAddAsset()}
              />
              <button className={styles.addButton} onClick={handleAddAsset} disabled={!newAssetValue.trim()}>
                <Plus size={14} />
              </button>
            </div>
            {program.assets.length === 0 && <p className={styles.emptyState}>No scope entries yet.</p>}
            <ul className={styles.assetList}>
              {program.assets.map(asset => (
                <li key={asset.id} className={styles.assetItem}>
                  <span className={styles.assetType}>{assetTypeLabel(asset.type)}</span>
                  <span className={styles.assetValue}>{asset.value}</span>
                  <button
                    className={styles.assetDelete}
                    onClick={() => handleDeleteAsset(asset.id, asset.value)}
                    aria-label={`Remove ${asset.value}`}
                  >
                    <Trash2 size={13} />
                  </button>
                </li>
              ))}
            </ul>
          </section>

          <section className={styles.panel}>
            <h2 className={styles.panelTitle}>Targets ({program.projects.length})</h2>
            {program.projects.length === 0 && <p className={styles.emptyState}>No recon targets linked yet.</p>}
            <ul className={styles.assetList}>
              {program.projects.map(p => (
                <li key={p.id} className={styles.assetItem}>
                  <Link href={`/projects/${p.id}/settings`} className={styles.targetLink}>
                    <TargetIcon size={12} />
                    <span className={styles.assetValue}>{p.name}</span>
                  </Link>
                </li>
              ))}
            </ul>
          </section>

          <ProgramMemoryPanel programId={programId} />
        </div>
      </div>
    </div>
  )
}
