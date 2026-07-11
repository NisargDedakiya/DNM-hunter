'use client'

import { useState, useEffect, useCallback, useRef } from 'react'
import { ChevronDown, Smartphone, Upload, Trash2, FileArchive } from 'lucide-react'
import { Toggle, WikiInfoButton } from '@/components/ui'
import type { Project } from '@prisma/client'
import styles from '../ProjectForm.module.css'

type FormData = Omit<Project, 'id' | 'userId' | 'createdAt' | 'updatedAt' | 'user'>

interface UploadedApk {
  name: string
  size: number
  uploaded_at: string
}

interface MobileScanSectionProps {
  data: FormData
  updateField: <K extends keyof FormData>(field: K, value: FormData[K]) => void
  projectId?: string
}

export function MobileScanSection({ data, updateField, projectId }: MobileScanSectionProps) {
  const [isOpen, setIsOpen] = useState(false)
  const [files, setFiles] = useState<UploadedApk[]>([])
  const [isUploading, setIsUploading] = useState(false)
  const [uploadError, setUploadError] = useState<string | null>(null)
  const fileInputRef = useRef<HTMLInputElement>(null)
  const canUpload = !!projectId

  const loadFiles = useCallback(async () => {
    if (!canUpload) return
    try {
      const res = await fetch(`/api/mobile-scan/${projectId}/upload`)
      if (res.ok) setFiles((await res.json()).files || [])
    } catch {
      // non-fatal
    }
  }, [canUpload, projectId])

  useEffect(() => { loadFiles() }, [loadFiles])

  const handleUpload = async (file: File) => {
    if (!projectId) return
    setIsUploading(true)
    setUploadError(null)
    try {
      const formData = new FormData()
      formData.append('file', file)
      const res = await fetch(`/api/mobile-scan/${projectId}/upload`, { method: 'POST', body: formData })
      const body = await res.json()
      if (!res.ok) {
        setUploadError(body.error || 'Upload failed')
      } else {
        await loadFiles()
      }
    } catch {
      setUploadError('Upload failed')
    } finally {
      setIsUploading(false)
      if (fileInputRef.current) fileInputRef.current.value = ''
    }
  }

  const handleDelete = async (filename: string) => {
    if (!projectId) return
    await fetch(`/api/mobile-scan/${projectId}/upload?name=${encodeURIComponent(filename)}`, { method: 'DELETE' })
    await loadFiles()
  }

  return (
    <div className={styles.section}>
      <div className={styles.sectionHeader} onClick={() => setIsOpen(!isOpen)}>
        <h2 className={styles.sectionTitle}>
          <Smartphone size={16} />
          Mobile APK Static Analysis
          <WikiInfoButton target="MobileScan" />
          <span className={styles.badgePassive}>Passive</span>
        </h2>
        <ChevronDown size={16} className={`${styles.sectionIcon} ${isOpen ? styles.sectionIconOpen : ''}`} />
      </div>

      {isOpen && (
        <div className={styles.sectionContent}>
          <p className={styles.sectionDescription}>
            Static analysis of uploaded Android APKs — debuggable/backup-enabled builds, cleartext traffic
            defaults, unprotected exported activities/services/providers, dangerous permission grants, and
            hardcoded secrets embedded in the compiled DEX string pool.
          </p>

          <div className={styles.toggleRow}>
            <div>
              <span className={styles.toggleLabel}>Enable Mobile Scanning</span>
              <p className={styles.toggleDescription}>Analyze every APK uploaded below when the scan runs</p>
            </div>
            <Toggle
              checked={data.mobileScanEnabled}
              onChange={(checked) => updateField('mobileScanEnabled', checked)}
            />
          </div>

          {!canUpload ? (
            <p className={styles.fieldHint}>Save the project first to enable APK uploads.</p>
          ) : (
            <div className={styles.fieldGroup}>
              <label className={styles.fieldLabel}>Upload APKs</label>
              <input
                ref={fileInputRef}
                type="file"
                accept=".apk"
                disabled={isUploading}
                onChange={(e) => e.target.files?.[0] && handleUpload(e.target.files[0])}
                style={{ display: 'none' }}
                id="mobile-scan-apk-input"
              />
              <label htmlFor="mobile-scan-apk-input" className="btn-secondary" style={{ display: 'inline-flex', alignItems: 'center', gap: '6px', cursor: 'pointer', width: 'fit-content' }}>
                <Upload size={14} />
                {isUploading ? 'Uploading…' : 'Choose APK file'}
              </label>
              {uploadError && <p style={{ color: 'var(--error)', fontSize: 'var(--text-xs)', marginTop: '6px' }}>{uploadError}</p>}

              {files.length > 0 && (
                <ul style={{ listStyle: 'none', padding: 0, marginTop: '10px', display: 'flex', flexDirection: 'column', gap: '6px' }}>
                  {files.map(f => (
                    <li key={f.name} style={{ display: 'flex', alignItems: 'center', gap: '8px', fontSize: '13px' }}>
                      <FileArchive size={13} style={{ flexShrink: 0, color: 'var(--text-tertiary)' }} />
                      <span style={{ flex: 1 }}>{f.name}</span>
                      <span style={{ color: 'var(--text-tertiary)', fontSize: '11px' }}>{(f.size / 1024 / 1024).toFixed(1)} MB</span>
                      <button type="button" onClick={() => handleDelete(f.name)} style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--text-tertiary)' }} aria-label={`Delete ${f.name}`}>
                        <Trash2 size={13} />
                      </button>
                    </li>
                  ))}
                </ul>
              )}
            </div>
          )}
        </div>
      )}
    </div>
  )
}
