'use client'

import { useState } from 'react'
import { ChevronDown, Cloud } from 'lucide-react'
import { Toggle, WikiInfoButton } from '@/components/ui'
import type { Project } from '@prisma/client'
import styles from '../ProjectForm.module.css'

type FormData = Omit<Project, 'id' | 'userId' | 'createdAt' | 'updatedAt' | 'user'>

interface CloudReconSectionProps {
  data: FormData
  updateField: <K extends keyof FormData>(field: K, value: FormData[K]) => void
}

const PROVIDERS: { id: string; label: string }[] = [
  { id: 'aws_s3', label: 'AWS S3' },
  { id: 'gcs', label: 'Google Cloud Storage' },
  { id: 'azure_blob', label: 'Azure Blob Storage' },
]

export function CloudReconSection({ data, updateField }: CloudReconSectionProps) {
  const [isOpen, setIsOpen] = useState(false)
  const selectedProviders = new Set((data.cloudReconProviders || '').split(',').map(p => p.trim()).filter(Boolean))

  const toggleProvider = (id: string) => {
    const next = new Set(selectedProviders)
    if (next.has(id)) next.delete(id)
    else next.add(id)
    updateField('cloudReconProviders', Array.from(next).join(','))
  }

  return (
    <div className={styles.section}>
      <div className={styles.sectionHeader} onClick={() => setIsOpen(!isOpen)}>
        <h2 className={styles.sectionTitle}>
          <Cloud size={16} />
          Cloud Storage Bucket Enumeration
          <WikiInfoButton target="CloudRecon" />
          <span className={styles.badgePassive}>Passive</span>
        </h2>
        <ChevronDown size={16} className={`${styles.sectionIcon} ${isOpen ? styles.sectionIconOpen : ''}`} />
      </div>

      {isOpen && (
        <div className={styles.sectionContent}>
          <p className={styles.sectionDescription}>
            Generates candidate bucket/container names from seed words and probes AWS S3, Google Cloud
            Storage, and Azure Blob Storage with unauthenticated, read-only requests to detect publicly
            listable or readable storage.
          </p>

          <div className={styles.toggleRow}>
            <div>
              <span className={styles.toggleLabel}>Enable Cloud Bucket Enumeration</span>
              <p className={styles.toggleDescription}>Only reads what an anonymous internet user could already read — no credentials used</p>
            </div>
            <Toggle
              checked={data.cloudReconEnabled}
              onChange={(checked) => updateField('cloudReconEnabled', checked)}
            />
          </div>

          <div className={styles.fieldGroup}>
            <label className={styles.fieldLabel}>Seed Words</label>
            <input
              type="text"
              className="textInput"
              value={data.cloudReconSeeds}
              onChange={(e) => updateField('cloudReconSeeds', e.target.value)}
              placeholder="acme-corp, acme.com, acmeapp"
            />
            <span className={styles.fieldHint}>
              Comma-separated org/product/domain names used to generate bucket name candidates (e.g. acme-backup, acme-prod, cdn-acme).
            </span>
          </div>

          <div className={styles.fieldGroup}>
            <label className={styles.fieldLabel}>Providers</label>
            <div style={{ display: 'flex', gap: '16px', flexWrap: 'wrap' }}>
              {PROVIDERS.map(p => (
                <label key={p.id} style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '13px', cursor: 'pointer' }}>
                  <input type="checkbox" checked={selectedProviders.has(p.id)} onChange={() => toggleProvider(p.id)} />
                  {p.label}
                </label>
              ))}
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
