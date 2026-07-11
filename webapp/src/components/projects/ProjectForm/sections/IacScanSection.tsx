'use client'

import { useState } from 'react'
import { ChevronDown, FileCode, AlertTriangle } from 'lucide-react'
import { Toggle, WikiInfoButton } from '@/components/ui'
import type { Project } from '@prisma/client'
import styles from '../ProjectForm.module.css'
import Link from 'next/link'

type FormData = Omit<Project, 'id' | 'userId' | 'createdAt' | 'updatedAt' | 'user'>

interface IacScanSectionProps {
  data: FormData
  updateField: <K extends keyof FormData>(field: K, value: FormData[K]) => void
  hasGithubToken?: boolean
}

export function IacScanSection({ data, updateField, hasGithubToken = false }: IacScanSectionProps) {
  const [isOpen, setIsOpen] = useState(false)

  return (
    <div className={styles.section}>
      <div className={styles.sectionHeader} onClick={() => setIsOpen(!isOpen)}>
        <h2 className={styles.sectionTitle}>
          <FileCode size={16} />
          IaC / DevOps Config Scanner
          <WikiInfoButton target="IacScan" />
          <span className={styles.badgePassive}>Passive</span>
        </h2>
        <ChevronDown size={16} className={`${styles.sectionIcon} ${isOpen ? styles.sectionIconOpen : ''}`} />
      </div>

      {isOpen && (
        <div className={styles.sectionContent}>
          <p className={styles.sectionDescription}>
            Offline static analysis of Dockerfiles, docker-compose, Kubernetes manifests, GitHub Actions
            workflows, and Terraform in the target repositories — privileged containers, exposed secrets,
            open security groups, pull_request_target script injection, and more.
          </p>

          <div className={styles.toggleRow}>
            <div>
              <span className={styles.toggleLabel}>Enable IaC Scanning</span>
              <p className={styles.toggleDescription}>Run the misconfiguration scanner against the repositories below</p>
            </div>
            <Toggle
              checked={data.iacScanEnabled}
              onChange={(checked) => updateField('iacScanEnabled', checked)}
            />
          </div>

          {!hasGithubToken && (
            <div style={{
              display: 'flex',
              alignItems: 'center',
              gap: '8px',
              padding: '10px 14px',
              background: 'rgba(245, 158, 11, 0.1)',
              border: '1px solid rgba(245, 158, 11, 0.3)',
              borderRadius: '8px',
              marginBottom: '12px',
            }}>
              <AlertTriangle size={16} style={{ color: '#f59e0b', flexShrink: 0 }} />
              <span style={{ fontSize: '13px', color: 'var(--text-secondary)' }}>
                GitHub Access Token required.{' '}
                <Link href="/settings" style={{ color: 'var(--accent-primary)', fontWeight: 500 }}>
                  Configure it in Global Settings
                </Link>
              </span>
            </div>
          )}

          <div className={styles.fieldGroup}>
            <label className={styles.fieldLabel}>GitHub Organization</label>
            <input
              type="text"
              className="textInput"
              value={data.iacScanGithubOrg}
              onChange={(e) => updateField('iacScanGithubOrg', e.target.value)}
              placeholder="organization-name"
              disabled={!hasGithubToken}
            />
            <span className={styles.fieldHint}>Scans every non-archived repo in the org. Ignored if repos are set below.</span>
          </div>

          <div className={styles.fieldGroup}>
            <label className={styles.fieldLabel}>GitHub Repositories</label>
            <input
              type="text"
              className="textInput"
              value={data.iacScanGithubRepos}
              onChange={(e) => updateField('iacScanGithubRepos', e.target.value)}
              placeholder="org/repo1, org/repo2"
              disabled={!hasGithubToken}
            />
            <span className={styles.fieldHint}>Comma-separated. Takes priority over the org above.</span>
          </div>
        </div>
      )}
    </div>
  )
}
