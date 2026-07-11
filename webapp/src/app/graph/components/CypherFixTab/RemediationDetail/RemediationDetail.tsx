'use client'

import { ArrowLeft, Trash2, XCircle } from 'lucide-react'
import { SeverityBadge } from '../RemediationDashboard/SeverityBadge'
import { StatusBadge } from '../RemediationDashboard/StatusBadge'
import { ValidatorBadge } from '../RemediationDashboard/ValidatorBadge'
import { RemediationTypeIcon } from '../RemediationDashboard/RemediationTypeIcon'
import { EvidenceSection } from './EvidenceSection'
import { EvidenceGallery } from './EvidenceGallery'
import { SolutionSection } from './SolutionSection'
import { ValidatorSection } from './ValidatorSection'
import { CodeFixButton } from './CodeFixButton'
import { PlatformSubmissionSection } from './PlatformSubmissionSection'
import { CommentsSection } from './CommentsSection'
import type { Remediation, ValidatorStatus } from '@/lib/cypherfix-types'
import styles from './RemediationDetail.module.css'

interface RemediationDetailProps {
  remediation: Remediation
  projectId: string
  userId: string
  onBack: () => void
  onDismiss: (id: string) => void
  onDelete: (id: string) => void
  onRefresh: () => void
  onStartCodeFix: (remediationId: string) => void
  onOverrideValidatorStatus: (id: string, validatorStatus: ValidatorStatus) => void
  missingSettings?: string[]
}

export function RemediationDetail({
  remediation,
  projectId,
  userId,
  onBack,
  onDismiss,
  onDelete,
  onRefresh,
  onStartCodeFix,
  onOverrideValidatorStatus,
  missingSettings = [],
}: RemediationDetailProps) {
  return (
    <div className={styles.detail}>
      {/* Top bar */}
      <div className={styles.topBar}>
        <button className={styles.backBtn} onClick={onBack}>
          <ArrowLeft size={14} />
          Back to Dashboard
        </button>
        <div className={styles.topActions}>
          {remediation.status === 'pending' && (
            <button
              className={styles.dismissBtn}
              onClick={() => onDismiss(remediation.id)}
            >
              <XCircle size={14} />
              Dismiss
            </button>
          )}
          <button
            className={styles.deleteBtn}
            onClick={() => {
              onDelete(remediation.id)
            }}
          >
            <Trash2 size={14} />
            Delete
          </button>
        </div>
      </div>

      {/* Scrollable content */}
      <div className={styles.content}>
        {/* Header */}
        <div className={styles.detailHeader}>
          <div className={styles.badges}>
            <SeverityBadge severity={remediation.severity} />
            <StatusBadge status={remediation.status} />
            <ValidatorBadge status={remediation.validatorStatus} confidenceScore={remediation.confidenceScore} />
            <RemediationTypeIcon type={remediation.remediationType} />
            {remediation.cvssScore !== null && (
              <span className={styles.cvss}>CVSS {remediation.cvssScore.toFixed(1)}</span>
            )}
          </div>
          <h2 className={styles.detailTitle}>{remediation.title}</h2>
          <p className={styles.description}>{remediation.description}</p>
        </div>

        {/* AI Validator */}
        <ValidatorSection remediation={remediation} onOverrideValidatorStatus={onOverrideValidatorStatus} />

        {/* Evidence */}
        <EvidenceSection remediation={remediation} />
        <EvidenceGallery remediationId={remediation.id} />

        {/* Solution */}
        <SolutionSection remediation={remediation} />

        {/* Bug-bounty platform submission text */}
        <PlatformSubmissionSection remediation={remediation} projectId={projectId} />

        {/* CodeFix */}
        <CodeFixButton remediation={remediation} onStartCodeFix={onStartCodeFix} missingSettings={missingSettings} projectId={projectId} />

        {/* Comments */}
        <CommentsSection remediationId={remediation.id} userId={userId} />
      </div>
    </div>
  )
}
