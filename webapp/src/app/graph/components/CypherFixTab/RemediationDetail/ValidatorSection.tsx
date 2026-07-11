'use client'

import { memo } from 'react'
import { ShieldCheck } from 'lucide-react'
import { VALIDATOR_STATUS_LABELS, type Remediation, type ValidatorStatus } from '@/lib/cypherfix-types'
import styles from './RemediationDetail.module.css'

const VALIDATOR_STATUSES: ValidatorStatus[] = ['confirmed', 'likely', 'needs_manual_review', 'ignored']

interface ValidatorSectionProps {
  remediation: Remediation
  onOverrideValidatorStatus: (id: string, validatorStatus: ValidatorStatus) => void
}

// Surfaces the AI validator's self-assessment (Phase 09) — separate from the
// fix-workflow StatusBadge above it — and lets an operator override the
// verdict once they've actually looked at the evidence.
export const ValidatorSection = memo(function ValidatorSection({ remediation, onOverrideValidatorStatus }: ValidatorSectionProps) {
  const hasAssessment = remediation.confidenceScore != null || remediation.falsePositiveScore != null
    || !!remediation.businessImpact || !!remediation.likelihood

  return (
    <div className={styles.section}>
      <h4 className={styles.sectionTitle}>
        <ShieldCheck size={14} />
        AI Validator Assessment
      </h4>

      {hasAssessment ? (
        <>
          {remediation.businessImpact && (
            <div className={styles.solutionText}>{remediation.businessImpact}</div>
          )}
          <div className={styles.metaRow}>
            {remediation.confidenceScore != null && (
              <>
                <span className={styles.metaLabel}>Confidence:</span>
                <span className={styles.metaValue}>{Math.round(remediation.confidenceScore)}%</span>
              </>
            )}
            {remediation.falsePositiveScore != null && (
              <>
                <span className={styles.metaLabel}>False-positive risk:</span>
                <span className={styles.metaValue}>{Math.round(remediation.falsePositiveScore)}%</span>
              </>
            )}
            {remediation.likelihood && (
              <>
                <span className={styles.metaLabel}>Exploit likelihood:</span>
                <span className={styles.metaValue}>{remediation.likelihood}</span>
              </>
            )}
          </div>
        </>
      ) : (
        <div className={styles.solutionText}>No AI assessment recorded for this finding yet.</div>
      )}

      <div className={styles.metaRow}>
        <span className={styles.metaLabel}>Verdict:</span>
        <select
          className={styles.metaValue}
          value={remediation.validatorStatus}
          onChange={e => onOverrideValidatorStatus(remediation.id, e.target.value as ValidatorStatus)}
        >
          {VALIDATOR_STATUSES.map(s => (
            <option key={s} value={s}>{VALIDATOR_STATUS_LABELS[s]}</option>
          ))}
        </select>
      </div>
    </div>
  )
})
