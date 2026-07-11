'use client'

import { memo } from 'react'
import { ShieldCheck, ShieldQuestion, ShieldAlert, ShieldX } from 'lucide-react'
import { VALIDATOR_STATUS_LABELS, VALIDATOR_STATUS_COLORS, type ValidatorStatus } from '@/lib/cypherfix-types'

const VALIDATOR_ICONS: Record<ValidatorStatus, typeof ShieldCheck> = {
  confirmed: ShieldCheck,
  likely: ShieldAlert,
  needs_manual_review: ShieldQuestion,
  ignored: ShieldX,
}

interface ValidatorBadgeProps {
  status: ValidatorStatus
  confidenceScore?: number | null
}

// AI validator status badge — separate from StatusBadge (fix workflow state).
// This answers "how sure is the AI this is a real true positive", not
// "where is the fix at". confidenceScore, when present, is appended so
// operators can compare two "needs_manual_review" findings at a glance.
export const ValidatorBadge = memo(function ValidatorBadge({ status, confidenceScore }: ValidatorBadgeProps) {
  const color = VALIDATOR_STATUS_COLORS[status] || VALIDATOR_STATUS_COLORS.needs_manual_review
  const Icon = VALIDATOR_ICONS[status] || ShieldQuestion

  return (
    <span
      title={`AI validator: ${VALIDATOR_STATUS_LABELS[status]}`}
      style={{
        display: 'inline-flex',
        alignItems: 'center',
        gap: '4px',
        padding: '2px 8px',
        borderRadius: 'var(--radius-md)',
        fontSize: '11px',
        fontWeight: 500,
        color,
        background: `color-mix(in srgb, ${color} 10%, transparent)`,
      }}
    >
      <Icon size={12} />
      {VALIDATOR_STATUS_LABELS[status]}
      {confidenceScore != null && <>&nbsp;· {Math.round(confidenceScore)}%</>}
    </span>
  )
})
