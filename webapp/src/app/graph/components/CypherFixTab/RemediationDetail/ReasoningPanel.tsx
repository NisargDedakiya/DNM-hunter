'use client'

import { memo } from 'react'
import { Brain, Wrench, Crosshair, Target, ShieldAlert, Gauge } from 'lucide-react'
import { useReasoning } from '@/hooks/useReasoning'
import type { Remediation } from '@/lib/cypherfix-types'
import styles from './RemediationDetail.module.css'

interface ReasoningPanelProps {
  remediation: Remediation
}

interface QARowProps {
  icon: React.ReactNode
  question: string
  children: React.ReactNode
}

function QARow({ icon, question, children }: QARowProps) {
  return (
    <div style={{ display: 'flex', gap: 'var(--space-2)', alignItems: 'flex-start' }}>
      <span style={{ flexShrink: 0, color: 'var(--text-tertiary)', marginTop: 2 }}>{icon}</span>
      <div style={{ flex: 1, minWidth: 0 }}>
        <div style={{ fontSize: 'var(--text-xs)', fontWeight: 600, color: 'var(--text-secondary)' }}>{question}</div>
        <div className={styles.solutionText} style={{ marginTop: 2 }}>{children}</div>
      </div>
    </div>
  )
}

// AI Reasoning panel: answers "why this tool / why this payload / why this
// endpoint / why this finding / why this severity" in one place. The first
// three come from the Neo4j ChainStep(s) that produced this remediation's
// source finding(s) (Phase 16, see api/remediations/[id]/reasoning); the
// last two re-present the same AI-validator fields ValidatorSection already
// shows, in the "why" narrative framing the spec asks for — same data,
// not a duplicate source of truth.
export const ReasoningPanel = memo(function ReasoningPanel({ remediation }: ReasoningPanelProps) {
  const { available, steps, isLoading } = useReasoning(remediation.id)

  return (
    <div className={styles.section}>
      <h4 className={styles.sectionTitle}>
        <Brain size={14} />
        AI Reasoning
      </h4>

      <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-3)' }}>
        <QARow icon={<ShieldAlert size={13} />} question="Why this finding?">
          {remediation.businessImpact || remediation.description || 'No explicit reasoning recorded for this finding.'}
        </QARow>

        <QARow icon={<Gauge size={13} />} question="Why this severity?">
          {remediation.severity.charAt(0).toUpperCase() + remediation.severity.slice(1)}
          {remediation.likelihood && ` — an attacker with this exposure has ${remediation.likelihood} likelihood of finding and exploiting it`}
          {remediation.confidenceScore != null && ` (${Math.round(remediation.confidenceScore)}% confidence this is a true positive)`}.
        </QARow>

        {isLoading && (
          <p className={styles.evidenceEmpty}>Loading agent reasoning…</p>
        )}

        {!isLoading && !available && (
          <p className={styles.evidenceEmpty}>
            No tool/payload/endpoint provenance available — this finding wasn&apos;t derived from a live attack-chain session
            (e.g. it came from a DAST/CVE correlation), so there&apos;s no agent tool-choice to explain.
          </p>
        )}

        {!isLoading && available && steps.map((step, i) => (
          <div key={`${step.findingId}-${i}`} className={styles.evidenceCard} style={{ flexDirection: 'column', alignItems: 'stretch', gap: 'var(--space-2)' }}>
            {step.toolName && (
              <QARow icon={<Wrench size={13} />} question="Why this tool?">
                <strong>{step.toolName}</strong>{step.reasoning ? ` — ${step.reasoning}` : ''}
              </QARow>
            )}
            {(step.toolArgsSummary || step.payload) && (
              <QARow icon={<Crosshair size={13} />} question="Why this payload?">
                <code style={{ fontSize: '0.9em' }}>{step.payload || step.toolArgsSummary}</code>
                {step.thought ? ` — ${step.thought}` : ''}
              </QARow>
            )}
            {(step.targetIp || step.targetPort || step.attackType) && (
              <QARow icon={<Target size={13} />} question="Why this endpoint?">
                {[
                  step.targetIp,
                  step.targetPort ? `:${step.targetPort}` : null,
                  step.attackType ? `(${step.attackType})` : null,
                ].filter(Boolean).join(' ')}
                {step.outputAnalysis ? ` — ${step.outputAnalysis}` : ''}
              </QARow>
            )}
          </div>
        ))}
      </div>
    </div>
  )
})
