'use client'

import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Sparkles, Check, SkipForward, RotateCw, ChevronRight } from 'lucide-react'
import type { ReconPlan, PlanStep, Priority } from '@/lib/reconPlan'
import styles from './workspace.module.css'

interface PlanResponse extends ReconPlan {
  detectedTech: string[]
  assetCount: number
}

const PRIORITY_CLASS: Record<Priority, string> = {
  high: styles.prioHigh,
  medium: styles.prioMedium,
  low: styles.prioLow,
}

async function fetchPlan(programId: string): Promise<PlanResponse> {
  const res = await fetch(`/api/programs/${programId}/plan`)
  if (!res.ok) throw new Error('Failed to build plan')
  return res.json()
}

// Approve-before-execute recon plan (master-plan Phase 3, Priority 2). The user
// reviews each AI-proposed step and approves or skips it; only approved steps
// are staged for execution. This is the single biggest thing that makes the
// platform feel intelligent rather than a tool launcher.
export function ReconPlanPanel({ programId }: { programId: string }) {
  const { data: plan, isLoading, isError, refetch, isFetching } = useQuery({
    queryKey: ['recon-plan', programId],
    queryFn: () => fetchPlan(programId),
  })

  // Per-step decision: undefined = undecided, true = approved, false = skipped.
  const [decisions, setDecisions] = useState<Record<string, boolean>>({})

  const decide = (moduleName: string, approved: boolean) =>
    setDecisions(d => ({ ...d, [moduleName]: approved }))

  const approvedCount = Object.values(decisions).filter(Boolean).length

  if (isLoading) return <p className={styles.muted}>Building recon plan…</p>
  if (isError || !plan) return <p className={styles.muted}>Could not build a plan. Add in-scope assets first.</p>

  return (
    <div>
      <div className={styles.submitHeaderRow}>
        <h3 className={styles.subSectionTitle}><Sparkles size={14} /> AI recon plan</h3>
        <button className={styles.editLink} onClick={() => refetch()} disabled={isFetching}>
          <RotateCw size={12} /> Rebuild
        </button>
      </div>

      <p className={styles.planReasoning}>{plan.reasoning}</p>
      {plan.detectedTech.length > 0 && (
        <div className={styles.techRow}>
          {plan.detectedTech.map(t => <span key={t} className={styles.techChip}>{t}</span>)}
        </div>
      )}

      <ul className={styles.planList}>
        {plan.steps.map((step: PlanStep) => {
          const decision = decisions[step.moduleName]
          return (
            <li
              key={step.moduleName}
              className={`${styles.planStep} ${decision === false ? styles.planStepSkipped : ''} ${decision === true ? styles.planStepApproved : ''}`}
            >
              <div className={styles.planStepMain}>
                <div className={styles.planStepHead}>
                  <span className={`${styles.prioPill} ${PRIORITY_CLASS[step.priority]}`}>{step.priority}</span>
                  <span className={styles.planModule}>{step.displayName}</span>
                </div>
                <p className={styles.planRationale}>{step.rationale}</p>
                <p className={styles.planValue}><ChevronRight size={11} /> {step.estimatedValue}</p>
              </div>
              <div className={styles.planActions}>
                <button
                  className={`${styles.planBtn} ${decision === true ? styles.planBtnOn : ''}`}
                  onClick={() => decide(step.moduleName, true)}
                  aria-label={`Approve ${step.displayName}`}
                >
                  <Check size={14} /> Approve
                </button>
                <button
                  className={`${styles.planBtn} ${decision === false ? styles.planBtnSkip : ''}`}
                  onClick={() => decide(step.moduleName, false)}
                  aria-label={`Skip ${step.displayName}`}
                >
                  <SkipForward size={14} /> Skip
                </button>
              </div>
            </li>
          )
        })}
      </ul>

      <p className={styles.planFooter}>
        {approvedCount} of {plan.steps.length} step(s) approved. Approved steps are staged for the recon
        queue; nothing runs until you launch it from the recon target.
      </p>
    </div>
  )
}
