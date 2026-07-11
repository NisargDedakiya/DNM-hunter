'use client'

import { useMemo, useState } from 'react'
import { Send, Copy, Check } from 'lucide-react'
import { useProjectById } from '@/hooks/useProjects'
import { formatForPlatform, PLATFORM_LABELS, type BugBountyPlatform } from '@/lib/report/platformTemplates'
import type { Remediation } from '@/lib/cypherfix-types'
import styles from './RemediationDetail.module.css'

const PLATFORMS: BugBountyPlatform[] = ['hackerone', 'bugcrowd', 'intigriti', 'yeswehack']

interface PlatformSubmissionSectionProps {
  remediation: Remediation
  projectId: string
}

// Generates a ready-to-paste submission body in each bug-bounty platform's
// own dialect (webapp/src/lib/report/platformTemplates.ts) so a hunter
// doesn't have to reformat a finding by hand before submitting it.
export function PlatformSubmissionSection({ remediation, projectId }: PlatformSubmissionSectionProps) {
  const { data: project } = useProjectById(projectId || null)
  const [platform, setPlatform] = useState<BugBountyPlatform>('hackerone')
  const [copied, setCopied] = useState(false)

  const targetName = project?.targetDomain || project?.name || 'the target'

  const text = useMemo(
    () => formatForPlatform(platform, remediation, { targetName }),
    [platform, remediation, targetName]
  )

  const handleCopy = async () => {
    await navigator.clipboard.writeText(text)
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }

  return (
    <div className={styles.section}>
      <h4 className={styles.sectionTitle}>
        <Send size={14} />
        Platform Submission Text
      </h4>

      <div className={styles.metaRow}>
        <span className={styles.metaLabel}>Format for:</span>
        <select className={styles.metaValue} value={platform} onChange={e => setPlatform(e.target.value as BugBountyPlatform)}>
          {PLATFORMS.map(p => (
            <option key={p} value={p}>{PLATFORM_LABELS[p]}</option>
          ))}
        </select>
        <button className={styles.evidenceUploadBtn} onClick={handleCopy}>
          {copied ? <Check size={12} /> : <Copy size={12} />}
          {copied ? 'Copied' : 'Copy to clipboard'}
        </button>
      </div>

      <pre className={styles.evidenceBlock}>{text}</pre>
    </div>
  )
}
