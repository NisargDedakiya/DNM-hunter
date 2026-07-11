'use client'

import { Brain, RefreshCw } from 'lucide-react'
import { useProgramMemory } from '@/hooks/useProgramMemory'
import styles from './page.module.css'

interface ProgramMemoryPanelProps {
  programId: string
}

export function ProgramMemoryPanel({ programId }: ProgramMemoryPanelProps) {
  const { memory, isLoading, recompute, isRecomputing } = useProgramMemory(programId)

  return (
    <section className={styles.panel}>
      <div className={styles.memoryHeader}>
        <h2 className={styles.panelTitle}>
          <Brain size={14} /> Program Memory
        </h2>
        <button className={styles.memoryRefreshBtn} onClick={() => recompute()} disabled={isRecomputing}>
          <RefreshCw size={12} className={isRecomputing ? styles.spin : ''} />
          {isRecomputing ? 'Refreshing…' : 'Refresh from findings'}
        </button>
      </div>

      {isLoading && <p className={styles.emptyState}>Loading…</p>}

      {!isLoading && !memory?.priorFindingsSummary && (
        <p className={styles.emptyState}>
          No memory yet — this fills in from confirmed findings across every scan of this program,
          and gets fed to the AI at the start of future sessions. Click refresh once you have findings.
        </p>
      )}

      {memory?.priorFindingsSummary && (
        <>
          <p className={styles.memorySummary}>{memory.priorFindingsSummary}</p>

          {memory.knownPaths.length > 0 && (
            <div className={styles.memorySubsection}>
              <h3 className={styles.memorySubtitle}>Known paths ({memory.knownPaths.length})</h3>
              <ul className={styles.assetList}>
                {memory.knownPaths.slice(0, 10).map((p, i) => (
                  <li key={i} className={styles.assetItem}>
                    <span className={styles.assetValue}>{p.path}</span>
                  </li>
                ))}
              </ul>
            </div>
          )}

          {memory.workingPayloads.length > 0 && (
            <div className={styles.memorySubsection}>
              <h3 className={styles.memorySubtitle}>Confirmed from prior scans ({memory.workingPayloads.length})</h3>
              <ul className={styles.assetList}>
                {memory.workingPayloads.slice(0, 8).map((p, i) => (
                  <li key={i} className={styles.assetItem}>
                    <span className={styles.assetType}>{p.category}</span>
                    <span className={styles.assetValue}>{p.workedOn}</span>
                  </li>
                ))}
              </ul>
            </div>
          )}
        </>
      )}
    </section>
  )
}
