'use client'

import { useMemo } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Activity, ListOrdered, HeartPulse, Loader2, PauseCircle, RotateCw } from 'lucide-react'
import { useJobs, type Job } from '@/hooks/useJobs'
import styles from './page.module.css'

interface PluginHealth { id: string; health: 'healthy' | 'active' | 'unreachable' | 'unknown'; latencyMs: number | null }

async function fetchHealth(): Promise<{ health: PluginHealth[] }> {
  const res = await fetch('/api/plugins/health')
  return res.json()
}

const STATE_ICON: Partial<Record<Job['status'], React.ReactNode>> = {
  running: <Loader2 size={13} className={styles.spin} />,
  paused: <PauseCircle size={13} />,
  retrying: <RotateCw size={13} />,
}

// Live operations cockpit (master-plan Phase 5, Priority 5): running scans, the
// recon queue with positions, and tool health — all reading REAL data from the
// Phase-2 job lifecycle projection and the plugin health probe.
export function OperationsPanel() {
  const { data: jobs = [], isLoading } = useJobs({ active: true })
  const { data: healthData } = useQuery({ queryKey: ['plugins-health'], queryFn: fetchHealth, refetchInterval: 60000 })

  const running = useMemo(() => jobs.filter(j => j.status === 'running' || j.status === 'paused' || j.status === 'retrying'), [jobs])
  const queued = useMemo(() => jobs.filter(j => j.status === 'queued'), [jobs])
  const health = healthData?.health ?? []
  const healthy = health.filter(h => h.health === 'healthy' || h.health === 'active').length

  return (
    <div className={styles.opsGrid}>
      {/* Running scans */}
      <section className={styles.opsCard}>
        <h3 className={styles.opsTitle}><Activity size={15} /> Running scans</h3>
        {isLoading && <p className={styles.opsMuted}>Loading…</p>}
        {!isLoading && running.length === 0 && <p className={styles.opsMuted}>Nothing running right now.</p>}
        <ul className={styles.opsList}>
          {running.map(j => (
            <li key={j.id} className={styles.opsItem}>
              <span className={styles.opsIcon}>{STATE_ICON[j.status]}</span>
              <span className={styles.opsModule}>{j.moduleName}</span>
              <span className={styles.opsProgress}>{Math.round((j.progress || 0) * 100)}%</span>
            </li>
          ))}
        </ul>
      </section>

      {/* Recon queue */}
      <section className={styles.opsCard}>
        <h3 className={styles.opsTitle}><ListOrdered size={15} /> Recon queue</h3>
        {queued.length === 0 && <p className={styles.opsMuted}>Queue is empty.</p>}
        <ul className={styles.opsList}>
          {queued.map((j, i) => (
            <li key={j.id} className={styles.opsItem}>
              <span className={styles.opsPos}>#{i + 1}</span>
              <span className={styles.opsModule}>{j.moduleName}</span>
            </li>
          ))}
        </ul>
      </section>

      {/* Tool health */}
      <section className={styles.opsCard}>
        <h3 className={styles.opsTitle}><HeartPulse size={15} /> Tool health</h3>
        {health.length === 0 && <p className={styles.opsMuted}>Health data unavailable.</p>}
        {health.length > 0 && (
          <>
            <p className={styles.opsHealthSummary}>{healthy} / {health.length} healthy</p>
            <ul className={styles.opsList}>
              {health.slice(0, 6).map(h => (
                <li key={h.id} className={styles.opsItem}>
                  <span className={`${styles.opsDot} ${h.health === 'unreachable' ? styles.opsDotBad : styles.opsDotOk}`} />
                  <span className={styles.opsModule}>{h.id}</span>
                  {h.latencyMs != null && <span className={styles.opsProgress}>{h.latencyMs}ms</span>}
                </li>
              ))}
            </ul>
          </>
        )}
      </section>
    </div>
  )
}
