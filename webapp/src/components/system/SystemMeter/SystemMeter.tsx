'use client'

import { useSystemStats, toGB } from '@/hooks/useSystemStats'
import styles from './SystemMeter.module.css'

function Meter({ label, pct, value, detail }: { label: string; pct: number; value?: string; detail: string }) {
  const clamped = Math.min(100, Math.max(0, pct))
  const level = clamped > 90 ? 'high' : clamped > 70 ? 'mid' : 'low'
  return (
    <div className={styles.meter} title={detail}>
      <span className={styles.label}>{label}</span>
      <span className={styles.track}>
        <span className={`${styles.fill} ${styles[level]}`} style={{ width: `${clamped}%` }} />
      </span>
      <span className={styles.pct}>{Math.round(clamped)}%</span>
      {value && <span className={styles.value}>{value}</span>}
    </div>
  )
}

/**
 * htop-style RAM + CPU meters for the bottom-right of the footer (Part 5).
 * The RAM number shown is FREE ram (available), consistent with the bar % so the
 * two agree. The governor's separate "room for a new scan" (remaining_for_new,
 * which subtracts memory reserved by running scans) is in the tooltip.
 */
export function SystemMeter() {
  const { data } = useSystemStats()
  if (!data?.mem) return null

  const m = data.mem
  const total = m.host_total || 1
  const used = total - m.available
  const ramPct = (100 * used) / total
  const cpuPct = data.cpu?.percent ?? 0

  const ramTooltip = [
    `${toGB(m.available)} GB free of ${toGB(total)} GB (${Math.round(ramPct)}% used)`,
    `${toGB(m.remaining_for_new)} GB available for a new scan` +
      (m.active_scans ? ` (${m.active_scans} scan${m.active_scans === 1 ? '' : 's'} reserving ${toGB(m.committed)} GB)` : ''),
  ].join('\n')

  return (
    <div className={styles.wrap}>
      <Meter label="RAM" pct={ramPct} value={`${toGB(m.available)} GB free`} detail={ramTooltip} />
      <Meter label="CPU" pct={cpuPct} detail={`${Math.round(cpuPct)}% of ${data.cpu?.cores ?? '?'} cores`} />
    </div>
  )
}
