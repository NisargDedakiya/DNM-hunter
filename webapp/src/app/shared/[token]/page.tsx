'use client'

import { use, useEffect, useState } from 'react'
import { Loader2, ShieldCheck, Download } from 'lucide-react'
import styles from '@/components/scan/Shared.module.css'

interface Finding {
  id: string; scanner: string; ruleId: string; title: string; severity: string
  file: string; line: number | null; detail: string; vrt: string; cwe: string; cvss: number
}
interface Shared {
  target: string; scanType: string; status: string; total: number
  bySeverity: Record<string, number>; maxCvss: number; createdAt: string; findings: Finding[]
}

const SEV = ['critical', 'high', 'medium', 'low', 'info']
const SEV_COLOR: Record<string, string> = { critical: '#b3123b', high: '#d1471c', medium: '#c08a00', low: '#2b6cb0', info: '#5a6270' }

export default function SharedReportPage({ params }: { params: Promise<{ token: string }> }) {
  const { token } = use(params)
  const [data, setData] = useState<Shared | null>(null)
  const [state, setState] = useState<'loading' | 'ok' | 'error'>('loading')

  useEffect(() => {
    fetch(`/api/scan/shared/${token}`)
      .then((r) => (r.ok ? r.json() : Promise.reject()))
      .then((d) => { setData(d); setState('ok') })
      .catch(() => setState('error'))
  }, [token])

  if (state === 'loading') return <div className={styles.center}><Loader2 className="spin" /> Loading report…</div>
  if (state === 'error' || !data) return <div className={styles.center}>This report link is not valid or was revoked.</div>

  const highest = SEV.find((s) => (data.bySeverity?.[s] ?? 0) > 0) ?? 'none'

  return (
    <div className={styles.page}>
      <div className={styles.brand}><ShieldCheck size={16} /> NisargHunter AI — Security Report</div>
      <h1 className={styles.h1}>Security Assessment</h1>
      <p className={styles.sub}>
        Target <strong>{data.target}</strong> · {new Date(data.createdAt).toLocaleDateString()} ·
        {' '}{data.total} finding(s), highest severity <strong>{highest}</strong> (max CVSS {data.maxCvss})
      </p>

      <div className={styles.chips}>
        {SEV.filter((s) => (data.bySeverity?.[s] ?? 0) > 0).map((s) => (
          <span key={s} className={styles.chip} style={{ ['--c' as string]: SEV_COLOR[s] }}>{s}: {data.bySeverity[s]}</span>
        ))}
      </div>

      <div className={styles.downloads}>
        <a className={`${styles.dl} ${styles.dlPrimary}`} href={`/api/scan/shared/${token}/report?format=html`} target="_blank" rel="noopener noreferrer"><Download size={14} /> Full HTML report</a>
        <a className={styles.dl} href={`/api/scan/shared/${token}/report?format=md`}><Download size={14} /> Markdown</a>
        <a className={styles.dl} href={`/api/scan/shared/${token}/report?format=sarif`}><Download size={14} /> SARIF</a>
      </div>

      <table className={styles.table}>
        <thead><tr><th>Severity</th><th className={styles.num}>CVSS</th><th>Finding</th><th>Location</th><th>VRT</th></tr></thead>
        <tbody>
          {data.findings.map((f) => (
            <tr key={f.id}>
              <td><span className={`${styles.sev} ${styles['sev' + f.severity as keyof typeof styles]}`}>{f.severity}</span></td>
              <td className={styles.num}>{f.cvss}</td>
              <td>{f.title}<div className={styles.detail}>{f.detail}</div></td>
              <td>{f.file ? <code>{f.file}{f.line ? ':' + f.line : ''}</code> : '—'}</td>
              <td>{f.vrt || '—'}</td>
            </tr>
          ))}
        </tbody>
      </table>

      <div className={styles.cta}>
        <p className={styles.ctaTitle}>Generated with NisargHunter AI</p>
        <p className={styles.ctaText}>Scan your own code, cloud, binaries, smart contracts and live targets — free to start.</p>
        <a className={styles.ctaBtn} href="/pricing">Run your own scan →</a>
      </div>

      <p className={styles.footer}>This is a read-only shared report. Findings are automated and should be manually verified.</p>
    </div>
  )
}
