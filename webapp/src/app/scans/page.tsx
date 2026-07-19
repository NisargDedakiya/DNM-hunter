'use client'

import { useCallback, useEffect, useState } from 'react'
import Link from 'next/link'
import { Loader2, Play, Download, Lock, ArrowLeft, Trash2 } from 'lucide-react'
import styles from '@/components/scan/Scans.module.css'

type ScanType = 'url' | 'repo'
interface ScanRow {
  id: string; target: string; scanType: string; status: string; total: number
  bySeverity: Record<string, number>; maxCvss: number; createdAt: string
}
interface Finding {
  id: string; scanner: string; ruleId: string; title: string; severity: string
  file: string; line: number | null; detail: string; vrt: string; cwe: string; cvss: number
}
interface ScanDetail extends ScanRow { findings: Finding[]; error?: string | null }
interface Ent { plan: string; features: string[]; usage: { scansUsed: number; scansLimit: number; scansRemaining: number } }

const SEV = ['critical', 'high', 'medium', 'low', 'info']

export default function ScansPage() {
  const [ent, setEnt] = useState<Ent | null>(null)
  const [scans, setScans] = useState<ScanRow[]>([])
  const [detail, setDetail] = useState<ScanDetail | null>(null)
  const [scanType, setScanType] = useState<ScanType>('url')
  const [target, setTarget] = useState('')
  const [running, setRunning] = useState(false)
  const [error, setError] = useState('')

  const loadEnt = useCallback(async () => {
    const r = await fetch('/api/subscription', { credentials: 'include' })
    if (r.ok) setEnt((await r.json()).entitlements)
  }, [])
  const loadScans = useCallback(async () => {
    const r = await fetch('/api/scan', { credentials: 'include' })
    if (r.ok) setScans(await r.json())
  }, [])

  useEffect(() => { loadEnt(); loadScans() }, [loadEnt, loadScans])

  const run = async () => {
    setRunning(true); setError(''); setDetail(null)
    try {
      const r = await fetch('/api/scan', {
        method: 'POST', credentials: 'include',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ scanType, target: target.trim() }),
      })
      const body = await r.json()
      if (!r.ok) {
        if (body.code === 'quota_exceeded') setError(`${body.error} `)
        else if (body.code === 'feature_locked') setError(`${body.error} `)
        else setError(body.error || 'Scan failed')
        return
      }
      setDetail(body)
      setTarget('')
      await Promise.all([loadEnt(), loadScans()])
    } catch {
      setError('Scan failed')
    } finally {
      setRunning(false)
    }
  }

  const openScan = async (id: string) => {
    const r = await fetch(`/api/scan/${id}`, { credentials: 'include' })
    if (r.ok) setDetail(await r.json())
  }
  const del = async (id: string) => {
    if (!confirm('Delete this scan?')) return
    await fetch(`/api/scan/${id}`, { method: 'DELETE', credentials: 'include' })
    if (detail?.id === id) setDetail(null)
    loadScans()
  }

  const has = (f: string) => ent?.features.includes(f)
  const limitTxt = ent ? (ent.usage.scansLimit < 0 ? '∞' : ent.usage.scansLimit) : '—'
  const pct = ent && ent.usage.scansLimit > 0 ? Math.min(100, (ent.usage.scansUsed / ent.usage.scansLimit) * 100) : 0
  const repoLocked = !has('scan.github_repo')

  return (
    <div className={styles.page}>
      <h1 className={styles.h1}>Scans</h1>
      <p className={styles.sub}>Run a security scan, keep the history, and export a submission-ready report.</p>

      <div className={styles.card}>
        <p className={styles.sectionTitle}>New scan</p>
        <div className={styles.form}>
          <select className={styles.select} value={scanType} onChange={(e) => setScanType(e.target.value as ScanType)}>
            <option value="url">Live URL (headers, cookies, CORS…)</option>
            <option value="repo">GitHub repo{repoLocked ? ' — Pro' : ''}</option>
          </select>
          <input
            className={styles.input}
            placeholder={scanType === 'url' ? 'https://target.example' : 'https://github.com/owner/repo or owner/repo'}
            value={target}
            onChange={(e) => setTarget(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && !running && target.trim() && run()}
          />
          <button className={styles.btn} onClick={run} disabled={running || !target.trim() || (scanType === 'repo' && repoLocked)}>
            {running ? <Loader2 size={15} className="spin" /> : <Play size={15} />} Scan
          </button>
        </div>
        {scanType === 'repo' && repoLocked && (
          <p className={styles.hint}><Lock size={12} /> GitHub-repo scanning is a Pro feature. <Link className={styles.upgrade} href="/pricing">Upgrade →</Link></p>
        )}
        {error && (
          <p className={styles.err}>
            {error}
            {(error.includes('limit') || error.includes('plan')) && <Link className={styles.upgrade} href="/pricing">Upgrade →</Link>}
          </p>
        )}
        {ent && (
          <div className={styles.quota}>
            <span>{ent.usage.scansUsed} / {limitTxt} scans used ({ent.plan})</span>
            <span className={styles.quotaBar}><span className={styles.quotaFill} style={{ width: `${pct}%` }} /></span>
          </div>
        )}
      </div>

      {detail ? (
        <ScanDetailView detail={detail} ent={ent} onBack={() => setDetail(null)} onDelete={del} />
      ) : (
        <div className={styles.card}>
          <p className={styles.sectionTitle}>History</p>
          {scans.length === 0 ? (
            <div className={styles.empty}>No scans yet — run your first one above.</div>
          ) : (
            <table className={styles.table}>
              <thead><tr><th>Target</th><th>Type</th><th>Findings</th><th>Max CVSS</th><th>When</th><th></th></tr></thead>
              <tbody>
                {scans.map((s) => (
                  <tr key={s.id}>
                    <td><button className={styles.rowBtn} onClick={() => openScan(s.id)}>{s.target}</button></td>
                    <td>{s.scanType}</td>
                    <td className={styles.num}>{s.total}{s.status === 'failed' ? ' (failed)' : ''}</td>
                    <td className={styles.num}>{s.maxCvss || '—'}</td>
                    <td>{new Date(s.createdAt).toLocaleString()}</td>
                    <td><button className={styles.rowBtn} onClick={() => del(s.id)} title="Delete"><Trash2 size={14} /></button></td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      )}
    </div>
  )
}

function ScanDetailView({ detail, ent, onBack, onDelete }: { detail: ScanDetail; ent: Ent | null; onBack: () => void; onDelete: (id: string) => void }) {
  const has = (f: string) => ent?.features.includes(f)
  const dl = (fmt: string) => { window.location.href = `/api/scan/${detail.id}/report?format=${fmt}` }
  return (
    <div className={styles.card}>
      <button className={styles.back} onClick={onBack}><ArrowLeft size={14} /> Back to history</button>
      <p className={styles.sectionTitle}>{detail.target} — {detail.total} finding(s)</p>

      <div className={styles.pills}>
        {SEV.filter((s) => (detail.bySeverity?.[s] ?? 0) > 0).map((s) => (
          <span key={s} className={`${styles.pill} ${styles['sev' + s as keyof typeof styles]}`}>{s}: {detail.bySeverity[s]}</span>
        ))}
      </div>

      <div className={styles.downloads}>
        <button className={styles.dl} onClick={() => dl('md')}><Download size={14} /> Markdown</button>
        <button className={`${styles.dl} ${!has('report.html') ? styles.dlLocked : ''}`} onClick={() => has('report.html') ? dl('html') : null} disabled={!has('report.html')}>
          {has('report.html') ? <Download size={14} /> : <Lock size={14} />} HTML report
        </button>
        <button className={`${styles.dl} ${!has('export.sarif') ? styles.dlLocked : ''}`} onClick={() => has('export.sarif') ? dl('sarif') : null} disabled={!has('export.sarif')}>
          {has('export.sarif') ? <Download size={14} /> : <Lock size={14} />} SARIF
        </button>
        {(!has('report.html') || !has('export.sarif')) && (
          <span className={styles.lockNote}>HTML &amp; SARIF export are Pro. <Link className={styles.upgrade} href="/pricing">Upgrade →</Link></span>
        )}
      </div>

      {detail.status === 'failed' ? (
        <p className={styles.err}>Scan failed: {detail.error}</p>
      ) : (
        <table className={styles.table}>
          <thead><tr><th>Severity</th><th>CVSS</th><th>Finding</th><th>Location</th><th>VRT</th></tr></thead>
          <tbody>
            {detail.findings.map((f) => (
              <tr key={f.id}>
                <td><span className={`${styles.sev} ${styles['sev' + f.severity as keyof typeof styles]}`}>{f.severity}</span></td>
                <td className={styles.num}>{f.cvss}</td>
                <td>{f.title}<div className={styles.findingDetail}>{f.detail}</div></td>
                <td>{f.file ? `${f.file}${f.line ? ':' + f.line : ''}` : '—'}</td>
                <td>{f.vrt || '—'}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  )
}
