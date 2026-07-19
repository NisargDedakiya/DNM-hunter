// In-app scan runner. Bridges the web app to the Python scanner suite:
//   type 'url'  → `python -m web_probe <url> --json`        (live HTTP / DAST)
//   type 'repo' → `nh-scan <repo-or-path> --format json`    (full static suite)
//
// The parsing/normalisation is a pure function (unit-tested); the process spawn
// is isolated in `runScan` so it can be stubbed in tests and fails gracefully
// when the Python suite is not installed.

import { spawn } from 'node:child_process'

export type ScanType = 'url' | 'repo'

export interface NormalizedFinding {
  scanner: string
  ruleId: string
  title: string
  severity: string
  file: string
  line: number | null
  detail: string
  vrt: string
  cwe: string
  cvss: number
}

export interface ScanRunResult {
  ok: boolean
  findings: NormalizedFinding[]
  bySeverity: Record<string, number>
  total: number
  maxCvss: number
  error?: string
}

const SEV_ORDER = ['critical', 'high', 'medium', 'low', 'info']
// Base CVSS defaults by severity — matches the report generator's fallback so
// the label and the number are always consistent.
const CVSS_BY_SEV: Record<string, number> = { critical: 9.8, high: 7.5, medium: 5.4, low: 3.1, info: 0 }

function extractCwe(detail: string): string {
  const m = /(CWE-\d+)/.exec(detail || '')
  return m ? m[1] : ''
}

function extractVrt(detail: string, explicit?: string): string {
  if (explicit) return explicit
  const m = /\[VRT\s+([a-z0-9_.]+)/.exec(detail || '')
  return m ? m[1] : ''
}

/** Parse scanner-suite (`--format json`) or web_probe (`--json`) stdout into a
 * single normalised finding list. Pure — no I/O. */
export function parseFindings(type: ScanType, stdout: string): NormalizedFinding[] {
  let data: unknown
  try {
    data = JSON.parse(stdout)
  } catch {
    return []
  }

  // web_probe emits a bare array; scanner_suite/repo_scan emit { findings: [...] }
  const raw: any[] = Array.isArray(data)
    ? data
    : Array.isArray((data as any)?.findings)
      ? (data as any).findings
      : []

  return raw.map((f) => {
    const severity = String(f.severity ?? 'info').toLowerCase()
    const detail = String(f.detail ?? '')
    return {
      scanner: String(f.scanner ?? (type === 'url' ? 'web_probe' : f.kind ?? '')),
      ruleId: String(f.rule_id ?? f.ruleId ?? ''),
      title: String(f.title ?? ''),
      severity: SEV_ORDER.includes(severity) ? severity : 'info',
      file: String(f.file ?? f.url ?? ''),
      line: typeof f.line === 'number' ? f.line : null,
      detail,
      vrt: extractVrt(detail, f.vrt),
      cwe: extractCwe(detail || (f.cwe ?? '')),
      cvss: CVSS_BY_SEV[severity] ?? 5,
    }
  })
}

export function summarize(findings: NormalizedFinding[]): { bySeverity: Record<string, number>; total: number; maxCvss: number } {
  const bySeverity: Record<string, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 }
  let maxCvss = 0
  for (const f of findings) {
    bySeverity[f.severity] = (bySeverity[f.severity] ?? 0) + 1
    if (f.cvss > maxCvss) maxCvss = f.cvss
  }
  return { bySeverity, total: findings.length, maxCvss }
}

function sortFindings(findings: NormalizedFinding[]): NormalizedFinding[] {
  return [...findings].sort(
    (a, b) => SEV_ORDER.indexOf(a.severity) - SEV_ORDER.indexOf(b.severity) || b.cvss - a.cvss,
  )
}

// A conservative validity gate for a scan target (defence in depth; the UI also
// validates). URLs must be http(s); repos are a URL or owner/name.
export function isValidTarget(type: ScanType, target: string): boolean {
  const t = target.trim()
  if (!t) return false
  if (type === 'url') return /^https?:\/\/[^\s]+$/i.test(t)
  return /^https?:\/\/[^\s]+$/i.test(t) || /^[\w.-]+\/[\w.-]+$/.test(t)
}

function spawnJson(cmd: string, args: string[], timeoutMs: number): Promise<{ code: number; stdout: string; stderr: string }> {
  return new Promise((resolve) => {
    const child = spawn(cmd, args, { env: process.env })
    let stdout = ''
    let stderr = ''
    const timer = setTimeout(() => { try { child.kill('SIGKILL') } catch { /* noop */ } }, timeoutMs)
    child.stdout.on('data', (d) => { stdout += d.toString() })
    child.stderr.on('data', (d) => { stderr += d.toString() })
    child.on('error', (e) => { clearTimeout(timer); resolve({ code: -1, stdout, stderr: stderr + String(e) }) })
    child.on('close', (code) => { clearTimeout(timer); resolve({ code: code ?? -1, stdout, stderr }) })
  })
}

/** Run a scan by spawning the Python suite. Never throws — failures come back
 * as { ok:false, error }. */
export async function runScan(type: ScanType, target: string, timeoutMs = 120_000): Promise<ScanRunResult> {
  if (!isValidTarget(type, target)) {
    return { ok: false, findings: [], bySeverity: {}, total: 0, maxCvss: 0, error: 'Invalid target' }
  }

  // Use the installed console scripts (on PATH via `pip install -e .`) so the
  // spawn is independent of the working directory / module layout.
  const [cmd, args] = type === 'url'
    ? ['nh-web-probe', [target, '--json']]
    : ['nh-scan', [target, '--format', 'json', '--fail-on', 'none']]

  const { code, stdout, stderr } = await spawnJson(cmd, args as string[], timeoutMs)
  if (!stdout.trim()) {
    return { ok: false, findings: [], bySeverity: {}, total: 0, maxCvss: 0, error: stderr.slice(0, 400) || `scanner exited ${code}` }
  }
  const findings = sortFindings(parseFindings(type, stdout))
  return { ok: true, findings, ...summarize(findings) }
}
