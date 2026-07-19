import { describe, it, expect } from 'vitest'
import { parseFindings, summarize, isValidTarget } from './runner'
import { toSarif, toMarkdown, toHtml, remediationFor, type ReportFinding, type ReportMeta } from './report'
import { sampleMeta, sampleScanPayload, SAMPLE_FINDINGS } from './sample'

const SUITE_JSON = JSON.stringify({
  summary: { total: 2 },
  findings: [
    { scanner: 'code_audit', rule_id: 'CA-SQLI', title: 'SQL injection', severity: 'critical',
      file: 'app.py', line: 6, detail: 'SQLi [VRT server_side_injection.sql_injection; CWE-89]' },
    { scanner: 'code_audit', rule_id: 'CA-HASH', title: 'Weak hash', severity: 'medium',
      file: 'app.py', line: 8, detail: 'MD5 [VRT cryptographic_weakness.weak_hash; CWE-327]' },
  ],
})
const WEBPROBE_JSON = JSON.stringify([
  { vrt: 'server_security_misconfiguration.lack_of_security_headers_content_security_policy',
    rule_id: 'WP-CSP', severity: 'low', title: 'Missing CSP', url: 'https://x.example', detail: 'no CSP' },
])

describe('scan runner parsing', () => {
  it('parses scanner-suite {findings} shape with VRT + CWE + CVSS', () => {
    const f = parseFindings('repo', SUITE_JSON)
    expect(f).toHaveLength(2)
    expect(f[0].ruleId).toBe('CA-SQLI')
    expect(f[0].vrt).toBe('server_side_injection.sql_injection')
    expect(f[0].cwe).toBe('CWE-89')
    expect(f[0].cvss).toBe(9.8) // critical default
  })

  it('parses web_probe bare-array shape and defaults scanner', () => {
    const f = parseFindings('url', WEBPROBE_JSON)
    expect(f).toHaveLength(1)
    expect(f[0].scanner).toBe('web_probe')
    expect(f[0].file).toBe('https://x.example') // url mapped to file
    expect(f[0].severity).toBe('low')
  })

  it('returns [] on invalid json (never throws)', () => {
    expect(parseFindings('repo', 'not json')).toEqual([])
    expect(parseFindings('url', '')).toEqual([])
  })

  it('summarize counts by severity and max cvss', () => {
    const s = summarize(parseFindings('repo', SUITE_JSON))
    expect(s.total).toBe(2)
    expect(s.bySeverity.critical).toBe(1)
    expect(s.bySeverity.medium).toBe(1)
    expect(s.maxCvss).toBe(9.8)
  })

  it('validates targets', () => {
    expect(isValidTarget('url', 'https://a.b')).toBe(true)
    expect(isValidTarget('url', 'ftp://a.b')).toBe(false)
    expect(isValidTarget('repo', 'owner/repo')).toBe(true)
    expect(isValidTarget('repo', 'https://github.com/o/r')).toBe(true)
    expect(isValidTarget('url', '')).toBe(false)
  })
})

const META: ReportMeta = {
  target: 'https://x.example', scanType: 'url', createdAt: '2026-07-19T00:00:00Z',
  total: 2, bySeverity: { critical: 1, high: 0, medium: 1, low: 0, info: 0 }, maxCvss: 9.8,
}
const FINDINGS: ReportFinding[] = parseFindings('repo', SUITE_JSON)

describe('report renderers', () => {
  it('remediation resolves by vrt, then category, then severity', () => {
    expect(remediationFor('server_side_injection.sql_injection', 'critical')).toMatch(/parameteris/i)
    expect(remediationFor('server_security_misconfiguration.lack_of_security_headers_x', 'low')).toMatch(/header/i)
    expect(remediationFor('unknown.thing', 'high')).toMatch(/prioritise/i)
  })

  it('SARIF 2.1.0 shape is valid', () => {
    const doc: any = toSarif(META, FINDINGS)
    expect(doc.version).toBe('2.1.0')
    expect(doc.runs[0].tool.driver.name).toBe('NisargHunter AI')
    expect(doc.runs[0].results).toHaveLength(2)
    const ruleIds = doc.runs[0].tool.driver.rules.map((r: any) => r.id)
    for (const r of doc.runs[0].results) expect(ruleIds).toContain(r.ruleId)
  })

  it('Markdown has the key sections and remediation', () => {
    const md = toMarkdown(META, FINDINGS)
    expect(md).toContain('# Security Assessment Report')
    expect(md).toContain('## Executive summary')
    expect(md).toContain('Remediation.')
    expect(md).toContain('CVSS')
  })

  it('HTML is self-contained and XSS-safe', () => {
    const evil: ReportFinding[] = [{ ...FINDINGS[0], title: '<script>alert(1)</script>' }]
    const html = toHtml(META, evil)
    expect(html.startsWith('<!doctype html>')).toBe(true)
    expect(html).toContain('<style>')
    expect(html).not.toContain('<script>alert(1)</script>') // escaped
    expect(html).toContain('&lt;script&gt;')
  })
})

describe('public sample scan', () => {
  it('sampleMeta summarises the fixed findings', () => {
    const m = sampleMeta()
    expect(m.total).toBe(SAMPLE_FINDINGS.length)
    expect(m.bySeverity.critical).toBeGreaterThan(0)
    expect(m.maxCvss).toBe(9.8)
  })

  it('payload has stable ids and renders as a valid report', () => {
    const p = sampleScanPayload()
    expect(p.id).toBe('sample')
    expect(p.isSample).toBe(true)
    expect(p.findings.every((f) => typeof f.id === 'string')).toBe(true)
    // the sample renders through every format without error
    const meta = sampleMeta()
    expect(toMarkdown(meta, SAMPLE_FINDINGS)).toContain('# Security Assessment Report')
    expect((toSarif(meta, SAMPLE_FINDINGS) as any).runs[0].results.length).toBe(SAMPLE_FINDINGS.length)
    expect(toHtml(meta, SAMPLE_FINDINGS).startsWith('<!doctype html>')).toBe(true)
  })
})
