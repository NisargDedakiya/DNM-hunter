// Premium report rendering (the subscription's headline deliverable), produced
// in TypeScript from stored findings so export is instant and needs no re-scan.
// Formats: SARIF 2.1.0 (code scanning), Markdown (bounty submissions), and a
// self-contained HTML report (client deliverable).

export interface ReportFinding {
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

export interface ReportMeta {
  target: string
  scanType: string
  createdAt: string | Date
  total: number
  bySeverity: Record<string, number>
  maxCvss: number
}

const SEV_ORDER = ['critical', 'high', 'medium', 'low', 'info']
const SEV_COLOR: Record<string, string> = {
  critical: '#b3123b', high: '#d1471c', medium: '#c08a00', low: '#2b6cb0', info: '#5a6270',
}
const SARIF_LEVEL: Record<string, string> = {
  critical: 'error', high: 'error', medium: 'warning', low: 'note', info: 'note',
}

// Compact remediation guidance keyed by VRT id, then by category prefix, then a
// severity fallback — so every finding gets actionable text.
const REMEDIATION: Record<string, string> = {
  'server_side_injection.sql_injection': 'Use parameterised queries / prepared statements; never build SQL by string concatenation.',
  'server_side_injection.rce': 'Never pass untrusted data to eval/exec/command sinks or deserialize it; use safe APIs and allow-listing.',
  'server_side_injection.file_inclusion_local': 'Resolve the canonical path and confine it to an allow-listed base directory; reject "..".',
  'server_side_injection.ssti': 'Never render user input as a template; pass it as data with auto-escaping.',
  'server_side_injection.ssrf': 'Allow-list outbound hosts; block link-local/private ranges; disable redirects to internal targets.',
  'server_side_injection.xxe': 'Disable external entities/DTDs in the XML parser.',
  'cross_site_scripting.stored': 'Contextually output-encode untrusted data; prefer safe DOM APIs; add a strict CSP.',
  'cryptographic_weakness.weak_hash': 'Use SHA-256+ for integrity and a memory-hard KDF (bcrypt/scrypt/Argon2) for passwords.',
  'cryptographic_weakness.broken_cryptography': 'Use AES-GCM or ChaCha20-Poly1305; never ECB/DES/RC4.',
  'cryptographic_weakness.insufficient_entropy': 'Use a CSPRNG (secrets / crypto.randomBytes / os.urandom) for security values.',
  'smart_contract.reentrancy': 'Apply checks-effects-interactions and/or a nonReentrant guard.',
  'smart_contract.owner_takeover': 'Add an access-control modifier (onlyOwner / role-based) to every privileged function.',
  'smart_contract.integer_overflow': 'Compile with Solidity >=0.8 (checked arithmetic) or use SafeMath.',
}
const CATEGORY_FALLBACK: Array<[string, string]> = [
  ['server_security_misconfiguration.lack_of_security_headers', 'Set the missing security header at the edge/app for all responses.'],
  ['server_security_misconfiguration.missing_secure_or_httponly', 'Set Secure, HttpOnly and SameSite on session cookies.'],
  ['server_security_misconfiguration.unsafe_cross_origin', 'Reflect only allow-listed origins; never combine wildcard ACAO with credentials.'],
  ['cryptographic_weakness', 'Replace the weak primitive with a modern, vetted algorithm and key size.'],
  ['server_side_injection', 'Validate and neutralise untrusted input before it reaches the sink.'],
  ['smart_contract', 'Follow the referenced SWC guidance and add tests for the invariant.'],
]
const SEVERITY_FALLBACK: Record<string, string> = {
  critical: 'Remediate immediately; this is directly exploitable.',
  high: 'Prioritise remediation this cycle.',
  medium: 'Fix as part of routine hardening.',
  low: 'Address as defence-in-depth.',
  info: 'Informational — verify relevance.',
}

export function remediationFor(vrt: string, severity: string): string {
  if (vrt && REMEDIATION[vrt]) return REMEDIATION[vrt]
  for (const [prefix, text] of CATEGORY_FALLBACK) {
    if (vrt.startsWith(prefix)) return text
  }
  return SEVERITY_FALLBACK[severity] ?? SEVERITY_FALLBACK.medium
}

function esc(s: string): string {
  return String(s).replace(/[&<>"']/g, (c) => (
    { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c] as string
  ))
}

function loc(f: ReportFinding): string {
  return f.line ? `${f.file}:${f.line}` : (f.file || '—')
}

const highest = (bySev: Record<string, number>): string =>
  SEV_ORDER.find((s) => (bySev[s] ?? 0) > 0) ?? 'none'

// ─────────────────────────── SARIF 2.1.0 ───────────────────────────
export function toSarif(meta: ReportMeta, findings: ReportFinding[]): object {
  const rules = new Map<string, object>()
  const results = findings.map((f) => {
    const rid = f.ruleId || 'GENERIC'
    if (!rules.has(rid)) {
      rules.set(rid, {
        id: rid,
        shortDescription: { text: (f.title || rid).slice(0, 120) },
        defaultConfiguration: { level: SARIF_LEVEL[f.severity] ?? 'warning' },
        properties: { 'security-severity': String(f.cvss), tags: ['security', f.scanner].filter(Boolean), vrt: f.vrt || undefined },
      })
    }
    const result: any = {
      ruleId: rid,
      level: SARIF_LEVEL[f.severity] ?? 'warning',
      message: { text: f.detail || f.title },
      properties: { scanner: f.scanner, severity: f.severity, vrt: f.vrt || undefined, cvss: f.cvss },
    }
    if (f.file) {
      result.locations = [{
        physicalLocation: {
          artifactLocation: { uri: f.file },
          ...(f.line ? { region: { startLine: f.line } } : {}),
        },
      }]
    }
    return result
  })
  return {
    version: '2.1.0',
    $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
    runs: [{
      tool: { driver: { name: 'NisargHunter AI', version: '1.0.0', rules: [...rules.values()] } },
      results,
      properties: { target: meta.target, summary: { total: meta.total, bySeverity: meta.bySeverity } },
    }],
  }
}

// ─────────────────────────── Markdown ───────────────────────────
export function toMarkdown(meta: ReportMeta, findings: ReportFinding[]): string {
  const date = new Date(meta.createdAt).toISOString().slice(0, 16).replace('T', ' ')
  const lines = [
    '# Security Assessment Report', '',
    `- **Target:** ${meta.target}`,
    `- **Scan type:** ${meta.scanType}`,
    `- **Generated:** ${date} UTC`,
    `- **Tool:** NisargHunter AI`, '',
    '## Executive summary', '',
    `The assessment identified **${meta.total} finding(s)**. Highest severity: **${highest(meta.bySeverity)}** (max CVSS ${meta.maxCvss}).`, '',
    '| Severity | Count |', '|----------|-------|',
    ...SEV_ORDER.filter((s) => (meta.bySeverity[s] ?? 0) > 0).map((s) => `| ${s[0].toUpperCase() + s.slice(1)} | ${meta.bySeverity[s]} |`),
    '', '## Findings', '',
  ]
  findings.forEach((f, i) => {
    lines.push(
      `### ${i + 1}. ${f.title}`, '',
      `- **Severity:** ${f.severity} · **CVSS:** ${f.cvss} · **Rule:** \`${f.ruleId}\` · **Scanner:** ${f.scanner}`,
      `- **Location:** \`${loc(f)}\``,
      `- **Classification:** VRT \`${f.vrt || '—'}\`${f.cwe ? ` · ${f.cwe}` : ''}`, '',
      `**Description.** ${f.detail}`, '',
      `**Remediation.** ${remediationFor(f.vrt, f.severity)}`, '',
    )
  })
  lines.push('---', '', '_Findings are automated and should be manually verified before submission or sign-off._')
  return lines.join('\n')
}

// ─────────────────────────── HTML ───────────────────────────
export function toHtml(meta: ReportMeta, findings: ReportFinding[]): string {
  const date = new Date(meta.createdAt).toISOString().slice(0, 16).replace('T', ' ')
  const chips = SEV_ORDER.filter((s) => (meta.bySeverity[s] ?? 0) > 0)
    .map((s) => `<span class="chip" style="--c:${SEV_COLOR[s]}">${s}: ${meta.bySeverity[s]}</span>`).join('')
  const rows = findings.map((f, i) =>
    `<tr><td>${i + 1}</td><td><span class="sev" style="--c:${SEV_COLOR[f.severity] || '#888'}">${f.severity}</span></td>`
    + `<td class="num">${f.cvss}</td><td>${esc(f.title)}</td><td><code>${esc(loc(f))}</code></td><td>${esc(f.vrt || '—')}</td></tr>`).join('')
  const details = findings.map((f, i) => `
    <article class="finding">
      <h3><span class="sev" style="--c:${SEV_COLOR[f.severity] || '#888'}">${f.severity}</span> ${i + 1}. ${esc(f.title)}</h3>
      <div class="meta"><span><b>CVSS</b> ${f.cvss}</span><span><b>Rule</b> <code>${esc(f.ruleId)}</code></span>
        <span><b>Scanner</b> ${esc(f.scanner)}</span><span><b>Location</b> <code>${esc(loc(f))}</code></span>
        <span><b>VRT</b> ${esc(f.vrt || '—')}</span>${f.cwe ? `<span><b>CWE</b> ${esc(f.cwe)}</span>` : ''}</div>
      <p><b>Description.</b> ${esc(f.detail)}</p>
      <p><b>Remediation.</b> ${esc(remediationFor(f.vrt, f.severity))}</p>
    </article>`).join('')
  return `<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1"><title>Security Assessment — ${esc(meta.target)}</title>
<style>
:root{--bg:#fff;--fg:#1a1d24;--muted:#5a6270;--line:#e6e8ee}
@media(prefers-color-scheme:dark){:root{--bg:#14171d;--fg:#e7e9ee;--muted:#9aa2b1;--line:#262b34}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.6 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif}
.wrap{max-width:960px;margin:0 auto;padding:40px 24px 80px}h1{font-size:28px;margin:0 0 4px}
h2{font-size:20px;margin:34px 0 12px;padding-bottom:6px;border-bottom:2px solid var(--line)}h3{font-size:17px;margin:0 0 10px}
.sub{color:var(--muted);margin:0 0 18px}.chips{display:flex;gap:8px;flex-wrap:wrap;margin:14px 0}
.chip{--c:#888;color:var(--c);border:1px solid var(--c);border-radius:999px;padding:3px 10px;font-weight:600;font-size:13px;text-transform:capitalize}
table{width:100%;border-collapse:collapse;font-size:14px}th,td{text-align:left;padding:8px 10px;border-bottom:1px solid var(--line);vertical-align:top}
th{color:var(--muted);font-size:12px;text-transform:uppercase;letter-spacing:.04em}td.num{font-variant-numeric:tabular-nums}
.sev{color:var(--c);font-weight:700;text-transform:capitalize}code{background:rgba(128,128,128,.15);padding:1px 5px;border-radius:4px;font:13px ui-monospace,Menlo,monospace}
.finding{border:1px solid var(--line);border-left:4px solid var(--line);border-radius:8px;padding:16px 18px;margin:14px 0}
.finding .meta{display:flex;flex-wrap:wrap;gap:6px 18px;color:var(--muted);font-size:13px;margin:0 0 12px}
@media print{.finding{break-inside:avoid}}</style></head><body><div class="wrap">
<h1>Security Assessment Report</h1>
<p class="sub">Target: <b>${esc(meta.target)}</b> · ${esc(date)} UTC · NisargHunter AI</p>
<h2>Executive summary</h2><p>The assessment identified <b>${meta.total} finding(s)</b>. Highest severity: <b>${highest(meta.bySeverity)}</b> (max CVSS ${meta.maxCvss}).</p>
<div class="chips">${chips}</div>
<h2>Findings overview</h2><table><thead><tr><th>#</th><th>Severity</th><th>CVSS</th><th>Finding</th><th>Location</th><th>VRT</th></tr></thead><tbody>${rows}</tbody></table>
<h2>Detailed findings</h2>${details}
<p class="sub" style="margin-top:32px;border-top:1px solid var(--line);padding-top:16px">Findings are automated and should be manually verified before submission or sign-off.</p>
</div></body></html>`
}
