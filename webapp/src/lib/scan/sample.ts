// A fixed, realistic sample scan — the instant-value demo a prospect can see
// before signing up (public, no auth, no quota). Findings mirror what the real
// scanners produce so the sample report is a faithful preview of the deliverable.

import type { ReportFinding, ReportMeta } from './report'

export const SAMPLE_SCAN = {
  id: 'sample',
  target: 'github.com/acme/demo-shop',
  scanType: 'repo',
  status: 'completed',
  createdAt: '2026-07-19T12:00:00Z',
}

// Ordered most-severe first, as the real pipeline returns them.
export const SAMPLE_FINDINGS: ReportFinding[] = [
  {
    scanner: 'code_audit', ruleId: 'CA-SQLI', title: 'SQL query built from untrusted input (SQL injection)',
    severity: 'critical', file: 'server/routes/products.js', line: 42, cvss: 9.8,
    vrt: 'server_side_injection.sql_injection', cwe: 'CWE-89',
    detail: 'A request parameter is concatenated into a SQL query — an attacker can read or modify the database.',
  },
  {
    scanner: 'code_audit', ruleId: 'CA-CMDI', title: 'OS command built from untrusted input (command injection / RCE)',
    severity: 'critical', file: 'server/util/thumbnailer.js', line: 17, cvss: 9.8,
    vrt: 'server_side_injection.rce', cwe: 'CWE-78',
    detail: 'A filename from the request reaches child_process.exec — this is remote code execution.',
  },
  {
    scanner: 'contract_audit', ruleId: 'SC-REENTRANCY', title: 'State updated after an external call (reentrancy)',
    severity: 'critical', file: 'contracts/Vault.sol', line: 88, cvss: 9.8,
    vrt: 'smart_contract.reentrancy', cwe: 'CWE-841',
    detail: 'An external call is made before contract state is finalised and no reentrancy guard is present.',
  },
  {
    scanner: 'code_audit', ruleId: 'CA-DESERIAL', title: 'Insecure deserialization of untrusted data',
    severity: 'high', file: 'server/session.js', line: 9, cvss: 7.5,
    vrt: 'server_side_injection.rce', cwe: 'CWE-502',
    detail: 'Untrusted session data is deserialized with an unsafe loader — a gadget payload yields code execution.',
  },
  {
    scanner: 'code_audit', ruleId: 'CA-SSRF', title: 'Outbound request to an untrusted URL (SSRF)',
    severity: 'high', file: 'server/routes/preview.js', line: 23, cvss: 8.6,
    vrt: 'server_side_injection.ssrf', cwe: 'CWE-918',
    detail: 'A user-supplied URL is fetched server-side without allow-listing — reachable internal services can be hit.',
  },
  {
    scanner: 'iac_scan', ruleId: 'TF-001', title: 'Publicly readable/writable S3 bucket ACL',
    severity: 'high', file: 'infra/s3.tf', line: 3, cvss: 7.5,
    vrt: 'cloud_security.storage_misconfigurations', cwe: 'CWE-284',
    detail: 'The bucket ACL is public-read — its objects are exposed to anyone on the internet.',
  },
  {
    scanner: 'code_audit', ruleId: 'CA-HASH', title: 'Weak/broken hash used for security (MD5/SHA1)',
    severity: 'medium', file: 'server/auth/password.js', line: 5, cvss: 5.4,
    vrt: 'cryptographic_weakness.weak_hash', cwe: 'CWE-327',
    detail: 'Passwords are hashed with MD5 — trivially crackable. Use a memory-hard KDF (bcrypt/scrypt/Argon2).',
  },
  {
    scanner: 'web_probe', ruleId: 'WP-CSP', title: 'Missing Content-Security-Policy header',
    severity: 'low', file: 'https://demo-shop.acme.example', line: null, cvss: 3.1,
    vrt: 'server_security_misconfiguration.lack_of_security_headers_content_security_policy', cwe: '',
    detail: 'No Content-Security-Policy is set, removing a key defence-in-depth control against XSS.',
  },
]

export function sampleMeta(): ReportMeta {
  const bySeverity: Record<string, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 }
  let maxCvss = 0
  for (const f of SAMPLE_FINDINGS) {
    bySeverity[f.severity] = (bySeverity[f.severity] ?? 0) + 1
    if (f.cvss > maxCvss) maxCvss = f.cvss
  }
  return {
    target: SAMPLE_SCAN.target,
    scanType: SAMPLE_SCAN.scanType,
    createdAt: SAMPLE_SCAN.createdAt,
    total: SAMPLE_FINDINGS.length,
    bySeverity,
    maxCvss,
  }
}

/** The full sample payload the UI renders like a real scan. */
export function sampleScanPayload() {
  const meta = sampleMeta()
  return {
    ...SAMPLE_SCAN,
    total: meta.total,
    bySeverity: meta.bySeverity,
    maxCvss: meta.maxCvss,
    isSample: true,
    findings: SAMPLE_FINDINGS.map((f, i) => ({ id: `sample-${i}`, ...f })),
  }
}
