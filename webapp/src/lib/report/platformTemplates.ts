/**
 * Bug-bounty platform submission templates (Phase 10).
 *
 * A full HTML/PDF pentest report is the wrong shape for a bug-bounty
 * submission — each platform wants ONE finding at a time, in its own
 * markdown dialect, submitted through its own web form. These are pure
 * functions: Remediation (+ minimal project/program context) in,
 * platform-formatted markdown text out. No new subsystem — this is the
 * "structured prompt over Finding + evidence" the roadmap calls for,
 * just template-driven instead of LLM-driven since the shape per platform
 * is fixed and well-documented.
 */

import type { Remediation } from '@/lib/cypherfix-types'

export type BugBountyPlatform = 'hackerone' | 'bugcrowd' | 'intigriti' | 'yeswehack'

export const PLATFORM_LABELS: Record<BugBountyPlatform, string> = {
  hackerone: 'HackerOne',
  bugcrowd: 'Bugcrowd',
  intigriti: 'Intigriti',
  yeswehack: 'YesWeHack',
}

export interface SubmissionContext {
  targetName: string // program/project display name, e.g. "acme-corp" or a domain
}

function assetLines(remediation: Remediation): string {
  const assets = Array.isArray(remediation.affectedAssets) ? remediation.affectedAssets : []
  if (assets.length === 0) return '_(no affected assets recorded)_'
  return assets.map(a => `- ${a.type}: \`${a.name}\`${a.url ? ` — ${a.url}` : ''}`).join('\n')
}

function referenceLines(remediation: Remediation): string {
  const refs: string[] = []
  for (const cve of remediation.cveIds) refs.push(`https://nvd.nist.gov/vuln/detail/${cve}`)
  for (const cwe of remediation.cweIds) refs.push(`https://cwe.mitre.org/data/definitions/${cwe.replace(/^CWE-/i, '')}.html`)
  return refs.length > 0 ? refs.map(r => `- ${r}`).join('\n') : '_(none)_'
}

// Bugcrowd's Vulnerability Rating Taxonomy uses P1 (critical) .. P5
// (informational) priority tiers instead of critical/high/medium/low/info.
const BUGCROWD_PRIORITY: Record<Remediation['severity'], string> = {
  critical: 'P1', high: 'P2', medium: 'P3', low: 'P4', info: 'P5',
}

function impactLine(remediation: Remediation): string {
  if (remediation.businessImpact) return remediation.businessImpact
  return `A ${remediation.severity}-severity ${remediation.category} issue affecting the assets listed above.`
}

function stepsToReproduce(remediation: Remediation): string {
  // The triage evidence field is the closest thing to captured reproduction
  // steps today; Phase 10's Evidence Gallery (screenshots/notes attached in
  // the UI) supplements this — reference it explicitly so the human
  // submitter knows to attach the gallery items before sending.
  const base = remediation.evidence || remediation.attackChainPath
  const steps = base
    ? base
    : '_(add step-by-step reproduction instructions here)_'
  return `${steps}\n\n_See the Evidence Gallery on this finding for supporting screenshots._`
}

export function formatForHackerOne(remediation: Remediation, ctx: SubmissionContext): string {
  return `## Summary
${remediation.title} on **${ctx.targetName}**.

${remediation.description}

## Severity
${remediation.severity.toUpperCase()}${remediation.cvssScore != null ? ` (CVSS ${remediation.cvssScore.toFixed(1)})` : ''}

## Affected Assets
${assetLines(remediation)}

## Steps To Reproduce
${stepsToReproduce(remediation)}

## Impact
${impactLine(remediation)}

## Suggested Fix
${remediation.solution || '_(no suggested fix recorded)_'}

## Supporting Material / References
${referenceLines(remediation)}
`
}

export function formatForBugcrowd(remediation: Remediation, ctx: SubmissionContext): string {
  const priority = BUGCROWD_PRIORITY[remediation.severity] || 'P3'
  return `## Description
${remediation.title} on **${ctx.targetName}**.

${remediation.description}

## Priority
${priority} (VRT — mapped from ${remediation.severity} severity${remediation.cvssScore != null ? `, CVSS ${remediation.cvssScore.toFixed(1)}` : ''})

## Domains / Targets In Scope
${assetLines(remediation)}

## Steps to Reproduce
${stepsToReproduce(remediation)}

## Impact
${impactLine(remediation)}

## Suggested Fix
${remediation.solution || '_(no suggested fix recorded)_'}

## References
${referenceLines(remediation)}
`
}

export function formatForIntigriti(remediation: Remediation, ctx: SubmissionContext): string {
  return `## Summary
${remediation.title} — **${ctx.targetName}**

${remediation.description}

## Severity
${remediation.severity.toUpperCase()}${remediation.cvssScore != null ? ` — CVSS ${remediation.cvssScore.toFixed(1)}` : ''}

## Reproduction steps
${stepsToReproduce(remediation)}

## Impact
${impactLine(remediation)}

## Mitigation
${remediation.solution || '_(no suggested fix recorded)_'}

## Affected assets
${assetLines(remediation)}

## References
${referenceLines(remediation)}
`
}

export function formatForYesWeHack(remediation: Remediation, ctx: SubmissionContext): string {
  return `## Description
${remediation.title} on **${ctx.targetName}**.

${remediation.description}

## Criticité / Severity
${remediation.severity.toUpperCase()}${remediation.cvssScore != null ? ` (CVSS ${remediation.cvssScore.toFixed(1)})` : ''}

## Cibles concernées / Affected targets
${assetLines(remediation)}

## Étapes de reproduction / Steps to reproduce
${stepsToReproduce(remediation)}

## Impact
${impactLine(remediation)}

## Remédiation / Remediation
${remediation.solution || '_(no suggested fix recorded)_'}

## Références / References
${referenceLines(remediation)}
`
}

export function formatForPlatform(platform: BugBountyPlatform, remediation: Remediation, ctx: SubmissionContext): string {
  switch (platform) {
    case 'hackerone': return formatForHackerOne(remediation, ctx)
    case 'bugcrowd': return formatForBugcrowd(remediation, ctx)
    case 'intigriti': return formatForIntigriti(remediation, ctx)
    case 'yeswehack': return formatForYesWeHack(remediation, ctx)
  }
}
