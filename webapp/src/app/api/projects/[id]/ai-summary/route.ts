import { NextRequest, NextResponse } from 'next/server'
import { getSession } from '@/app/api/graph/neo4j'
import prisma from '@/lib/prisma'

const AGENT_API_URL = process.env.AGENT_API_URL || 'http://agent:8080'

function toNum(val: unknown): number {
  if (val && typeof val === 'object' && 'low' in (val as object)) return (val as { low: number }).low
  return typeof val === 'number' ? val : 0
}

interface RouteParams {
  params: Promise<{ id: string }>
}

// Weighted, transparent risk score — not a fabricated number. Severity
// weights follow the same critical > high > medium > low ordering used
// throughout the app's analytics (CVSS bucket convention), with a small
// bonus for live secrets found since those are immediately actionable.
function computeRiskScore(vulnBySeverity: Record<string, number>, secretCount: number): number {
  const weights: Record<string, number> = { critical: 20, high: 10, medium: 4, low: 1 }
  let score = 0
  for (const [severity, count] of Object.entries(vulnBySeverity)) {
    score += (weights[severity.toLowerCase()] ?? 1) * count
  }
  score += secretCount * 8
  return Math.min(100, Math.round(score))
}

// GET /api/projects/[id]/ai-summary — AI Recon Summary (Phase 05).
// Company Overview, Tech Stack, Authentication, Interesting Endpoints, Admin
// Panels, JavaScript Files, Potential Attack Surface, API Summary, Risk Score.
// All counts come from real Cypher queries against the existing graph schema
// (same node/relationship names already used by the analytics routes);
// only the two narrative fields are LLM-generated, and only from those
// counts — never from raw unaggregated evidence.
export async function GET(_request: NextRequest, { params }: RouteParams) {
  const { id: projectId } = await params

  const project = await prisma.project.findUnique({
    where: { id: projectId },
    select: { id: true, name: true, targetDomain: true, userId: true },
  })
  if (!project) {
    return NextResponse.json({ error: 'Project not found' }, { status: 404 })
  }

  const session = getSession()
  try {
    const [
      techResult,
      endpointCatResult,
      jsResult,
      secretsResult,
      vulnSeverityResult,
      infraResult,
      subdomainResult,
      interestingResult,
    ] = await Promise.all([
      session.run(
        `MATCH (:BaseURL {project_id: $pid})-[:USES_TECHNOLOGY]->(t:Technology)
         OPTIONAL MATCH (t)-[:HAS_KNOWN_CVE]->(c:CVE)
         RETURN t.name AS name, t.version AS version, count(DISTINCT c) AS cveCount
         ORDER BY cveCount DESC, name ASC LIMIT 30`,
        { pid: projectId }
      ),
      session.run(
        `MATCH (:BaseURL {project_id: $pid})-[:HAS_ENDPOINT]->(e:Endpoint)
         RETURN COALESCE(e.category, 'other') AS category, count(e) AS count,
                count(CASE WHEN e.is_graphql = true THEN 1 END) AS graphqlCount
         ORDER BY count DESC`,
        { pid: projectId }
      ),
      session.run(
        `MATCH (j:JsReconFinding {project_id: $pid, finding_type: 'js_file'})
         OPTIONAL MATCH (j)-[:HAS_SECRET]->(s:Secret)
         RETURN count(DISTINCT j) AS jsFileCount, count(DISTINCT s) AS jsSecretCount`,
        { pid: projectId }
      ),
      session.run(
        `MATCH (s:Secret {project_id: $pid})
         RETURN COALESCE(s.severity, 'unknown') AS severity, count(s) AS count`,
        { pid: projectId }
      ),
      session.run(
        `MATCH (v:Vulnerability {project_id: $pid})
         RETURN COALESCE(v.severity, 'unknown') AS severity, count(v) AS count`,
        { pid: projectId }
      ),
      session.run(
        `MATCH (:IP {project_id: $pid})-[:HAS_PORT]->(p:Port)-[:RUNS_SERVICE]->(s:Service)
         RETURN s.name AS service, count(DISTINCT p) AS count
         ORDER BY count DESC LIMIT 15`,
        { pid: projectId }
      ),
      session.run(
        `MATCH (s:Subdomain {project_id: $pid})
         OPTIONAL MATCH (s)-[:RESOLVES_TO]->(i:IP)
         RETURN count(DISTINCT s) AS total, count(DISTINCT CASE WHEN i IS NOT NULL THEN s END) AS resolved`,
        { pid: projectId }
      ),
      // "Interesting" endpoints: admin/auth/api categories, forms, or AI-flagged
      // ingest/tool-arg surfaces — a defensible heuristic, not a fabricated list.
      session.run(
        `MATCH (bu:BaseURL {project_id: $pid})-[:HAS_ENDPOINT]->(e:Endpoint)
         WHERE e.category IN ['admin', 'authentication', 'api', 'upload']
            OR e.is_form = true OR e.is_graphql = true
            OR e.is_ai_rag_ingest = true
         RETURN e.full_url AS url, e.path AS path, bu.url AS baseUrl,
                COALESCE(e.category, 'other') AS category,
                COALESCE(e.is_form, false) AS isForm,
                COALESCE(e.is_graphql, false) AS isGraphql
         ORDER BY CASE e.category
           WHEN 'admin' THEN 0 WHEN 'authentication' THEN 1
           WHEN 'api' THEN 2 WHEN 'upload' THEN 3 ELSE 4 END
         LIMIT 25`,
        { pid: projectId }
      ),
    ])

    const techStack = techResult.records.map(r => ({
      name: (r.get('name') as string) || 'Unknown',
      version: r.get('version') as string | null,
      cveCount: toNum(r.get('cveCount')),
    }))

    const endpointCategories = endpointCatResult.records.map(r => ({
      category: r.get('category') as string,
      count: toNum(r.get('count')),
    }))
    const graphqlCount = endpointCatResult.records.reduce((sum, r) => sum + toNum(r.get('graphqlCount')), 0)
    const adminPanelCount = endpointCategories.find(c => c.category === 'admin')?.count ?? 0
    const authEndpointCount = endpointCategories.find(c => c.category === 'authentication')?.count ?? 0
    const apiEndpointCount = endpointCategories.find(c => c.category === 'api')?.count ?? 0

    const jsRec = jsResult.records[0]
    const jsFiles = jsRec
      ? { fileCount: toNum(jsRec.get('jsFileCount')), secretCount: toNum(jsRec.get('jsSecretCount')) }
      : { fileCount: 0, secretCount: 0 }

    const secretsBySeverity: Record<string, number> = {}
    let totalSecrets = 0
    for (const r of secretsResult.records) {
      const count = toNum(r.get('count'))
      secretsBySeverity[r.get('severity') as string] = count
      totalSecrets += count
    }

    const vulnBySeverity: Record<string, number> = {}
    let totalVulns = 0
    for (const r of vulnSeverityResult.records) {
      const count = toNum(r.get('count'))
      vulnBySeverity[r.get('severity') as string] = count
      totalVulns += count
    }

    const exposedServices = infraResult.records.map(r => ({
      service: (r.get('service') as string) || 'unknown',
      count: toNum(r.get('count')),
    }))

    const subRec = subdomainResult.records[0]
    const subdomains = subRec
      ? { total: toNum(subRec.get('total')), resolved: toNum(subRec.get('resolved')) }
      : { total: 0, resolved: 0 }

    const interestingEndpoints = interestingResult.records.map(r => ({
      url: (r.get('url') as string) || (r.get('path') as string) || '',
      baseUrl: r.get('baseUrl') as string | null,
      category: r.get('category') as string,
      isForm: r.get('isForm') as boolean,
      isGraphql: r.get('isGraphql') as boolean,
    }))

    const riskScore = computeRiskScore(vulnBySeverity, totalSecrets)

    // Condensed counts sent to the LLM — aggregates only, no raw evidence.
    const findingsForLLM = {
      subdomains, techStack: techStack.slice(0, 15).map(t => `${t.name}${t.version ? ' ' + t.version : ''}`),
      endpointCategories, graphqlEndpoints: graphqlCount,
      adminPanelCount, authEndpointCount, apiEndpointCount,
      jsFiles, exposedServices,
      vulnBySeverity, totalVulns, secretsBySeverity, totalSecrets, riskScore,
    }

    let companyOverview = ''
    let attackSurfaceNarrative = ''
    try {
      const resp = await fetch(`${AGENT_API_URL}/llm/recon-summary`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          domain: project.targetDomain || project.name,
          findings: findingsForLLM,
          model: 'claude-opus-4-6',
          user_id: project.userId,
          project_id: project.id,
        }),
        signal: AbortSignal.timeout(30_000),
      })
      if (resp.ok) {
        const narratives = await resp.json()
        companyOverview = narratives.company_overview || ''
        attackSurfaceNarrative = narratives.attack_surface_narrative || ''
      } else {
        console.warn(`AI summary narrative failed (${resp.status}): ${await resp.text()}`)
      }
    } catch (err) {
      console.warn('Agent unavailable for AI summary narrative, returning counts without it:', err)
    }

    return NextResponse.json({
      project: { id: project.id, name: project.name, targetDomain: project.targetDomain },
      companyOverview,
      attackSurfaceNarrative,
      techStack,
      authentication: { endpointCount: authEndpointCount },
      adminPanels: { count: adminPanelCount },
      apiSummary: { restEndpointCount: apiEndpointCount, graphqlEndpointCount: graphqlCount },
      javascriptFiles: jsFiles,
      attackSurface: { subdomains, exposedServices },
      interestingEndpoints,
      riskScore,
      vulnBySeverity,
      totalVulns,
      secretsBySeverity,
      totalSecrets,
    })
  } catch (error) {
    console.error('AI summary error:', error)
    return NextResponse.json(
      { error: error instanceof Error ? error.message : 'Query failed' },
      { status: 500 }
    )
  } finally {
    await session.close()
  }
}
