import { NextRequest, NextResponse } from 'next/server'
import prisma from '@/lib/prisma'
import { getSession as getNeo4jSession } from '@/app/api/graph/neo4j'
import { createRequestLogger } from '@/lib/logger'

interface RouteParams {
  params: Promise<{ id: string }>
}

export interface ReasoningStep {
  findingId: string
  findingTitle: string | null
  evidence: string | null
  targetIp: string | null
  targetPort: number | null
  attackType: string | null
  payload: string | null
  toolName: string | null
  toolArgsSummary: string | null
  thought: string | null
  reasoning: string | null
  outputSummary: string | null
  outputAnalysis: string | null
}

function toNum(val: unknown): number | null {
  if (val && typeof val === 'object' && 'low' in val) return (val as { low: number }).low
  return typeof val === 'number' ? val : null
}

/**
 * GET /api/remediations/[id]/reasoning — AI Reasoning panel data (Phase 16).
 *
 * Answers "why this tool / why this payload / why this endpoint" by walking
 * from the Remediation's sourceFindingIds (set by the triage LLM when it
 * synthesized this remediation from one or more Neo4j ChainFindings) back
 * to the ChainStep(s) that produced them — which carry the agent's actual
 * tool_name/reasoning/thought/tool_args_summary for that action.
 *
 * `available: false` is the expected, non-error response for the majority
 * of remediations (anything not derived from a live attack-chain session,
 * e.g. a DAST/CVE correlation) — the frontend renders a graceful fallback,
 * not an error state, in that case.
 */
export async function GET(request: NextRequest, { params }: RouteParams) {
  const log = createRequestLogger(request, 'api.remediations.reasoning')
  try {
    const { id } = await params

    const remediation = await prisma.remediation.findUnique({
      where: { id },
      select: { id: true, sourceFindingIds: true, project: { select: { userId: true } } },
    })

    if (!remediation) {
      return NextResponse.json({ error: 'Remediation not found' }, { status: 404 })
    }

    if (!remediation.sourceFindingIds || remediation.sourceFindingIds.length === 0) {
      return NextResponse.json({ available: false, reason: 'not_chain_derived', steps: [] })
    }

    const session = getNeo4jSession()
    try {
      const result = await session.run(
        `MATCH (cf:ChainFinding {user_id: $userId})
         WHERE cf.finding_id IN $findingIds
         OPTIONAL MATCH (step:ChainStep)-[:PRODUCED]->(cf)
         RETURN cf.finding_id AS findingId, cf.title AS findingTitle, cf.evidence AS evidence,
                cf.target_ip AS targetIp, cf.target_port AS targetPort, cf.attack_type AS attackType,
                cf.payload AS payload,
                step.tool_name AS toolName, step.tool_args_summary AS toolArgsSummary,
                step.thought AS thought, step.reasoning AS reasoning,
                step.output_summary AS outputSummary, step.output_analysis AS outputAnalysis`,
        { userId: remediation.project.userId, findingIds: remediation.sourceFindingIds }
      )

      const steps: ReasoningStep[] = result.records.map(r => ({
        findingId: r.get('findingId') as string,
        findingTitle: (r.get('findingTitle') as string) || null,
        evidence: (r.get('evidence') as string) || null,
        targetIp: (r.get('targetIp') as string) || null,
        targetPort: toNum(r.get('targetPort')),
        attackType: (r.get('attackType') as string) || null,
        payload: (r.get('payload') as string) || null,
        toolName: (r.get('toolName') as string) || null,
        toolArgsSummary: (r.get('toolArgsSummary') as string) || null,
        thought: (r.get('thought') as string) || null,
        reasoning: (r.get('reasoning') as string) || null,
        outputSummary: (r.get('outputSummary') as string) || null,
        outputAnalysis: (r.get('outputAnalysis') as string) || null,
      }))

      if (steps.length === 0) {
        // sourceFindingIds pointed at IDs that no longer exist in the graph
        // (e.g. project data was reset) — a graceful empty result, not a 500.
        return NextResponse.json({ available: false, reason: 'source_findings_not_in_graph', steps: [] })
      }

      return NextResponse.json({ available: true, steps })
    } finally {
      await session.close()
    }
  } catch (error) {
    log.error('failed to fetch reasoning', { error: error instanceof Error ? error.message : String(error) })
    return NextResponse.json({ error: 'Failed to fetch reasoning' }, { status: 500 })
  }
}
