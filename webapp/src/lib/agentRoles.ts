import {
  Compass, Waypoints, Radar, Code2, KeyRound, Zap, ScanSearch, ShieldCheck, FileText, Database,
  type LucideIcon,
} from 'lucide-react'

// Mirrors agentic/orchestrator_helpers/agent_roles.py's canonical roster.
// Kept in sync manually — the icon field there is this map's key.
export interface AgentRoleMeta {
  id: string
  label: string
  icon: LucideIcon
}

export const AGENT_ROLE_ICONS: Record<string, LucideIcon> = {
  Compass, Waypoints, Radar, Code2, KeyRound, Zap, ScanSearch, ShieldCheck, FileText, Database,
}

// role id -> icon, mirroring agent_roles.py AGENT_ROLES[i].icon so badges
// render without waiting on an /api/agent-roles round-trip.
export const AGENT_ROLE_ICON_BY_ID: Record<string, LucideIcon> = {
  planner: Compass,
  coordinator: Waypoints,
  recon: Radar,
  js: Code2,
  api: Waypoints,
  auth: KeyRound,
  payload: Zap,
  scanner: ScanSearch,
  validator: ShieldCheck,
  report: FileText,
  memory: Database,
}

// Static fallback labels so badges render correctly even before /api/agent-roles
// has loaded (or if the agent service is offline) — matches agent_roles.py ids.
export const AGENT_ROLE_LABELS: Record<string, string> = {
  planner: 'Planner',
  coordinator: 'Coordinator',
  recon: 'Recon Agent',
  js: 'JS Analyst',
  api: 'API Analyst',
  auth: 'Auth Specialist',
  payload: 'Payload Engineer',
  scanner: 'Scanner',
  validator: 'Validator',
  report: 'Report Writer',
  memory: 'Memory Keeper',
}

export function roleLabel(roleId: string | null | undefined): string | null {
  if (!roleId) return null
  return AGENT_ROLE_LABELS[roleId] ?? roleId
}
