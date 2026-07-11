/**
 * Role-based access control: named roles as sets of permissions, checked
 * centrally (middleware.ts, requirePermission()) instead of ad hoc
 * `role !== 'admin'` string comparisons scattered across route handlers.
 *
 * Backward compatible by construction: 'admin' and 'standard' keep exactly
 * the permission boundary they had before this module existed (see the
 * matrix below) — nothing that worked for an existing user stops working.
 * 'operator' and 'viewer' are additive: new, opt-in roles for teams that
 * want a lead-hunter tier (sees everything, can't manage users) or a
 * read-only stakeholder tier (client/report viewer, no write access).
 *
 * Edge-runtime compatible: no Node built-ins, pure data + functions, safe
 * to import from middleware.ts as well as route handlers and client code.
 */

export type RoleId = 'admin' | 'operator' | 'standard' | 'viewer'

export const ROLE_IDS: RoleId[] = ['admin', 'operator', 'standard', 'viewer']

export const ROLE_LABELS: Record<RoleId, string> = {
  admin: 'Admin',
  operator: 'Operator',
  standard: 'Standard',
  viewer: 'Viewer',
}

export const ROLE_DESCRIPTIONS: Record<RoleId, string> = {
  admin: 'Full control: manage users and roles, view the audit log, see every project.',
  operator: 'Sees and can act on every project (not just their own), but cannot manage users or view the audit log.',
  standard: 'Full control over their own projects and account. The default role for new users.',
  viewer: 'Read-only access to projects they are given — no scans, no edits, no destructive actions.',
}

export type Permission =
  | 'users.manage' // create/edit/delete other users, change roles
  | 'users.view_all' // list all users, not just self
  | 'audit_log.view'
  | 'projects.view_all' // see every user's projects, not just own
  | 'projects.manage' // create/edit/delete/run scans on own projects
  | 'settings.manage_global' // LLM providers, GitHub token, other global settings
  | 'data.write' // create/modify findings, comments, evidence, trigger scans
  | 'data.read' // view findings, reports, dashboards

const ALL_PERMISSIONS: Permission[] = [
  'users.manage',
  'users.view_all',
  'audit_log.view',
  'projects.view_all',
  'projects.manage',
  'settings.manage_global',
  'data.write',
  'data.read',
]

const STANDARD_PERMISSIONS: Permission[] = ['projects.manage', 'settings.manage_global', 'data.write', 'data.read']

const ROLE_PERMISSIONS: Record<RoleId, ReadonlySet<Permission>> = {
  admin: new Set(ALL_PERMISSIONS),
  operator: new Set<Permission>([...STANDARD_PERMISSIONS, 'projects.view_all']),
  standard: new Set(STANDARD_PERMISSIONS),
  viewer: new Set<Permission>(['data.read']),
}

export function isKnownRole(role: string): role is RoleId {
  return (ROLE_IDS as string[]).includes(role)
}

/**
 * Unknown/legacy role strings are denied everything except nothing — fail
 * closed rather than silently granting access to a typo'd or future role
 * string this version of the app doesn't recognize yet.
 */
export function hasPermission(role: string, permission: Permission): boolean {
  if (!isKnownRole(role)) return false
  return ROLE_PERMISSIONS[role].has(permission)
}

export function permissionsFor(role: string): Permission[] {
  if (!isKnownRole(role)) return []
  return [...ROLE_PERMISSIONS[role]]
}

/**
 * Declarative route -> required-permission map, checked centrally in
 * middleware.ts for every matching request before it reaches the route
 * handler. Path-prefix matched. Routes not listed here fall through to
 * their own (session- or ownership-aware) checks — middleware can't know,
 * e.g., whether a /api/users/[id] request is a user viewing their own
 * record, so that nuance stays in the route handler.
 */
export const ROUTE_PERMISSIONS: { prefix: string; permission: Permission }[] = [
  { prefix: '/api/audit-log', permission: 'audit_log.view' },
  { prefix: '/settings/users', permission: 'users.manage' },
]

export function requiredPermissionForPath(pathname: string): Permission | null {
  const match = ROUTE_PERMISSIONS.find(r => pathname === r.prefix || pathname.startsWith(r.prefix + '/'))
  return match ? match.permission : null
}
