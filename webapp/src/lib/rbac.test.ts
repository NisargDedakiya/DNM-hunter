import { describe, test, expect } from 'vitest'
import { hasPermission, isKnownRole, permissionsFor, requiredPermissionForPath, ROLE_IDS } from './rbac'

describe('rbac - backward compatibility', () => {
  test('admin retains full access (superset of every permission)', () => {
    for (const permission of [
      'users.manage', 'users.view_all', 'audit_log.view', 'projects.view_all',
      'projects.manage', 'settings.manage_global', 'data.write', 'data.read',
    ] as const) {
      expect(hasPermission('admin', permission)).toBe(true)
    }
  })

  test('standard keeps exactly its historical boundary: own-resource CRUD, no user/audit management', () => {
    expect(hasPermission('standard', 'projects.manage')).toBe(true)
    expect(hasPermission('standard', 'data.write')).toBe(true)
    expect(hasPermission('standard', 'data.read')).toBe(true)
    expect(hasPermission('standard', 'settings.manage_global')).toBe(true)

    expect(hasPermission('standard', 'users.manage')).toBe(false)
    expect(hasPermission('standard', 'users.view_all')).toBe(false)
    expect(hasPermission('standard', 'audit_log.view')).toBe(false)
    expect(hasPermission('standard', 'projects.view_all')).toBe(false)
  })
})

describe('rbac - new roles', () => {
  test('operator sees every project but cannot manage users or view the audit log', () => {
    expect(hasPermission('operator', 'projects.view_all')).toBe(true)
    expect(hasPermission('operator', 'projects.manage')).toBe(true)
    expect(hasPermission('operator', 'data.write')).toBe(true)
    expect(hasPermission('operator', 'users.manage')).toBe(false)
    expect(hasPermission('operator', 'users.view_all')).toBe(false)
    expect(hasPermission('operator', 'audit_log.view')).toBe(false)
  })

  test('viewer is read-only', () => {
    expect(hasPermission('viewer', 'data.read')).toBe(true)
    expect(hasPermission('viewer', 'data.write')).toBe(false)
    expect(hasPermission('viewer', 'projects.manage')).toBe(false)
    expect(hasPermission('viewer', 'projects.view_all')).toBe(false)
    expect(hasPermission('viewer', 'users.manage')).toBe(false)
  })
})

describe('rbac - unknown roles fail closed', () => {
  test('an unrecognized role string is denied every permission', () => {
    expect(isKnownRole('superuser')).toBe(false)
    expect(hasPermission('superuser', 'data.read')).toBe(false)
    expect(hasPermission('', 'data.read')).toBe(false)
    expect(permissionsFor('superuser')).toEqual([])
  })
})

describe('rbac - ROLE_IDS is exhaustive and matches isKnownRole', () => {
  test('every id in ROLE_IDS is recognized by isKnownRole', () => {
    for (const role of ROLE_IDS) {
      expect(isKnownRole(role)).toBe(true)
    }
  })
})

describe('rbac - requiredPermissionForPath', () => {
  test('gates /api/audit-log on audit_log.view', () => {
    expect(requiredPermissionForPath('/api/audit-log')).toBe('audit_log.view')
  })

  test('gates /settings/users (and subpaths) on users.manage', () => {
    expect(requiredPermissionForPath('/settings/users')).toBe('users.manage')
    expect(requiredPermissionForPath('/settings/users/anything')).toBe('users.manage')
  })

  test('returns null for unlisted paths', () => {
    expect(requiredPermissionForPath('/api/projects')).toBeNull()
    expect(requiredPermissionForPath('/graph')).toBeNull()
  })

  test('does not false-positive on paths that merely share a prefix', () => {
    expect(requiredPermissionForPath('/settings/users-export')).toBeNull()
    expect(requiredPermissionForPath('/api/audit-logging')).toBeNull()
  })
})
