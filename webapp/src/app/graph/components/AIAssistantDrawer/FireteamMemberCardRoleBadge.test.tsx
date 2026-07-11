/**
 * Phase 08 — named agent role badge on FireteamMemberCard.
 *
 * `member.role` is optional and purely classificatory (agent_roles.py
 * DISPATCHABLE_ROLE_IDS). The badge should render when a known role is
 * declared, and the card should render identically to before when it is
 * absent or unknown — additive, non-breaking.
 */

import React from 'react'
import { describe, test, expect, afterEach } from 'vitest'
import { render, screen, cleanup } from '@testing-library/react'
import { FireteamMemberCard } from './FireteamMemberCard'
import type { FireteamMemberPanel } from './types'

afterEach(cleanup)

function makeMember(overrides: Partial<FireteamMemberPanel> = {}): FireteamMemberPanel {
  return {
    member_id: 'm1',
    name: 'Vulnerability Scanner',
    task: 'scan target',
    skills: [],
    status: 'running',
    started_at: new Date('2026-05-11T17:00:00Z'),
    tools: [],
    planWaves: [],
    iterations_used: 0,
    tokens_used: 0,
    input_tokens_used: 0,
    output_tokens_used: 0,
    findings_count: 0,
    ...overrides,
  }
}

describe('FireteamMemberCard — named agent role badge', () => {
  test('renders the role badge with the correct label for a known role', () => {
    const member = makeMember({ role: 'auth' })
    render(<FireteamMemberCard member={member} />)
    expect(screen.getByText('Auth Specialist')).toBeTruthy()
  })

  test('renders no badge when role is absent', () => {
    const member = makeMember({ role: undefined })
    render(<FireteamMemberCard member={member} />)
    expect(screen.queryByText('Auth Specialist')).toBeNull()
    expect(screen.queryByText('Recon Agent')).toBeNull()
  })

  test('renders no badge for an unrecognized role id (no crash)', () => {
    const member = makeMember({ role: 'not-a-real-role' })
    render(<FireteamMemberCard member={member} />)
    // AGENT_ROLE_ICON_BY_ID has no entry, so RoleIcon is undefined and the
    // badge is skipped even though roleLabel() would fall back to the raw id.
    expect(screen.queryByText('not-a-real-role')).toBeNull()
    expect(screen.getByText('Vulnerability Scanner')).toBeTruthy()
  })

  test('each dispatchable role id maps to a distinct label', () => {
    const roles = ['recon', 'js', 'api', 'auth', 'payload', 'scanner', 'validator', 'report']
    const labels = new Set<string>()
    for (const role of roles) {
      cleanup()
      const member = makeMember({ role, member_id: role })
      render(<FireteamMemberCard member={member} />)
      const badge = document.querySelector('[title]')
      expect(badge).toBeTruthy()
      labels.add(badge!.getAttribute('title')!)
    }
    expect(labels.size).toBe(roles.length)
  })
})
