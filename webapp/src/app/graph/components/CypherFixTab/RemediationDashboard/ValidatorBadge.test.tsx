import React from 'react'
import { describe, test, expect, afterEach } from 'vitest'
import { render, screen, cleanup } from '@testing-library/react'
import { ValidatorBadge } from './ValidatorBadge'

afterEach(cleanup)

describe('ValidatorBadge', () => {
  test('renders label and confidence percentage when provided', () => {
    render(<ValidatorBadge status="confirmed" confidenceScore={92.5} />)
    expect(screen.getByText(/Confirmed/)).toBeTruthy()
    expect(screen.getByText(/93%/)).toBeTruthy()
  })

  test('renders label without a percentage when confidenceScore is null', () => {
    render(<ValidatorBadge status="needs_manual_review" confidenceScore={null} />)
    expect(screen.getByText(/Needs Review/)).toBeTruthy()
    expect(screen.queryByText(/%/)).toBeNull()
  })

  test('renders each validator status with a distinct label', () => {
    const statuses = ['confirmed', 'likely', 'needs_manual_review', 'ignored'] as const
    const seen = new Set<string>()
    for (const status of statuses) {
      cleanup()
      render(<ValidatorBadge status={status} />)
      const el = document.querySelector('[title]')
      expect(el).toBeTruthy()
      seen.add(el!.getAttribute('title')!)
    }
    expect(seen.size).toBe(statuses.length)
  })
})
