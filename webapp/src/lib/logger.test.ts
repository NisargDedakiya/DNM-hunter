import { describe, test, expect, vi, afterEach } from 'vitest'
import { createLogger, createRequestLogger } from './logger'

describe('logger - createLogger', () => {
  afterEach(() => {
    vi.restoreAllMocks()
  })

  test('info() logs a line with timestamp, level, module, request id, and message', () => {
    const spy = vi.spyOn(console, 'log').mockImplementation(() => {})
    const log = createLogger('api.users', 'req-123')
    log.info('created user')

    expect(spy).toHaveBeenCalledTimes(1)
    const line = spy.mock.calls[0][0] as string
    expect(line).toMatch(/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} \| INFO {2}\| api\.users \| req=req-123 \| created user$/)
  })

  test('each level routes to the matching console method', () => {
    const debugSpy = vi.spyOn(console, 'debug').mockImplementation(() => {})
    const logSpy = vi.spyOn(console, 'log').mockImplementation(() => {})
    const warnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {})
    const errorSpy = vi.spyOn(console, 'error').mockImplementation(() => {})

    const log = createLogger('test.mod')
    log.debug('d')
    log.info('i')
    log.warn('w')
    log.error('e')

    expect(debugSpy).toHaveBeenCalledTimes(1)
    expect(logSpy).toHaveBeenCalledTimes(1)
    expect(warnSpy).toHaveBeenCalledTimes(1)
    expect(errorSpy).toHaveBeenCalledTimes(1)
  })

  test('meta object is appended as JSON', () => {
    const spy = vi.spyOn(console, 'log').mockImplementation(() => {})
    const log = createLogger('api.users', 'req-1')
    log.info('login attempt', { email: 'a@b.com', success: false })

    const line = spy.mock.calls[0][0] as string
    expect(line).toContain('login attempt {"email":"a@b.com","success":false}')
  })

  test('omitting meta produces no trailing JSON', () => {
    const spy = vi.spyOn(console, 'log').mockImplementation(() => {})
    createLogger('api.users', 'req-1').info('no meta here')
    const line = spy.mock.calls[0][0] as string
    expect(line.endsWith('no meta here')).toBe(true)
  })

  test('an empty meta object also produces no trailing JSON', () => {
    const spy = vi.spyOn(console, 'log').mockImplementation(() => {})
    createLogger('api.users', 'req-1').info('empty meta', {})
    const line = spy.mock.calls[0][0] as string
    expect(line.endsWith('empty meta')).toBe(true)
  })

  test('defaults to "-" when no request id is given', () => {
    const spy = vi.spyOn(console, 'log').mockImplementation(() => {})
    createLogger('api.users').info('unscoped')
    const line = spy.mock.calls[0][0] as string
    expect(line).toContain('req=- |')
  })

  test('a meta value that cannot be JSON-serialized does not throw or crash the log line', () => {
    const spy = vi.spyOn(console, 'log').mockImplementation(() => {})
    const circular: Record<string, unknown> = {}
    circular.self = circular
    expect(() => createLogger('api.users', 'req-1').info('circular meta', circular)).not.toThrow()
    const line = spy.mock.calls[0][0] as string
    expect(line).toContain('circular meta')
  })
})

describe('logger - createRequestLogger', () => {
  afterEach(() => {
    vi.restoreAllMocks()
  })

  test('pulls the request id off the x-request-id header', () => {
    const spy = vi.spyOn(console, 'log').mockImplementation(() => {})
    const fakeRequest = { headers: new Headers({ 'x-request-id': 'trace-42' }) }
    createRequestLogger(fakeRequest, 'api.projects').info('hit')
    const line = spy.mock.calls[0][0] as string
    expect(line).toContain('req=trace-42')
    expect(line).toContain('api.projects')
  })

  test('falls back to "-" when the request has no x-request-id header', () => {
    const spy = vi.spyOn(console, 'log').mockImplementation(() => {})
    const fakeRequest = { headers: new Headers() }
    createRequestLogger(fakeRequest, 'api.projects').info('hit')
    const line = spy.mock.calls[0][0] as string
    expect(line).toContain('req=-')
  })
})
