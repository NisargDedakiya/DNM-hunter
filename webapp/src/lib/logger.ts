/**
 * Structured logging with request-ID correlation (Phase 16).
 *
 * middleware.ts stamps every request with an x-request-id header (reusing
 * one from an upstream caller, or minting a fresh one) — route handlers
 * read it back off the (headers-forwarded) NextRequest and pass it here so
 * every log line for a request can be grepped together, and correlated
 * with the same request-id surfacing in the agentic service's own logs
 * (see agentic/logging_config.py) when the webapp calls it on-request.
 *
 * Output format mirrors the Python side's for a consistent read across
 * both halves of the stack:
 *   2026-07-11 12:00:00 | INFO  | api.users | req=<id> | message {"meta":1}
 */

export type LogLevel = 'debug' | 'info' | 'warn' | 'error'

const LEVEL_LABEL: Record<LogLevel, string> = {
  debug: 'DEBUG',
  info: 'INFO',
  warn: 'WARN',
  error: 'ERROR',
}

const CONSOLE_METHOD: Record<LogLevel, 'debug' | 'log' | 'warn' | 'error'> = {
  debug: 'debug',
  info: 'log',
  warn: 'warn',
  error: 'error',
}

export interface Logger {
  debug: (message: string, meta?: Record<string, unknown>) => void
  info: (message: string, meta?: Record<string, unknown>) => void
  warn: (message: string, meta?: Record<string, unknown>) => void
  error: (message: string, meta?: Record<string, unknown>) => void
}

function timestamp(): string {
  // Same "YYYY-MM-DD HH:MM:SS" shape as agentic/logging_config.py's
  // LOG_DATE_FORMAT, so lines from both services line up when interleaved.
  return new Date().toISOString().replace('T', ' ').slice(0, 19)
}

function formatLine(level: LogLevel, moduleName: string, requestId: string, message: string, meta?: Record<string, unknown>): string {
  const base = `${timestamp()} | ${LEVEL_LABEL[level].padEnd(5)} | ${moduleName} | req=${requestId} | ${message}`
  if (!meta || Object.keys(meta).length === 0) return base
  try {
    return `${base} ${JSON.stringify(meta)}`
  } catch {
    return base
  }
}

function emit(level: LogLevel, moduleName: string, requestId: string, message: string, meta?: Record<string, unknown>) {
  // eslint-disable-next-line no-console
  console[CONSOLE_METHOD[level]](formatLine(level, moduleName, requestId, message, meta))
}

/**
 * Build a logger bound to a module name and a fixed request id. Prefer
 * createRequestLogger(request, moduleName) in route handlers — this is the
 * lower-level building block for anywhere a NextRequest isn't in scope
 * (background jobs, tests).
 */
export function createLogger(moduleName: string, requestId = '-'): Logger {
  return {
    debug: (message, meta) => emit('debug', moduleName, requestId, message, meta),
    info: (message, meta) => emit('info', moduleName, requestId, message, meta),
    warn: (message, meta) => emit('warn', moduleName, requestId, message, meta),
    error: (message, meta) => emit('error', moduleName, requestId, message, meta),
  }
}

/**
 * Build a logger for an API route handler, pulling the request id off the
 * x-request-id header middleware.ts already stamped onto every request.
 *
 * Usage:
 *   const log = createRequestLogger(request, 'api.users')
 *   log.info('creating user', { email })
 */
export function createRequestLogger(request: { headers: { get(name: string): string | null } }, moduleName: string): Logger {
  const requestId = request.headers.get('x-request-id') || '-'
  return createLogger(moduleName, requestId)
}
