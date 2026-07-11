/**
 * In-memory token-bucket rate limiter.
 *
 * The webapp runs as a single long-lived Next.js container (see
 * docker-compose.yml `webapp` service), not distributed serverless/edge —
 * an in-process Map is a correct, sufficient store here. This mirrors the
 * Phase 13 decision to defer Redis: introduce shared external state once an
 * actual multi-instance deployment creates the need for it, not ahead of it.
 *
 * Edge-runtime compatible: no Node built-ins, just Map/Date.
 */

export interface RateLimitTier {
  /** Max requests allowed per window. */
  limit: number
  /** Window size in milliseconds. */
  windowMs: number
}

export interface RateLimitResult {
  allowed: boolean
  limit: number
  remaining: number
  /** Unix ms timestamp when the bucket is expected to have a free token. */
  resetAt: number
}

interface Bucket {
  tokens: number
  lastRefill: number
}

const buckets = new Map<string, Bucket>()

// Opportunistic cleanup so long-idle keys don't accumulate forever. Runs at
// most once per this interval, on whichever request happens to trigger it.
const CLEANUP_INTERVAL_MS = 5 * 60_000
let lastCleanup = Date.now()

function cleanupStaleBuckets(now: number) {
  if (now - lastCleanup < CLEANUP_INTERVAL_MS) return
  lastCleanup = now
  for (const [key, bucket] of buckets) {
    // A bucket idle for 10x its own window is safe to drop — it will have
    // fully refilled to max tokens again well before that.
    if (now - bucket.lastRefill > CLEANUP_INTERVAL_MS * 2) {
      buckets.delete(key)
    }
  }
}

/**
 * Consume one token from the named bucket, refilling proportionally to
 * elapsed time since the last check. Returns whether the request is allowed.
 */
export function consumeRateLimit(key: string, tier: RateLimitTier): RateLimitResult {
  const now = Date.now()
  cleanupStaleBuckets(now)

  let bucket = buckets.get(key)
  if (!bucket) {
    bucket = { tokens: tier.limit, lastRefill: now }
    buckets.set(key, bucket)
  } else {
    const elapsed = now - bucket.lastRefill
    if (elapsed > 0) {
      const refillRate = tier.limit / tier.windowMs
      bucket.tokens = Math.min(tier.limit, bucket.tokens + elapsed * refillRate)
      bucket.lastRefill = now
    }
  }

  if (bucket.tokens >= 1) {
    bucket.tokens -= 1
    return { allowed: true, limit: tier.limit, remaining: Math.floor(bucket.tokens), resetAt: now + tier.windowMs }
  }

  const msUntilNextToken = (1 - bucket.tokens) / (tier.limit / tier.windowMs)
  return { allowed: false, limit: tier.limit, remaining: 0, resetAt: now + msUntilNextToken }
}

/** Test-only: clear all bucket state between test cases. */
export function _resetRateLimitState() {
  buckets.clear()
  lastCleanup = Date.now()
}

function envInt(name: string, fallback: number): number {
  const raw = process.env[name]
  if (!raw) return fallback
  const parsed = parseInt(raw, 10)
  return Number.isFinite(parsed) && parsed > 0 ? parsed : fallback
}

// Configurable via env — same "make everything configurable" convention
// used elsewhere in the project settings system.
export const RATE_LIMIT_TIERS: Record<'auth' | 'default', RateLimitTier> = {
  auth: {
    limit: envInt('RATE_LIMIT_AUTH_MAX', 10),
    windowMs: envInt('RATE_LIMIT_AUTH_WINDOW_MS', 60_000),
  },
  default: {
    limit: envInt('RATE_LIMIT_DEFAULT_MAX', 300),
    windowMs: envInt('RATE_LIMIT_DEFAULT_WINDOW_MS', 60_000),
  },
}

const AUTH_TIER_PATHS = ['/api/auth/login', '/api/auth/login-2fa']

export function tierForPath(pathname: string): RateLimitTier {
  if (AUTH_TIER_PATHS.some(p => pathname === p || pathname.startsWith(p + '/'))) {
    return RATE_LIMIT_TIERS.auth
  }
  return RATE_LIMIT_TIERS.default
}
