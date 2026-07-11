import { randomBytes, createHash } from 'crypto'

const TOKEN_PREFIX = 'nh_'

/** Generate a new raw bearer token. Only ever returned to the caller once —
 *  the DB stores hashToken(raw), never the raw value. */
export function generateApiToken(): string {
  return TOKEN_PREFIX + randomBytes(32).toString('base64url')
}

export function hashApiToken(raw: string): string {
  return createHash('sha256').update(raw).digest('hex')
}

/** First 8 chars after the prefix, for display ("nh_a1b2c3d4…"). */
export function tokenPreview(raw: string): string {
  return raw.slice(0, TOKEN_PREFIX.length + 8) + '…'
}
