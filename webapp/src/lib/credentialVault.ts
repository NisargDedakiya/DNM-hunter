import crypto from 'crypto'

/**
 * Encryption at rest for the auth credential vault (Phase 07). These rows
 * hold live session cookies/JWTs/OAuth tokens for the *target* application
 * under test, not the user's own account -- a leak here can enable account
 * takeover on someone else's product. That's a materially higher bar than
 * the plaintext-in-Postgres convention the rest of the app's API-key fields
 * use today, so this gets its own AES-256-GCM layer rather than following
 * that precedent forward.
 *
 * Key: CREDENTIAL_VAULT_ENCRYPTION_KEY, a 32-byte key as 64 hex chars
 * (generate with `openssl rand -hex 32`, same convention as AUTH_SECRET).
 */

const ALGORITHM = 'aes-256-gcm'
const IV_LENGTH = 12 // GCM standard nonce size

function getKey(): Buffer {
  const hex = process.env.CREDENTIAL_VAULT_ENCRYPTION_KEY
  if (!hex || hex === 'changeme') {
    throw new Error('CREDENTIAL_VAULT_ENCRYPTION_KEY environment variable is not set')
  }
  const key = Buffer.from(hex, 'hex')
  if (key.length !== 32) {
    throw new Error('CREDENTIAL_VAULT_ENCRYPTION_KEY must be 32 bytes (64 hex characters)')
  }
  return key
}

/** Encrypt a plaintext string. Returns `iv:authTag:ciphertext`, all hex. */
export function encryptSecret(plaintext: string): string {
  if (!plaintext) return ''
  const key = getKey()
  const iv = crypto.randomBytes(IV_LENGTH)
  const cipher = crypto.createCipheriv(ALGORITHM, key, iv)
  const encrypted = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()])
  const authTag = cipher.getAuthTag()
  return `${iv.toString('hex')}:${authTag.toString('hex')}:${encrypted.toString('hex')}`
}

/** Decrypt a string produced by encryptSecret(). Returns '' for empty input. */
export function decryptSecret(payload: string): string {
  if (!payload) return ''
  const parts = payload.split(':')
  if (parts.length !== 3) {
    throw new Error('Malformed encrypted payload')
  }
  const [ivHex, authTagHex, dataHex] = parts
  const key = getKey()
  const decipher = crypto.createDecipheriv(ALGORITHM, key, Buffer.from(ivHex, 'hex'))
  decipher.setAuthTag(Buffer.from(authTagHex, 'hex'))
  const decrypted = Buffer.concat([decipher.update(Buffer.from(dataHex, 'hex')), decipher.final()])
  return decrypted.toString('utf8')
}

/** Mask a secret for list views: show first 4 / last 2 chars, redact the rest. */
export function maskSecretPreview(plaintext: string): string {
  if (!plaintext) return ''
  if (plaintext.length <= 8) return '••••••••'
  return `${plaintext.slice(0, 4)}••••${plaintext.slice(-2)}`
}
