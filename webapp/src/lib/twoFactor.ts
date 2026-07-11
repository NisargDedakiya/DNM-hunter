import { generateSecret, verify, generateURI } from 'otplib'
import QRCode from 'qrcode'
import { randomBytes } from 'crypto'

const ISSUER = 'NisargHunter AI'

export function generateTotpSecret(): string {
  return generateSecret()
}

export async function verifyTotpToken(secret: string, token: string): Promise<boolean> {
  try {
    const result = await verify({ secret, token })
    return result.valid
  } catch {
    return false
  }
}

export async function generateQrCodeDataUri(email: string, secret: string): Promise<string> {
  const otpauthUrl = generateURI({ secret, label: email, issuer: ISSUER })
  return QRCode.toDataURL(otpauthUrl)
}

/** 8 backup codes, 10 hex chars each, formatted as XXXX-XXXXXX for readability. */
export function generateBackupCodes(count = 8): string[] {
  return Array.from({ length: count }, () => {
    const raw = randomBytes(5).toString('hex')
    return `${raw.slice(0, 4)}-${raw.slice(4)}`.toUpperCase()
  })
}
