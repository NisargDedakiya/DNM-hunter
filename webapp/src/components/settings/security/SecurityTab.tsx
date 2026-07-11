'use client'

import { useState, useEffect, useCallback } from 'react'
import { ShieldCheck, KeyRound, Plus, Trash2, Loader2, Copy, Check, ScrollText } from 'lucide-react'
import { useAlertModal, useToast } from '@/components/ui'
import styles from './SecurityTab.module.css'

interface Props {
  userId: string
  isAdmin: boolean
}

interface ApiTokenMeta {
  id: string
  name: string
  tokenPrefix: string
  lastUsedAt: string | null
  expiresAt: string | null
  revokedAt: string | null
  createdAt: string
}

interface AuditLogEntry {
  id: string
  action: string
  resourceType: string
  resourceId: string
  createdAt: string
  user?: { name: string; email: string } | null
}

export default function SecurityTab({ userId, isAdmin }: Props) {
  const toast = useToast()
  const { dangerConfirm } = useAlertModal()

  // ── API Tokens ──
  const [tokens, setTokens] = useState<ApiTokenMeta[]>([])
  const [tokenName, setTokenName] = useState('')
  const [creatingToken, setCreatingToken] = useState(false)
  const [revealedToken, setRevealedToken] = useState<string | null>(null)
  const [copied, setCopied] = useState(false)

  const loadTokens = useCallback(async () => {
    const res = await fetch(`/api/users/${userId}/api-tokens`)
    if (res.ok) setTokens(await res.json())
  }, [userId])

  useEffect(() => { loadTokens() }, [loadTokens])

  const handleCreateToken = async () => {
    setCreatingToken(true)
    try {
      const res = await fetch(`/api/users/${userId}/api-tokens`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name: tokenName.trim() || 'Unnamed token' }),
      })
      const data = await res.json()
      if (!res.ok) throw new Error(data.error)
      setRevealedToken(data.token)
      setTokenName('')
      await loadTokens()
    } catch (err) {
      toast.error(err instanceof Error ? err.message : 'Failed to create token')
    } finally {
      setCreatingToken(false)
    }
  }

  const handleRevokeToken = async (id: string, name: string) => {
    if (!(await dangerConfirm(`Revoke token "${name}"? Anything using it will stop working immediately.`))) return
    const res = await fetch(`/api/users/${userId}/api-tokens/${id}`, { method: 'DELETE' })
    if (res.ok) { toast.success('Token revoked'); loadTokens() } else { toast.error('Failed to revoke token') }
  }

  const handleCopyToken = async () => {
    if (!revealedToken) return
    await navigator.clipboard.writeText(revealedToken)
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }

  // ── 2FA ──
  const [twoFactorEnabled, setTwoFactorEnabled] = useState(false)
  const [qrCode, setQrCode] = useState<string | null>(null)
  const [backupCodes, setBackupCodes] = useState<string[] | null>(null)
  const [totpInput, setTotpInput] = useState('')
  const [twoFactorBusy, setTwoFactorBusy] = useState(false)

  const loadTwoFactorStatus = useCallback(async () => {
    const res = await fetch(`/api/users/${userId}`)
    if (res.ok) {
      const user = await res.json()
      setTwoFactorEnabled(!!user.twoFactorEnabled)
    }
  }, [userId])

  useEffect(() => { loadTwoFactorStatus() }, [loadTwoFactorStatus])

  const handleStartTwoFactorSetup = async () => {
    setTwoFactorBusy(true)
    try {
      const res = await fetch(`/api/users/${userId}/2fa/setup`, { method: 'POST' })
      const data = await res.json()
      if (!res.ok) throw new Error(data.error)
      setQrCode(data.qrCode)
      setBackupCodes(data.backupCodes)
    } catch (err) {
      toast.error(err instanceof Error ? err.message : 'Failed to start 2FA setup')
    } finally {
      setTwoFactorBusy(false)
    }
  }

  const handleVerifyTwoFactor = async () => {
    setTwoFactorBusy(true)
    try {
      const res = await fetch(`/api/users/${userId}/2fa/verify`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ token: totpInput.trim() }),
      })
      const data = await res.json()
      if (!res.ok) throw new Error(data.error)
      toast.success('2FA enabled')
      setTwoFactorEnabled(true)
      setQrCode(null)
      setTotpInput('')
    } catch (err) {
      toast.error(err instanceof Error ? err.message : 'Invalid code')
    } finally {
      setTwoFactorBusy(false)
    }
  }

  const handleDisableTwoFactor = async () => {
    if (!(await dangerConfirm('Disable two-factor authentication?'))) return
    setTwoFactorBusy(true)
    try {
      const res = await fetch(`/api/users/${userId}/2fa/disable`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ token: totpInput.trim() }),
      })
      const data = await res.json()
      if (!res.ok) throw new Error(data.error)
      toast.success('2FA disabled')
      setTwoFactorEnabled(false)
      setTotpInput('')
    } catch (err) {
      toast.error(err instanceof Error ? err.message : 'Invalid code')
    } finally {
      setTwoFactorBusy(false)
    }
  }

  // ── Audit log (admin only, global) ──
  const [auditLog, setAuditLog] = useState<AuditLogEntry[] | null>(null)
  const loadAuditLog = useCallback(async () => {
    const res = await fetch('/api/audit-log?limit=50')
    if (res.ok) setAuditLog(await res.json())
  }, [])
  useEffect(() => { if (isAdmin) loadAuditLog() }, [isAdmin, loadAuditLog])

  return (
    <div>
      <div className={styles.section}>
        <h2 className={styles.sectionTitle}><ShieldCheck size={18} /> Two-Factor Authentication</h2>
        <p className={styles.sectionDescription}>
          Require a TOTP code (Google Authenticator, 1Password, etc.) in addition to your password at login.
        </p>

        {twoFactorEnabled ? (
          <div className={styles.row}>
            <span className={styles.badgeEnabled}>Enabled</span>
            <input
              className={styles.input}
              placeholder="Current 6-digit code to disable"
              value={totpInput}
              onChange={e => setTotpInput(e.target.value)}
              maxLength={6}
            />
            <button className={styles.buttonDanger} onClick={handleDisableTwoFactor} disabled={twoFactorBusy || totpInput.length !== 6}>
              Disable 2FA
            </button>
          </div>
        ) : qrCode ? (
          <div className={styles.row} style={{ flexDirection: 'column', alignItems: 'flex-start' }}>
            {/* eslint-disable-next-line @next/next/no-img-element */}
            <img src={qrCode} alt="2FA QR code" className={styles.qrCode} />
            {backupCodes && (
              <>
                <p className={styles.sectionDescription}>Save these backup codes somewhere safe — each works once if you lose your authenticator.</p>
                <div className={styles.backupCodes}>
                  {backupCodes.map(c => <span key={c}>{c}</span>)}
                </div>
              </>
            )}
            <div className={styles.row}>
              <input
                className={styles.input}
                placeholder="6-digit code from your app"
                value={totpInput}
                onChange={e => setTotpInput(e.target.value)}
                maxLength={6}
              />
              <button className={styles.button} onClick={handleVerifyTwoFactor} disabled={twoFactorBusy || totpInput.length !== 6}>
                {twoFactorBusy ? <Loader2 size={14} /> : null} Verify & Enable
              </button>
            </div>
          </div>
        ) : (
          <div className={styles.row}>
            <span className={styles.badgeDisabled}>Disabled</span>
            <button className={styles.button} onClick={handleStartTwoFactorSetup} disabled={twoFactorBusy}>
              Set up 2FA
            </button>
          </div>
        )}
      </div>

      <div className={styles.section}>
        <div className={styles.row} style={{ justifyContent: 'space-between' }}>
          <h2 className={styles.sectionTitle}><KeyRound size={18} /> API Tokens</h2>
        </div>
        <p className={styles.sectionDescription}>
          Bearer tokens for programmatic/CI access — send as <code>Authorization: Bearer &lt;token&gt;</code>.
          The full value is shown only once, right after creation.
        </p>

        {revealedToken && (
          <div className={styles.tokenReveal}>
            <span className={styles.sectionDescription}>Copy this now — you won&apos;t be able to see it again.</span>
            <div className={styles.row}>
              <span className={styles.tokenValue}>{revealedToken}</span>
              <button className={styles.buttonSecondary} onClick={handleCopyToken}>
                {copied ? <Check size={14} /> : <Copy size={14} />}
              </button>
            </div>
          </div>
        )}

        <div className={styles.row}>
          <input
            className={styles.input}
            placeholder="Token name (e.g. CI pipeline)"
            value={tokenName}
            onChange={e => setTokenName(e.target.value)}
          />
          <button className={styles.button} onClick={handleCreateToken} disabled={creatingToken}>
            <Plus size={14} /> Create token
          </button>
        </div>

        {tokens.length === 0 ? (
          <p className={styles.empty}>No API tokens yet.</p>
        ) : (
          <div className={styles.list}>
            {tokens.map(t => (
              <div key={t.id} className={styles.listItem}>
                <div className={styles.listItemMain}>
                  <span className={styles.listItemTitle}>{t.name}</span>
                  <span className={styles.listItemMeta}>
                    {t.tokenPrefix}… · created {new Date(t.createdAt).toLocaleDateString()}
                    {t.lastUsedAt && ` · last used ${new Date(t.lastUsedAt).toLocaleDateString()}`}
                  </span>
                </div>
                {t.revokedAt ? (
                  <span className={styles.badgeRevoked}>Revoked</span>
                ) : (
                  <button className={styles.buttonSecondary} onClick={() => handleRevokeToken(t.id, t.name)}>
                    <Trash2 size={13} /> Revoke
                  </button>
                )}
              </div>
            ))}
          </div>
        )}
      </div>

      {isAdmin && (
        <div className={styles.section}>
          <h2 className={styles.sectionTitle}><ScrollText size={18} /> Audit Log</h2>
          <p className={styles.sectionDescription}>Global security/activity log — last 50 events.</p>
          {!auditLog ? (
            <p className={styles.empty}>Loading…</p>
          ) : auditLog.length === 0 ? (
            <p className={styles.empty}>No events recorded yet.</p>
          ) : (
            <table className={styles.auditTable}>
              <thead>
                <tr><th>When</th><th>Action</th><th>User</th><th>Resource</th></tr>
              </thead>
              <tbody>
                {auditLog.map(entry => (
                  <tr key={entry.id}>
                    <td>{new Date(entry.createdAt).toLocaleString()}</td>
                    <td>{entry.action}</td>
                    <td>{entry.user?.email || '—'}</td>
                    <td>{entry.resourceType ? `${entry.resourceType}${entry.resourceId ? `:${entry.resourceId.slice(0, 8)}` : ''}` : '—'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      )}
    </div>
  )
}
