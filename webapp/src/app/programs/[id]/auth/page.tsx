'use client'

import { useState } from 'react'
import { useParams, useRouter } from 'next/navigation'
import Link from 'next/link'
import { ArrowLeft, Plus, Trash2, Send, KeyRound, Loader2 } from 'lucide-react'
import {
  useAuthCredentials, useCreateCredential, useDeleteCredential,
  replayRequest, AUTH_TYPES, type ReplayResult,
} from '@/hooks/useAuthCredentials'
import { Modal, useAlertModal, useToast } from '@/components/ui'
import styles from './page.module.css'

export default function ProgramAuthManagerPage() {
  const params = useParams()
  const router = useRouter()
  const programId = typeof params.id === 'string' ? params.id : null

  const { data: credentials, isLoading } = useAuthCredentials(programId)
  const createMutation = useCreateCredential()
  const deleteMutation = useDeleteCredential()
  const { dangerConfirm } = useAlertModal()
  const toast = useToast()

  const [showNew, setShowNew] = useState(false)
  const [form, setForm] = useState({
    label: '', role: '', authType: 'cookie', cookies: '', jwt: '', headers: '', oauthToken: '', notes: '',
  })

  const [replayMethod, setReplayMethod] = useState('GET')
  const [replayUrl, setReplayUrl] = useState('')
  const [replayHeaders, setReplayHeaders] = useState('')
  const [replayBody, setReplayBody] = useState('')
  const [replayCredentialId, setReplayCredentialId] = useState('')
  const [replaying, setReplaying] = useState(false)
  const [replayResult, setReplayResult] = useState<ReplayResult | null>(null)
  const [replayError, setReplayError] = useState('')

  if (!programId) return null

  const handleCreate = async () => {
    if (!form.label.trim()) return
    let headersObj: Record<string, string> | undefined
    if (form.headers.trim()) {
      try {
        headersObj = JSON.parse(form.headers)
      } catch {
        toast.error('Custom headers must be valid JSON, e.g. {"X-Api-Key": "..."}')
        return
      }
    }
    try {
      await createMutation.mutateAsync({
        programId,
        data: {
          label: form.label.trim(), role: form.role, authType: form.authType,
          cookies: form.cookies || undefined, jwt: form.jwt || undefined,
          headers: headersObj, oauthToken: form.oauthToken || undefined, notes: form.notes || undefined,
        },
      })
      setShowNew(false)
      setForm({ label: '', role: '', authType: 'cookie', cookies: '', jwt: '', headers: '', oauthToken: '', notes: '' })
      toast.success('Identity stored')
    } catch (error) {
      toast.error(error instanceof Error ? error.message : 'Failed to store identity')
    }
  }

  const handleDelete = async (id: string, label: string) => {
    if (await dangerConfirm(`Delete stored identity "${label}"? This cannot be undone.`)) {
      await deleteMutation.mutateAsync({ programId, credentialId: id })
      toast.success('Identity deleted')
    }
  }

  const handleReplay = async () => {
    if (!replayUrl.trim()) return
    let headersObj: Record<string, string> | undefined
    if (replayHeaders.trim()) {
      try {
        headersObj = JSON.parse(replayHeaders)
      } catch {
        toast.error('Request headers must be valid JSON')
        return
      }
    }
    setReplaying(true)
    setReplayError('')
    setReplayResult(null)
    try {
      const result = await replayRequest(programId, {
        method: replayMethod, url: replayUrl.trim(), headers: headersObj,
        body: replayBody || undefined, credentialId: replayCredentialId || undefined,
      })
      setReplayResult(result)
    } catch (error) {
      setReplayError(error instanceof Error ? error.message : 'Replay failed')
    } finally {
      setReplaying(false)
    }
  }

  return (
    <div className={styles.page}>
      <div className={styles.header}>
        <button className={styles.backButton} onClick={() => router.push(`/programs/${programId}`)}>
          <ArrowLeft size={14} /> Back to program
        </button>
        <h1 className={styles.title}><KeyRound size={18} /> Auth Manager</h1>
        <p className={styles.subtitle}>
          Stored identities for the target under test — cookies, JWTs, headers, OAuth tokens.
          Use Replay below to re-issue the same request as different identities for IDOR/BOLA checks.
        </p>
      </div>

      <div className={styles.grid}>
        <section className={styles.panel}>
          <div className={styles.panelHeader}>
            <h2 className={styles.panelTitle}>Stored identities ({credentials?.length ?? 0})</h2>
            <button className={styles.addButton} onClick={() => setShowNew(true)}>
              <Plus size={14} /> Add identity
            </button>
          </div>
          {isLoading && <p className={styles.emptyState}>Loading…</p>}
          {!isLoading && (!credentials || credentials.length === 0) && (
            <p className={styles.emptyState}>No stored identities yet. Add one to enable cross-account replay.</p>
          )}
          <ul className={styles.credList}>
            {credentials?.map(cred => (
              <li key={cred.id} className={styles.credItem}>
                <div className={styles.credInfo}>
                  <span className={styles.credLabel}>{cred.label}</span>
                  {cred.role && <span className={styles.credRole}>{cred.role}</span>}
                  <span className={styles.credType}>{cred.authType}</span>
                </div>
                <div className={styles.credFlags}>
                  {cred.hasCookies && <span className={styles.flag}>cookie</span>}
                  {cred.hasJwt && <span className={styles.flag}>jwt</span>}
                  {cred.hasHeaders && <span className={styles.flag}>headers</span>}
                  {cred.hasOauthToken && <span className={styles.flag}>oauth</span>}
                </div>
                <button className={styles.credDelete} onClick={() => handleDelete(cred.id, cred.label)} aria-label={`Delete ${cred.label}`}>
                  <Trash2 size={13} />
                </button>
              </li>
            ))}
          </ul>
        </section>

        <section className={styles.panel}>
          <h2 className={styles.panelTitle}><Send size={15} /> Replay</h2>
          <p className={styles.hint}>
            Capture a request, pick an identity, send it. Re-run with a different identity to diff responses.
          </p>
          <div className={styles.replayRow}>
            <select className={styles.methodSelect} value={replayMethod} onChange={e => setReplayMethod(e.target.value)}>
              {['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD'].map(m => <option key={m} value={m}>{m}</option>)}
            </select>
            <input
              className={styles.urlInput}
              value={replayUrl}
              onChange={e => setReplayUrl(e.target.value)}
              placeholder="https://target.example.com/api/orders/123"
            />
          </div>
          <label className={styles.label}>
            Identity
            <select className={styles.input} value={replayCredentialId} onChange={e => setReplayCredentialId(e.target.value)}>
              <option value="">No identity (as-is request)</option>
              {credentials?.map(c => <option key={c.id} value={c.id}>{c.label}{c.role ? ` (${c.role})` : ''}</option>)}
            </select>
          </label>
          <label className={styles.label}>
            Extra headers (JSON, optional)
            <textarea className={styles.textarea} rows={2} value={replayHeaders} onChange={e => setReplayHeaders(e.target.value)} placeholder='{"X-Custom": "value"}' />
          </label>
          {!['GET', 'HEAD'].includes(replayMethod) && (
            <label className={styles.label}>
              Body
              <textarea className={styles.textarea} rows={3} value={replayBody} onChange={e => setReplayBody(e.target.value)} placeholder='{"key": "value"}' />
            </label>
          )}
          <button className={styles.sendButton} onClick={handleReplay} disabled={!replayUrl.trim() || replaying}>
            {replaying ? <Loader2 size={14} className={styles.spin} /> : <Send size={14} />} Send
          </button>

          {replayError && <p className={styles.replayError}>{replayError}</p>}
          {replayResult && (
            <div className={styles.replayResult}>
              <div className={styles.replayStatus}>
                <span className={`${styles.statusBadge} ${replayResult.response.status < 400 ? styles.statusOk : styles.statusErr}`}>
                  {replayResult.response.status} {replayResult.response.statusText}
                </span>
                <span className={styles.timing}>{replayResult.timingMs}ms · {replayResult.response.bodyLength} bytes</span>
              </div>
              <pre className={styles.replayBody}>{replayResult.response.body || '(empty body)'}</pre>
            </div>
          )}
        </section>
      </div>

      <Modal
        isOpen={showNew}
        onClose={() => setShowNew(false)}
        title="Add identity"
        footer={
          <>
            <button className={styles.secondaryButton} onClick={() => setShowNew(false)}>Cancel</button>
            <button className={styles.addButton} onClick={handleCreate} disabled={!form.label.trim() || createMutation.isPending}>
              Save
            </button>
          </>
        }
      >
        <div className={styles.form}>
          <label className={styles.label}>
            Label
            <input className={styles.input} value={form.label} onChange={e => setForm({ ...form, label: e.target.value })} placeholder="Admin user" autoFocus />
          </label>
          <div className={styles.row}>
            <label className={styles.label}>
              Role
              <input className={styles.input} value={form.role} onChange={e => setForm({ ...form, role: e.target.value })} placeholder="admin" />
            </label>
            <label className={styles.label}>
              Auth type
              <select className={styles.input} value={form.authType} onChange={e => setForm({ ...form, authType: e.target.value })}>
                {AUTH_TYPES.map(t => <option key={t.value} value={t.value}>{t.label}</option>)}
              </select>
            </label>
          </div>
          <label className={styles.label}>
            Cookies
            <textarea className={styles.textarea} rows={2} value={form.cookies} onChange={e => setForm({ ...form, cookies: e.target.value })} placeholder="session=...; role=..." />
          </label>
          <label className={styles.label}>
            JWT
            <textarea className={styles.textarea} rows={2} value={form.jwt} onChange={e => setForm({ ...form, jwt: e.target.value })} placeholder="eyJhbGciOi..." />
          </label>
          <label className={styles.label}>
            OAuth token
            <textarea className={styles.textarea} rows={2} value={form.oauthToken} onChange={e => setForm({ ...form, oauthToken: e.target.value })} />
          </label>
          <label className={styles.label}>
            Custom headers (JSON)
            <textarea className={styles.textarea} rows={2} value={form.headers} onChange={e => setForm({ ...form, headers: e.target.value })} placeholder='{"X-Api-Key": "..."}' />
          </label>
          <label className={styles.label}>
            Notes
            <textarea className={styles.textarea} rows={2} value={form.notes} onChange={e => setForm({ ...form, notes: e.target.value })} placeholder="SAML IdP config ref, MFA backup location, etc." />
          </label>
        </div>
      </Modal>
    </div>
  )
}
