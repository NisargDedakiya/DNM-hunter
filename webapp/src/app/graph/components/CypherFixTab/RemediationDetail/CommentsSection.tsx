'use client'

import { useState } from 'react'
import { MessageSquare, Trash2, Send } from 'lucide-react'
import { useComments } from '@/hooks/useComments'
import styles from './RemediationDetail.module.css'

interface CommentsSectionProps {
  remediationId: string
  userId: string
}

function initials(name: string): string {
  return name.split(' ').map(p => p[0]).filter(Boolean).slice(0, 2).join('').toUpperCase() || '?'
}

function relativeTime(iso: string): string {
  const diffMs = Date.now() - new Date(iso).getTime()
  const mins = Math.floor(diffMs / 60_000)
  if (mins < 1) return 'just now'
  if (mins < 60) return `${mins}m ago`
  const hours = Math.floor(mins / 60)
  if (hours < 24) return `${hours}h ago`
  return new Date(iso).toLocaleDateString()
}

// Lightweight collaboration (Phase 12): a discussion thread on a finding so
// more than one hunter can work it together. No teams/roles/assignment
// model yet — every user with access to the project can comment.
export function CommentsSection({ remediationId, userId }: CommentsSectionProps) {
  const { comments, isLoading, addComment, isAdding, deleteComment } = useComments(remediationId)
  const [draft, setDraft] = useState('')

  const handlePost = () => {
    if (!draft.trim()) return
    addComment({ userId, body: draft.trim() })
    setDraft('')
  }

  return (
    <div className={styles.section}>
      <h4 className={styles.sectionTitle}>
        <MessageSquare size={14} />
        Comments {comments.length > 0 && `(${comments.length})`}
      </h4>

      {!isLoading && comments.length === 0 && (
        <p className={styles.evidenceEmpty}>No comments yet — start the discussion.</p>
      )}

      {comments.length > 0 && (
        <div className={styles.evidenceGrid} style={{ gridTemplateColumns: '1fr' }}>
          {comments.map(c => (
            <div key={c.id} className={styles.evidenceCard} style={{ flexDirection: 'row', alignItems: 'flex-start', gap: 'var(--space-2)', padding: 'var(--space-2)' }}>
              <span
                aria-hidden
                style={{
                  flexShrink: 0, width: 24, height: 24, borderRadius: '50%',
                  background: 'var(--accent-primary)', color: 'white', fontSize: 10, fontWeight: 600,
                  display: 'flex', alignItems: 'center', justifyContent: 'center',
                }}
              >
                {initials(c.user.name)}
              </span>
              <div style={{ flex: 1, minWidth: 0 }}>
                <div className={styles.evidenceCardMeta} style={{ padding: 0 }}>
                  <span className={styles.evidenceLabel} style={{ fontWeight: 600 }}>{c.user.name}</span>
                  <span style={{ fontSize: 10, color: 'var(--text-tertiary)' }}>{relativeTime(c.createdAt)}</span>
                  {c.userId === userId && (
                    <button className={styles.evidenceDeleteBtn} onClick={() => deleteComment(c.id)} aria-label="Delete comment">
                      <Trash2 size={11} />
                    </button>
                  )}
                </div>
                <p style={{ margin: '4px 0 0', fontSize: 'var(--text-xs)', color: 'var(--text-primary)', whiteSpace: 'pre-wrap' }}>{c.body}</p>
              </div>
            </div>
          ))}
        </div>
      )}

      <div className={styles.evidenceNoteForm}>
        <textarea
          className={styles.evidenceNoteText}
          placeholder="Add a comment…"
          rows={2}
          value={draft}
          onChange={e => setDraft(e.target.value)}
        />
        <button className={styles.evidenceUploadBtn} onClick={handlePost} disabled={!draft.trim() || isAdding}>
          <Send size={12} /> Post comment
        </button>
      </div>
    </div>
  )
}
