'use client'

import { useRef, useState } from 'react'
import { Camera, FileText, Trash2, Upload, Bot, User } from 'lucide-react'
import { useEvidence } from '@/hooks/useEvidence'
import styles from './RemediationDetail.module.css'

interface EvidenceGalleryProps {
  remediationId: string
}

function readFileAsBase64(file: File): Promise<string> {
  return new Promise((resolve, reject) => {
    const reader = new FileReader()
    reader.onload = () => resolve(reader.result as string)
    reader.onerror = reject
    reader.readAsDataURL(file)
  })
}

// Manual evidence-capture panel — screenshots and text notes an operator
// attaches to a finding. This is the operator-facing half of Phase 10's
// evidence pipeline; the agent side (MCP execute_playwright screenshot mode)
// writes through the same /api/remediations/{id}/evidence endpoint tagged
// source="agent", so both surfaces converge on one gallery.
export function EvidenceGallery({ remediationId }: EvidenceGalleryProps) {
  const { evidence, isLoading, attachScreenshot, attachNote, deleteEvidence, isAttaching } = useEvidence(remediationId)
  const [noteText, setNoteText] = useState('')
  const [noteLabel, setNoteLabel] = useState('')
  const fileInputRef = useRef<HTMLInputElement>(null)

  const handleFileChange = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0]
    if (!file) return
    const base64 = await readFileAsBase64(file)
    attachScreenshot({ imageBase64: base64, label: file.name })
    if (fileInputRef.current) fileInputRef.current.value = ''
  }

  const handleAddNote = () => {
    if (!noteText.trim()) return
    attachNote({ textContent: noteText.trim(), label: noteLabel.trim() })
    setNoteText('')
    setNoteLabel('')
  }

  return (
    <div className={styles.section}>
      <h4 className={styles.sectionTitle}>
        <Camera size={14} />
        Evidence Gallery {evidence.length > 0 && `(${evidence.length})`}
      </h4>

      <div className={styles.subsection}>
        <input
          ref={fileInputRef}
          type="file"
          accept="image/png,image/jpeg"
          onChange={handleFileChange}
          style={{ display: 'none' }}
        />
        <button
          className={styles.evidenceUploadBtn}
          onClick={() => fileInputRef.current?.click()}
          disabled={isAttaching}
        >
          <Upload size={12} /> Attach screenshot
        </button>
      </div>

      <div className={styles.subsection}>
        <div className={styles.evidenceNoteForm}>
          <input
            className={styles.evidenceNoteLabel}
            placeholder="Label (optional)"
            value={noteLabel}
            onChange={e => setNoteLabel(e.target.value)}
          />
          <textarea
            className={styles.evidenceNoteText}
            placeholder="Paste a request/response, terminal output, or any other text evidence..."
            rows={3}
            value={noteText}
            onChange={e => setNoteText(e.target.value)}
          />
          <button className={styles.evidenceUploadBtn} onClick={handleAddNote} disabled={!noteText.trim() || isAttaching}>
            <FileText size={12} /> Add note
          </button>
        </div>
      </div>

      {!isLoading && evidence.length === 0 && (
        <p className={styles.evidenceEmpty}>No evidence attached yet.</p>
      )}

      {evidence.length > 0 && (
        <div className={styles.evidenceGrid}>
          {evidence.map(item => (
            <div key={item.id} className={styles.evidenceCard}>
              {item.type === 'screenshot' ? (
                <a href={`/api/remediations/${remediationId}/evidence/${item.id}`} target="_blank" rel="noreferrer">
                  <img
                    className={styles.evidenceThumb}
                    src={`/api/remediations/${remediationId}/evidence/${item.id}`}
                    alt={item.label || 'evidence screenshot'}
                  />
                </a>
              ) : (
                <pre className={styles.evidenceNotePreview}>{item.textContent}</pre>
              )}
              <div className={styles.evidenceCardMeta}>
                <span title={item.source === 'agent' ? 'Captured by AI agent' : 'Attached manually'}>
                  {item.source === 'agent' ? <Bot size={11} /> : <User size={11} />}
                </span>
                <span className={styles.evidenceLabel}>{item.label || (item.type === 'screenshot' ? 'Screenshot' : 'Note')}</span>
                <button
                  className={styles.evidenceDeleteBtn}
                  onClick={() => deleteEvidence(item.id)}
                  aria-label="Delete evidence"
                >
                  <Trash2 size={11} />
                </button>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}
