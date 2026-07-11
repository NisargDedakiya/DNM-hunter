'use client'

import { useState, useEffect, useCallback } from 'react'
import { Bell, Plus, Trash2, Send, Loader2 } from 'lucide-react'
import { useAlertModal, useToast } from '@/components/ui'
import styles from './NotificationsTab.module.css'

interface Props {
  userId: string
}

interface ChannelMeta {
  id: string
  name: string
  type: 'discord' | 'slack' | 'telegram' | 'webhook'
  enabled: boolean
  events: string[]
  configured: boolean
  lastTriggeredAt: string | null
  createdAt: string
}

const EVENT_OPTIONS = [
  { value: 'critical_finding', label: 'Critical finding' },
  { value: 'scan_complete', label: 'Scan complete' },
  { value: 'report_ready', label: 'Report ready' },
]

const TYPE_FIELDS: Record<ChannelMeta['type'], { key: string; label: string; placeholder: string }[]> = {
  discord: [{ key: 'webhookUrl', label: 'Webhook URL', placeholder: 'https://discord.com/api/webhooks/…' }],
  slack: [{ key: 'webhookUrl', label: 'Webhook URL', placeholder: 'https://hooks.slack.com/services/…' }],
  telegram: [
    { key: 'botToken', label: 'Bot token', placeholder: '123456:ABC-DEF...' },
    { key: 'chatId', label: 'Chat ID', placeholder: '-1001234567890' },
  ],
  webhook: [{ key: 'url', label: 'Webhook URL', placeholder: 'https://example.com/hook' }],
}

export default function NotificationsTab({ userId }: Props) {
  const toast = useToast()
  const { dangerConfirm } = useAlertModal()

  const [channels, setChannels] = useState<ChannelMeta[]>([])
  const [name, setName] = useState('')
  const [type, setType] = useState<ChannelMeta['type']>('discord')
  const [fieldValues, setFieldValues] = useState<Record<string, string>>({})
  const [selectedEvents, setSelectedEvents] = useState<string[]>(['critical_finding'])
  const [creating, setCreating] = useState(false)
  const [testingId, setTestingId] = useState<string | null>(null)
  const [testResults, setTestResults] = useState<Record<string, string>>({})

  const loadChannels = useCallback(async () => {
    const res = await fetch(`/api/users/${userId}/notification-channels`)
    if (res.ok) setChannels(await res.json())
  }, [userId])

  useEffect(() => { loadChannels() }, [loadChannels])

  const handleCreate = async () => {
    const fields = TYPE_FIELDS[type]
    const config: Record<string, string> = {}
    for (const f of fields) {
      if (!fieldValues[f.key]?.trim()) {
        toast.error(`${f.label} is required`)
        return
      }
      config[f.key] = fieldValues[f.key].trim()
    }

    setCreating(true)
    try {
      const res = await fetch(`/api/users/${userId}/notification-channels`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name: name.trim() || `${type} channel`, type, config, events: selectedEvents }),
      })
      const data = await res.json()
      if (!res.ok) throw new Error(data.error)
      toast.success('Notification channel created')
      setName('')
      setFieldValues({})
      await loadChannels()
    } catch (err) {
      toast.error(err instanceof Error ? err.message : 'Failed to create channel')
    } finally {
      setCreating(false)
    }
  }

  const handleToggle = async (channel: ChannelMeta) => {
    const res = await fetch(`/api/users/${userId}/notification-channels/${channel.id}`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ enabled: !channel.enabled }),
    })
    if (res.ok) loadChannels()
  }

  const handleDelete = async (channel: ChannelMeta) => {
    if (!(await dangerConfirm(`Delete notification channel "${channel.name}"?`))) return
    const res = await fetch(`/api/users/${userId}/notification-channels/${channel.id}`, { method: 'DELETE' })
    if (res.ok) { toast.success('Channel deleted'); loadChannels() } else { toast.error('Failed to delete channel') }
  }

  const handleTest = async (channel: ChannelMeta) => {
    setTestingId(channel.id)
    try {
      const res = await fetch(`/api/users/${userId}/notification-channels/${channel.id}/test`, { method: 'POST' })
      const data = await res.json()
      setTestResults(prev => ({ ...prev, [channel.id]: data.ok ? 'Sent successfully' : `Failed: ${data.error || res.status}` }))
    } catch {
      setTestResults(prev => ({ ...prev, [channel.id]: 'Failed: network error' }))
    } finally {
      setTestingId(null)
    }
  }

  const toggleEvent = (value: string) => {
    setSelectedEvents(prev => prev.includes(value) ? prev.filter(e => e !== value) : [...prev, value])
  }

  return (
    <div className={styles.section}>
      <h2 className={styles.sectionTitle}><Bell size={18} /> Notification Channels</h2>
      <p className={styles.sectionDescription}>
        Get pinged in Discord, Slack, Telegram, or any webhook endpoint when the agent finds something critical.
      </p>

      <div className={styles.form}>
        <div className={styles.row}>
          <input className={styles.input} placeholder="Channel name" value={name} onChange={e => setName(e.target.value)} />
          <select className={styles.select} value={type} onChange={e => { setType(e.target.value as ChannelMeta['type']); setFieldValues({}) }}>
            <option value="discord">Discord</option>
            <option value="slack">Slack</option>
            <option value="telegram">Telegram</option>
            <option value="webhook">Generic Webhook</option>
          </select>
        </div>
        {TYPE_FIELDS[type].map(f => (
          <input
            key={f.key}
            className={styles.input}
            placeholder={f.placeholder}
            value={fieldValues[f.key] || ''}
            onChange={e => setFieldValues(prev => ({ ...prev, [f.key]: e.target.value }))}
          />
        ))}
        <div className={styles.eventCheckboxes}>
          {EVENT_OPTIONS.map(opt => (
            <label key={opt.value} className={styles.checkboxLabel}>
              <input type="checkbox" checked={selectedEvents.includes(opt.value)} onChange={() => toggleEvent(opt.value)} />
              {opt.label}
            </label>
          ))}
        </div>
        <button className={styles.button} onClick={handleCreate} disabled={creating}>
          <Plus size={14} /> Add channel
        </button>
      </div>

      {channels.length === 0 ? (
        <p className={styles.empty}>No notification channels configured.</p>
      ) : (
        <div className={styles.list}>
          {channels.map(c => (
            <div key={c.id} className={styles.listItem}>
              <div className={styles.listItemMain}>
                <span className={styles.listItemTitle}>
                  <span className={styles.typeTag}>{c.type}</span>
                  {c.name}
                  {!c.enabled && <span style={{ color: 'var(--text-tertiary)' }}>(disabled)</span>}
                </span>
                <span className={styles.listItemMeta}>
                  events: {c.events.join(', ') || 'none'}
                  {c.lastTriggeredAt && ` · last sent ${new Date(c.lastTriggeredAt).toLocaleString()}`}
                </span>
                {testResults[c.id] && (
                  <span className={testResults[c.id].startsWith('Sent') ? styles.testResultOk : styles.testResultFail}>
                    {testResults[c.id]}
                  </span>
                )}
              </div>
              <div className={styles.listItemActions}>
                <button className={styles.buttonSecondary} onClick={() => handleTest(c)} disabled={testingId === c.id}>
                  {testingId === c.id ? <Loader2 size={12} /> : <Send size={12} />} Test
                </button>
                <button className={styles.buttonSecondary} onClick={() => handleToggle(c)}>
                  {c.enabled ? 'Disable' : 'Enable'}
                </button>
                <button className={styles.buttonSecondary} onClick={() => handleDelete(c)}>
                  <Trash2 size={12} />
                </button>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}
