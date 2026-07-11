/**
 * Outbound notification adapters (Phase 12). Each channel type formats and
 * sends the same logical event (critical finding, scan complete, report
 * ready) in its own platform's expected shape.
 */

export type NotificationChannelType = 'discord' | 'slack' | 'telegram' | 'webhook'

export interface DiscordConfig { webhookUrl: string }
export interface SlackConfig { webhookUrl: string }
export interface TelegramConfig { botToken: string; chatId: string }
export interface WebhookConfig { url: string; headers?: Record<string, string> }

export type ChannelConfig = DiscordConfig | SlackConfig | TelegramConfig | WebhookConfig

export interface NotificationPayload {
  event: string // e.g. "critical_finding" | "scan_complete" | "report_ready"
  title: string
  message: string
  url?: string // deep link back into the app, when relevant
}

interface SendResult {
  ok: boolean
  status?: number
  error?: string
}

async function postJson(url: string, body: unknown, headers?: Record<string, string>): Promise<SendResult> {
  try {
    const res = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', ...headers },
      body: JSON.stringify(body),
      signal: AbortSignal.timeout(10_000),
    })
    if (!res.ok) {
      return { ok: false, status: res.status, error: await res.text().catch(() => res.statusText) }
    }
    return { ok: true, status: res.status }
  } catch (err) {
    return { ok: false, error: err instanceof Error ? err.message : 'Request failed' }
  }
}

async function sendDiscord(config: DiscordConfig, payload: NotificationPayload): Promise<SendResult> {
  const content = `**${payload.title}**\n${payload.message}${payload.url ? `\n${payload.url}` : ''}`
  return postJson(config.webhookUrl, { content })
}

async function sendSlack(config: SlackConfig, payload: NotificationPayload): Promise<SendResult> {
  const text = `*${payload.title}*\n${payload.message}${payload.url ? `\n${payload.url}` : ''}`
  return postJson(config.webhookUrl, { text })
}

async function sendTelegram(config: TelegramConfig, payload: NotificationPayload): Promise<SendResult> {
  const text = `${payload.title}\n${payload.message}${payload.url ? `\n${payload.url}` : ''}`
  return postJson(`https://api.telegram.org/bot${config.botToken}/sendMessage`, { chat_id: config.chatId, text })
}

async function sendWebhook(config: WebhookConfig, payload: NotificationPayload): Promise<SendResult> {
  return postJson(config.url, payload, config.headers)
}

export async function sendNotification(
  type: NotificationChannelType,
  config: ChannelConfig,
  payload: NotificationPayload
): Promise<SendResult> {
  switch (type) {
    case 'discord': return sendDiscord(config as DiscordConfig, payload)
    case 'slack': return sendSlack(config as SlackConfig, payload)
    case 'telegram': return sendTelegram(config as TelegramConfig, payload)
    case 'webhook': return sendWebhook(config as WebhookConfig, payload)
  }
}
