/**
 * Renders the report's self-contained HTML string (reportTemplate.ts) to a
 * PDF buffer using a headless Chromium instance. No new report-building
 * logic — this reuses the exact same HTML the browser-viewable report
 * already generates and just prints it.
 *
 * Requires Chromium to be installed and discoverable via Playwright's
 * PLAYWRIGHT_BROWSERS_PATH convention (installed in the webapp Docker image
 * via `npx playwright install --with-deps chromium`, see Dockerfile).
 */

import { chromium } from 'playwright'

export async function renderHtmlToPdf(html: string): Promise<Buffer> {
  const browser = await chromium.launch({ headless: true })
  try {
    const page = await browser.newPage()
    await page.setContent(html, { waitUntil: 'networkidle' })
    const pdf = await page.pdf({
      format: 'A4',
      printBackground: true,
      margin: { top: '12mm', bottom: '14mm', left: '10mm', right: '10mm' },
    })
    return Buffer.from(pdf)
  } finally {
    await browser.close()
  }
}
