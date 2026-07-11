'use client'

import { useMemo } from 'react'
import { BarChart, Bar, XAxis, YAxis, ResponsiveContainer, Tooltip, Legend } from 'recharts'
import { useTheme } from '@/hooks/useTheme'
import { getChartChrome, getSeverityPalette, getTooltipStyle, getTooltipItemStyle, getTooltipLabelStyle, getCursorStyle } from '../utils/chartTheme'
import { ChartCard } from './ChartCard'
import type { VulnerabilityData } from '../types'

interface SecurityModulesBarProps {
  data: VulnerabilityData['securityModules'] | undefined
  isLoading: boolean
}

const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low'] as const

export function SecurityModulesBar({ data, isLoading }: SecurityModulesBarProps) {
  const { theme } = useTheme()
  const chrome = useMemo(() => getChartChrome(), [theme])
  const severityPalette = useMemo(() => getSeverityPalette(), [theme])
  const tooltipStyle = useMemo(() => getTooltipStyle(), [theme])
  const tooltipItemStyle = useMemo(() => getTooltipItemStyle(), [theme])
  const tooltipLabelStyle = useMemo(() => getTooltipLabelStyle(), [theme])
  const cursorStyle = useMemo(() => getCursorStyle(), [theme])

  const { chartData, total } = useMemo(() => {
    const modules = ['IaC / DevOps', 'Cloud Storage', 'Mobile APK'] as const
    const rows = modules.map(module => {
      const row: Record<string, string | number> = { module }
      for (const sev of SEVERITY_ORDER) row[sev] = 0
      return row
    })
    const indexByModule = new Map(modules.map((m, i) => [m, i]))
    let sum = 0
    for (const entry of data ?? []) {
      const idx = indexByModule.get(entry.module)
      if (idx === undefined) continue
      const key = entry.severity?.toLowerCase()
      if (!SEVERITY_ORDER.includes(key as (typeof SEVERITY_ORDER)[number])) continue
      rows[idx][key] = (rows[idx][key] as number) + entry.count
      sum += entry.count
    }
    return { chartData: rows, total: sum }
  }, [data])

  return (
    <ChartCard
      title="Security Modules (IaC, Cloud, Mobile)"
      subtitle={`${total} finding${total === 1 ? '' : 's'} across DevOps config, cloud storage & APK scans`}
      isLoading={isLoading}
      isEmpty={total === 0}
    >
      <ResponsiveContainer width="100%" height={220}>
        <BarChart data={chartData} layout="vertical" margin={{ left: 4, right: 16, top: 8, bottom: 8 }}>
          <XAxis type="number" tick={{ fontSize: 11, fill: chrome.axisColor }} axisLine={false} tickLine={false} allowDecimals={false} />
          <YAxis
            type="category"
            dataKey="module"
            tick={{ fontSize: 11, fill: chrome.axisColor }}
            axisLine={false}
            tickLine={false}
            width={90}
          />
          <Tooltip
            cursor={cursorStyle}
            contentStyle={tooltipStyle}
            itemStyle={tooltipItemStyle}
            labelStyle={tooltipLabelStyle}
          />
          <Legend wrapperStyle={{ fontSize: 11 }} />
          {SEVERITY_ORDER.map(sev => (
            <Bar
              key={sev}
              dataKey={sev}
              stackId="severity"
              fill={severityPalette[sev]}
              name={sev.charAt(0).toUpperCase() + sev.slice(1)}
              maxBarSize={22}
            />
          ))}
        </BarChart>
      </ResponsiveContainer>
    </ChartCard>
  )
}
