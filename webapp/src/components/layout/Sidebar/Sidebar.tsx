'use client'

import { useEffect, useState } from 'react'
import Image from 'next/image'
import Link from 'next/link'
import { usePathname } from 'next/navigation'
import {
  Home, LayoutDashboard, Radar, Crosshair, Target, Shield, TrendingUp, FileText,
  Layers, Store, BookOpen, FolderOpen, Users, Settings, PanelLeftClose, PanelLeftOpen,
} from 'lucide-react'
import { ThemeToggle } from '@/components/ThemeToggle'
import { UserSelector } from '../GlobalHeader/UserSelector'
import { useAuth } from '@/providers/AuthProvider'
import { useProject } from '@/providers/ProjectProvider'
import styles from './Sidebar.module.css'

interface NavItem {
  label: string
  href: string
  icon: React.ReactNode
}
interface NavGroup {
  title: string
  items: NavItem[]
}

const COLLAPSE_KEY = 'dnmhunter-sidebar-collapsed'

export function Sidebar() {
  const pathname = usePathname()
  const { can } = useAuth()
  const { projectId } = useProject()
  const [collapsed, setCollapsed] = useState(false)
  const [mounted, setMounted] = useState(false)

  useEffect(() => {
    setMounted(true)
    try {
      setCollapsed(localStorage.getItem(COLLAPSE_KEY) === '1')
    } catch { /* ignore */ }
  }, [])

  const toggle = () => {
    setCollapsed((v) => {
      const next = !v
      try { localStorage.setItem(COLLAPSE_KEY, next ? '1' : '0') } catch { /* ignore */ }
      return next
    })
  }

  const groups: NavGroup[] = [
    {
      title: 'Hunt',
      items: [
        { label: 'Home', href: '/overview', icon: <Home size={18} /> },
        { label: 'Dashboard', href: '/dashboard', icon: <LayoutDashboard size={18} /> },
        { label: 'Programs', href: '/programs', icon: <Radar size={18} /> },
        { label: 'Scans', href: '/scans', icon: <Target size={18} /> },
        { label: 'Bug Hunter', href: '/hunt', icon: <Crosshair size={18} /> },
        { label: 'Red Zone', href: '/graph', icon: <Crosshair size={18} /> },
      ],
    },
    {
      title: 'Analyze',
      items: [
        { label: 'CypherFix', href: '/cypherfix', icon: <Shield size={18} /> },
        { label: 'Insights', href: '/insights', icon: <TrendingUp size={18} /> },
        { label: 'Reports', href: '/reports', icon: <FileText size={18} /> },
      ],
    },
    {
      title: 'Platform',
      items: [
        { label: 'Workspace', href: '/workspace', icon: <Layers size={18} /> },
        { label: 'Marketplace', href: '/marketplace', icon: <Store size={18} /> },
        { label: 'Academy', href: '/academy', icon: <BookOpen size={18} /> },
        { label: 'Projects', href: '/projects', icon: <FolderOpen size={18} /> },
      ],
    },
  ]

  const isActive = (href: string) => pathname === href || pathname.startsWith(`${href}/`)

  return (
    <aside className={`${styles.sidebar} ${collapsed ? styles.collapsed : ''} ${mounted ? styles.ready : ''}`}>
      {/* Brand — sized so the full emblem is always visible */}
      <div className={styles.brand}>
        <Link href="/overview" className={styles.brandLink} title="DNM-Hunter">
          <Image src="/logo_icon.png" alt="DNM-Hunter" width={40} height={40} className={styles.brandLogo} priority />
          {!collapsed && (
            <span className={styles.brandText}>
              <span className={styles.brandAccent}>DNM</span>-HUNTER
            </span>
          )}
        </Link>
        <button type="button" className={styles.collapseBtn} onClick={toggle} title={collapsed ? 'Expand' : 'Collapse'} aria-label="Toggle sidebar">
          {collapsed ? <PanelLeftOpen size={18} /> : <PanelLeftClose size={18} />}
        </button>
      </div>

      <nav className={styles.nav}>
        {groups.map((group) => (
          <div key={group.title} className={styles.group}>
            {!collapsed && <p className={styles.groupTitle}>{group.title}</p>}
            {group.items.map((item) => (
              <Link
                key={item.href}
                href={item.href}
                className={`${styles.item} ${isActive(item.href) ? styles.itemActive : ''}`}
                title={collapsed ? item.label : undefined}
              >
                <span className={styles.itemIcon}>{item.icon}</span>
                {!collapsed && <span className={styles.itemLabel}>{item.label}</span>}
                {isActive(item.href) && <span className={styles.activeBar} aria-hidden />}
              </Link>
            ))}
          </div>
        ))}

        {projectId && (
          <div className={styles.group}>
            {!collapsed && <p className={styles.groupTitle}>Project</p>}
            <Link href={`/projects/${projectId}/settings`} className={`${styles.item} ${isActive(`/projects/${projectId}/settings`) ? styles.itemActive : ''}`} title={collapsed ? 'Recon Pipeline' : undefined}>
              <span className={styles.itemIcon}><Radar size={18} /></span>
              {!collapsed && <span className={styles.itemLabel}>Recon Pipeline</span>}
            </Link>
          </div>
        )}
      </nav>

      <div className={styles.footer}>
        {can('users.manage') && (
          <Link href="/settings/users" className={`${styles.item} ${pathname === '/settings/users' ? styles.itemActive : ''}`} title={collapsed ? 'Users' : undefined}>
            <span className={styles.itemIcon}><Users size={18} /></span>
            {!collapsed && <span className={styles.itemLabel}>Users</span>}
          </Link>
        )}
        <Link href="/settings" className={`${styles.item} ${pathname === '/settings' ? styles.itemActive : ''}`} title={collapsed ? 'Settings' : undefined}>
          <span className={styles.itemIcon}><Settings size={18} /></span>
          {!collapsed && <span className={styles.itemLabel}>Settings</span>}
        </Link>
        <div className={styles.footerRow}>
          <ThemeToggle />
          {!collapsed && <UserSelector />}
        </div>
        {collapsed && <div className={styles.footerRow}><UserSelector /></div>}
      </div>
    </aside>
  )
}
