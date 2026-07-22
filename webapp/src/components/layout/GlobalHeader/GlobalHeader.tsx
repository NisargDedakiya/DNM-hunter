'use client'

import { useEffect, useRef, useState } from 'react'
import Image from 'next/image'
import Link from 'next/link'
import { usePathname } from 'next/navigation'
import {
  Crosshair, FolderOpen, Shield, BookOpen, TrendingUp, FileText, Settings, Users,
  GitBranch, LayoutDashboard, Radar, Sparkles, Store, Layers, MoreHorizontal,
} from 'lucide-react'
import { ThemeToggle } from '@/components/ThemeToggle'
import { ProjectSelector } from './ProjectSelector'
import { UserSelector } from './UserSelector'
import { useAuth } from '@/providers/AuthProvider'
import { useProject } from '@/providers/ProjectProvider'
import styles from './GlobalHeader.module.css'

interface NavLink {
  label: string
  href: string
  icon: React.ReactNode
}

export function GlobalHeader() {
  const pathname = usePathname()
  const { can } = useAuth()
  const { projectId } = useProject()
  const [moreOpen, setMoreOpen] = useState(false)
  const moreRef = useRef<HTMLDivElement>(null)

  // Close the overflow menu on outside click or route change.
  useEffect(() => {
    if (!moreOpen) return
    function onDown(e: MouseEvent) {
      if (moreRef.current && !moreRef.current.contains(e.target as Node)) setMoreOpen(false)
    }
    document.addEventListener('mousedown', onDown)
    return () => document.removeEventListener('mousedown', onDown)
  }, [moreOpen])
  useEffect(() => setMoreOpen(false), [pathname])

  // The five highest-frequency destinations stay in the bar; everything else
  // lives behind a tidy "More" menu so the header never becomes a wall of links.
  const primaryNav: NavLink[] = [
    { label: 'Dashboard', href: '/dashboard', icon: <LayoutDashboard size={15} /> },
    { label: 'Programs', href: '/programs', icon: <Radar size={15} /> },
    { label: 'Red Zone', href: '/graph', icon: <Crosshair size={15} /> },
    { label: 'Scans', href: '/scans', icon: <Radar size={15} /> },
    { label: 'Reports', href: '/reports', icon: <FileText size={15} /> },
  ]

  const moreNav: NavLink[] = [
    { label: 'Workspace', href: '/workspace', icon: <Layers size={15} /> },
    { label: 'CypherFix', href: '/cypherfix', icon: <Shield size={15} /> },
    { label: 'Insights', href: '/insights', icon: <TrendingUp size={15} /> },
    { label: 'Marketplace', href: '/marketplace', icon: <Store size={15} /> },
    { label: 'Academy', href: '/academy', icon: <BookOpen size={15} /> },
    ...(projectId
      ? [
          { label: 'Recon Pipeline', href: `/projects/${projectId}/settings`, icon: <GitBranch size={15} /> },
          { label: 'AI Summary', href: `/projects/${projectId}/summary`, icon: <Sparkles size={15} /> },
        ]
      : []),
  ]

  const isActive = (href: string) => pathname === href || pathname.startsWith(`${href}/`)
  const moreActive = moreNav.some((n) => isActive(n.href))

  return (
    <header className={styles.header}>
      <Link href="/overview" className={styles.logo}>
        <Image src="/logo.svg" alt="DNM-Hunter" width={26} height={26} className={styles.logoImg} />
        <span className={styles.logoText}>
          <span className={styles.logoAccent}>DNM</span>-HUNTER
        </span>
      </Link>

      <nav className={styles.primaryNav}>
        {primaryNav.map((item) => (
          <Link
            key={item.href}
            href={item.href}
            className={`${styles.navItem} ${isActive(item.href) ? styles.navItemActive : ''}`}
          >
            {item.icon}
            <span className={styles.navLabel}>{item.label}</span>
          </Link>
        ))}

        <div className={styles.moreWrap} ref={moreRef}>
          <button
            type="button"
            className={`${styles.navItem} ${moreActive ? styles.navItemActive : ''}`}
            onClick={() => setMoreOpen((v) => !v)}
            aria-haspopup="menu"
            aria-expanded={moreOpen}
          >
            <MoreHorizontal size={15} />
            <span className={styles.navLabel}>More</span>
          </button>
          {moreOpen && (
            <div className={styles.moreMenu}>
              {moreNav.map((item) => (
                <Link
                  key={item.href}
                  href={item.href}
                  className={`${styles.moreItem} ${isActive(item.href) ? styles.moreItemActive : ''}`}
                >
                  {item.icon}
                  <span>{item.label}</span>
                </Link>
              ))}
            </div>
          )}
        </div>
      </nav>

      <div className={styles.spacer} />

      <div className={styles.actions}>
        <Link
          href="/projects"
          className={`${styles.navItem} ${isActive('/projects') ? styles.navItemActive : ''}`}
        >
          <FolderOpen size={15} />
          <span className={styles.navLabel}>Projects</span>
        </Link>

        {can('users.manage') && (
          <Link
            href="/settings/users"
            className={`${styles.iconBtn} ${pathname === '/settings/users' ? styles.iconBtnActive : ''}`}
            title="Users"
          >
            <Users size={17} />
          </Link>
        )}

        <div className={styles.divider} />

        <ProjectSelector />

        <div className={styles.divider} />

        <ThemeToggle />

        <a
          href="https://github.com/samugit83/redamon/wiki"
          target="_blank"
          rel="noopener noreferrer"
          className={styles.iconBtn}
          title="Wiki Documentation"
        >
          <BookOpen size={17} />
        </a>

        <Link
          href="/settings"
          className={`${styles.iconBtn} ${pathname === '/settings' ? styles.iconBtnActive : ''}`}
          title="Global Settings"
        >
          <Settings size={17} />
        </Link>

        <div className={styles.divider} />

        <UserSelector />
      </div>
    </header>
  )
}
