'use client'

import { BookOpen } from 'lucide-react'
import { ProjectSelector } from '../GlobalHeader/ProjectSelector'
import styles from './TopBar.module.css'

export function TopBar() {
  return (
    <header className={styles.topbar}>
      <ProjectSelector />
      <div className={styles.spacer} />
      <a
        href="https://github.com/NisargDedakiya/DNM-hunter/wiki"
        target="_blank"
        rel="noopener noreferrer"
        className={styles.iconBtn}
        title="Wiki Documentation"
      >
        <BookOpen size={17} />
      </a>
    </header>
  )
}
