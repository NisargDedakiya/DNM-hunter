'use client'

import { Sidebar } from '../Sidebar'
import { TopBar } from '../TopBar'
import { Footer } from '../Footer'
import { DisclaimerGate } from '../DisclaimerGate'
import { UpdateNotification } from '../UpdateNotification'
import styles from './AppLayout.module.css'

interface AppLayoutProps {
  children: React.ReactNode
}

export function AppLayout({ children }: AppLayoutProps) {
  return (
    <div className={styles.layout}>
      <Sidebar />
      <div className={styles.body}>
        <TopBar />
        <main className={styles.main}>
          <DisclaimerGate>{children}</DisclaimerGate>
        </main>
        <Footer />
      </div>
      <UpdateNotification />
    </div>
  )
}
