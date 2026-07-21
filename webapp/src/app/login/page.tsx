'use client'

import { useState, FormEvent } from 'react'
import { useRouter } from 'next/navigation'
import Link from 'next/link'
import Image from 'next/image'
import { useVersionCheck } from '@/hooks/useVersionCheck'
import styles from './page.module.css'

export default function LoginPage() {
  const router = useRouter()
  const { currentVersion } = useVersionCheck()
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)

  async function handleSubmit(e: FormEvent) {
    e.preventDefault()
    setError('')
    setLoading(true)

    try {
      const res = await fetch('/api/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, password }),
      })

      if (!res.ok) {
        const data = await res.json()
        setError(data.error || 'Login failed')
        setLoading(false)
        return
      }

      // Force full page reload to pick up the new cookie in middleware
      window.location.href = '/overview'
    } catch {
      setError('Unable to connect to the server')
      setLoading(false)
    }
  }

  return (
    <div className={styles.page}>
      <Image
        src="/logo.svg"
        alt=""
        width={520}
        height={520}
        className={styles.watermark}
        priority
      />

      <div className={styles.card}>
        <div className={styles.header}>
          <div className={styles.logoRow}>
            <Image src="/logo.svg" alt="DNM-Hunter" width={44} height={44} priority />
            <span className={styles.logoText}>
              <span className={styles.logoAccent}>DNM</span>-HUNTER
            </span>
          </div>
          <p className={styles.tagline}>Hunt bugs. Secure future.</p>
          <p className={styles.subtitle}>Sign in to your account</p>
        </div>

        <div className={styles.body}>
          <form className={styles.form} onSubmit={handleSubmit}>
            {error && <div className={styles.error}>{error}</div>}

            <div className={styles.field}>
              <label htmlFor="email" className={styles.label}>Email</label>
              <input
                id="email"
                type="email"
                className={styles.input}
                placeholder="admin@nisarghunter.local"
                value={email}
                onChange={e => setEmail(e.target.value)}
                required
                autoFocus
                autoComplete="email"
              />
            </div>

            <div className={styles.field}>
              <label htmlFor="password" className={styles.label}>Password</label>
              <input
                id="password"
                type="password"
                className={styles.input}
                placeholder="Enter your password"
                value={password}
                onChange={e => setPassword(e.target.value)}
                required
                autoComplete="current-password"
              />
            </div>

            <button
              type="submit"
              className={styles.submitButton}
              disabled={loading || !email || !password}
            >
              {loading ? 'Signing in...' : 'Sign In'}
            </button>

            <div className={styles.altAction}>
              <span>Don&apos;t have an account?</span>
              <Link href="/register" className={styles.altLink}>Register</Link>
            </div>
          </form>
        </div>

        <div className={styles.footer}>
          <span className={styles.version}>v{currentVersion}</span>
        </div>
      </div>
    </div>
  )
}
