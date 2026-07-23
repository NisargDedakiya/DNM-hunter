'use client'

import { useState, FormEvent } from 'react'
import Link from 'next/link'
import Image from 'next/image'
import { useVersionCheck } from '@/hooks/useVersionCheck'
import styles from '../login/page.module.css'

export default function RegisterPage() {
  const { currentVersion } = useVersionCheck()
  const [name, setName] = useState('')
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [confirm, setConfirm] = useState('')
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)

  async function handleSubmit(e: FormEvent) {
    e.preventDefault()
    setError('')

    if (password !== confirm) {
      setError('Passwords do not match')
      return
    }
    if (password.length < 8) {
      setError('Password must be at least 8 characters')
      return
    }

    setLoading(true)
    try {
      const res = await fetch('/api/auth/register', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name, email, password }),
      })

      if (!res.ok) {
        const data = await res.json().catch(() => ({}))
        setError(data.error || 'Registration failed')
        setLoading(false)
        return
      }

      // Registration signs the user in (sets the auth cookie). Force a full
      // page reload so middleware sees the new cookie.
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
            <Image src="/logo_icon.png" alt="DNM-Hunter" width={44} height={44} priority />
            <span className={styles.logoText}>
              <span className={styles.logoAccent}>DNM</span>-HUNTER
            </span>
          </div>
          <p className={styles.tagline}>Hunt bugs. Secure future.</p>
          <p className={styles.subtitle}>Create your account</p>
        </div>

        <div className={styles.body}>
          <form className={styles.form} onSubmit={handleSubmit}>
            {error && <div className={styles.error}>{error}</div>}

            <div className={styles.field}>
              <label htmlFor="name" className={styles.label}>Name</label>
              <input
                id="name"
                type="text"
                className={styles.input}
                placeholder="Your name"
                value={name}
                onChange={e => setName(e.target.value)}
                required
                autoFocus
                autoComplete="name"
              />
            </div>

            <div className={styles.field}>
              <label htmlFor="email" className={styles.label}>Email</label>
              <input
                id="email"
                type="email"
                className={styles.input}
                placeholder="you@example.com"
                value={email}
                onChange={e => setEmail(e.target.value)}
                required
                autoComplete="email"
              />
            </div>

            <div className={styles.field}>
              <label htmlFor="password" className={styles.label}>Password</label>
              <input
                id="password"
                type="password"
                className={styles.input}
                placeholder="At least 8 characters"
                value={password}
                onChange={e => setPassword(e.target.value)}
                required
                minLength={8}
                autoComplete="new-password"
              />
            </div>

            <div className={styles.field}>
              <label htmlFor="confirm" className={styles.label}>Confirm password</label>
              <input
                id="confirm"
                type="password"
                className={styles.input}
                placeholder="Re-enter your password"
                value={confirm}
                onChange={e => setConfirm(e.target.value)}
                required
                autoComplete="new-password"
              />
            </div>

            <button
              type="submit"
              className={styles.submitButton}
              disabled={loading || !name || !email || !password || !confirm}
            >
              {loading ? 'Creating account...' : 'Create Account'}
            </button>

            <div className={styles.altAction}>
              <span>Already have an account?</span>
              <Link href="/login" className={styles.altLink}>Sign in</Link>
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
