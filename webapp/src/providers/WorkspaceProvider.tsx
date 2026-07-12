'use client'

import { createContext, useContext, useState, useEffect, useCallback, ReactNode } from 'react'
import { useSearchParams, useRouter, usePathname } from 'next/navigation'
import { useProject } from './ProjectProvider'

// The Workspace is the top-level container of the master-plan Phase 1 spine:
// Workspace -> Program -> Scope -> Assets -> Recon -> Findings -> Evidence ->
// Reports. This provider tracks the active workspace + active program and keeps
// them in sync with the URL (?ws=..&program=..) and localStorage, mirroring the
// existing ProjectProvider pattern so pages read context rather than prop-drill.

export interface WorkspaceSummary {
  id: string
  name: string
  description: string
  _count?: { programs: number }
}

interface WorkspaceContextValue {
  workspaces: WorkspaceSummary[]
  activeWorkspaceId: string | null
  activeProgramId: string | null
  setActiveWorkspaceId: (id: string | null) => void
  setActiveProgramId: (id: string | null) => void
  refreshWorkspaces: () => void
  isLoading: boolean
}

const WorkspaceContext = createContext<WorkspaceContextValue | null>(null)

const STORAGE_KEY_WS = 'nisarghunter-active-workspace'
const STORAGE_KEY_PROGRAM = 'nisarghunter-active-program'

export function WorkspaceProvider({ children }: { children: ReactNode }) {
  const { userId } = useProject()
  const searchParams = useSearchParams()
  const router = useRouter()
  const pathname = usePathname()

  const [workspaces, setWorkspaces] = useState<WorkspaceSummary[]>([])
  const [activeWorkspaceId, setActiveWorkspaceIdState] = useState<string | null>(null)
  const [activeProgramId, setActiveProgramIdState] = useState<string | null>(null)
  const [isLoading, setIsLoading] = useState(true)
  const [reloadToken, setReloadToken] = useState(0)

  const refreshWorkspaces = useCallback(() => setReloadToken(t => t + 1), [])

  // Load the current user's workspaces whenever the user (or a manual refresh) changes.
  useEffect(() => {
    if (!userId) {
      setWorkspaces([])
      setIsLoading(false)
      return
    }
    let cancelled = false
    setIsLoading(true)
    fetch(`/api/workspaces?userId=${encodeURIComponent(userId)}`)
      .then(res => (res.ok ? res.json() : []))
      .then((list: WorkspaceSummary[]) => {
        if (cancelled) return
        setWorkspaces(Array.isArray(list) ? list : [])
      })
      .catch(() => { if (!cancelled) setWorkspaces([]) })
      .finally(() => { if (!cancelled) setIsLoading(false) })
    return () => { cancelled = true }
  }, [userId, reloadToken])

  // Resolve the active workspace from URL -> localStorage -> first available,
  // once the workspace list is known. Keeps a valid selection at all times.
  useEffect(() => {
    if (isLoading) return
    const fromUrl = searchParams.get('ws')
    const fromStorage = typeof window !== 'undefined' ? localStorage.getItem(STORAGE_KEY_WS) : null
    const candidate = [fromUrl, fromStorage, workspaces[0]?.id].find(
      id => id && workspaces.some(w => w.id === id),
    ) ?? null
    setActiveWorkspaceIdState(candidate)

    const progUrl = searchParams.get('program')
    const progStorage = typeof window !== 'undefined' ? localStorage.getItem(STORAGE_KEY_PROGRAM) : null
    setActiveProgramIdState(progUrl || progStorage || null)
    // Intentionally not depending on searchParams beyond first resolution to
    // avoid clobbering an in-page selection; explicit setters own URL updates.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [isLoading, workspaces])

  const syncUrl = useCallback((ws: string | null, program: string | null) => {
    // Only rewrite the URL on pages that actually walk the spine, so we don't
    // pollute unrelated routes' query strings.
    if (!(pathname.startsWith('/programs') || pathname.startsWith('/dashboard') || pathname.startsWith('/workspace'))) return
    const params = new URLSearchParams(searchParams.toString())
    if (ws) params.set('ws', ws); else params.delete('ws')
    if (program) params.set('program', program); else params.delete('program')
    const qs = params.toString()
    router.replace(qs ? `${pathname}?${qs}` : pathname, { scroll: false })
  }, [pathname, searchParams, router])

  const setActiveWorkspaceId = useCallback((id: string | null) => {
    setActiveWorkspaceIdState(id)
    // Switching workspace clears the active program — it belonged to the old one.
    setActiveProgramIdState(null)
    if (typeof window !== 'undefined') {
      if (id) localStorage.setItem(STORAGE_KEY_WS, id); else localStorage.removeItem(STORAGE_KEY_WS)
      localStorage.removeItem(STORAGE_KEY_PROGRAM)
    }
    syncUrl(id, null)
  }, [syncUrl])

  const setActiveProgramId = useCallback((id: string | null) => {
    setActiveProgramIdState(id)
    if (typeof window !== 'undefined') {
      if (id) localStorage.setItem(STORAGE_KEY_PROGRAM, id); else localStorage.removeItem(STORAGE_KEY_PROGRAM)
    }
    syncUrl(activeWorkspaceId, id)
  }, [syncUrl, activeWorkspaceId])

  return (
    <WorkspaceContext.Provider value={{
      workspaces,
      activeWorkspaceId,
      activeProgramId,
      setActiveWorkspaceId,
      setActiveProgramId,
      refreshWorkspaces,
      isLoading,
    }}>
      {children}
    </WorkspaceContext.Provider>
  )
}

export function useWorkspace() {
  const context = useContext(WorkspaceContext)
  if (!context) {
    throw new Error('useWorkspace must be used within WorkspaceProvider')
  }
  return context
}
