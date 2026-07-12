import type { Metadata } from 'next'
import { Suspense } from 'react'
import '@/styles/index.css'
import { QueryProvider } from '@/providers/QueryProvider'
import { AuthProvider } from '@/providers/AuthProvider'
import { ProjectProvider } from '@/providers/ProjectProvider'
import { WorkspaceProvider } from '@/providers/WorkspaceProvider'
import { ToastProvider, AlertProvider } from '@/components/ui'
import { AppLayout } from '@/components/layout'
import { ThemeDbBridge } from '@/components/ThemeDbBridge'

export const metadata: Metadata = {
  title: 'NisargHunter AI',
  description: 'Security reconnaissance and vulnerability assessment dashboard',
  icons: {
    icon: '/favicon.ico',
    apple: '/favicon.png',
  },
}

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode
}>) {
  return (
    <html lang="en" suppressHydrationWarning>
      <head>
        {/* Prevent flash of wrong theme */}
        <script
          dangerouslySetInnerHTML={{
            __html: `
              (function() {
                try {
                  var theme = localStorage.getItem('nisarghunter-theme');
                  if (theme === 'dark' || theme === 'light') {
                    document.documentElement.setAttribute('data-theme', theme);
                  } else if (window.matchMedia('(prefers-color-scheme: light)').matches) {
                    document.documentElement.setAttribute('data-theme', 'light');
                  } else {
                    document.documentElement.setAttribute('data-theme', 'dark');
                  }
                } catch (e) {
                  document.documentElement.setAttribute('data-theme', 'dark');
                }
              })();
            `,
          }}
        />
      </head>
      <body>
        <QueryProvider>
          <Suspense fallback={null}>
            <AuthProvider>
              <ThemeDbBridge />
              <ProjectProvider>
                <WorkspaceProvider>
                  <ToastProvider>
                    <AlertProvider>
                      <AppLayout>{children}</AppLayout>
                    </AlertProvider>
                  </ToastProvider>
                </WorkspaceProvider>
              </ProjectProvider>
            </AuthProvider>
          </Suspense>
        </QueryProvider>
      </body>
    </html>
  )
}
