import type { NextConfig } from 'next'

const nextConfig: NextConfig = {
  output: 'standalone',

  serverExternalPackages: ['neo4j-driver', 'pdfjs-dist', 'pdf-parse'],

  images: {
    remotePatterns: [],
    // The brand emblem ships as a first-party SVG (public/logo.svg). Next's
    // image optimizer refuses SVG unless explicitly allowed; these are our own
    // trusted assets, and the strict CSP + attachment disposition below defang
    // the usual risk of optimizing untrusted user-supplied SVGs.
    dangerouslyAllowSVG: true,
    contentDispositionType: 'attachment',
    contentSecurityPolicy: "default-src 'self'; script-src 'none'; sandbox;",
  },

  env: {
    NEO4J_URI: process.env.NEO4J_URI,
    NEO4J_USER: process.env.NEO4J_USER,
    NEO4J_PASSWORD: process.env.NEO4J_PASSWORD,
    NEXT_PUBLIC_NISARGHUNTER_VERSION: process.env.NEXT_PUBLIC_NISARGHUNTER_VERSION,
  },
}

export default nextConfig
