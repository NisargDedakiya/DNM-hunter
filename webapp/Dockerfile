# ============================================
# NisargHunter AI Web Application - Production Dockerfile
# Multi-stage build for optimized production image
# ============================================

# Stage 1: Dependencies
FROM node:22-slim AS deps
RUN apt-get update && apt-get install -y --no-install-recommends \
        openssl ca-certificates \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app

# NOTE: build context is the REPO ROOT (see docker-compose.yml), so webapp files
# are addressed as webapp/… and the Python scanner packages are available too.
COPY webapp/package.json webapp/package-lock.json* ./
COPY webapp/prisma ./prisma
RUN npm ci --no-audit --no-fund && npm cache clean --force

# Stage 2: Builder
FROM node:22-slim AS builder
WORKDIR /app

COPY --from=deps /app/node_modules ./node_modules
COPY webapp/ ./

ARG NISARGHUNTER_VERSION=0.0.0
ENV NEXT_PUBLIC_NISARGHUNTER_VERSION=$NISARGHUNTER_VERSION
ENV NEXT_TELEMETRY_DISABLED=1
ENV NODE_ENV=production
# Dummy DATABASE_URL for Prisma client generation at build time (not used at runtime)
ENV DATABASE_URL="postgresql://build:build@localhost:5432/build"
ENV NODE_OPTIONS=--max-old-space-size=4096

RUN npm run build

# Stage 3: Runner (Production)
FROM node:22-slim AS runner
WORKDIR /app

ENV NODE_ENV=production
ENV NEXT_TELEMETRY_DISABLED=1

RUN apt-get update && apt-get install -y --no-install-recommends \
        openssl ca-certificates wget \
        python3 python3-pip git \
    && ln -sf /usr/bin/python3 /usr/local/bin/python \
    && rm -rf /var/lib/apt/lists/*

# Install the Python scanner suite so the in-app scan runner can spawn its CLIs
# (nh-web-probe / nh-web-attack / nh-scan / nh-mobile-audit …). The suite is
# stdlib-only (no PyPI runtime deps), installed with the runner's own Debian
# python3 so console-script shebangs + import paths stay consistent. git is
# needed for `nh-scan <github-url>` repo scans. The optional IaC parsers
# (python-hcl2, pyyaml) are best-effort so Terraform/YAML repo scans work too.
COPY pyproject.toml README.md /opt/scanner-src/
COPY scanner_suite  /opt/scanner-src/scanner_suite
COPY report_gen     /opt/scanner-src/report_gen
COPY code_audit     /opt/scanner-src/code_audit
COPY contract_audit /opt/scanner-src/contract_audit
COPY llm_audit      /opt/scanner-src/llm_audit
COPY os_audit       /opt/scanner-src/os_audit
COPY binary_audit   /opt/scanner-src/binary_audit
COPY deep_binary    /opt/scanner-src/deep_binary
COPY web_probe      /opt/scanner-src/web_probe
COPY web_attack     /opt/scanner-src/web_attack
COPY verify         /opt/scanner-src/verify
COPY vrt            /opt/scanner-src/vrt
COPY vuln_kb        /opt/scanner-src/vuln_kb
COPY mobile_audit   /opt/scanner-src/mobile_audit
COPY repo_scan      /opt/scanner-src/repo_scan
COPY iac_scan       /opt/scanner-src/iac_scan
RUN python3 -m pip install --no-cache-dir --break-system-packages /opt/scanner-src \
    && (python3 -m pip install --no-cache-dir --break-system-packages python-hcl2 pyyaml || true) \
    && rm -rf /opt/scanner-src \
    && python3 -c "import web_probe, web_attack, verify, scanner_suite" \
    && nh-web-probe --help >/dev/null \
    && echo "scanner suite installed OK (nh-web-probe on PATH)"

RUN groupadd --system --gid 1001 nodejs
RUN useradd --system --uid 1001 --gid nodejs --no-create-home nextjs

COPY --from=builder /app/public ./public

RUN mkdir .next
RUN chown nextjs:nodejs .next

# Pre-create data dirs so named volumes inherit correct ownership
RUN mkdir -p /data/reports && chown nextjs:nodejs /data/reports
RUN mkdir -p /data/evidence && chown nextjs:nodejs /data/evidence
RUN mkdir -p /data/js-recon-uploads && chown nextjs:nodejs /data/js-recon-uploads
RUN mkdir -p /data/js-recon-custom && chown nextjs:nodejs /data/js-recon-custom

# Headless Chromium for server-side HTML->PDF report rendering (Phase 10,
# webapp/src/lib/report/pdfRenderer.ts). Installed to a fixed, known path so
# it survives independent of node_modules layout; --with-deps pulls the
# Debian shared libraries Chromium needs (fonts, libnss3, etc). Same
# version-pinning trick as the prisma CLI install above.
ENV PLAYWRIGHT_BROWSERS_PATH=/opt/pw-browsers
COPY --from=builder /app/node_modules/playwright/package.json /tmp/playwright-pkg.json
RUN PW_VER=$(node -p "require('/tmp/playwright-pkg.json').version") && \
    npm install --no-save "playwright@${PW_VER}" && \
    npx playwright install --with-deps chromium && \
    npm cache clean --force && rm /tmp/playwright-pkg.json

# Leverage output traces to reduce image size
# https://nextjs.org/docs/advanced-features/output-file-tracing
COPY --from=builder --chown=nextjs:nodejs /app/.next/standalone ./
COPY --from=builder --chown=nextjs:nodejs /app/.next/static ./.next/static

# CLI utility scripts (admin setup, password reset)
COPY --from=builder --chown=nextjs:nodejs /app/scripts ./scripts

# Prisma schema + CLI for automatic migration on startup
COPY --from=builder /app/prisma ./prisma
COPY --from=builder /app/node_modules/prisma/package.json /tmp/prisma-pkg.json
RUN PRISMA_VER=$(node -p "require('/tmp/prisma-pkg.json').version") && \
    npm install --no-save "prisma@${PRISMA_VER}" bcryptjs && \
    npm cache clean --force && rm /tmp/prisma-pkg.json

# Entrypoint: sync schema to PostgreSQL, then start server
RUN printf '#!/bin/sh\necho "Syncing Prisma schema..."\nnode node_modules/prisma/build/index.js db push --skip-generate --accept-data-loss --schema ./prisma/schema.prisma 2>&1\nexec node server.js\n' > /app/entrypoint.sh \
    && chmod +x /app/entrypoint.sh

USER nextjs

EXPOSE 3000

ENV PORT=3000
ENV HOSTNAME="0.0.0.0"

CMD ["/app/entrypoint.sh"]
