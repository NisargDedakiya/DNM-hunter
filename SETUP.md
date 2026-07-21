# NisargHunter AI — Setup & Running (Windows, macOS, Linux)

This guide answers a common question — **"can I run this on Windows?"** — and gives
you three ways to run it depending on what you need.

## Short answer

**Yes.** The recommended way on Windows is **Docker Desktop with the WSL2 backend**
(the whole platform is containerised). You can also run the **standalone scanner
suite** (`nh-scan`) in a single container with zero host installs, or run the
scanner + web app **natively** on Windows with a couple of Linux-only exceptions.

## What runs where

| Component | Windows (Docker Desktop / WSL2) | Windows native (no Docker) | Linux / macOS |
|-----------|:---:|:---:|:---:|
| **Scanner suite** — SAST, IaC, Solidity, LLM Top 10, secrets, live-HTTP (`nh-scan`, `nh-web-probe`) | ✅ | ✅ | ✅ |
| **Web app** — dashboard, scans, bug-hunter, subscriptions | ✅ | ✅ (needs Node + Postgres) | ✅ |
| **Report export** — Markdown / HTML / SARIF | ✅ | ✅ | ✅ |
| **binary_audit** — ELF hardening (`readelf`/`nm`) | ✅ | ⚠️ Linux tools only | ✅ |
| **os_audit host agent** — reads `/proc`, SUID inventory | ✅ (inside a Linux container) | ❌ Linux-only | ✅ |
| **deep_binary** — angr symbolic execution | ✅ (optional extra) | ⚠️ hard to install | ✅ |
| **Full offensive stack** — Kali tools, nuclei, sqlmap, OpenVAS/GVM, the AI agent | ✅ | ❌ needs Linux/Docker | ✅ |

> The offensive/recon half (Kali sandbox, GVM, the autonomous agent) is
> fundamentally Linux + Docker. On Windows that means Docker Desktop — which is
> exactly what Option A below uses.

---

## Option A — Full platform via Docker Desktop (recommended on Windows)

Runs everything: web app, PostgreSQL, Neo4j, the scanners, and the agent.

**Prerequisites**
1. Install **[Docker Desktop](https://www.docker.com/products/docker-desktop/)** and,
   when prompted, **enable the WSL2 backend** (Settings → General → *Use the WSL 2
   based engine*). Install a WSL2 distro (`wsl --install` in an admin PowerShell)
   if you don't have one.
2. Give Docker Desktop enough resources (Settings → Resources): **≥ 8 GB RAM**
   (16 GB recommended if you enable GVM/OpenVAS).

**Run** — from a **WSL2 shell** (Ubuntu), clone into the Linux filesystem
(`~/…`, not `/mnt/c/…`, for speed and correct file permissions):

```bash
git clone https://github.com/NisargDedakiya/DNM-hunter.git
cd DNM-hunter
cp .env.example .env          # then edit secrets/LLM keys as needed
./nisarghunter.sh install     # builds images and starts the core stack
```

Or drive Compose directly:

```bash
docker compose up -d          # core services
docker compose ps             # check health
```

Open the web app at **http://localhost:3000** and sign in.

> **Windows path note:** always work inside the WSL2 filesystem. The orchestrator
> already handles Windows-style Docker Desktop paths (see the `sibling_host_path`
> fix in the CHANGELOG), but bind-mount performance and permissions are far better
> under `~/` than under `/mnt/c/`.

---

## Option B — Scanner suite only (`nh-scan`) — one container, zero installs

If you just want the **VRT-mapped scanner and reports** (the product a bug hunter
or pentester uses day-to-day), build the dedicated image — every tool the scanners
need is pre-installed.

```powershell
# from the repo root
docker build -f Dockerfile.scanner -t nisarghunter-scan .
```

**Scan a folder** (mount it read-only at `/target`):

```powershell
# PowerShell (Windows)
docker run --rm -v "${PWD}:/target" nisarghunter-scan nh-scan /target
```
```bash
# Linux / macOS / WSL2 / Git-Bash
docker run --rm -v "$PWD:/target" nisarghunter-scan nh-scan /target
```

**Produce a report** (writes into the mounted folder):

```powershell
docker run --rm -v "${PWD}:/target" nisarghunter-scan nh-scan /target --format html -o /target/report.html
docker run --rm -v "${PWD}:/target" nisarghunter-scan nh-scan /target --format sarif -o /target/report.sarif
```

**Other entry points** (all on the image's PATH):

```powershell
docker run --rm nisarghunter-scan nh-web-probe https://example.com   # live-HTTP (DAST)
docker run --rm nisarghunter-scan python -m vrt.coverage             # VRT coverage
docker run --rm -v "${PWD}:/target" nisarghunter-scan nh-code-audit /target
```

**CI gate** — `--fail-on <severity>` exits non-zero when a finding at/above that
level exists (drop it into a pipeline step):

```bash
docker run --rm -v "$PWD:/target" nisarghunter-scan nh-scan /target --fail-on high
```

What's pre-installed in the image: Python 3.12, the scanner suite (`nh-*`
console scripts), `python-hcl2` (Terraform IaC rules), and **binutils** +
**gcc** + **git** (for ELF binary analysis and repo cloning). Deep symbolic
execution (angr) is a heavy optional extra — add it with
`pip install ".[deep-binary]"` in a derived image if you need `deep_binary`.

---

## Option C — Native (no Docker): scanner + web app

Works on Windows/macOS/Linux for the scanner and web app. The Linux-only pieces
(`os_audit` host agent, `binary_audit`) simply degrade — the other analysers run
fine.

**Scanner suite** (Python 3.10+):

```bash
python -m pip install -e .            # installs the nh-* console scripts
pip install python-hcl2               # enables the Terraform IaC rules
nh-scan ./path/to/target --format html -o report.html
```

**Web app** (Node 20+, PostgreSQL 14+):

```bash
cd webapp
npm ci
# point DATABASE_URL at your Postgres, then:
npx prisma migrate deploy             # or: npx prisma db push
npm run build && npm start            # http://localhost:3000
```

On Windows, install Node from nodejs.org and Postgres from postgresql.org (or run
just Postgres in Docker: `docker run -e POSTGRES_PASSWORD=... -p 5432:5432 postgres:16`).

---

## Troubleshooting

- **`docker: command not found` in WSL** — enable *Settings → Resources → WSL
  Integration* for your distro in Docker Desktop.
- **Slow builds / file-watch not working on Windows** — you're on `/mnt/c/…`;
  move the repo into the WSL2 home (`~/DNM-hunter`).
- **Port already in use (3000/5432/7474)** — stop the conflicting service or
  change the published port in `docker-compose.yml`.
- **Out of memory when GVM is enabled** — raise Docker Desktop's RAM limit or run
  without GVM (`./nisarghunter.sh` core services only).
- **`iac_scan` findings missing** — make sure `python-hcl2` is installed (it is,
  in the container image and in `pip install ".[iac]"`).

## Notes

- The scanner container is self-contained and safe to run offline; `repo_scan`
  and `nh-web-probe` need outbound network only when you point them at a remote
  repo or URL.
- Payments in the web app run in an **offline mock mode** until you set
  `STRIPE_SECRET_KEY` (see `webapp/src/lib/subscription/billing.ts`).
- See [readmes/README.DEV.md](readmes/README.DEV.md) for the full developer guide
  and [docs/SECURITY_MODULES.md](docs/SECURITY_MODULES.md) for the scanner
  architecture.
