import { NextRequest, NextResponse } from 'next/server'
import prisma from '@/lib/prisma'
import { mkdir, readdir, stat, unlink, writeFile } from 'fs/promises'
import { existsSync } from 'fs'
import path from 'path'

const MOBILE_SCAN_UPLOAD_PATH = process.env.MOBILE_SCAN_UPLOAD_PATH || '/data/mobile-scan-uploads'
const MAX_FILE_SIZE = 150 * 1024 * 1024 // 150 MB
const ALLOWED_EXTENSIONS = ['.apk']

interface RouteParams {
  params: Promise<{ projectId: string }>
}

const PROJECT_ID_RE = /^[a-zA-Z0-9_-]+$/

function sanitizeFilename(name: string): string {
  return path.basename(name).replace(/[^a-zA-Z0-9._-]/g, '_')
}

function isAllowedExtension(filename: string): boolean {
  const ext = path.extname(filename).toLowerCase()
  return ALLOWED_EXTENSIONS.includes(ext)
}

// ---------------------------------------------------------------------------
// GET /api/mobile-scan/[projectId]/upload -- list uploaded APK files
// ---------------------------------------------------------------------------
export async function GET(request: NextRequest, { params }: RouteParams) {
  try {
    const { projectId } = await params
    if (!PROJECT_ID_RE.test(projectId)) {
      return NextResponse.json({ error: 'Invalid project ID' }, { status: 400 })
    }

    const projectDir = path.join(MOBILE_SCAN_UPLOAD_PATH, projectId)
    if (!existsSync(projectDir)) {
      return NextResponse.json({ files: [] })
    }

    const entries = await readdir(projectDir)
    const files = []

    for (const entry of entries) {
      const filePath = path.join(projectDir, entry)
      try {
        const fileStat = await stat(filePath)
        if (fileStat.isFile()) {
          files.push({ name: entry, size: fileStat.size, uploaded_at: fileStat.mtime.toISOString() })
        }
      } catch {
        // Skip unreadable files
      }
    }

    return NextResponse.json({ files })
  } catch (error) {
    console.error('Error listing mobile scan uploads:', error)
    return NextResponse.json({ error: 'Failed to list files' }, { status: 500 })
  }
}

// ---------------------------------------------------------------------------
// POST /api/mobile-scan/[projectId]/upload -- upload an APK for analysis
// ---------------------------------------------------------------------------
export async function POST(request: NextRequest, { params }: RouteParams) {
  try {
    const { projectId } = await params
    if (!PROJECT_ID_RE.test(projectId)) {
      return NextResponse.json({ error: 'Invalid project ID' }, { status: 400 })
    }

    const formData = await request.formData()
    const file = formData.get('file') as File | null

    if (!file) {
      return NextResponse.json({ error: 'No file provided' }, { status: 400 })
    }

    if (file.size > MAX_FILE_SIZE) {
      return NextResponse.json(
        { error: `File too large. Maximum size is ${MAX_FILE_SIZE / 1024 / 1024}MB` },
        { status: 400 }
      )
    }

    const filename = sanitizeFilename(file.name)
    if (!isAllowedExtension(filename)) {
      return NextResponse.json({ error: 'Invalid file type. Only .apk files are accepted' }, { status: 400 })
    }

    const projectDir = path.join(MOBILE_SCAN_UPLOAD_PATH, projectId)
    await mkdir(projectDir, { recursive: true })

    const filePath = path.join(projectDir, filename)
    if (existsSync(filePath)) {
      return NextResponse.json(
        { error: `File '${filename}' already exists. Delete it first before re-uploading.` },
        { status: 409 }
      )
    }

    const buffer = Buffer.from(await file.arrayBuffer())
    await writeFile(filePath, buffer)

    try {
      const currentFiles = (await prisma.project.findUnique({
        where: { id: projectId },
        select: { mobileScanUploadedFiles: true },
      }))?.mobileScanUploadedFiles || []

      if (!currentFiles.includes(filename)) {
        await prisma.project.update({
          where: { id: projectId },
          data: { mobileScanUploadedFiles: [...currentFiles, filename] },
        })
      }
    } catch {
      // Project may not exist yet -- file is on disk, DB update will happen on save
    }

    return NextResponse.json({ uploaded: { name: filename, size: file.size } })
  } catch (error) {
    console.error('Error uploading APK:', error)
    return NextResponse.json({ error: 'Failed to upload file' }, { status: 500 })
  }
}

// ---------------------------------------------------------------------------
// DELETE /api/mobile-scan/[projectId]/upload?name=... -- remove an uploaded APK
// ---------------------------------------------------------------------------
export async function DELETE(request: NextRequest, { params }: RouteParams) {
  try {
    const { projectId } = await params
    const filename = request.nextUrl.searchParams.get('name')

    if (!filename) {
      return NextResponse.json({ error: 'Missing name parameter' }, { status: 400 })
    }

    const project = await prisma.project.findUnique({
      where: { id: projectId },
      select: { id: true, mobileScanUploadedFiles: true },
    })

    if (!project) {
      return NextResponse.json({ error: 'Project not found' }, { status: 404 })
    }

    const safeName = sanitizeFilename(filename)
    const filePath = path.join(MOBILE_SCAN_UPLOAD_PATH, projectId, safeName)

    if (existsSync(filePath)) {
      await unlink(filePath)
    }

    const updatedFiles = (project.mobileScanUploadedFiles || []).filter(f => f !== safeName)
    await prisma.project.update({
      where: { id: projectId },
      data: { mobileScanUploadedFiles: updatedFiles },
    })

    return NextResponse.json({ deleted: safeName })
  } catch (error) {
    console.error('Error deleting APK:', error)
    return NextResponse.json({ error: 'Failed to delete file' }, { status: 500 })
  }
}
