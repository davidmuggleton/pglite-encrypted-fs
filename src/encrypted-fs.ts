import {
  BaseFilesystem,
  type FsStats,
  ERRNO_CODES,
} from '@electric-sql/pglite/basefs'

const EIO = 5
import type { PGlite } from '@electric-sql/pglite'
import { randomBytes } from 'crypto'
import * as fs from 'fs'
import * as path from 'path'
import {
  PAGE_SIZE,
  ENCRYPTED_PAGE_SIZE,
  SALT_SIZE,
  FILE_ID_SIZE,
  FILE_HEADER_SIZE,
  type DerivedKeys,
  encryptPage,
  decryptPage,
  VERIFICATION_MAGIC,
  VERIFICATION_FILE_ID,
} from './crypto.js'

/**
 * Emscripten Module interface — the subset of the Emscripten runtime
 * used by this filesystem implementation.
 */
interface EmModule {
  FS: EmFS
  HEAP8: Int8Array
  mmapAlloc(length: number): number
}

/**
 * Emscripten FS interface — virtual filesystem operations provided by
 * the Emscripten runtime. Used to create/mount our custom filesystem.
 */
interface EmFS {
  isDir(mode: number): boolean
  isFile(mode: number): boolean
  createNode(
    parent: EmNode | null,
    name: string,
    mode: number,
    dev: number,
  ): EmNode
  ErrnoError: new (errno: number) => Error
  mkdir(path: string): void
  mount(
    type: unknown,
    opts: Record<string, unknown>,
    mountpoint: string,
  ): void
}

/** Emscripten filesystem node, representing a file or directory in the VFS. */
interface EmNode {
  id: number
  rdev: number
  name: string
  parent: EmNode
  mount: { opts: { root?: string } }
  node_ops: unknown
  stream_ops: unknown
  mode: number
}

/** Emscripten stream, representing an open file handle in the VFS. */
interface EmStream {
  node: EmNode
  flags: number
  position: number
  nfd?: number
  shared?: { refcount: number }
}

/** Attributes passed to setattr by Emscripten's VFS layer. */
interface EmNodeAttr {
  mode?: number
  size?: number
  timestamp?: number
}

/** Extended Error with filesystem metadata for Emscripten error translation. */
interface FilesystemError extends Error {
  pgSymbol: string
  codeSym: string
  code: string
  errno: number
}

/**
 * POSIX open flags as used by Emscripten (Linux convention).
 * These differ from Node.js fs.constants on macOS/Windows but are correct
 * here because they decode flags coming from the Emscripten/WASM side.
 */
const O_WRONLY = 1
const O_RDWR = 2
const O_CREAT = 64
const O_EXCL = 128
const O_TRUNC = 512
const O_APPEND = 1024

/** Mount configuration following PGLite's convention. */
const WASM_PREFIX = '/tmp/pglite'
const PGDATA = WASM_PREFIX + '/base'

/**
 * Converts numeric POSIX flags to Node.js string flags.
 * PostgreSQL uses numeric flags like 193 (O_CREAT|O_EXCL|O_WRONLY).
 */
function emFlagsToNode(flags: number | string): string {
  if (typeof flags === 'string') {
    return flags
  }

  const isWrite = (flags & O_WRONLY) === O_WRONLY
  const isReadWrite = (flags & O_RDWR) === O_RDWR
  const isAppend = (flags & O_APPEND) === O_APPEND
  const isTrunc = (flags & O_TRUNC) === O_TRUNC
  const isCreate = (flags & O_CREAT) === O_CREAT
  const isExcl = (flags & O_EXCL) === O_EXCL

  let base: string
  if (isAppend) {
    base = isReadWrite ? 'a+' : 'a'
  } else if (isTrunc) {
    base = isReadWrite ? 'w+' : isWrite ? 'w' : 'w'
  } else if (isCreate && isWrite && !isReadWrite) {
    base = 'w'
  } else if (isReadWrite) {
    base = 'r+'
  } else if (isWrite) {
    base = 'w'
  } else {
    base = 'r'
  }

  if (isExcl && isCreate) {
    if (base === 'w') base = 'wx'
    else if (base === 'w+') base = 'wx+'
    else if (base === 'a') base = 'ax'
    else if (base === 'a+') base = 'ax+'
  }

  return base
}

interface OpenFile {
  realFd: number
  path: string
  flags: string
  position: number
  encrypted: boolean
  fileId: Buffer
}

export class EncryptedFS extends BaseFilesystem {
  private readonly keys: DerivedKeys
  private readonly salt: Buffer
  private openFiles: Map<number, OpenFile> = new Map()
  private cwd: string = '/'
  private nextFd: number = 100

  private destroyed = false

  constructor(
    dataDir: string,
    keys: DerivedKeys,
    salt: Buffer,
    options?: { debug?: boolean },
  ) {
    super(dataDir, options)
    this.keys = keys
    this.salt = salt

    const baseDir = this.dataDir ?? dataDir
    if (!fs.existsSync(baseDir)) {
      fs.mkdirSync(baseDir, { recursive: true })
    }

    this.verifyOrCreateToken(baseDir)

    if (this.debug) {
      console.log('EncryptedFS initialized with dataDir:', baseDir)
    }
  }

  /**
   * Zeros key material from memory. Call this after closing PGlite.
   * While JavaScript cannot guarantee complete erasure (the GC may have
   * copied data), this reduces the window of exposure in heap dumps.
   */
  destroy(): void {
    if (this.destroyed) return
    this.keys.encKey.fill(0)
    this.salt.fill(0)
    this.destroyed = true
  }

  /**
   * On first init, creates a verification token file.
   * On reopen, decrypts it to verify the passphrase is correct.
   * Throws immediately if the passphrase is wrong.
   */
  private verifyOrCreateToken(baseDir: string): void {
    const tokenPath = path.join(baseDir, '.encryption-verify')

    if (!fs.existsSync(tokenPath)) {
      const magic = Buffer.alloc(PAGE_SIZE)
      VERIFICATION_MAGIC.copy(magic)
      const encrypted = encryptPage(magic, 0, this.keys, VERIFICATION_FILE_ID)
      fs.writeFileSync(tokenPath, encrypted)
      return
    }

    const data = fs.readFileSync(tokenPath)
    if (data.length !== ENCRYPTED_PAGE_SIZE) {
      throw new Error('Invalid passphrase or corrupted encryption keys')
    }

    try {
      const decrypted = decryptPage(data, 0, this.keys, VERIFICATION_FILE_ID)
      if (
        !decrypted
          .subarray(0, VERIFICATION_MAGIC.length)
          .equals(VERIFICATION_MAGIC)
      ) {
        throw new Error('Invalid passphrase or corrupted encryption keys')
      }
    } catch (e: unknown) {
      if (
        e instanceof Error &&
        e.message === 'Invalid passphrase or corrupted encryption keys'
      ) {
        throw e
      }
      throw Object.assign(
        new Error('Invalid passphrase or corrupted encryption keys'),
        { cause: e },
      )
    }
  }

  /**
   * Normalizes a path, resolving relative paths against the current working directory.
   */
  private normalizePath(p: string): string {
    if (!p) return ''

    if (!p.startsWith('/')) {
      p = path.join(this.cwd, p)
    }

    return path.normalize(p)
  }

  /**
   * Updates the working directory for relative path resolution.
   */
  chdir(newPath: string): void {
    this.cwd = this.normalizePath(newPath)
    if (this.debug) console.log(`[CHDIR] ${this.cwd}`)
  }

  /**
   * Reads the 32-byte file ID from an encrypted file's header.
   * The file ID is stored at offset SALT_SIZE in the file header.
   */
  private readFileId(fd: number): Buffer {
    const fileId = Buffer.alloc(FILE_ID_SIZE)
    const bytesRead = fs.readSync(fd, fileId, 0, FILE_ID_SIZE, SALT_SIZE)
    if (bytesRead !== FILE_ID_SIZE) {
      throw this.createError('EIO', 'Could not read file ID from header')
    }
    return fileId
  }

  /**
   * Determines whether a file should be encrypted based on its name.
   * PostgreSQL configuration files and small control files are left unencrypted.
   */
  private shouldEncrypt(filename: string): boolean {
    const basename = path.basename(filename)

    return (
      !basename.endsWith('.conf') &&
      !basename.endsWith('.pid') &&
      !basename.includes('PG_VERSION') &&
      !basename.includes('pg_internal.init') &&
      !basename.includes('postmaster') &&
      !basename.includes('.lock') &&
      !basename.includes('replorigin_checkpoint')
    )
  }

  /**
   * Resolves a virtual path to an absolute path on the host filesystem.
   */
  private resolvePath(p: string): string {
    const baseDir = this.dataDir ?? ''

    if (p.startsWith('/')) {
      p = p.substring(1)
    }

    return path.join(baseDir, p)
  }

  /**
   * Initializes a new encrypted file with a [salt][fileId] header.
   * @returns The 32-byte random file ID written to the header.
   */
  private initializeEncryptedFile(fullPath: string): Buffer {
    const fileId = Buffer.from(randomBytes(FILE_ID_SIZE))
    if (!fs.existsSync(fullPath)) {
      fs.writeFileSync(fullPath, Buffer.concat([this.salt, fileId]))
    }
    return fileId
  }

  /**
   * Extracts a POSIX error code from an unknown caught value.
   * Returns 'EIO' if the error doesn't carry a recognized code.
   */
  private getErrorCode(e: unknown): keyof typeof ERRNO_CODES | 'EIO' {
    if (e instanceof Error && 'code' in e && typeof e.code === 'string') {
      if (e.code === 'EIO') return 'EIO'
      if (e.code in ERRNO_CODES) return e.code as keyof typeof ERRNO_CODES
    }
    return 'EIO'
  }

  /**
   * Opens a file, initializing the encryption header for new encrypted files.
   *
   * For new files opened with write flags, the header is pre-created before
   * openSync so the fd is valid, then re-written after 'w' truncation.
   * Existing files opened with 'w' get a fresh file ID since all pages are lost.
   */
  open(
    pathStr: string,
    flags: string | number = 'r',
    mode: number = 0o666,
  ): number {
    try {
      pathStr = this.normalizePath(pathStr)
      const nodeFlags = emFlagsToNode(flags)
      const fullPath = this.resolvePath(pathStr)

      if (fs.existsSync(fullPath) && fs.statSync(fullPath).isDirectory()) {
        const virtualFd = this.nextFd++
        this.openFiles.set(virtualFd, {
          realFd: -1,
          path: fullPath,
          flags: nodeFlags,
          position: 0,
          encrypted: false,
          fileId: Buffer.alloc(0),
        })
        if (this.debug) {
          console.log(`[OPEN] ${pathStr} -> fd ${virtualFd} (directory)`)
        }
        return virtualFd
      }

      const dir = path.dirname(fullPath)
      if (!fs.existsSync(dir)) {
        fs.mkdirSync(dir, { recursive: true })
      }

      const writeMode = /[wa]/.test(nodeFlags)
      const isTruncate = /w/.test(nodeFlags)
      const fileExists = fs.existsSync(fullPath)
      const needsEncryption = this.shouldEncrypt(pathStr)
      let fileId: Buffer = Buffer.alloc(0)

      if (needsEncryption && writeMode && !fileExists) {
        fileId = this.initializeEncryptedFile(fullPath)
      }

      const realFd = fs.openSync(fullPath, nodeFlags, mode)

      if (needsEncryption && isTruncate) {
        if (!fileId.length) {
          fileId = Buffer.from(randomBytes(FILE_ID_SIZE))
        }
        const header = Buffer.concat([this.salt, fileId])
        fs.writeSync(realFd, header, 0, FILE_HEADER_SIZE, 0)
      } else if (needsEncryption && fileExists) {
        fileId = this.readFileId(realFd)
      }

      const virtualFd = this.nextFd++

      this.openFiles.set(virtualFd, {
        realFd,
        path: fullPath,
        flags: nodeFlags,
        position: 0,
        encrypted: needsEncryption,
        fileId,
      })

      if (this.debug) {
        console.log(
          `[OPEN] ${pathStr} -> fd ${virtualFd}, encrypted: ${this.shouldEncrypt(pathStr)}`,
        )
      }

      return virtualFd
    } catch (e: unknown) {
      throw this.createError(this.getErrorCode(e), `open '${pathStr}'`, e)
    }
  }

  close(virtualFd: number): void {
    const file = this.openFiles.get(virtualFd)
    if (!file) {
      throw this.createError('EBADF', `close '${virtualFd}'`)
    }

    if (file.realFd !== -1) {
      fs.closeSync(file.realFd)
    }
    this.openFiles.delete(virtualFd)

    if (this.debug) {
      console.log(`[CLOSE] fd ${virtualFd}`)
    }
  }

  fsync(virtualFd: number): void {
    if (this.debug) console.log('EncryptedFS.fsync:', virtualFd)

    const file = this.openFiles.get(virtualFd)
    if (!file) {
      throw this.createError('EBADF', `fsync '${virtualFd}'`)
    }

    if (file.realFd !== -1) {
      fs.fsyncSync(file.realFd)
    }
  }

  /** Alias for fsync — Node.js does not distinguish the two. */
  fdatasync(virtualFd: number): void {
    return this.fsync(virtualFd)
  }

  read(
    virtualFd: number,
    buffer: Uint8Array,
    offset: number,
    length: number,
    position: number | null,
  ): number {
    const file = this.openFiles.get(virtualFd)
    if (!file) {
      throw this.createError('EBADF', `read '${virtualFd}'`)
    }

    if (this.destroyed) {
      throw this.createError('EIO', 'filesystem has been destroyed')
    }

    if (length === 0) return 0

    if (!(buffer instanceof Uint8Array)) {
      const view = buffer as unknown as ArrayBufferView
      buffer = new Uint8Array(view.buffer, view.byteOffset, view.byteLength)
    }

    if (file.realFd === -1) {
      throw this.createError('EISDIR', `read from directory`)
    }

    let logicalPos = position
    if (logicalPos === undefined || logicalPos === null || logicalPos < 0) {
      logicalPos = file.position ?? 0
    }

    if (!file.encrypted) {
      const bytesRead = fs.readSync(
        file.realFd,
        buffer,
        offset,
        length,
        logicalPos,
      )
      file.position = logicalPos + bytesRead
      return bytesRead
    }

    const startPage = Math.floor(logicalPos / PAGE_SIZE)
    const endPage = Math.floor((logicalPos + length - 1) / PAGE_SIZE)
    let bytesReadTotal = 0

    for (let pageNo = startPage; pageNo <= endPage; pageNo++) {
      const physicalOffset = FILE_HEADER_SIZE + pageNo * ENCRYPTED_PAGE_SIZE
      const encryptedPage = Buffer.alloc(ENCRYPTED_PAGE_SIZE)

      const bytesRead = fs.readSync(
        file.realFd,
        encryptedPage,
        0,
        ENCRYPTED_PAGE_SIZE,
        physicalOffset,
      )

      if (bytesRead === 0) break

      if (bytesRead < ENCRYPTED_PAGE_SIZE) {
        throw this.createError(
          'EIO',
          `Short encrypted page read (expected ${ENCRYPTED_PAGE_SIZE}, got ${bytesRead}) at page ${pageNo}`,
        )
      }

      try {
        const decryptedPage = decryptPage(
          encryptedPage,
          pageNo,
          this.keys,
          file.fileId,
        )

        const pageOffset = logicalPos + bytesReadTotal - pageNo * PAGE_SIZE
        const bytesToCopy = Math.min(
          length - bytesReadTotal,
          PAGE_SIZE - pageOffset,
        )

        decryptedPage.copy(
          buffer,
          offset + bytesReadTotal,
          pageOffset,
          pageOffset + bytesToCopy,
        )

        bytesReadTotal += bytesToCopy
      } catch (e: unknown) {
        if (this.debug) {
          console.error(
            `Decryption failed for page ${pageNo}`,
            e instanceof Error ? e.message : e,
          )
        }
        throw this.createError(
          'EIO',
          `Decryption failed for page ${pageNo}, file may be corrupt`,
          e,
        )
      }
    }

    file.position = logicalPos + bytesReadTotal
    return bytesReadTotal
  }

  write(
    virtualFd: number,
    buffer: Uint8Array,
    offset: number,
    length: number,
    position: number | null,
  ): number {
    const file = this.openFiles.get(virtualFd)
    if (!file) {
      throw this.createError('EBADF', `write '${virtualFd}'`)
    }

    if (this.destroyed) {
      throw this.createError('EIO', 'filesystem has been destroyed')
    }

    if (length === 0) return 0

    if (!(buffer instanceof Uint8Array)) {
      const view = buffer as unknown as ArrayBufferView
      buffer = new Uint8Array(view.buffer, view.byteOffset, view.byteLength)
    }

    if (file.realFd === -1) {
      throw this.createError('EISDIR', `write to directory`)
    }

    let logicalPos = position
    if (logicalPos === undefined || logicalPos === null || logicalPos < 0) {
      logicalPos = file.position ?? 0
    }

    if (!file.encrypted) {
      const bytesWritten = fs.writeSync(
        file.realFd,
        buffer,
        offset,
        length,
        logicalPos,
      )
      file.position = logicalPos + bytesWritten
      return bytesWritten
    }

    const startPage = Math.floor(logicalPos / PAGE_SIZE)
    const endPage = Math.floor((logicalPos + length - 1) / PAGE_SIZE)
    let bytesWrittenTotal = 0

    for (let pageNo = startPage; pageNo <= endPage; pageNo++) {
      const physicalOffset = FILE_HEADER_SIZE + pageNo * ENCRYPTED_PAGE_SIZE
      let pagePlain: Buffer

      let bytesRead = 0
      const encryptedPageData = Buffer.alloc(ENCRYPTED_PAGE_SIZE)

      try {
        const stats = fs.fstatSync(file.realFd)
        if (physicalOffset < stats.size) {
          bytesRead = fs.readSync(
            file.realFd,
            encryptedPageData,
            0,
            ENCRYPTED_PAGE_SIZE,
            physicalOffset,
          )
        }
      } catch (_e: unknown) {
        bytesRead = 0
      }

      if (bytesRead === ENCRYPTED_PAGE_SIZE) {
        try {
          pagePlain = decryptPage(
            encryptedPageData,
            pageNo,
            this.keys,
            file.fileId,
          )
        } catch (e: unknown) {
          if (this.debug) {
            console.error(
              `Decryption failed during write for page ${pageNo}`,
              e instanceof Error ? e.message : e,
            )
          }
          throw this.createError(
            'EIO',
            `Decryption failed during write for page ${pageNo}, file may be corrupt`,
            e,
          )
        }
      } else {
        pagePlain = Buffer.alloc(PAGE_SIZE)
      }

      const pageOffset = logicalPos + bytesWrittenTotal - pageNo * PAGE_SIZE
      const bytesToWrite = Math.min(
        length - bytesWrittenTotal,
        PAGE_SIZE - pageOffset,
      )

      Buffer.from(buffer).copy(
        pagePlain,
        pageOffset,
        offset + bytesWrittenTotal,
        offset + bytesWrittenTotal + bytesToWrite,
      )

      const encryptedNewPage = encryptPage(
        pagePlain,
        pageNo,
        this.keys,
        file.fileId,
      )
      fs.writeSync(
        file.realFd,
        encryptedNewPage,
        0,
        ENCRYPTED_PAGE_SIZE,
        physicalOffset,
      )

      bytesWrittenTotal += bytesToWrite
    }

    file.position = logicalPos + bytesWrittenTotal
    return bytesWrittenTotal
  }

  chmod(pathStr: string, mode: number): void {
    const fullPath = this.resolvePath(pathStr)
    fs.chmodSync(fullPath, mode)
  }

  fstat(virtualFd: number): FsStats {
    const file = this.openFiles.get(virtualFd)
    if (!file) {
      throw this.createError('EBADF', `fstat '${virtualFd}'`)
    }

    if (file.realFd === -1) {
      const stats = fs.statSync(file.path)
      return this.toFsStats(stats)
    }

    const stats = fs.fstatSync(file.realFd)
    const pathStr = file.path.replace((this.dataDir ?? '') + '/', '')

    if (stats.isFile() && this.shouldEncrypt(pathStr)) {
      const phys = stats.size
      const logical = this.logicalSizeFromPhysical(phys)

      if (this.debug && phys === FILE_HEADER_SIZE) {
        console.log(
          `STAT TRACE fstat ${pathStr} phys=${phys} enc=true reported.size=${logical} (was FILE_HEADER_SIZE, now 0)`,
        )
      }

      return this.toFsStats(stats, logical)
    }

    return this.toFsStats(stats)
  }

  lstat(pathStr: string): FsStats {
    pathStr = this.normalizePath(pathStr)
    const fullPath = this.resolvePath(pathStr)

    try {
      const stats = fs.lstatSync(fullPath)

      if (stats.isFile() && this.shouldEncrypt(pathStr)) {
        const logicalSize = this.logicalSizeFromPhysical(stats.size)
        return this.toFsStats(stats, logicalSize)
      }

      return this.toFsStats(stats)
    } catch (e: unknown) {
      if (this.debug) {
        const code =
          e instanceof Error && 'code' in e
            ? (e as NodeJS.ErrnoException).code
            : undefined
        console.log(`lstat failed for ${pathStr} (${fullPath}):`, code)
      }
      if (
        e instanceof Error &&
        'code' in e &&
        (e as NodeJS.ErrnoException).code === 'ENOENT'
      ) {
        throw this.createError('ENOENT', `stat '${pathStr}'`)
      }
      throw e
    }
  }

  mkdir(
    pathStr: string,
    options?: { recursive?: boolean; mode?: number },
  ): void {
    if (this.debug) console.log('EncryptedFS.mkdir:', pathStr, options)
    const fullPath = this.resolvePath(pathStr)
    fs.mkdirSync(fullPath, options)
  }

  readdir(pathStr: string): string[] {
    const fullPath = this.resolvePath(pathStr)
    try {
      const result = fs.readdirSync(fullPath)
      if (this.debug) {
        console.log(`readdir ${pathStr} (${fullPath}):`, result)
      }
      return result
    } catch (e: unknown) {
      if (this.debug) {
        const code =
          e instanceof Error && 'code' in e
            ? (e as NodeJS.ErrnoException).code
            : undefined
        console.log(`readdir failed for ${pathStr} (${fullPath}):`, code)
      }
      if (
        e instanceof Error &&
        'code' in e &&
        (e as NodeJS.ErrnoException).code === 'ENOENT'
      ) {
        throw this.createError('ENOENT', `readdir '${pathStr}'`)
      }
      throw e
    }
  }

  rename(oldPath: string, newPath: string): void {
    const oldFullPath = this.resolvePath(oldPath)
    const newFullPath = this.resolvePath(newPath)
    fs.renameSync(oldFullPath, newFullPath)
  }

  rmdir(pathStr: string): void {
    const fullPath = this.resolvePath(pathStr)
    fs.rmdirSync(fullPath)
  }

  truncate(pathStr: string, len: number): void {
    const fullPath = this.resolvePath(pathStr)

    if (!this.shouldEncrypt(pathStr)) {
      fs.truncateSync(fullPath, len)
      return
    }

    const currentPhysical = fs.existsSync(fullPath)
      ? fs.statSync(fullPath).size
      : 0
    const currentPageCount =
      currentPhysical > FILE_HEADER_SIZE
        ? Math.floor((currentPhysical - FILE_HEADER_SIZE) / ENCRYPTED_PAGE_SIZE)
        : 0
    const newPageCount = Math.ceil(len / PAGE_SIZE)

    if (newPageCount > currentPageCount) {
      const fd = fs.openSync(fullPath, 'r+')
      try {
        const zeroPage = Buffer.alloc(PAGE_SIZE, 0)
        const fileId = this.readFileId(fd)
        for (let pageNo = currentPageCount; pageNo < newPageCount; pageNo++) {
          const encrypted = encryptPage(zeroPage, pageNo, this.keys, fileId)
          const offset = FILE_HEADER_SIZE + pageNo * ENCRYPTED_PAGE_SIZE
          fs.writeSync(fd, encrypted, 0, encrypted.length, offset)
        }
      } finally {
        fs.closeSync(fd)
      }
    } else {
      const newPhysicalSize =
        FILE_HEADER_SIZE + newPageCount * ENCRYPTED_PAGE_SIZE
      fs.truncateSync(fullPath, newPhysicalSize)
    }
  }

  unlink(pathStr: string): void {
    pathStr = this.normalizePath(pathStr)
    const fullPath = this.resolvePath(pathStr)
    fs.unlinkSync(fullPath)
  }

  utimes(pathStr: string, atime: number, mtime: number): void {
    const fullPath = this.resolvePath(pathStr)
    fs.utimesSync(fullPath, new Date(atime), new Date(mtime))
  }

  /**
   * Writes data to a file, creating it if it doesn't exist.
   * Do NOT call initializeEncryptedFile before this — open('w') handles
   * header initialization. Calling it first would write the header, then
   * open('w') would truncate it away.
   */
  writeFile(
    pathStr: string,
    data: string | Uint8Array,
    options?: { encoding?: string; mode?: number; flag?: string },
  ): void {
    const fd = this.open(pathStr, options?.flag || 'w', options?.mode)
    try {
      const buffer =
        typeof data === 'string'
          ? Buffer.from(data, (options?.encoding as BufferEncoding) || 'utf8')
          : Buffer.from(data)

      this.write(fd, buffer, 0, buffer.length, 0)
    } finally {
      this.close(fd)
    }
  }

  /**
   * Converts a physical file size (on disk) to the logical size seen by PostgreSQL.
   * Accounts for the file header and encrypted page overhead.
   */
  private logicalSizeFromPhysical(physicalSize: number): number {
    if (physicalSize < FILE_HEADER_SIZE) return 0
    const payload = physicalSize - FILE_HEADER_SIZE
    if (payload === 0) return 0
    const fullPages = Math.floor(payload / ENCRYPTED_PAGE_SIZE)
    const tail = payload % ENCRYPTED_PAGE_SIZE
    if (tail !== 0) {
      throw this.createError(
        'EIO',
        `Partial encrypted page (physicalSize=${physicalSize}, tail=${tail})`,
      )
    }
    return fullPages * PAGE_SIZE
  }

  private toFsStats(stats: fs.Stats, sizeOverride?: number): FsStats {
    const toSec = (ms: number) => Math.trunc(ms / 1000)
    return {
      dev: stats.dev,
      ino: stats.ino,
      mode: stats.mode,
      nlink: stats.nlink,
      uid: stats.uid,
      gid: stats.gid,
      rdev: stats.rdev,
      size: sizeOverride ?? stats.size,
      blksize: stats.blksize,
      blocks: stats.blocks,
      atime: toSec(stats.atimeMs),
      mtime: toSec(stats.mtimeMs),
      ctime: toSec(stats.ctimeMs),
    }
  }

  private createError(
    code: keyof typeof ERRNO_CODES | 'EIO',
    message: string,
    cause?: unknown,
  ): FilesystemError {
    const num =
      code === 'EIO' ? EIO : ERRNO_CODES[code]
    return Object.assign(
      new Error(`${code}: ${message}`),
      {
        pgSymbol: code as string,
        codeSym: code as string,
        code: code as string,
        errno: num,
        ...(cause !== undefined && { cause }),
      },
    )
  }

  /**
   * Syscall stubs required by PGlite's Emscripten layer.
   * These return success (0) since PostgreSQL's WASM build expects them
   * to exist but their behavior is not meaningful in this context.
   */
  fcntl(fd: number, cmd: number, _arg?: unknown): number {
    if (this.debug) console.log('fcntl stub', fd, cmd, _arg)
    return 0
  }

  flock(fd: number, operation: number): number {
    if (this.debug) console.log('flock stub', fd, operation)
    return 0
  }

  access(pathStr: string, _mode: number): number {
    try {
      this.lstat(pathStr)
      return 0
    } catch {
      return -1
    }
  }

  // eslint-disable-next-line @typescript-eslint/require-await -- base class requires async signature
  async init(
    pg: PGlite,
    emscriptenOptions: Parameters<BaseFilesystem['init']>[1],
  ): ReturnType<BaseFilesystem['init']> {
    this.pg = pg
    const options: Parameters<BaseFilesystem['init']>[1] = {
      ...emscriptenOptions,
      preRun: [
        ...(emscriptenOptions.preRun ?? []),
        (mod) => {
          const emMod = mod as unknown as EmModule
          const EMFS = this.createEmscriptenFS(emMod)
          emMod.FS.mkdir(PGDATA)
          emMod.FS.mount(EMFS, {}, PGDATA)
          if (this.debug) {
            console.log(`[EncryptedFS] Mounted at ${PGDATA}`)
          }
        },
      ],
    }
    return { emscriptenOpts: options }
  }

  /**
   * Creates the Emscripten filesystem interface that bridges PGlite's
   * WASM layer to this encrypted filesystem implementation.
   */
  private createEmscriptenFS(Module: EmModule) {
    const FS = Module.FS
    // eslint-disable-next-line @typescript-eslint/no-this-alias -- captured for use in EMFS object literal
    const baseFS = this
    const log = this.debug ? console.log : null

    const EMFS = {
      tryFSOperation<T>(f: () => T): T {
        try {
          return f()
        } catch (e: unknown) {
          if (e instanceof Error && 'pgSymbol' in e) {
            const sym = (e as FilesystemError).pgSymbol
            const num =
              ERRNO_CODES[sym as keyof typeof ERRNO_CODES] ?? ERRNO_CODES.EINVAL
            throw new FS.ErrnoError(num)
          }
          if (e instanceof Error && 'errno' in e) {
            throw new FS.ErrnoError((e as FilesystemError).errno)
          }
          if (e instanceof Error && 'code' in e) {
            const code = (e as NodeJS.ErrnoException).code
            if (code === 'ENOENT') {
              throw new FS.ErrnoError(ERRNO_CODES.ENOENT)
            }
            if (
              code !== undefined &&
              ERRNO_CODES[code as keyof typeof ERRNO_CODES] !== undefined
            ) {
              throw new FS.ErrnoError(
                ERRNO_CODES[code as keyof typeof ERRNO_CODES],
              )
            }
          }
          throw new FS.ErrnoError(ERRNO_CODES.EINVAL)
        }
      },
      mount(_mount: unknown) {
        return EMFS.createNode(null, '/', 16384 | 511, 0)
      },
      syncfs(
        _mount: unknown,
        _populate: unknown,
        _done: (err?: number | null) => unknown,
      ): void {},
      createNode(
        parent: EmNode | null,
        name: string,
        mode: number,
        _dev?: unknown,
      ): EmNode {
        if (!FS.isDir(mode) && !FS.isFile(mode)) {
          throw new FS.ErrnoError(ERRNO_CODES.EINVAL)
        }
        const node: EmNode = FS.createNode(parent, name, mode, 0)
        node.node_ops = EMFS.node_ops
        node.stream_ops = EMFS.stream_ops
        return node
      },
      getMode(path: string): number {
        log?.('getMode', path)
        return EMFS.tryFSOperation(() => {
          if (path.startsWith('//')) {
            path = path.substring(1)
          }
          const stats = baseFS.lstat(path)
          return stats.mode
        })
      },
      realPath(node: EmNode): string {
        const parts: string[] = []
        while (node.parent !== node) {
          parts.push(node.name)
          node = node.parent
        }
        parts.push(node.mount.opts.root || '')
        parts.reverse()
        return parts.join('/').replace(/\/+/g, '/') || '/'
      },
      node_ops: {
        getattr: (node: EmNode) => {
          log?.('getattr', EMFS.realPath(node))
          const path = EMFS.realPath(node)
          return EMFS.tryFSOperation(() => {
            const stats = baseFS.lstat(path)
            return {
              ...stats,
              dev: 0,
              ino: node.id,
              nlink: 1,
              rdev: node.rdev,
              atime: new Date(stats.atime),
              mtime: new Date(stats.mtime),
              ctime: new Date(stats.ctime),
            }
          })
        },
        setattr: (node: EmNode, attr: EmNodeAttr) => {
          log?.('setattr', EMFS.realPath(node), attr)
          const path = EMFS.realPath(node)
          EMFS.tryFSOperation(() => {
            if (attr.mode !== undefined) {
              baseFS.chmod(path, attr.mode)
            }
            if (attr.size !== undefined) {
              baseFS.truncate(path, attr.size)
            }
            if (attr.timestamp !== undefined) {
              baseFS.utimes(path, attr.timestamp, attr.timestamp)
            }
          })
        },
        lookup: (parent: EmNode, name: string) => {
          log?.('lookup', EMFS.realPath(parent), name)
          const full = [EMFS.realPath(parent), name].join('/')
          const mode = EMFS.getMode(full)
          return EMFS.createNode(parent, name, mode)
        },
        mknod: (parent: EmNode, name: string, mode: number, dev: unknown) => {
          log?.('mknod', EMFS.realPath(parent), name, mode, dev)
          const node = EMFS.createNode(parent, name, mode, dev)
          const full = EMFS.realPath(node)
          return EMFS.tryFSOperation(() => {
            if (FS.isDir(mode)) {
              baseFS.mkdir(full, { mode })
            } else {
              baseFS.writeFile(full, '', { mode })
            }
            return node
          })
        },
        rename: (oldNode: EmNode, newDir: EmNode, newName: string) => {
          log?.(
            'rename',
            EMFS.realPath(oldNode),
            EMFS.realPath(newDir),
            newName,
          )
          const oldPath = EMFS.realPath(oldNode)
          const newPath = [EMFS.realPath(newDir), newName].join('/')
          EMFS.tryFSOperation(() => {
            baseFS.rename(oldPath, newPath)
          })
          oldNode.name = newName
        },
        unlink: (parent: EmNode, name: string) => {
          log?.('unlink', EMFS.realPath(parent), name)
          const path = [EMFS.realPath(parent), name].join('/')
          try {
            baseFS.unlink(path)
          } catch (e: unknown) {
            if (
              !(
                e instanceof Error &&
                'code' in e &&
                (e as NodeJS.ErrnoException).code === 'ENOENT'
              )
            ) {
              throw e
            }
          }
        },
        rmdir: (parent: EmNode, name: string) => {
          log?.('rmdir', EMFS.realPath(parent), name)
          const path = [EMFS.realPath(parent), name].join('/')
          return EMFS.tryFSOperation(() => {
            baseFS.rmdir(path)
          })
        },
        readdir: (node: EmNode) => {
          log?.('readdir', EMFS.realPath(node))
          const path = EMFS.realPath(node)
          return EMFS.tryFSOperation(() => {
            return baseFS.readdir(path)
          })
        },
        symlink: (_parent: EmNode, _newName: string, _oldPath: string) => {
          log?.('symlink - not supported')
          throw new FS.ErrnoError(63)
        },
        readlink: (_node: EmNode) => {
          log?.('readlink - not supported')
          throw new FS.ErrnoError(63)
        },
      },
      stream_ops: {
        open: (stream: EmStream) => {
          log?.('open stream', EMFS.realPath(stream.node))
          const path = EMFS.realPath(stream.node)
          return EMFS.tryFSOperation(() => {
            if (FS.isFile(stream.node.mode)) {
              stream.shared = stream.shared || { refcount: 1 }
              stream.shared.refcount = 1
              stream.nfd = baseFS.open(
                path,
                stream.flags,
                stream.node.mode & 0o777,
              )
            }
          })
        },
        close: (stream: EmStream) => {
          log?.('close stream', EMFS.realPath(stream.node))
          return EMFS.tryFSOperation(() => {
            if (
              FS.isFile(stream.node.mode) &&
              stream.nfd &&
              stream.shared &&
              --stream.shared.refcount === 0
            ) {
              baseFS.close(stream.nfd)
            }
          })
        },
        dup: (stream: EmStream) => {
          log?.('dup stream', EMFS.realPath(stream.node))
          stream.shared!.refcount++
        },
        read: (
          stream: EmStream,
          buffer: Uint8Array,
          offset: number,
          length: number,
          position: number,
        ) => {
          log?.(
            'read stream',
            EMFS.realPath(stream.node),
            offset,
            length,
            position,
          )
          if (length === 0) return 0
          return EMFS.tryFSOperation(() =>
            baseFS.read(stream.nfd!, buffer, offset, length, position),
          )
        },
        write: (
          stream: EmStream,
          buffer: Uint8Array,
          offset: number,
          length: number,
          position: number,
        ) => {
          log?.(
            'write stream',
            EMFS.realPath(stream.node),
            offset,
            length,
            position,
          )
          return EMFS.tryFSOperation(() => {
            if (buffer.buffer) {
              const actualBuffer = new Uint8Array(
                buffer.buffer,
                buffer.byteOffset + offset,
                length,
              )
              return baseFS.write(
                stream.nfd!,
                actualBuffer,
                0,
                length,
                position,
              )
            } else {
              return baseFS.write(stream.nfd!, buffer, offset, length, position)
            }
          })
        },
        llseek: (stream: EmStream, offset: number, whence: number) => {
          log?.('llseek stream', EMFS.realPath(stream.node), offset, whence)
          let position = offset
          if (whence === 1) {
            position += stream.position
          } else if (whence === 2) {
            if (FS.isFile(stream.node.mode)) {
              EMFS.tryFSOperation(() => {
                const stat = baseFS.fstat(stream.nfd!)
                position += stat.size
              })
            }
          }
          if (position < 0) {
            throw new FS.ErrnoError(28)
          }
          return position
        },
        mmap: (
          stream: EmStream,
          length: number,
          position: number,
          _prot: unknown,
          _flags: unknown,
        ) => {
          log?.(
            'mmap stream',
            EMFS.realPath(stream.node),
            length,
            position,
            _prot,
            _flags,
          )
          if (!FS.isFile(stream.node.mode)) {
            throw new FS.ErrnoError(ERRNO_CODES.ENODEV)
          }

          const ptr = Module.mmapAlloc(length)
          const heap = new Uint8Array(
            Module.HEAP8.buffer,
            Module.HEAP8.byteOffset,
            Module.HEAP8.byteLength,
          )

          EMFS.stream_ops.read(stream, heap, ptr, length, position)
          return { ptr, allocated: true }
        },
        msync: (
          stream: EmStream,
          buffer: Uint8Array,
          offset: number,
          length: number,
          _mmapFlags: unknown,
        ) => {
          log?.(
            'msync stream',
            EMFS.realPath(stream.node),
            offset,
            length,
            _mmapFlags,
          )
          EMFS.stream_ops.write(stream, buffer, 0, length, offset)
          return 0
        },
      },
    }

    return EMFS
  }
}
