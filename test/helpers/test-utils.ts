import {
  EncryptedFS,
  deriveKeys,
  SALT_SIZE,
  type DerivedKeys,
} from '../../src/index.js'
import { PGlite } from '@electric-sql/pglite'
import * as fs from 'fs'
import * as path from 'path'
import * as os from 'os'

/**
 * Create a unique temporary directory for tests
 */
export function createTestDir(): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'pglite-test-'))
}

/**
 * Clean up a test directory
 */
export function cleanupTestDir(dir: string): void {
  fs.rmSync(dir, { recursive: true, force: true })
}

/**
 * Create an EncryptedFS instance for testing
 */
export function createEncryptedFS(
  dataDir: string,
  passphrase = 'test-passphrase',
): { fs: EncryptedFS; salt: Buffer; keys: DerivedKeys } {
  const encFs = new EncryptedFS(dataDir, passphrase)
  const tokenPath = path.join(dataDir, '.encryption-verify')
  const salt = Buffer.from(fs.readFileSync(tokenPath).subarray(0, SALT_SIZE))
  const keys = deriveKeys(passphrase, salt)
  return { fs: encFs, salt, keys }
}

/**
 * Create an EncryptedFS with existing salt (for reopen tests)
 */
export function createEncryptedFSWithSalt(
  dataDir: string,
  _salt: Buffer,
  passphrase = 'test-passphrase',
): { fs: EncryptedFS; keys: DerivedKeys } {
  const encFs = new EncryptedFS(dataDir, passphrase)
  const tokenPath = path.join(dataDir, '.encryption-verify')
  const salt = Buffer.from(fs.readFileSync(tokenPath).subarray(0, SALT_SIZE))
  const keys = deriveKeys(passphrase, salt)
  return { fs: encFs, keys }
}

/**
 * Create an EncryptedFS with passphrase only (no manual salt)
 */
export function createPassphraseFS(
  dataDir: string,
  passphrase = 'test-passphrase',
): EncryptedFS {
  return new EncryptedFS(dataDir, passphrase)
}

/**
 * Create an encrypted PGlite with passphrase only (no manual salt)
 */
export async function createPassphrasePGlite(
  dataDir: string,
  passphrase = 'test-passphrase',
  extensions?: Record<string, unknown>,
): Promise<PGlite> {
  const encFs = new EncryptedFS(dataDir, passphrase)
  return PGlite.create({ dataDir, fs: encFs, extensions })
}

/**
 * Create an encrypted PGlite instance for testing
 */
export async function createEncryptedPGlite(
  dataDir: string,
  passphrase = 'test-passphrase',
  extensions?: Record<string, unknown>,
): Promise<{ db: PGlite; salt: Buffer; keys: DerivedKeys }> {
  const { fs: encFs, salt, keys } = createEncryptedFS(dataDir, passphrase)
  const db = await PGlite.create({ dataDir, fs: encFs, extensions })
  return { db, salt, keys }
}

/**
 * Reopen an encrypted PGlite with existing salt
 */
export async function reopenEncryptedPGlite(
  dataDir: string,
  _salt: Buffer,
  passphrase = 'test-passphrase',
  extensions?: Record<string, unknown>,
): Promise<{ db: PGlite; keys: DerivedKeys }> {
  const encFs = new EncryptedFS(dataDir, passphrase)
  const tokenPath = path.join(dataDir, '.encryption-verify')
  const salt = Buffer.from(fs.readFileSync(tokenPath).subarray(0, SALT_SIZE))
  const keys = deriveKeys(passphrase, salt)
  const db = await PGlite.create({ dataDir, fs: encFs, extensions })
  return { db, keys }
}

/**
 * Verify a file contains encrypted data (plaintext not visible)
 */
export function verifyFileEncrypted(
  filePath: string,
  plaintext: string,
): boolean {
  if (!fs.existsSync(filePath)) return false
  const content = fs.readFileSync(filePath)
  return !content.toString('utf8').includes(plaintext)
}

/**
 * Corrupt a file at a specific offset by flipping a byte
 */
export function corruptFileAt(filePath: string, offset: number): void {
  const fd = fs.openSync(filePath, 'r+')
  const buf = Buffer.alloc(1)
  fs.readSync(fd, buf, 0, 1, offset)
  buf[0] ^= 0xff
  fs.writeSync(fd, buf, 0, 1, offset)
  fs.closeSync(fd)
}

/**
 * Get the physical size of a file on disk
 */
export function getPhysicalSize(filePath: string): number {
  return fs.statSync(filePath).size
}

/**
 * Find files in a directory matching a pattern (recursive)
 */
export function findFiles(dir: string, pattern: RegExp): string[] {
  const results: string[] = []

  function walk(currentDir: string) {
    if (!fs.existsSync(currentDir)) return
    const entries = fs.readdirSync(currentDir, { withFileTypes: true })
    for (const entry of entries) {
      const fullPath = path.join(currentDir, entry.name)
      if (entry.isDirectory()) {
        walk(fullPath)
      } else if (pattern.test(entry.name)) {
        results.push(fullPath)
      }
    }
  }

  walk(dir)
  return results
}

/**
 * Find the first data file in a PGlite data directory
 * (useful for corruption tests)
 */
export function findFirstDataFile(dataDir: string): string | null {
  const baseDir = path.join(dataDir, 'base')
  if (!fs.existsSync(baseDir)) return null

  const entries = fs.readdirSync(baseDir, { withFileTypes: true })
  for (const entry of entries) {
    if (entry.isDirectory() && /^\d+$/.test(entry.name)) {
      const dbDir = path.join(baseDir, entry.name)
      const files = fs.readdirSync(dbDir)
      for (const file of files) {
        if (/^\d+$/.test(file)) {
          return path.join(dbDir, file)
        }
      }
    }
  }
  return null
}
