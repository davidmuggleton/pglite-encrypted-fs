import { describe, it, expect, beforeEach, afterEach } from 'vitest'
import * as fs from 'fs'
import * as path from 'path'
import {
  createTestDir,
  cleanupTestDir,
  createEncryptedFS,
  createEncryptedFSWithSalt,
  getPhysicalSize,
} from '../helpers/test-utils.js'
import {
  PAGE_SIZE,
  FILE_HEADER_SIZE,
  ENCRYPTED_PAGE_SIZE,
} from '../../src/crypto.js'

describe('EncryptedFS', () => {
  let testDir: string

  beforeEach(() => {
    testDir = createTestDir()
  })

  afterEach(() => {
    cleanupTestDir(testDir)
  })

  describe('basic file operations', () => {
    it('creates and reads a file', () => {
      const { fs: encFs } = createEncryptedFS(testDir)
      const testPath = '/testfile'

      const fd = encFs.open(testPath, 'w')
      const data = Buffer.from('hello world')
      encFs.write(fd, data, 0, data.length, 0)
      encFs.close(fd)

      const fd2 = encFs.open(testPath, 'r')
      const readBuf = new Uint8Array(data.length)
      const bytesRead = encFs.read(fd2, readBuf, 0, data.length, 0)
      encFs.close(fd2)

      expect(bytesRead).toBe(data.length)
      expect(Buffer.from(readBuf).toString()).toBe('hello world')
    })

    it('reopens file with same keys and reads data', () => {
      const { fs: encFs, salt } = createEncryptedFS(testDir)
      const testPath = '/testfile'

      const fd = encFs.open(testPath, 'w')
      const data = Buffer.from('persistent data')
      encFs.write(fd, data, 0, data.length, 0)
      encFs.close(fd)

      const { fs: encFs2 } = createEncryptedFSWithSalt(testDir, salt)

      const fd2 = encFs2.open(testPath, 'r')
      const readBuf = new Uint8Array(data.length)
      const bytesRead = encFs2.read(fd2, readBuf, 0, data.length, 0)
      encFs2.close(fd2)

      expect(bytesRead).toBe(data.length)
      expect(Buffer.from(readBuf).toString()).toBe('persistent data')
    })

    it('handles writeFile convenience method', () => {
      const { fs: encFs } = createEncryptedFS(testDir)
      const testPath = '/writefile-test'

      encFs.writeFile(testPath, 'test content')

      const fd = encFs.open(testPath, 'r')
      const readBuf = new Uint8Array(12)
      encFs.read(fd, readBuf, 0, 12, 0)
      encFs.close(fd)

      expect(Buffer.from(readBuf).toString()).toBe('test content')
    })
  })

  describe('page boundary handling', () => {
    it('writes and reads data spanning two pages', () => {
      const { fs: encFs } = createEncryptedFS(testDir)
      const testPath = '/cross-page'

      const data = Buffer.alloc(PAGE_SIZE + 100, 0)
      data.fill(0xaa, 0, PAGE_SIZE)
      data.fill(0xbb, PAGE_SIZE, PAGE_SIZE + 100)

      const fd = encFs.open(testPath, 'w')
      encFs.write(fd, data, 0, data.length, 0)
      encFs.close(fd)

      const fd2 = encFs.open(testPath, 'r')
      const readBuf = new Uint8Array(data.length)
      const bytesRead = encFs.read(fd2, readBuf, 0, data.length, 0)
      encFs.close(fd2)

      expect(bytesRead).toBe(data.length)
      expect(Buffer.from(readBuf).equals(data)).toBe(true)
    })

    it('reads across page boundary (position 8191, length 2)', () => {
      const { fs: encFs } = createEncryptedFS(testDir)
      const testPath = '/boundary-read'

      const data = Buffer.alloc(PAGE_SIZE + 100, 0)
      data[PAGE_SIZE - 1] = 0xaa
      data[PAGE_SIZE] = 0xbb

      const fd = encFs.open(testPath, 'w')
      encFs.write(fd, data, 0, data.length, 0)
      encFs.close(fd)

      const fd2 = encFs.open(testPath, 'r')
      const readBuf = new Uint8Array(2)
      const bytesRead = encFs.read(fd2, readBuf, 0, 2, PAGE_SIZE - 1)
      encFs.close(fd2)

      expect(bytesRead).toBe(2)
      expect(readBuf[0]).toBe(0xaa)
      expect(readBuf[1]).toBe(0xbb)
    })

    it('writes at exact page boundary (position 8192)', () => {
      const { fs: encFs } = createEncryptedFS(testDir)
      const testPath = '/exact-boundary'

      const page0Data = Buffer.alloc(PAGE_SIZE, 0x11)
      const fd = encFs.open(testPath, 'w')
      encFs.write(fd, page0Data, 0, page0Data.length, 0)

      const page1Data = Buffer.from('page1 data')
      encFs.write(fd, page1Data, 0, page1Data.length, PAGE_SIZE)
      encFs.close(fd)

      const fd2 = encFs.open(testPath, 'r')
      const readBuf0 = new Uint8Array(PAGE_SIZE)
      encFs.read(fd2, readBuf0, 0, PAGE_SIZE, 0)
      expect(readBuf0.every((b) => b === 0x11)).toBe(true)

      const readBuf1 = new Uint8Array(page1Data.length)
      encFs.read(fd2, readBuf1, 0, page1Data.length, PAGE_SIZE)
      encFs.close(fd2)
      expect(Buffer.from(readBuf1).toString()).toBe('page1 data')
    })

    it('partial page write preserves existing data', () => {
      const { fs: encFs } = createEncryptedFS(testDir)
      const testPath = '/partial-preserve'

      const fd = encFs.open(testPath, 'w')
      const initial = Buffer.alloc(PAGE_SIZE, 0xff)
      encFs.write(fd, initial, 0, initial.length, 0)
      encFs.close(fd)

      const fd2 = encFs.open(testPath, 'r+')
      const patch = Buffer.from('0123456789')
      encFs.write(fd2, patch, 0, patch.length, 100)
      encFs.close(fd2)

      const fd3 = encFs.open(testPath, 'r')
      const readBuf = new Uint8Array(PAGE_SIZE)
      encFs.read(fd3, readBuf, 0, PAGE_SIZE, 0)
      encFs.close(fd3)

      expect(readBuf.slice(0, 100).every((b) => b === 0xff)).toBe(true)
      expect(Buffer.from(readBuf.slice(100, 110)).toString()).toBe('0123456789')
      expect(readBuf.slice(110).every((b) => b === 0xff)).toBe(true)
    })
  })

  describe('size mapping', () => {
    it('reports correct physical size for 1 byte write', () => {
      const { fs: encFs } = createEncryptedFS(testDir)
      const testPath = '/size-1byte'
      const fullPath = path.join(testDir, testPath)

      const fd = encFs.open(testPath, 'w')
      encFs.write(fd, Buffer.from([0x42]), 0, 1, 0)
      encFs.close(fd)

      const physicalSize = getPhysicalSize(fullPath)
      expect(physicalSize).toBe(FILE_HEADER_SIZE + ENCRYPTED_PAGE_SIZE)
    })

    it('reports correct physical size for exactly PAGE_SIZE bytes', () => {
      const { fs: encFs } = createEncryptedFS(testDir)
      const testPath = '/size-page'
      const fullPath = path.join(testDir, testPath)

      const fd = encFs.open(testPath, 'w')
      encFs.write(fd, Buffer.alloc(PAGE_SIZE, 0x42), 0, PAGE_SIZE, 0)
      encFs.close(fd)

      const physicalSize = getPhysicalSize(fullPath)
      expect(physicalSize).toBe(FILE_HEADER_SIZE + ENCRYPTED_PAGE_SIZE)
    })

    it('reports correct physical size for PAGE_SIZE + 1 bytes (2 pages)', () => {
      const { fs: encFs } = createEncryptedFS(testDir)
      const testPath = '/size-2pages'
      const fullPath = path.join(testDir, testPath)

      const fd = encFs.open(testPath, 'w')
      encFs.write(fd, Buffer.alloc(PAGE_SIZE + 1, 0x42), 0, PAGE_SIZE + 1, 0)
      encFs.close(fd)

      const physicalSize = getPhysicalSize(fullPath)
      expect(physicalSize).toBe(FILE_HEADER_SIZE + 2 * ENCRYPTED_PAGE_SIZE)
    })

    it('fstat returns logical size (full pages)', () => {
      const { fs: encFs } = createEncryptedFS(testDir)
      const testPath = '/fstat-size'

      const fd = encFs.open(testPath, 'w')
      encFs.write(fd, Buffer.from('hello'), 0, 5, 0)

      const stats = encFs.fstat(fd)
      encFs.close(fd)

      expect(stats.size).toBe(PAGE_SIZE)
    })

    it('lstat returns logical size for encrypted files', () => {
      const { fs: encFs } = createEncryptedFS(testDir)
      const testPath = '/lstat-size'

      const fd = encFs.open(testPath, 'w')
      encFs.write(
        fd,
        Buffer.alloc(PAGE_SIZE + 100, 0x42),
        0,
        PAGE_SIZE + 100,
        0,
      )
      encFs.close(fd)

      const stats = encFs.lstat(testPath)
      expect(stats.size).toBe(2 * PAGE_SIZE)
    })
  })

  describe('truncate', () => {
    it('truncates to 0 leaves only salt', () => {
      const { fs: encFs } = createEncryptedFS(testDir)
      const testPath = '/truncate-zero'
      const fullPath = path.join(testDir, testPath)

      const fd = encFs.open(testPath, 'w')
      encFs.write(fd, Buffer.alloc(PAGE_SIZE * 2, 0x42), 0, PAGE_SIZE * 2, 0)
      encFs.close(fd)

      expect(getPhysicalSize(fullPath)).toBe(
        FILE_HEADER_SIZE + 2 * ENCRYPTED_PAGE_SIZE,
      )

      encFs.truncate(testPath, 0)

      expect(getPhysicalSize(fullPath)).toBe(FILE_HEADER_SIZE)
    })

    it('truncates shrink reduces page count', () => {
      const { fs: encFs } = createEncryptedFS(testDir)
      const testPath = '/truncate-shrink'
      const fullPath = path.join(testDir, testPath)

      const fd = encFs.open(testPath, 'w')
      encFs.write(fd, Buffer.alloc(PAGE_SIZE * 3, 0x42), 0, PAGE_SIZE * 3, 0)
      encFs.close(fd)

      expect(getPhysicalSize(fullPath)).toBe(
        FILE_HEADER_SIZE + 3 * ENCRYPTED_PAGE_SIZE,
      )

      encFs.truncate(testPath, PAGE_SIZE + PAGE_SIZE / 2)

      expect(getPhysicalSize(fullPath)).toBe(
        FILE_HEADER_SIZE + 2 * ENCRYPTED_PAGE_SIZE,
      )
    })

    it('truncate extend creates readable zero pages', () => {
      const { fs: encFs } = createEncryptedFS(testDir)
      const testPath = '/truncate-extend'
      const fullPath = path.join(testDir, testPath)

      const fd = encFs.open(testPath, 'w')
      const page0 = Buffer.alloc(PAGE_SIZE, 0xaa)
      encFs.write(fd, page0, 0, PAGE_SIZE, 0)
      encFs.close(fd)

      expect(getPhysicalSize(fullPath)).toBe(
        FILE_HEADER_SIZE + ENCRYPTED_PAGE_SIZE,
      )

      encFs.truncate(testPath, PAGE_SIZE * 3)

      expect(getPhysicalSize(fullPath)).toBe(
        FILE_HEADER_SIZE + 3 * ENCRYPTED_PAGE_SIZE,
      )

      const fd2 = encFs.open(testPath, 'r')

      const readBuf0 = new Uint8Array(PAGE_SIZE)
      encFs.read(fd2, readBuf0, 0, PAGE_SIZE, 0)
      expect(readBuf0.every((b) => b === 0xaa)).toBe(true)

      const readBuf1 = new Uint8Array(PAGE_SIZE)
      encFs.read(fd2, readBuf1, 0, PAGE_SIZE, PAGE_SIZE)
      expect(readBuf1.every((b) => b === 0)).toBe(true)

      const readBuf2 = new Uint8Array(PAGE_SIZE)
      encFs.read(fd2, readBuf2, 0, PAGE_SIZE, PAGE_SIZE * 2)
      expect(readBuf2.every((b) => b === 0)).toBe(true)

      encFs.close(fd2)
    })

    it('truncate extend then write works', () => {
      const { fs: encFs } = createEncryptedFS(testDir)
      const testPath = '/truncate-extend-write'

      const fd = encFs.open(testPath, 'w')
      encFs.write(fd, Buffer.from([0x00]), 0, 1, 0)
      encFs.close(fd)

      encFs.truncate(testPath, PAGE_SIZE * 2)

      const fd2 = encFs.open(testPath, 'r+')
      const data = Buffer.from('data on page 1')
      encFs.write(fd2, data, 0, data.length, PAGE_SIZE)
      encFs.close(fd2)

      const fd3 = encFs.open(testPath, 'r')
      const readBuf = new Uint8Array(data.length)
      encFs.read(fd3, readBuf, 0, data.length, PAGE_SIZE)
      encFs.close(fd3)

      expect(Buffer.from(readBuf).toString()).toBe('data on page 1')
    })
  })

  describe('non-encrypted files', () => {
    it('.conf files are not encrypted', () => {
      const { fs: encFs } = createEncryptedFS(testDir)
      const testPath = '/postgresql.conf'
      const fullPath = path.join(testDir, testPath)

      const content = 'max_connections = 100'
      encFs.writeFile(testPath, content)

      const onDisk = fs.readFileSync(fullPath, 'utf8')
      expect(onDisk).toBe(content)
    })

    it('PG_VERSION is not encrypted', () => {
      const { fs: encFs } = createEncryptedFS(testDir)
      const testPath = '/PG_VERSION'
      const fullPath = path.join(testDir, testPath)

      encFs.writeFile(testPath, '16')

      const onDisk = fs.readFileSync(fullPath, 'utf8')
      expect(onDisk).toBe('16')
    })

    it('.pid files are not encrypted', () => {
      const { fs: encFs } = createEncryptedFS(testDir)
      const testPath = '/postmaster.pid'
      const fullPath = path.join(testDir, testPath)

      encFs.writeFile(testPath, '12345')

      const onDisk = fs.readFileSync(fullPath, 'utf8')
      expect(onDisk).toBe('12345')
    })

    it('non-encrypted file size matches actual bytes', () => {
      const { fs: encFs } = createEncryptedFS(testDir)
      const testPath = '/test.conf'
      const fullPath = path.join(testDir, testPath)

      const content = 'some config'
      encFs.writeFile(testPath, content)

      expect(getPhysicalSize(fullPath)).toBe(content.length)

      const fd = encFs.open(testPath, 'r')
      const stats = encFs.fstat(fd)
      encFs.close(fd)
      expect(stats.size).toBe(content.length)
    })
  })

  describe('directory operations', () => {
    it('creates and lists directories', () => {
      const { fs: encFs } = createEncryptedFS(testDir)

      encFs.mkdir('/subdir')
      encFs.writeFile('/subdir/file1', 'content1')
      encFs.writeFile('/subdir/file2', 'content2')

      const entries = encFs.readdir('/subdir')
      expect(entries).toContain('file1')
      expect(entries).toContain('file2')
    })

    it('renames files', () => {
      const { fs: encFs } = createEncryptedFS(testDir)
      const oldPath = '/oldname'
      const newPath = '/newname'

      encFs.writeFile(oldPath, 'content')
      encFs.rename(oldPath, newPath)

      expect(() => encFs.lstat(oldPath)).toThrow()

      const fd = encFs.open(newPath, 'r')
      const buf = new Uint8Array(7)
      encFs.read(fd, buf, 0, 7, 0)
      encFs.close(fd)
      expect(Buffer.from(buf).toString()).toBe('content')
    })

    it('removes files with unlink', () => {
      const { fs: encFs } = createEncryptedFS(testDir)
      const testPath = '/to-delete'

      encFs.writeFile(testPath, 'content')
      encFs.unlink(testPath)

      expect(() => encFs.lstat(testPath)).toThrow()
    })

    it('removes empty directories with rmdir', () => {
      const { fs: encFs } = createEncryptedFS(testDir)

      encFs.mkdir('/emptydir')
      encFs.rmdir('/emptydir')

      expect(() => encFs.lstat('/emptydir')).toThrow()
    })
  })

  describe('error handling', () => {
    it('throws on read of non-existent file', () => {
      const { fs: encFs } = createEncryptedFS(testDir)
      expect(() => encFs.open('/nonexistent', 'r')).toThrow()
    })

    it('throws on invalid file descriptor', () => {
      const { fs: encFs } = createEncryptedFS(testDir)
      expect(() => encFs.close(999)).toThrow(/EBADF/)
      expect(() => encFs.read(999, new Uint8Array(10), 0, 10, 0)).toThrow(
        /EBADF/,
      )
    })

    it('rejects wrong passphrase at construction time', () => {
      createEncryptedFS(testDir, 'correct-password')

      expect(() => createEncryptedFS(testDir, 'wrong-password')).toThrow(
        /Invalid passphrase or corrupted encryption keys/,
      )
    })

    it('accepts correct passphrase at construction time', () => {
      const { salt } = createEncryptedFS(testDir, 'my-password')

      expect(() =>
        createEncryptedFSWithSalt(testDir, salt, 'my-password'),
      ).not.toThrow()
    })

    it('detects corrupted partial page on read', () => {
      const { fs: encFs } = createEncryptedFS(testDir)
      const testPath = '/corrupt-partial'
      const fullPath = path.join(testDir, testPath)

      const fd = encFs.open(testPath, 'w')
      encFs.write(fd, Buffer.alloc(PAGE_SIZE, 0x42), 0, PAGE_SIZE, 0)
      encFs.close(fd)

      const currentSize = getPhysicalSize(fullPath)
      fs.truncateSync(fullPath, currentSize - 10)

      const fd2 = encFs.open(testPath, 'r')
      expect(() => {
        const buf = new Uint8Array(PAGE_SIZE)
        encFs.read(fd2, buf, 0, PAGE_SIZE, 0)
      }).toThrow()
      encFs.close(fd2)
    })
  })
})
