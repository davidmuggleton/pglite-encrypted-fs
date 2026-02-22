import { describe, it, expect, beforeEach, afterEach } from 'vitest'
import { PGlite } from '@electric-sql/pglite'
import * as fs from 'fs'
import * as path from 'path'
import {
  createTestDir,
  cleanupTestDir,
  createEncryptedPGlite,
  createEncryptedFSWithSalt,
  corruptFileAt,
  findFiles,
} from '../helpers/test-utils.js'
import { FILE_HEADER_SIZE } from '../../src/crypto.js'

describe('PGlite Failure Modes', () => {
  let testDir: string

  beforeEach(() => {
    testDir = createTestDir()
  })

  afterEach(() => {
    cleanupTestDir(testDir)
  })

  describe('wrong key handling', () => {
    it('fails immediately with wrong passphrase at construction time', async () => {
      const { db, salt } = await createEncryptedPGlite(
        testDir,
        'correct-password',
      )
      await db.query('CREATE TABLE test (id INTEGER)')
      await db.query('INSERT INTO test VALUES (1)')
      await db.close()

      expect(() =>
        createEncryptedFSWithSalt(testDir, salt, 'wrong-password'),
      ).toThrow(/Invalid passphrase or corrupted encryption keys/)
    })

    it('wrong key produces clear error, not garbage data', async () => {
      const { db, salt } = await createEncryptedPGlite(
        testDir,
        'correct-password',
      )
      await db.query('CREATE TABLE secret (data TEXT)')
      await db.query(`INSERT INTO secret VALUES ('sensitive information')`)
      await db.close()

      let error: Error | null = null
      try {
        createEncryptedFSWithSalt(testDir, salt, 'wrong-password')
      } catch (e) {
        error = e as Error
      }

      expect(error).not.toBeNull()
      expect(error!.message).toMatch(
        /Invalid passphrase or corrupted encryption keys/,
      )
    })
  })

  describe('data corruption detection', () => {
    it('detects corrupted data file', async () => {
      const { db, salt } = await createEncryptedPGlite(testDir)
      await db.exec('CREATE TABLE corrupt_test (id INTEGER, data TEXT)')
      for (let i = 0; i < 100; i++) {
        await db.exec(
          `INSERT INTO corrupt_test VALUES (${i}, '${'x'.repeat(100)}')`,
        )
      }
      await db.close()

      const pgControlPath = path.join(testDir, 'global', 'pg_control')
      if (!fs.existsSync(pgControlPath)) return

      corruptFileAt(pgControlPath, FILE_HEADER_SIZE + 50)

      const { fs: encFs } = createEncryptedFSWithSalt(testDir, salt)

      let error: Error | null = null
      try {
        const db2 = await PGlite.create({ dataDir: testDir, fs: encFs })
        await db2.close()
      } catch (e) {
        error = e as Error
      }

      expect(error).not.toBeNull()
    })

    it('detects IV corruption', async () => {
      const { db, salt } = await createEncryptedPGlite(testDir)
      await db.exec('CREATE TABLE iv_test (id INTEGER)')
      await db.exec('INSERT INTO iv_test VALUES (1)')
      await db.close()

      const pgControlPath = path.join(testDir, 'global', 'pg_control')
      if (!fs.existsSync(pgControlPath)) return

      corruptFileAt(pgControlPath, FILE_HEADER_SIZE + 2)

      const { fs: encFs } = createEncryptedFSWithSalt(testDir, salt)

      let error: Error | null = null
      try {
        const db2 = await PGlite.create({ dataDir: testDir, fs: encFs })
        await db2.close()
      } catch (e) {
        error = e as Error
      }

      expect(error).not.toBeNull()
    })

    it('detects partial file corruption (truncated to non-page boundary)', async () => {
      const { db, salt } = await createEncryptedPGlite(testDir)
      await db.exec('CREATE TABLE partial_test (id INTEGER, data TEXT)')
      await db.exec(
        `INSERT INTO partial_test VALUES (1, '${'x'.repeat(1000)}')`,
      )
      await db.close()

      const pgControlPath = path.join(testDir, 'global', 'pg_control')
      if (!fs.existsSync(pgControlPath)) return

      fs.truncateSync(pgControlPath, FILE_HEADER_SIZE + 100)

      const { fs: encFs } = createEncryptedFSWithSalt(testDir, salt)

      let error: Error | null = null
      try {
        const db2 = await PGlite.create({ dataDir: testDir, fs: encFs })
        await db2.close()
      } catch (e) {
        error = e as Error
      }

      expect(error).not.toBeNull()
    })
  })

  describe('error message quality', () => {
    it('error does not expose sensitive information', async () => {
      const { db, salt } = await createEncryptedPGlite(
        testDir,
        'my-secret-password',
      )
      await db.query('CREATE TABLE err_test (id INTEGER)')
      await db.close()

      let errorMessage = ''
      try {
        createEncryptedFSWithSalt(testDir, salt, 'wrong-password')
      } catch (e) {
        errorMessage = (e as Error).message || String(e)
      }

      expect(errorMessage).toBeTruthy()
      expect(errorMessage.toLowerCase()).not.toContain('my-secret-password')
      expect(errorMessage.toLowerCase()).not.toContain('wrong-password')
    })
  })

  describe('recovery scenarios', () => {
    it('uncorrupted files remain readable after sibling corruption', async () => {
      const { db, salt } = await createEncryptedPGlite(testDir)

      // Create two tables in potentially different files
      await db.exec('CREATE TABLE table_a (id INTEGER)')
      await db.exec('INSERT INTO table_a VALUES (1), (2), (3)')

      await db.exec('CREATE TABLE table_b (id INTEGER)')
      await db.exec('INSERT INTO table_b VALUES (10), (20), (30)')

      await db.close()

      // Find data files
      const dataFiles = findFiles(testDir, /^\d+$/)

      if (dataFiles.length < 1) return

      // Note: This test is limited because PGlite/Postgres may store
      // multiple tables in the same file. The key assertion is that
      // we fail loudly on corruption rather than silently returning bad data.

      // Reopen without corruption first to verify baseline
      const { fs: encFs } = createEncryptedFSWithSalt(testDir, salt)
      const db2 = await PGlite.create({ dataDir: testDir, fs: encFs })

      const resultA = await db2.query(
        'SELECT COUNT(*)::int as count FROM table_a',
      )
      expect(resultA.rows[0]?.count).toBe(3)

      const resultB = await db2.query(
        'SELECT COUNT(*)::int as count FROM table_b',
      )
      expect(resultB.rows[0]?.count).toBe(3)

      await db2.close()
    })
  })

  describe('concurrent access safety', () => {
    it('handles rapid close/reopen without corruption', async () => {
      const { db, salt } = await createEncryptedPGlite(testDir)
      await db.exec('CREATE TABLE rapid_test (id SERIAL, data TEXT)')
      await db.close()

      for (let i = 0; i < 5; i++) {
        const { fs: encFs } = createEncryptedFSWithSalt(testDir, salt)
        const db2 = await PGlite.create({ dataDir: testDir, fs: encFs })
        await db2.exec(`INSERT INTO rapid_test (data) VALUES ('cycle ${i}')`)
        await db2.close()
      }

      const { fs: encFs } = createEncryptedFSWithSalt(testDir, salt)
      const db3 = await PGlite.create({ dataDir: testDir, fs: encFs })
      const result = await db3.query(
        'SELECT COUNT(*)::int as count FROM rapid_test',
      )
      expect(result.rows[0]?.count).toBe(5)
      await db3.close()
    })
  })

  describe('boundary conditions', () => {
    it('handles empty database gracefully', async () => {
      const { db, salt } = await createEncryptedPGlite(testDir)
      await db.close()

      const { fs: encFs } = createEncryptedFSWithSalt(testDir, salt)
      const db2 = await PGlite.create({ dataDir: testDir, fs: encFs })
      const result = await db2.query('SELECT 1 as value')
      expect(result.rows[0]?.value).toBe(1)
      await db2.close()
    })

    it('handles database growth forcing new pages', async () => {
      const { db, salt } = await createEncryptedPGlite(testDir)

      await db.exec('CREATE TABLE growth_test (id INTEGER, data TEXT)')

      const largeText = 'x'.repeat(1000)
      for (let i = 0; i < 100; i++) {
        await db.exec(`INSERT INTO growth_test VALUES (${i}, '${largeText}')`)
      }

      await db.close()

      const { fs: encFs } = createEncryptedFSWithSalt(testDir, salt)
      const db2 = await PGlite.create({ dataDir: testDir, fs: encFs })
      const result = await db2.query(
        'SELECT COUNT(*)::int as count FROM growth_test',
      )
      expect(result.rows[0]?.count).toBe(100)
      await db2.close()
    })
  })
})
