import { describe, it, expect, beforeEach, afterEach } from 'vitest'
import {
  createTestDir,
  cleanupTestDir,
  createEncryptedPGlite,
  createPassphrasePGlite,
  reopenEncryptedPGlite,
  verifyFileEncrypted,
  findFiles,
} from '../helpers/test-utils.js'
import { EncryptedFS } from '../../src/index.js'

describe('PGlite Basic Integration', () => {
  let testDir: string

  beforeEach(() => {
    testDir = createTestDir()
  })

  afterEach(() => {
    cleanupTestDir(testDir)
  })

  describe('database lifecycle', () => {
    it('creates a new database with EncryptedFS', async () => {
      const { db } = await createEncryptedPGlite(testDir)

      const result = await db.query('SELECT 1 as value')
      expect(result.rows[0]).toEqual({ value: 1 })

      await db.close()
    })

    it('creates table and inserts data', async () => {
      const { db } = await createEncryptedPGlite(testDir)

      await db.exec(`
        CREATE TABLE items (
          id SERIAL PRIMARY KEY,
          name TEXT NOT NULL,
          value INTEGER
        )
      `)

      await db.exec(`INSERT INTO items (name, value) VALUES ('test', 42)`)

      const result = await db.query('SELECT * FROM items')
      expect(result.rows).toHaveLength(1)
      expect(result.rows[0]).toMatchObject({ name: 'test', value: 42 })

      await db.close()
    })
  })

  describe('restart durability', () => {
    it('data survives close and reopen', async () => {
      const { db, salt } = await createEncryptedPGlite(testDir)

      await db.exec(`
        CREATE TABLE persist_test (
          id SERIAL PRIMARY KEY,
          data TEXT
        )
      `)
      await db.exec(`INSERT INTO persist_test (data) VALUES ('persistent')`)
      await db.close()

      const { db: db2 } = await reopenEncryptedPGlite(testDir, salt)

      const result = await db2.query('SELECT * FROM persist_test')
      expect(result.rows).toHaveLength(1)
      expect(result.rows[0]).toMatchObject({ data: 'persistent' })

      await db2.close()
    })

    it('schema survives restart', async () => {
      const { db, salt } = await createEncryptedPGlite(testDir)

      await db.exec(`
        CREATE TABLE schema_test (
          id INTEGER PRIMARY KEY,
          created_at TIMESTAMP DEFAULT NOW(),
          metadata JSONB
        )
      `)
      await db.close()

      const { db: db2 } = await reopenEncryptedPGlite(testDir, salt)

      await db2.exec(
        `INSERT INTO schema_test (id, metadata) VALUES (1, '{"key": "value"}')`,
      )
      const result = await db2.query('SELECT id, metadata FROM schema_test')
      expect(result.rows[0]).toMatchObject({
        id: 1,
        metadata: { key: 'value' },
      })

      await db2.close()
    })

    it('indexes survive restart', async () => {
      const { db, salt } = await createEncryptedPGlite(testDir)

      await db.exec(`
        CREATE TABLE indexed_test (id INTEGER, name TEXT);
        CREATE INDEX idx_name ON indexed_test(name);
      `)
      await db.exec(`INSERT INTO indexed_test VALUES (1, 'alice'), (2, 'bob')`)
      await db.close()

      const { db: db2 } = await reopenEncryptedPGlite(testDir, salt)

      const result = await db2.query(
        `SELECT * FROM indexed_test WHERE name = 'bob'`,
      )
      expect(result.rows).toHaveLength(1)
      expect(result.rows[0]).toMatchObject({ id: 2, name: 'bob' })

      await db2.close()
    })

    it('sequences survive restart', async () => {
      const { db, salt } = await createEncryptedPGlite(testDir)

      await db.exec(`CREATE TABLE seq_test (id SERIAL PRIMARY KEY, data TEXT)`)
      await db.exec(`INSERT INTO seq_test (data) VALUES ('first'), ('second')`)
      await db.close()

      const { db: db2 } = await reopenEncryptedPGlite(testDir, salt)

      await db2.exec(`INSERT INTO seq_test (data) VALUES ('third')`)
      const result = await db2.query(
        `SELECT id FROM seq_test WHERE data = 'third'`,
      )
      expect(result.rows[0]?.id).toBe(3)

      await db2.close()
    })

    it('survives multiple restart cycles', async () => {
      let salt: Buffer

      {
        const { db, salt: s } = await createEncryptedPGlite(testDir)
        salt = s
        await db.exec(
          `CREATE TABLE multi_restart (id SERIAL PRIMARY KEY, cycle INTEGER)`,
        )
        await db.exec(`INSERT INTO multi_restart (cycle) VALUES (1)`)
        await db.close()
      }

      {
        const { db } = await reopenEncryptedPGlite(testDir, salt)
        await db.exec(`INSERT INTO multi_restart (cycle) VALUES (2)`)
        await db.close()
      }

      {
        const { db } = await reopenEncryptedPGlite(testDir, salt)
        await db.exec(`INSERT INTO multi_restart (cycle) VALUES (3)`)
        await db.close()
      }

      {
        const { db } = await reopenEncryptedPGlite(testDir, salt)
        const result = await db.query(
          `SELECT cycle FROM multi_restart ORDER BY cycle`,
        )
        expect(result.rows).toEqual([{ cycle: 1 }, { cycle: 2 }, { cycle: 3 }])
        await db.close()
      }
    })
  })

  describe('data operations', () => {
    it('SELECT with WHERE, JOIN, ORDER BY', async () => {
      const { db } = await createEncryptedPGlite(testDir)

      await db.exec(`
        CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT);
        CREATE TABLE orders (id INTEGER PRIMARY KEY, user_id INTEGER, amount INTEGER);
        INSERT INTO users VALUES (1, 'alice'), (2, 'bob');
        INSERT INTO orders VALUES (1, 1, 100), (2, 1, 200), (3, 2, 50);
      `)

      const result = await db.query(`
        SELECT u.name, SUM(o.amount) as total
        FROM users u
        JOIN orders o ON u.id = o.user_id
        GROUP BY u.name
        ORDER BY total DESC
      `)

      expect(result.rows).toHaveLength(2)
      expect(result.rows[0]?.name).toBe('alice')
      expect(Number(result.rows[0]?.total)).toBe(300)
      expect(result.rows[1]?.name).toBe('bob')
      expect(Number(result.rows[1]?.total)).toBe(50)

      await db.close()
    })

    it('UPDATE single and multiple rows', async () => {
      const { db } = await createEncryptedPGlite(testDir)

      await db.exec(`
        CREATE TABLE update_test (id INTEGER PRIMARY KEY, status TEXT);
        INSERT INTO update_test VALUES (1, 'pending'), (2, 'pending'), (3, 'done');
      `)

      await db.exec(`UPDATE update_test SET status = 'processing' WHERE id = 1`)
      let result = await db.query(`SELECT status FROM update_test WHERE id = 1`)
      expect(result.rows[0]?.status).toBe('processing')

      await db.exec(
        `UPDATE update_test SET status = 'archived' WHERE status = 'pending'`,
      )
      result = await db.query(
        `SELECT id FROM update_test WHERE status = 'archived'`,
      )
      expect(result.rows).toHaveLength(1)
      expect(result.rows[0]?.id).toBe(2)

      await db.close()
    })

    it('DELETE with conditions', async () => {
      const { db } = await createEncryptedPGlite(testDir)

      await db.exec(`
        CREATE TABLE delete_test (id INTEGER, category TEXT);
        INSERT INTO delete_test VALUES (1, 'a'), (2, 'b'), (3, 'a'), (4, 'b');
      `)

      await db.exec(`DELETE FROM delete_test WHERE category = 'a'`)
      const result = await db.query(
        `SELECT COUNT(*)::int as count FROM delete_test`,
      )
      expect(result.rows[0]?.count).toBe(2)

      await db.close()
    })

    it('handles NULL values correctly', async () => {
      const { db } = await createEncryptedPGlite(testDir)

      await db.exec(`
        CREATE TABLE null_test (id INTEGER, value TEXT);
        INSERT INTO null_test VALUES (1, 'not null'), (2, NULL);
      `)

      const result = await db.query(`SELECT * FROM null_test ORDER BY id`)
      expect(result.rows[0]).toEqual({ id: 1, value: 'not null' })
      expect(result.rows[1]).toEqual({ id: 2, value: null })

      await db.close()
    })
  })

  describe('transactions', () => {
    it('commit persists data', async () => {
      const { db, salt } = await createEncryptedPGlite(testDir)

      await db.exec(`CREATE TABLE tx_commit (id INTEGER, data TEXT)`)

      await db.transaction(async (tx) => {
        await tx.exec(`INSERT INTO tx_commit VALUES (1, 'committed')`)
      })

      await db.close()

      const { db: db2 } = await reopenEncryptedPGlite(testDir, salt)
      const result = await db2.query(`SELECT * FROM tx_commit`)
      expect(result.rows).toHaveLength(1)
      await db2.close()
    })

    it('rollback discards changes', async () => {
      const { db } = await createEncryptedPGlite(testDir)

      await db.exec(`CREATE TABLE tx_rollback (id INTEGER)`)
      await db.exec(`INSERT INTO tx_rollback VALUES (1)`)

      try {
        await db.transaction(async (tx) => {
          await tx.exec(`INSERT INTO tx_rollback VALUES (2)`)
          throw new Error('Force rollback')
        })
      } catch {}

      const result = await db.query(
        `SELECT COUNT(*)::int as count FROM tx_rollback`,
      )
      expect(result.rows[0]?.count).toBe(1)

      await db.close()
    })
  })

  describe('data types', () => {
    it('handles TEXT and VARCHAR', async () => {
      const { db } = await createEncryptedPGlite(testDir)

      await db.exec(`CREATE TABLE text_test (t TEXT, v VARCHAR(100))`)
      await db.exec(`INSERT INTO text_test VALUES ('hello', 'world')`)

      const result = await db.query(`SELECT * FROM text_test`)
      expect(result.rows[0]).toEqual({ t: 'hello', v: 'world' })

      await db.close()
    })

    it('handles INTEGER and BIGINT', async () => {
      const { db } = await createEncryptedPGlite(testDir)

      await db.exec(`CREATE TABLE int_test (i INTEGER, b BIGINT)`)
      await db.exec(`INSERT INTO int_test VALUES (42, 9223372036854775807)`)

      const result = await db.query(`SELECT * FROM int_test`)
      expect(result.rows[0]?.i).toBe(42)
      expect(result.rows[0]?.b).toBe(9223372036854775807n)

      await db.close()
    })

    it('handles FLOAT and NUMERIC', async () => {
      const { db } = await createEncryptedPGlite(testDir)

      await db.exec(`CREATE TABLE float_test (f FLOAT, n NUMERIC(10,2))`)
      await db.exec(`INSERT INTO float_test VALUES (3.14159, 123.45)`)

      const result = await db.query(`SELECT * FROM float_test`)
      expect(result.rows[0]?.f).toBeCloseTo(3.14159, 4)
      expect(result.rows[0]?.n).toBe('123.45')

      await db.close()
    })

    it('handles BOOLEAN', async () => {
      const { db } = await createEncryptedPGlite(testDir)

      await db.exec(`CREATE TABLE bool_test (active BOOLEAN)`)
      await db.exec(`INSERT INTO bool_test VALUES (true), (false)`)

      const result = await db.query(`SELECT * FROM bool_test ORDER BY active`)
      expect(result.rows[0]?.active).toBe(false)
      expect(result.rows[1]?.active).toBe(true)

      await db.close()
    })

    it('handles TIMESTAMP', async () => {
      const { db } = await createEncryptedPGlite(testDir)

      await db.exec(`CREATE TABLE time_test (ts TIMESTAMP)`)
      await db.exec(`INSERT INTO time_test VALUES ('2024-01-15 10:30:00')`)

      const result = await db.query(`SELECT ts FROM time_test`)
      expect(result.rows[0]?.ts).toBeInstanceOf(Date)

      await db.close()
    })

    it('handles JSON/JSONB', async () => {
      const { db } = await createEncryptedPGlite(testDir)

      await db.exec(`CREATE TABLE json_test (data JSONB)`)
      await db.exec(
        `INSERT INTO json_test VALUES ('{"name": "test", "values": [1, 2, 3]}')`,
      )

      const result = await db.query(`SELECT data FROM json_test`)
      expect(result.rows[0]?.data).toEqual({ name: 'test', values: [1, 2, 3] })

      const result2 = await db.query(
        `SELECT data->>'name' as name FROM json_test`,
      )
      expect(result2.rows[0]?.name).toBe('test')

      await db.close()
    })

    it('handles BYTEA (binary data)', async () => {
      const { db } = await createEncryptedPGlite(testDir)

      await db.exec(`CREATE TABLE bytea_test (data BYTEA)`)

      const binaryData = Buffer.from([0x00, 0x01, 0x02, 0xff, 0xfe])
      await db.query(`INSERT INTO bytea_test VALUES ($1)`, [binaryData])

      const result = await db.query(`SELECT data FROM bytea_test`)
      const retrieved = result.rows[0]?.data as Uint8Array
      expect(Buffer.from(retrieved).equals(binaryData)).toBe(true)

      await db.close()
    })

    it('handles ARRAY types', async () => {
      const { db } = await createEncryptedPGlite(testDir)

      await db.exec(`CREATE TABLE array_test (nums INTEGER[], tags TEXT[])`)
      await db.exec(
        `INSERT INTO array_test VALUES ('{1,2,3}', '{"a","b","c"}')`,
      )

      const result = await db.query(`SELECT * FROM array_test`)
      expect(result.rows[0]?.nums).toEqual([1, 2, 3])
      expect(result.rows[0]?.tags).toEqual(['a', 'b', 'c'])

      await db.close()
    })
  })

  describe('large data', () => {
    it('handles large TEXT fields', async () => {
      const { db } = await createEncryptedPGlite(testDir)

      await db.exec(`CREATE TABLE large_text (content TEXT)`)

      const largeContent = 'x'.repeat(100 * 1024)
      await db.query(`INSERT INTO large_text VALUES ($1)`, [largeContent])

      const result = await db.query(
        `SELECT LENGTH(content) as len FROM large_text`,
      )
      expect(result.rows[0]?.len).toBe(100 * 1024)

      await db.close()
    })

    it('handles many rows', async () => {
      const { db, salt } = await createEncryptedPGlite(testDir)

      await db.exec(`CREATE TABLE many_rows (id INTEGER, value TEXT)`)

      for (let i = 0; i < 1000; i += 100) {
        const values = Array.from(
          { length: 100 },
          (_, j) => `(${i + j}, 'value${i + j}')`,
        )
        await db.exec(`INSERT INTO many_rows VALUES ${values.join(',')}`)
      }

      const result = await db.query(
        `SELECT COUNT(*)::int as count FROM many_rows`,
      )
      expect(result.rows[0]?.count).toBe(1000)

      await db.close()

      const { db: db2 } = await reopenEncryptedPGlite(testDir, salt)
      const result2 = await db2.query(
        `SELECT COUNT(*)::int as count FROM many_rows`,
      )
      expect(result2.rows[0]?.count).toBe(1000)
      await db2.close()
    })
  })

  describe('encryption verification', () => {
    it('data files are actually encrypted (not plaintext)', async () => {
      const { db } = await createEncryptedPGlite(testDir)

      const secretData = 'SUPER_SECRET_DATA_12345'
      await db.exec(`CREATE TABLE secret (data TEXT)`)
      await db.exec(`INSERT INTO secret VALUES ('${secretData}')`)
      await db.close()

      const dataFiles = findFiles(testDir, /^\d+$/)

      let foundPlaintext = false
      for (const file of dataFiles) {
        if (!verifyFileEncrypted(file, secretData)) {
          foundPlaintext = true
          break
        }
      }

      expect(foundPlaintext).toBe(false)
    })
  })

  describe('passphrase-only API', () => {
    it('creates and queries with passphrase only', async () => {
      const db = await createPassphrasePGlite(testDir)

      await db.exec('CREATE TABLE simple (id SERIAL PRIMARY KEY, name TEXT)')
      await db.exec("INSERT INTO simple (name) VALUES ('passphrase-test')")

      const result = await db.query('SELECT * FROM simple')
      expect(result.rows).toHaveLength(1)
      expect(result.rows[0]).toMatchObject({ name: 'passphrase-test' })

      await db.close()
    })

    it('data survives close and reopen with same passphrase', async () => {
      const passphrase = 'my-reopen-test'
      const db = await createPassphrasePGlite(testDir, passphrase)

      await db.exec('CREATE TABLE reopen (id SERIAL PRIMARY KEY, data TEXT)')
      await db.exec("INSERT INTO reopen (data) VALUES ('persisted')")
      await db.close()

      const db2 = await createPassphrasePGlite(testDir, passphrase)
      const result = await db2.query('SELECT * FROM reopen')
      expect(result.rows).toHaveLength(1)
      expect(result.rows[0]).toMatchObject({ data: 'persisted' })

      await db2.close()
    })

    it('rejects wrong passphrase on reopen', async () => {
      const db = await createPassphrasePGlite(testDir, 'correct')
      await db.close()

      expect(() => new EncryptedFS(testDir, 'wrong')).toThrow(
        /Invalid passphrase or corrupted encryption keys/,
      )
    })
  })
})
