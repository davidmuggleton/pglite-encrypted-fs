import { describe, it, expect, beforeEach, afterEach } from 'vitest'
import { PGlite } from '@electric-sql/pglite'
import { vector } from '@electric-sql/pglite/vector'
import {
  createTestDir,
  cleanupTestDir,
  createEncryptedFS,
  createEncryptedFSWithSalt,
} from '../helpers/test-utils.js'

describe('PGlite pgvector Integration', () => {
  let testDir: string

  beforeEach(() => {
    testDir = createTestDir()
  })

  afterEach(() => {
    cleanupTestDir(testDir)
  })

  async function createVectorDB(
    dataDir: string,
    passphrase = 'test-passphrase',
  ) {
    const { fs: encFs, salt, keys } = createEncryptedFS(dataDir, passphrase)
    const db = await PGlite.create({
      dataDir,
      fs: encFs,
      extensions: { vector },
    })
    return { db, salt, keys }
  }

  async function reopenVectorDB(
    dataDir: string,
    salt: Buffer,
    passphrase = 'test-passphrase',
  ) {
    const { fs: encFs, keys } = createEncryptedFSWithSalt(
      dataDir,
      salt,
      passphrase,
    )
    const db = await PGlite.create({
      dataDir,
      fs: encFs,
      extensions: { vector },
    })
    return { db, keys }
  }

  describe('basic vector operations', () => {
    it('installs vector extension', async () => {
      const { db } = await createVectorDB(testDir)

      await db.exec('CREATE EXTENSION IF NOT EXISTS vector')
      const result = await db.query(
        `SELECT extname FROM pg_extension WHERE extname = 'vector'`,
      )
      expect(result.rows).toHaveLength(1)

      await db.close()
    })

    it('creates table with vector column', async () => {
      const { db } = await createVectorDB(testDir)

      await db.exec('CREATE EXTENSION IF NOT EXISTS vector')
      await db.exec(
        'CREATE TABLE embeddings (id SERIAL PRIMARY KEY, vec vector(3))',
      )

      const result = await db.query(`
        SELECT column_name, data_type
        FROM information_schema.columns
        WHERE table_name = 'embeddings' AND column_name = 'vec'
      `)
      expect(result.rows).toHaveLength(1)

      await db.close()
    })

    it('inserts and queries vector data', async () => {
      const { db } = await createVectorDB(testDir)

      await db.exec('CREATE EXTENSION IF NOT EXISTS vector')
      await db.exec('CREATE TABLE items (id INTEGER, embedding vector(3))')
      await db.exec(`
        INSERT INTO items VALUES
          (1, '[1,0,0]'),
          (2, '[0,1,0]'),
          (3, '[0,0,1]')
      `)

      const result = await db.query(
        'SELECT id, embedding::text FROM items ORDER BY id',
      )
      expect(result.rows).toHaveLength(3)
      expect(result.rows[0]).toMatchObject({ id: 1 })

      await db.close()
    })
  })

  describe('similarity search', () => {
    it('performs L2 distance search (<->)', async () => {
      const { db } = await createVectorDB(testDir)

      await db.exec('CREATE EXTENSION IF NOT EXISTS vector')
      await db.exec('CREATE TABLE docs (id INTEGER, embedding vector(3))')
      await db.exec(`
        INSERT INTO docs VALUES
          (1, '[1,0,0]'),
          (2, '[0,1,0]'),
          (3, '[0.9,0.1,0]')
      `)

      const result = await db.query(`
        SELECT id, embedding <-> '[1,0,0]' as distance
        FROM docs
        ORDER BY distance
        LIMIT 2
      `)

      expect(result.rows).toHaveLength(2)
      expect(result.rows[0]?.id).toBe(1)
      expect(result.rows[1]?.id).toBe(3)

      await db.close()
    })

    it('performs cosine distance search (<=>)', async () => {
      const { db } = await createVectorDB(testDir)

      await db.exec('CREATE EXTENSION IF NOT EXISTS vector')
      await db.exec('CREATE TABLE docs (id INTEGER, embedding vector(3))')
      await db.exec(`
        INSERT INTO docs VALUES
          (1, '[1,0,0]'),
          (2, '[0,1,0]'),
          (3, '[0.9,0.1,0]')
      `)

      const result = await db.query(`
        SELECT id, embedding <=> '[1,0,0]' as distance
        FROM docs
        ORDER BY distance
        LIMIT 2
      `)

      expect(result.rows).toHaveLength(2)
      expect(result.rows[0]?.id).toBe(1)
      expect(result.rows[1]?.id).toBe(3)

      await db.close()
    })

    it('performs inner product search (<#>)', async () => {
      const { db } = await createVectorDB(testDir)

      await db.exec('CREATE EXTENSION IF NOT EXISTS vector')
      await db.exec('CREATE TABLE docs (id INTEGER, embedding vector(3))')
      await db.exec(`
        INSERT INTO docs VALUES
          (1, '[1,0,0]'),
          (2, '[0,1,0]'),
          (3, '[2,0,0]')
      `)

      const result = await db.query(`
        SELECT id, embedding <#> '[1,0,0]' as neg_ip
        FROM docs
        ORDER BY neg_ip
        LIMIT 2
      `)

      expect(result.rows).toHaveLength(2)
      expect(result.rows[0]?.id).toBe(3)
      expect(result.rows[1]?.id).toBe(1)

      await db.close()
    })
  })

  describe('vector indexes', () => {
    it('creates IVFFlat index', async () => {
      const { db } = await createVectorDB(testDir)

      await db.exec('CREATE EXTENSION IF NOT EXISTS vector')
      await db.exec(
        'CREATE TABLE indexed_docs (id INTEGER, embedding vector(3))',
      )

      for (let i = 0; i < 100; i++) {
        await db.exec(
          `INSERT INTO indexed_docs VALUES (${i}, '[${Math.random()},${Math.random()},${Math.random()}]')`,
        )
      }

      await db.exec(`
        CREATE INDEX idx_ivfflat ON indexed_docs
        USING ivfflat (embedding vector_l2_ops)
        WITH (lists = 10)
      `)

      const result = await db.query(`
        SELECT indexname FROM pg_indexes WHERE indexname = 'idx_ivfflat'
      `)
      expect(result.rows).toHaveLength(1)

      await db.close()
    })

    it('creates HNSW index', async () => {
      const { db } = await createVectorDB(testDir)

      await db.exec('CREATE EXTENSION IF NOT EXISTS vector')
      await db.exec('CREATE TABLE hnsw_docs (id INTEGER, embedding vector(3))')

      for (let i = 0; i < 50; i++) {
        await db.exec(
          `INSERT INTO hnsw_docs VALUES (${i}, '[${Math.random()},${Math.random()},${Math.random()}]')`,
        )
      }

      await db.exec(`
        CREATE INDEX idx_hnsw ON hnsw_docs
        USING hnsw (embedding vector_l2_ops)
        WITH (m = 16, ef_construction = 64)
      `)

      const result = await db.query(`
        SELECT indexname FROM pg_indexes WHERE indexname = 'idx_hnsw'
      `)
      expect(result.rows).toHaveLength(1)

      await db.close()
    })

    it('query uses index (no error)', async () => {
      const { db } = await createVectorDB(testDir)

      await db.exec('CREATE EXTENSION IF NOT EXISTS vector')
      await db.exec(
        'CREATE TABLE search_docs (id INTEGER, embedding vector(3))',
      )

      for (let i = 0; i < 50; i++) {
        await db.exec(
          `INSERT INTO search_docs VALUES (${i}, '[${Math.random()},${Math.random()},${Math.random()}]')`,
        )
      }

      await db.exec(`
        CREATE INDEX idx_search ON search_docs
        USING hnsw (embedding vector_l2_ops)
      `)

      await db.exec('SET hnsw.ef_search = 40')
      const result = await db.query(`
        SELECT id FROM search_docs
        ORDER BY embedding <-> '[0.5, 0.5, 0.5]'
        LIMIT 5
      `)

      expect(result.rows).toHaveLength(5)

      await db.close()
    })
  })

  describe('persistence', () => {
    it('vector data survives restart', async () => {
      const { db, salt } = await createVectorDB(testDir)

      await db.exec('CREATE EXTENSION IF NOT EXISTS vector')
      await db.exec(
        'CREATE TABLE persist_vectors (id INTEGER, embedding vector(3))',
      )
      await db.exec(`
        INSERT INTO persist_vectors VALUES
          (1, '[1,2,3]'),
          (2, '[4,5,6]')
      `)
      await db.close()

      const { db: db2 } = await reopenVectorDB(testDir, salt)

      const result = await db2.query(
        'SELECT id FROM persist_vectors ORDER BY id',
      )
      expect(result.rows).toHaveLength(2)
      expect(result.rows[0]?.id).toBe(1)
      expect(result.rows[1]?.id).toBe(2)

      await db2.close()
    })

    it('extension remains loaded after restart', async () => {
      const { db, salt } = await createVectorDB(testDir)

      await db.exec('CREATE EXTENSION IF NOT EXISTS vector')
      await db.exec('CREATE TABLE ext_test (id INTEGER, embedding vector(3))')
      await db.close()

      const { db: db2 } = await reopenVectorDB(testDir, salt)

      const result = await db2.query(
        `SELECT extname FROM pg_extension WHERE extname = 'vector'`,
      )
      expect(result.rows).toHaveLength(1)

      await db2.exec(`INSERT INTO ext_test VALUES (1, '[1,1,1]')`)
      const data = await db2.query('SELECT * FROM ext_test')
      expect(data.rows).toHaveLength(1)

      await db2.close()
    })

    it('vector indexes survive restart', async () => {
      const { db, salt } = await createVectorDB(testDir)

      await db.exec('CREATE EXTENSION IF NOT EXISTS vector')
      await db.exec(
        'CREATE TABLE idx_persist (id INTEGER, embedding vector(3))',
      )

      for (let i = 0; i < 50; i++) {
        await db.exec(
          `INSERT INTO idx_persist VALUES (${i}, '[${Math.random()},${Math.random()},${Math.random()}]')`,
        )
      }

      await db.exec(`
        CREATE INDEX idx_persist_hnsw ON idx_persist
        USING hnsw (embedding vector_l2_ops)
      `)
      await db.close()

      const { db: db2 } = await reopenVectorDB(testDir, salt)

      const result = await db2.query(`
        SELECT indexname FROM pg_indexes WHERE indexname = 'idx_persist_hnsw'
      `)
      expect(result.rows).toHaveLength(1)

      const search = await db2.query(`
        SELECT id FROM idx_persist
        ORDER BY embedding <-> '[0.5,0.5,0.5]'
        LIMIT 3
      `)
      expect(search.rows).toHaveLength(3)

      await db2.close()
    })

    it('similarity search works after restart', async () => {
      const { db, salt } = await createVectorDB(testDir)

      await db.exec('CREATE EXTENSION IF NOT EXISTS vector')
      await db.exec(
        'CREATE TABLE search_persist (id INTEGER, embedding vector(3))',
      )
      await db.exec(`
        INSERT INTO search_persist VALUES
          (1, '[1,0,0]'),
          (2, '[0,1,0]'),
          (3, '[0,0,1]')
      `)
      await db.close()

      const { db: db2 } = await reopenVectorDB(testDir, salt)

      const result = await db2.query(`
        SELECT id FROM search_persist
        ORDER BY embedding <-> '[1,0,0]'
        LIMIT 1
      `)
      expect(result.rows[0]?.id).toBe(1)

      await db2.close()
    })
  })

  describe('high dimensions', () => {
    it('handles 1536-dimension vectors (OpenAI embedding size)', async () => {
      const { db, salt } = await createVectorDB(testDir)

      await db.exec('CREATE EXTENSION IF NOT EXISTS vector')
      await db.exec(
        'CREATE TABLE openai_embeddings (id INTEGER, embedding vector(1536))',
      )

      const vec1 = Array.from({ length: 1536 }, () => Math.random())
      const vec2 = Array.from({ length: 1536 }, () => Math.random())

      await db.query(`INSERT INTO openai_embeddings VALUES (1, $1)`, [
        `[${vec1.join(',')}]`,
      ])
      await db.query(`INSERT INTO openai_embeddings VALUES (2, $1)`, [
        `[${vec2.join(',')}]`,
      ])

      const result = await db.query(
        'SELECT COUNT(*)::int as count FROM openai_embeddings',
      )
      expect(result.rows[0]?.count).toBe(2)

      await db.close()

      const { db: db2 } = await reopenVectorDB(testDir, salt)
      const result2 = await db2.query(
        'SELECT COUNT(*)::int as count FROM openai_embeddings',
      )
      expect(result2.rows[0]?.count).toBe(2)

      const search = await db2.query(
        `
        SELECT id FROM openai_embeddings
        ORDER BY embedding <-> $1
        LIMIT 1
      `,
        [`[${vec1.join(',')}]`],
      )
      expect(search.rows[0]?.id).toBe(1)

      await db2.close()
    })
  })
})
