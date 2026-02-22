import { describe, bench } from 'vitest'
import { vector } from '@electric-sql/pglite/vector'
import { createBenchPair, generateVectorSQL } from './helpers/bench-utils.js'

const SCHEMA = `
  CREATE EXTENSION IF NOT EXISTS vector;
  CREATE TABLE vec3 (
    id SERIAL PRIMARY KEY,
    embedding vector(3) NOT NULL
  );
  CREATE TABLE vec1536 (
    id SERIAL PRIMARY KEY,
    embedding vector(1536) NOT NULL
  );
`

const pair = await createBenchPair(SCHEMA, { vector })

const seed3 = generateVectorSQL('vec3', 500, 3)
await pair.plainDb.exec(seed3)
await pair.encDb.exec(seed3)

const seed1536 = generateVectorSQL('vec1536', 500, 1536)
await pair.plainDb.exec(seed1536)
await pair.encDb.exec(seed1536)

describe('vector insert', () => {
  bench('plain - insert 100 vectors (3-dim)', async () => {
    await pair.plainDb.exec('TRUNCATE vec3')
    const sql = generateVectorSQL('vec3', 100, 3)
    await pair.plainDb.exec(sql)
  })

  bench('encrypted - insert 100 vectors (3-dim)', async () => {
    await pair.encDb.exec('TRUNCATE vec3')
    const sql = generateVectorSQL('vec3', 100, 3)
    await pair.encDb.exec(sql)
  })

  bench('plain - insert 50 vectors (1536-dim)', async () => {
    await pair.plainDb.exec('TRUNCATE vec1536')
    const sql = generateVectorSQL('vec1536', 50, 1536)
    await pair.plainDb.exec(sql)
  })

  bench('encrypted - insert 50 vectors (1536-dim)', async () => {
    await pair.encDb.exec('TRUNCATE vec1536')
    const sql = generateVectorSQL('vec1536', 50, 1536)
    await pair.encDb.exec(sql)
  })
})

describe('similarity search', () => {
  bench('plain - L2 distance search (3-dim, top 10)', async () => {
    await pair.plainDb.exec(
      "SELECT * FROM vec3 ORDER BY embedding <-> '[0.1, 0.2, 0.3]' LIMIT 10",
    )
  })

  bench('encrypted - L2 distance search (3-dim, top 10)', async () => {
    await pair.encDb.exec(
      "SELECT * FROM vec3 ORDER BY embedding <-> '[0.1, 0.2, 0.3]' LIMIT 10",
    )
  })

  bench('plain - cosine distance search (1536-dim, top 10)', async () => {
    const queryVec = Array.from({ length: 1536 }, () =>
      (Math.random() * 2 - 1).toFixed(6),
    )
    await pair.plainDb.exec(
      `SELECT * FROM vec1536 ORDER BY embedding <=> '[${queryVec.join(',')}]' LIMIT 10`,
    )
  })

  bench('encrypted - cosine distance search (1536-dim, top 10)', async () => {
    const queryVec = Array.from({ length: 1536 }, () =>
      (Math.random() * 2 - 1).toFixed(6),
    )
    await pair.encDb.exec(
      `SELECT * FROM vec1536 ORDER BY embedding <=> '[${queryVec.join(',')}]' LIMIT 10`,
    )
  })
})

describe('index creation', () => {
  bench(
    'plain - create HNSW index (500 x 3-dim)',
    async () => {
      await pair.plainDb.exec('DROP INDEX IF EXISTS idx_vec3_hnsw')
      await pair.plainDb.exec(
        'CREATE INDEX idx_vec3_hnsw ON vec3 USING hnsw (embedding vector_l2_ops)',
      )
    },
    { iterations: 3, time: 0 },
  )

  bench(
    'encrypted - create HNSW index (500 x 3-dim)',
    async () => {
      await pair.encDb.exec('DROP INDEX IF EXISTS idx_vec3_hnsw')
      await pair.encDb.exec(
        'CREATE INDEX idx_vec3_hnsw ON vec3 USING hnsw (embedding vector_l2_ops)',
      )
    },
    { iterations: 3, time: 0 },
  )
})
