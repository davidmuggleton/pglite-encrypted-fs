import { describe, bench } from 'vitest'
import { createBenchPair, generateInsertSQL } from './helpers/bench-utils.js'

const SCHEMA = `
  CREATE TABLE bench_data (
    id SERIAL PRIMARY KEY,
    data TEXT NOT NULL
  );
  CREATE INDEX idx_bench_data ON bench_data (id);
`

const pair = await createBenchPair(SCHEMA)
const seedSQL = generateInsertSQL('bench_data', 1000)
await pair.plainDb.exec(seedSQL)
await pair.encDb.exec(seedSQL)

describe('insert', () => {
  bench('plain - insert 100 rows', async () => {
    await pair.plainDb.exec('TRUNCATE bench_data')
    for (let i = 0; i < 100; i++) {
      await pair.plainDb.exec(
        `INSERT INTO bench_data (data) VALUES ('row_${i}')`,
      )
    }
  })

  bench('encrypted - insert 100 rows', async () => {
    await pair.encDb.exec('TRUNCATE bench_data')
    for (let i = 0; i < 100; i++) {
      await pair.encDb.exec(`INSERT INTO bench_data (data) VALUES ('row_${i}')`)
    }
  })
})

describe('bulk insert', () => {
  bench('plain - bulk insert 1000 rows', async () => {
    await pair.plainDb.exec('TRUNCATE bench_data')
    const sql = generateInsertSQL('bench_data', 1000)
    await pair.plainDb.exec(sql)
  })

  bench('encrypted - bulk insert 1000 rows', async () => {
    await pair.encDb.exec('TRUNCATE bench_data')
    const sql = generateInsertSQL('bench_data', 1000)
    await pair.encDb.exec(sql)
  })
})

describe('insert large text', () => {
  bench('plain - insert large text (10KB x 50)', async () => {
    await pair.plainDb.exec('TRUNCATE bench_data')
    const sql = generateInsertSQL('bench_data', 50, 10240)
    await pair.plainDb.exec(sql)
  })

  bench('encrypted - insert large text (10KB x 50)', async () => {
    await pair.encDb.exec('TRUNCATE bench_data')
    const sql = generateInsertSQL('bench_data', 50, 10240)
    await pair.encDb.exec(sql)
  })
})

describe('select rows', () => {
  bench('plain - select 1000 rows', async () => {
    await pair.plainDb.exec('SELECT * FROM bench_data')
  })

  bench('encrypted - select 1000 rows', async () => {
    await pair.encDb.exec('SELECT * FROM bench_data')
  })
})

describe('select with index', () => {
  bench('plain - select with index', async () => {
    await pair.plainDb.exec(
      'SELECT * FROM bench_data WHERE id BETWEEN 100 AND 200',
    )
  })

  bench('encrypted - select with index', async () => {
    await pair.encDb.exec(
      'SELECT * FROM bench_data WHERE id BETWEEN 100 AND 200',
    )
  })
})

describe('aggregate', () => {
  bench('plain - aggregate (COUNT/SUM)', async () => {
    await pair.plainDb.exec('SELECT COUNT(*), SUM(id) FROM bench_data')
  })

  bench('encrypted - aggregate (COUNT/SUM)', async () => {
    await pair.encDb.exec('SELECT COUNT(*), SUM(id) FROM bench_data')
  })
})

describe('mixed CRUD', () => {
  bench('plain - mixed CRUD cycle', async () => {
    await pair.plainDb.exec(
      "INSERT INTO bench_data (data) VALUES ('crud_test')",
    )
    const res = await pair.plainDb.query<{ id: number }>(
      "SELECT id FROM bench_data WHERE data = 'crud_test' LIMIT 1",
    )
    if (res.rows.length > 0) {
      const id = res.rows[0].id
      await pair.plainDb.exec(
        `UPDATE bench_data SET data = 'updated' WHERE id = ${id}`,
      )
      await pair.plainDb.exec(`DELETE FROM bench_data WHERE id = ${id}`)
    }
  })

  bench('encrypted - mixed CRUD cycle', async () => {
    await pair.encDb.exec("INSERT INTO bench_data (data) VALUES ('crud_test')")
    const res = await pair.encDb.query<{ id: number }>(
      "SELECT id FROM bench_data WHERE data = 'crud_test' LIMIT 1",
    )
    if (res.rows.length > 0) {
      const id = res.rows[0].id
      await pair.encDb.exec(
        `UPDATE bench_data SET data = 'updated' WHERE id = ${id}`,
      )
      await pair.encDb.exec(`DELETE FROM bench_data WHERE id = ${id}`)
    }
  })
})
