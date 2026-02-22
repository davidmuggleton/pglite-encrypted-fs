import { PGlite } from '@electric-sql/pglite'
import {
  createTestDir,
  cleanupTestDir,
  createEncryptedPGlite,
} from '../../test/helpers/test-utils.js'

export { createTestDir, cleanupTestDir, createEncryptedPGlite }

export interface BenchPair {
  plainDb: PGlite
  encDb: PGlite
  plainDir: string
  encDir: string
  cleanup: () => Promise<void>
}

/**
 * Creates a matched pair of plain and encrypted PGlite instances
 * with the same schema applied to both.
 */
export async function createBenchPair(
  schema: string,
  extensions?: Record<string, unknown>,
): Promise<BenchPair> {
  const plainDir = createTestDir()
  const encDir = createTestDir()

  const plainDb = await PGlite.create({
    dataDir: plainDir,
    ...(extensions ? { extensions } : {}),
  })

  const { db: encDb } = await createEncryptedPGlite(
    encDir,
    'bench-passphrase',
    extensions,
  )

  if (schema) {
    await plainDb.exec(schema)
    await encDb.exec(schema)
  }

  const cleanup = async () => {
    await plainDb.close()
    await encDb.close()
    cleanupTestDir(plainDir)
    cleanupTestDir(encDir)
  }

  return { plainDb, encDb, plainDir, encDir, cleanup }
}

/**
 * Generates a bulk INSERT statement with N rows of synthetic data.
 * Each row has an id (serial) and a text column of the given size.
 */
export function generateInsertSQL(
  table: string,
  count: number,
  textSize = 100,
): string {
  const text = 'x'.repeat(textSize)
  const values = Array.from({ length: count }, (_, i) => `('row_${i}_${text}')`)
  return `INSERT INTO ${table} (data) VALUES ${values.join(',')}`
}

/**
 * Generates a bulk INSERT with N rows of random vectors.
 */
export function generateVectorSQL(
  table: string,
  count: number,
  dims: number,
): string {
  const rows: string[] = []
  for (let i = 0; i < count; i++) {
    const vec = Array.from({ length: dims }, () =>
      (Math.random() * 2 - 1).toFixed(6),
    )
    rows.push(`('[${vec.join(',')}]')`)
  }
  return `INSERT INTO ${table} (embedding) VALUES ${rows.join(',')}`
}
