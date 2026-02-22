import { describe, bench } from 'vitest'
import { PGlite } from '@electric-sql/pglite'
import { EncryptedFS } from '../src/index.js'
import { createTestDir, createEncryptedPGlite } from './helpers/bench-utils.js'

describe('fresh init', () => {
  bench(
    'plain - fresh init',
    async () => {
      const dir = createTestDir()
      const db = await PGlite.create({ dataDir: dir })
      await db.close()
    },
    { iterations: 3, warmupIterations: 1, time: 0 },
  )

  bench(
    'encrypted - fresh init',
    async () => {
      const dir = createTestDir()
      const { db } = await createEncryptedPGlite(dir, 'bench-passphrase')
      await db.close()
    },
    { iterations: 3, warmupIterations: 1, time: 0 },
  )
})

describe('reopen', () => {
  let plainDir: string
  let encDir: string

  bench(
    'plain - reopen',
    async () => {
      if (!plainDir) {
        plainDir = createTestDir()
        const db = await PGlite.create({ dataDir: plainDir })
        await db.close()
      }
      const db = await PGlite.create({ dataDir: plainDir })
      await db.close()
    },
    { iterations: 3, warmupIterations: 1, time: 0 },
  )

  bench(
    'encrypted - reopen',
    async () => {
      if (!encDir) {
        encDir = createTestDir()
        const { db } = await createEncryptedPGlite(encDir, 'bench-passphrase')
        await db.close()
      }
      const encFs = new EncryptedFS(encDir, 'bench-passphrase')
      const db = await PGlite.create({ dataDir: encDir, fs: encFs })
      await db.close()
    },
    { iterations: 3, warmupIterations: 1, time: 0 },
  )
})
