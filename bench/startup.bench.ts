import { describe, bench } from 'vitest'
import { PGlite } from '@electric-sql/pglite'
import { createTestDir, createEncryptedPGlite } from './helpers/bench-utils.js'
import { reopenEncryptedPGlite } from '../test/helpers/test-utils.js'

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
  let encSalt: Buffer

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
        const { salt } = await createEncryptedPGlite(encDir, 'bench-passphrase')
        encSalt = salt
        const { db } = await reopenEncryptedPGlite(
          encDir,
          encSalt,
          'bench-passphrase',
        )
        await db.close()
      }
      const { db } = await reopenEncryptedPGlite(
        encDir,
        encSalt,
        'bench-passphrase',
      )
      await db.close()
    },
    { iterations: 3, warmupIterations: 1, time: 0 },
  )
})
