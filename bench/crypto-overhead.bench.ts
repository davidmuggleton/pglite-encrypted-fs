import { describe, bench } from 'vitest'
import {
  encryptPage,
  decryptPage,
  deriveKeys,
  randomSalt,
  PAGE_SIZE,
} from '../src/index.js'
import { randomBytes } from 'crypto'

const salt = randomSalt()
const keys = deriveKeys('bench-passphrase', salt)
const fileId = randomBytes(32)
const plainPage = randomBytes(PAGE_SIZE)
const encryptedPage = encryptPage(plainPage, 0, keys, fileId)

describe('single page', () => {
  bench('encryptPage (8KB)', () => {
    encryptPage(plainPage, 0, keys, fileId)
  })

  bench('decryptPage (8KB)', () => {
    decryptPage(encryptedPage, 0, keys, fileId)
  })
})

describe('batch (100 pages)', () => {
  bench('encrypt 100 pages', () => {
    for (let i = 0; i < 100; i++) {
      encryptPage(plainPage, i, keys, fileId)
    }
  })

  bench('decrypt 100 pages', () => {
    const pages = Array.from({ length: 100 }, (_, i) =>
      encryptPage(plainPage, i, keys, fileId),
    )
    for (let i = 0; i < 100; i++) {
      decryptPage(pages[i], i, keys, fileId)
    }
  })
})

describe('key derivation', () => {
  bench(
    'deriveKeys (PBKDF2 256K iterations)',
    () => {
      const s = randomSalt()
      deriveKeys('bench-passphrase', s)
    },
    { iterations: 5, time: 0 },
  )
})
